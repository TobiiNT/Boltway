using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Abstractions.Stores;

/// <summary>
/// Timing bounds every store implementation shares.
/// </summary>
/// <remarks>
/// <para>
/// Both grace windows are bounded below for the same reason: <c>now</c> comes from the caller and
/// this server runs as several instances, so a fast clock stamping a consumption in the future would
/// stretch a bounded window into an arbitrary one.
/// </para>
/// <para>
/// <b>Public, and in the contract assembly, because that is what makes it one definition.</b> It
/// lived as an <see langword="internal"/> constant inside <c>Boltway.Storage.InMemory</c>, which
/// grants <c>InternalsVisibleTo</c> to nobody - under a comment reading "one definition rather than
/// one per store … two copies of that number would eventually differ". An operability review pointed
/// out the obvious consequence: any SQL store, in this repo or a customer's, had no way to read it
/// and would have to retype it, so the divergence the comment warned against was guaranteed by the
/// accessibility rather than merely possible.
/// </para>
/// </remarks>
public static class GraceWindows
{
    /// <summary>How far a caller's clock may run ahead before its timestamps stop being believed.</summary>
    /// <remarks>
    /// Five seconds. A known-tight number for a fleet, and the failure direction is unpleasant: a
    /// benign transport retry arriving from an instance whose clock is further out than this reads
    /// as <c>ReplayedOutsideGrace</c>, which revokes the grant - a forced sign-out attributable to
    /// nothing the user or the client did. Measured: a node 6 s fast plus a 1 s-later retry lands
    /// 1 ms past the bound. Raising it widens the window in which a genuinely replayed credential is
    /// tolerated, so it is a real tradeoff rather than free headroom.
    /// </remarks>
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long a redeemed authorization code is kept after it has expired.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The sweeper deletes on expiry, and a code is redeemed whenever consent finishes - often in
    /// the last seconds of the minute it lives. The retry window starts at redemption rather than at
    /// issue, so it routinely outlives the code, and sweeping on expiry alone removes the row while
    /// the window it was written for is still open. That undoes N-07 one call later: a retry then
    /// presents a hash the store has no memory of, and an unknown hash is
    /// <see cref="CodeRedemption.ReplayedOutsideGrace"/>, which is the answer a caller revokes on.
    /// </para>
    /// <para>
    /// Not hypothetical. Measured over three runs of 200 attempts against the previous sweeper:
    /// 189, 197 and 183 ended with a redemption reporting <see cref="CodeRedemption.Redeemed"/> onto
    /// a row that had already been swept. No race was needed to produce it.
    /// </para>
    /// <para>
    /// What it buys is bounded, and stating the bound is the point: it covers a <c>graceWindow</c>
    /// up to this long. A caller passing <c>RedeemAsync</c> a longer one gets no promise from the
    /// sweeper once the code has also expired. This server's own code path uses ten seconds.
    /// </para>
    /// </remarks>
    public static readonly TimeSpan RedeemedRetention = TimeSpan.FromMinutes(5);
}

/// <summary>
/// Stores authorization codes.
/// </summary>
/// <remarks>
/// Thin, except where the atomicity <i>is</i> the requirement. <see cref="RedeemAsync"/> is not
/// a "find then update" helper a caller could assemble from the other two methods: the
/// check-and-mark has to be one operation, and whether it is depends on the database. Exposing
/// find and update separately would leave every store implementation to be raced correctly by
/// whoever wrote it.
/// </remarks>
public interface IAuthorizationCodeStore
{
    /// <summary>Persist a newly issued code. <b>Add-only.</b></summary>
    /// <exception cref="InvalidOperationException">
    /// A code with this hash already exists. Overwriting would clear its redemption and make it
    /// redeemable again, resetting N-07's replay protection - and a relational store's primary key
    /// throws here, so tolerating it would make two implementations disagree on identical input.
    /// </exception>
    Task StoreAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken);

    /// <summary>
    /// Find a code by hash, <b>including one already redeemed</b>.
    /// </summary>
    /// <remarks>
    /// Returning redeemed rows is the point. N-07 requires a replayed code to be validated in full
    /// - client binding, redirect URI, PKCE - <i>before</i> anything is revoked, and none of that
    /// is possible against a row that was deleted on first use. The alternative, revoking on the
    /// mere fact of a second presentation, is a denial of service: an attacker who sniffed a code
    /// but holds no verifier could kill the legitimate client's tokens at will.
    /// </remarks>
    Task<AuthorizationCodeRecord?> FindAsync(Sha256Hash codeHash, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically redeem a code, distinguishing a retry from a replay.
    /// </summary>
    /// <param name="codeHash">Which code.</param>
    /// <param name="now">Current time.</param>
    /// <param name="graceWindow">
    /// How long after redemption a second presentation is a retry rather than a replay. Bounded
    /// below against clock skew the same way the refresh window is: <paramref name="now"/> comes
    /// from the caller and this server runs as several instances.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// <para>
    /// The answer is the authority and it must come from the number of rows the update actually
    /// changed - not from a preceding read. Two simultaneous redemptions of one code must produce
    /// exactly one <see cref="CodeRedemption.Redeemed"/>, whatever the interleaving.
    /// </para>
    /// <para>
    /// Call this <b>last</b>, after every other check has passed, so
    /// <see cref="CodeRedemption.ReplayedOutsideGrace"/> means a presenter who holds the client
    /// authentication and the verifier - the evidence §7.5.2 requires before revoking.
    /// </para>
    /// <para>
    /// <b>Expiry is deliberately not checked here, and must not be added.</b> Folding it in would
    /// send an expired code down the revoke path, which is exactly the denial of service N-07
    /// exists to prevent. Expiry is the caller's check, after <see cref="FindAsync"/>.
    /// </para>
    /// </remarks>
    Task<CodeRedemption> RedeemAsync(
        Sha256Hash codeHash, DateTimeOffset now, TimeSpan graceWindow, CancellationToken cancellationToken);

    /// <summary>Delete codes past their expiry. Housekeeping, not a protocol operation.</summary>
    /// <remarks>
    /// <b>A redeemed code must survive its expiry for long enough to answer a retry.</b> Codes live
    /// about a minute and are redeemed whenever consent finishes, so redemption in the last seconds
    /// of that minute is ordinary - and the retry window opens at redemption, not at issue, so it
    /// routinely outlives the code. Sweeping on expiry alone therefore undoes
    /// <see cref="RedeemAsync"/> one call later: the retry presents a hash the store no longer
    /// knows, and an unknown hash is <see cref="CodeRedemption.ReplayedOutsideGrace"/>, which is the
    /// answer a caller revokes the grant on. An unredeemed code has no such window and goes as soon
    /// as it expires.
    /// </remarks>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>
/// Stores refresh tokens, and owns the rotation decision.
/// </summary>
/// <remarks>
/// <para>
/// The conventional shape here would be a thin store - <c>Find</c>, <c>Update</c>, <c>Add</c> -
/// with the rotation logic in a service above it. That is rejected deliberately.
/// </para>
/// <para>
/// The bug this design is guarding against is a race, and the race is only resolvable where the
/// atomicity lives. With a thin store, every implementation has to be raced correctly by whoever
/// wrote it, and the specific failure - two concurrent redemptions each minting a successor, so the
/// family forks and reuse detection stops working - is a known CVE class rather than a
/// hypothetical. Putting the decision behind a four-case result means a store <i>has</i> to answer
/// the question the protocol asks.
/// </para>
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Find a token by hash, <b>including a consumed one</b>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Needed because the client-binding check must happen <i>before</i> redemption, and redemption
    /// is the only other read. Without this the token endpoint has two choices, and both are wrong:
    /// skip the binding check that RFC 6749 §6 requires - "ensure that the refresh token was issued
    /// to the authenticated client" - or redeem first and check afterwards, which consumes a
    /// legitimate user's token on a request made by the wrong client. The second is the same denial
    /// of service that N-07 exists to prevent on the authorization-code path, arriving by a
    /// different route.
    /// </para>
    /// <para>
    /// Consumed rows are returned for the same reason redeemed codes are: the caller has to be able
    /// to validate a presentation fully before deciding what it was.
    /// </para>
    /// </remarks>
    Task<RefreshTokenRecord?> FindAsync(Sha256Hash tokenHash, CancellationToken cancellationToken);

    /// <summary>Persist the first refresh token of a family. <b>Add-only.</b></summary>
    /// <exception cref="InvalidOperationException">
    /// A token with this hash already exists. Overwriting would clear its consumption and let the
    /// parent rotate a second time - two live successors with one predecessor, which is the family
    /// fork this design exists to prevent.
    /// </exception>
    Task StoreAsync(RefreshTokenRecord record, CancellationToken cancellationToken);

    /// <summary>
    /// Redeem a refresh token, rotating it.
    /// </summary>
    /// <param name="presented">Hash of the token the client sent.</param>
    /// <param name="successor">What to persist if this rotates normally.</param>
    /// <param name="now">Current time.</param>
    /// <param name="graceWindow">
    /// How long after consumption a repeat presentation is treated as a retry rather than a reuse.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// <para>
    /// <b>Exactly one successor per parent, ever.</b> Inside the grace window the caller gets the
    /// successor that already exists; it is never given a second one.
    /// </para>
    /// <para>
    /// <b>The grace answer requires the successor to be unconsumed and unexpired.</b> An
    /// implementation that checks only that the successor <i>exists</i> lets an attacker walk the
    /// chain: replaying a stolen token returns the next one, whose own consumption is more recent,
    /// so every subsequent hop is also inside the window - the walk reaches the live head and
    /// <see cref="RefreshRedemption.ReuseDetected"/> is never raised. A consumed successor means
    /// the chain has moved on, so the presentation is a genuine replay.
    /// </para>
    /// <para>
    /// <b>The window is bounded below as well as above.</b> <paramref name="now"/> comes from the
    /// caller and this server runs as several instances, so a fast clock stamping a consumption in
    /// the future would otherwise turn a 45-second window into an arbitrarily long one.
    /// </para>
    /// <para>
    /// <b>Rows are never deleted on revocation.</b> Replaying a consumed token from a revoked
    /// family must still report <see cref="RefreshRedemption.ReuseDetected"/> rather than
    /// <see cref="RefreshRedemption.NotFound"/>, or a thief learns that nothing was noticed.
    /// </para>
    /// </remarks>
    Task<RefreshRedemption> RedeemAsync(
        Sha256Hash presented,
        RefreshTokenSeed successor,
        DateTimeOffset now,
        TimeSpan graceWindow,
        CancellationToken cancellationToken);

    /// <summary>Revoke every token in a family. Called on reuse detection.</summary>
    /// <returns>
    /// How many tokens <b>this call</b> transitioned, so a second revoke returns zero. Counting
    /// every row in the family, consumed and expired ones included, gives a number no caller can
    /// act on.
    /// </returns>
    Task<int> RevokeFamilyAsync(string familyId, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// When each of these grants last produced a refresh token.
    /// </summary>
    /// <param name="grantIds">Which grants to ask about. An empty set answers empty.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// One entry per grant that has ever issued a refresh token, holding the newest
    /// <see cref="RefreshTokenRecord.IssuedAt"/> among its tokens. <b>A grant with no entry is
    /// absent from the dictionary rather than present with a default</b>, so a caller cannot
    /// mistake "never refreshed" for "refreshed at the epoch".
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>What this is, and the name is chosen to stop it being read as more.</b> It is the last
    /// time this grant <i>minted</i> a token, which is the strongest liveness signal an
    /// authorization server has about a session it does not sit in front of. Access tokens are
    /// signed rather than looked up, so the resource server never asks us anything and a call made
    /// with an existing token is invisible here. "Last active" would therefore be a claim about
    /// activity this process cannot see; "last refreshed" is a claim about a row it wrote.
    /// </para>
    /// <para>
    /// <b>Granularity is one access-token lifetime, and that is a property of the answer rather
    /// than a limitation to fix.</b> A client refreshing on a 30-minute token appears here every
    /// 25 minutes or so; a session abandoned five minutes after its last refresh looks identical to
    /// one still in use. A surface showing this has to say which of the two it is showing.
    /// </para>
    /// <para>
    /// <b>Batched, because the caller that wants it holds a list.</b> The sessions page reads every
    /// grant a person has and then wants this for each - one call per grant is the shape that is
    /// fine with three sessions and is a page of round trips with thirty, discovered by whoever has
    /// the most.
    /// </para>
    /// <para>
    /// <b>Consumed and revoked rows count.</b> The question is when the grant last did something,
    /// not whether the token from that moment is still usable - and every token but the newest in a
    /// live family is consumed by definition, so excluding them would report the wrong moment for
    /// every session that has ever rotated.
    /// </para>
    /// </remarks>
    Task<IReadOnlyDictionary<string, DateTimeOffset>> LastIssuedForGrantsAsync(
        IReadOnlyCollection<string> grantIds, CancellationToken cancellationToken);
}

/// <summary>Stores grants, and the revocation denylist a resource server consults.</summary>
public interface IGrantStore
{
    /// <summary>Persist a new grant.</summary>
    Task StoreAsync(GrantRecord grant, CancellationToken cancellationToken);

    /// <summary>
    /// Every distinct <c>User-Agent</c> this subject has ever approved from.
    /// </summary>
    /// <param name="subject">Whose grants.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// The distinct non-empty headers, in no particular order. Empty when this subject has never
    /// approved anything, or approved only from clients that sent no header.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Every grant, revoked ones included, and that is the difference from
    /// <see cref="ListForSubjectAsync"/>.</b> This answers "has this person approved from here
    /// before", and a device does not stop having been used because the session it was used for was
    /// ended. Reading the active list instead would call somebody's own laptop new the first time
    /// they signed out of everything and reconnected - which is a false alarm delivered by mail, on
    /// the one channel whose value is that its messages are rare.
    /// </para>
    /// <para>
    /// <b>Raw headers, not descriptions.</b> <c>ApprovingDevice</c> keeps the interpretation out of
    /// the store because interpretations improve, and a stored phrase would freeze every old row at
    /// whatever the parser believed the day it was written. The caller describes both sides and
    /// compares those, so a better parser improves the comparison for rows already written.
    /// </para>
    /// <para>
    /// <b>Distinct in the store rather than in the caller.</b> An account that has approved a
    /// hundred times has a handful of devices, and this is read on the authorization path.
    /// </para>
    /// </remarks>
    Task<IReadOnlyList<string>> ListApprovedUserAgentsAsync(
        SubjectId subject, CancellationToken cancellationToken);

    /// <summary>Find a grant.</summary>
    Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken);

    /// <summary>
    /// Revoke a grant and everything descended from it.
    /// </summary>
    /// <remarks>
    /// RFC 7009 §2.1: revoking a refresh token SHOULD revoke the access tokens issued from it.
    /// Access tokens are self-contained JWTs, so "revoking" one means recording the grant id here
    /// and having the resource server refuse tokens carrying it - which is why the access token
    /// carries a grant id at all.
    /// </remarks>
    /// <returns>
    /// Whether this call performed the revocation. Revoking an unknown or already-revoked grant
    /// returns <see langword="false"/> rather than succeeding silently: a caller reacting to reuse
    /// detection needs to know the revocation actually landed.
    /// </returns>
    Task<bool> RevokeAsync(string grantId, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// Revoke every grant this subject holds. "Sign this person out of everything."
    /// </summary>
    /// <param name="subject">Whose grants.</param>
    /// <param name="now">When the revocation happened.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>
    /// How many grants <b>this call</b> transitioned, so a second call returns zero. The same shape
    /// as <see cref="IRefreshTokenStore.RevokeFamilyAsync"/>, and for the same reason: a count that
    /// included already-revoked grants would be a number no caller could act on.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>By subject, on the grants, and not by a subject column on the refresh rows.</b> The link
    /// already exists in the schema - refresh rows carry a grant id and grants carry the subject -
    /// so what was missing was a method, not a column. Denormalising the subject onto refresh rows
    /// would have been a second copy of a fact, kept in step by nothing.
    /// </para>
    /// <para>
    /// <b>A set operation rather than enumerate-then-revoke, and that is the security-relevant
    /// part.</b> Reading the grants and revoking them one at a time leaves a window in which a grant
    /// created in between is missed - and the moment this is called is exactly the moment somebody
    /// is responding to a compromise. One statement has no such window.
    /// </para>
    /// <para>
    /// <b>What this does and does not reach.</b> Refresh tokens stop working immediately: the
    /// refresh handler loads the grant and refuses when it is not active, so the whole chain dies
    /// with it. <b>Access tokens already issued keep working until they expire</b> - they are signed
    /// rather than looked up, and <see cref="IsRevokedAsync"/> exists for a resource server to
    /// consult and, measured across this repository, nothing calls it. A caller telling somebody
    /// "you are signed out everywhere" is overstating it by one token lifetime.
    /// </para>
    /// </remarks>
    Task<int> RevokeAllForSubjectAsync(
        SubjectId subject, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// Every grant this subject currently holds. "What am I signed in to?"
    /// </summary>
    /// <param name="subject">Whose grants.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The active grants, newest first. Empty when there are none.</returns>
    /// <remarks>
    /// <para>
    /// <b>The read half of <see cref="RevokeAllForSubjectAsync"/>, added separately and later on
    /// purpose.</b> That method revokes as one statement rather than enumerating, because the moment
    /// it is called is the moment somebody is responding to a compromise and a
    /// read-then-write-each-one leaves a window. This is the case where a <i>view</i> is the whole
    /// requirement - <c>E-35</c>, a person looking at their own sessions - and a view has no window
    /// to leave. Two methods because they are two operations, not one method used two ways.
    /// </para>
    /// <para>
    /// <b>Active only.</b> A revoked grant is not a session, and rows are never deleted on
    /// revocation - <see cref="IRefreshTokenStore.RedeemAsync"/> explains why - so returning
    /// everything would grow this list for the life of the account with entries whose only honest
    /// rendering is "ended". A caller wanting the history wants the audit log.
    /// </para>
    /// <para>
    /// <b>Newest first, and unpaged.</b> One row per (user, client, authorization): a person has
    /// tens of these, not thousands, and the surface that reads it acts on one account. If that ever
    /// stops being true this gains a cursor the way <c>IUserStore.ListAsync</c> has one - keyset,
    /// never <c>OFFSET</c>.
    /// </para>
    /// </remarks>
    Task<IReadOnlyList<GrantRecord>> ListForSubjectAsync(
        SubjectId subject, CancellationToken cancellationToken);

    /// <summary>Whether a grant has been revoked. The denylist check.</summary>
    Task<bool> IsRevokedAsync(string grantId, CancellationToken cancellationToken);
}
