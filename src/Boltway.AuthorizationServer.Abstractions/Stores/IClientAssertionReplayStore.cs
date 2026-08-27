using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Abstractions.Stores;

/// <summary>
/// Remembers the <c>jti</c> of every client assertion accepted, so none is accepted twice.
/// RFC 7523 §3.
/// </summary>
/// <remarks>
/// <para>
/// <b>One method, and it is a claim rather than a write.</b> <see cref="TryClaimAsync"/> is not a
/// "look it up, then insert it" helper a caller could assemble from two reads: the check and the
/// insert have to be one operation, or two requests presenting the same assertion at the same moment
/// both find it absent and both succeed. That is the same reasoning
/// <see cref="IAuthorizationCodeStore.RedeemAsync"/> is built on, and it fails the same way - under
/// concurrency, which is exactly when a replay is being attempted.
/// </para>
/// <para>
/// <b>Keyed on (client, jti), not on jti alone.</b> RFC 7523 §3 makes the assertion's <c>iss</c> the
/// client, and JWT identifiers are unique per issuer rather than globally. A global key would let
/// one client's choice of <c>jti</c> - which it picks, and which nothing stops it setting to
/// <c>"1"</c> - lock every other client out of that value permanently.
/// </para>
/// <para>
/// <b>Why this store exists at all, stated plainly, because the honest answer is narrower than it
/// looks.</b> A replayed assertion authenticates the client a second time; it does not by itself get
/// anybody a token, because the token endpoint still needs an authorization code bound to that
/// client and its PKCE verifier, or a live refresh token. So what this closes is the window in which
/// a captured assertion is a reusable client credential rather than a single-use one - worth having,
/// and not the only thing standing between an attacker and a token. RFC 7523 §3 states it as a MAY
/// for the same reason.
/// </para>
/// <para>
/// <b>Rows are deleted, not retained.</b> Unlike a redeemed authorization code - kept so that a
/// replay can be told apart from a first use, N-07 - there is nothing to learn from an expired
/// assertion: past its <c>exp</c> the validator refuses it on the expiry alone, so a row that
/// outlives the token it protected only takes space. <see cref="DeleteExpiredAsync"/> is how a
/// deployment reclaims it.
/// </para>
/// </remarks>
public interface IClientAssertionReplayStore
{
    /// <summary>
    /// Record this assertion as used, if it has not been used before.
    /// </summary>
    /// <param name="clientId">The client the assertion authenticates - its <c>iss</c> and <c>sub</c>.</param>
    /// <param name="jwtId">The assertion's <c>jti</c>, verbatim.</param>
    /// <param name="expiresAt">
    /// The assertion's <c>exp</c>. The row need not outlive it: after that instant the validator
    /// refuses the assertion without consulting this store at all.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// <see langword="true"/> when this call is the one that recorded it, and
    /// <see langword="false"/> when it was already there - which is a replay, and the only
    /// interesting answer.
    /// </returns>
    /// <remarks>
    /// <b>The return value is the authority, not a subsequent read.</b> An implementation reports
    /// what its own insert did - rows affected, or the unique-violation it caught - and never
    /// re-reads to decide, because between a read and an insert is precisely where the race lives.
    /// </remarks>
    Task<bool> TryClaimAsync(
        ClientIdentifier clientId,
        string jwtId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    /// <summary>Drop rows whose assertion has expired. Returns how many went.</summary>
    /// <param name="now">The instant to compare against, from the caller's clock.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// Housekeeping, and safe to never call: a store that grows is a storage problem, while a store
    /// that forgets early is a replay window. Nothing in this server schedules it, deliberately -
    /// the same position <see cref="IAuthorizationCodeStore.DeleteExpiredAsync"/> is in.
    /// </remarks>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken);
}
