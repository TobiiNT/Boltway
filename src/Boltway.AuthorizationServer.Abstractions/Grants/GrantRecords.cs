using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Abstractions.Grants;

/// <summary>
/// A user's standing authorization for one client: what everything else hangs off.
/// </summary>
/// <param name="GrantId">Identifies this grant in tokens and in the revocation denylist.</param>
/// <param name="Subject">Who authorized.</param>
/// <param name="ClientId">Who was authorized.</param>
/// <param name="Scope">What was authorized.</param>
/// <param name="Resources">
/// The RFC 8707 <b>grant set</b>: every resource the user consented to. A later token request may
/// narrow to one of these and may never widen beyond them.
/// </param>
/// <param name="CreatedAt">When consent was given.</param>
/// <param name="AuthTime">
/// When the user actually authenticated — <b>not</b> when any token derived from this grant was
/// issued.
/// </param>
/// <param name="RevokedAt">When it was withdrawn, if it was.</param>
/// <param name="UserAgent">
/// The browser the consent screen was clicked in, or <see langword="null"/> when none was recorded.
/// </param>
/// <remarks>
/// <para>
/// <paramref name="UserAgent"/> is what makes two grants for the same client tellable apart, which
/// is the moment somebody is asking whether one of them is theirs. It is stamped once, when the
/// grant is created, and no refresh touches it: the question a session list asks is which device
/// <i>approved</i>, and restamping would answer a different one at the cost of a write on the hot
/// path of every rotation. <b>No address is stored beside it</b> — that is the field that turns a
/// session list into a location history, and this deployment decided against it. Null on every
/// grant created before the field existed, and on any request that sent no header; null is what
/// comes back, because nobody can attribute those after the fact.
/// </para>
/// <para>
/// <paramref name="AuthTime"/> lives here rather than only on the authorization code because the
/// refresh path needs it and the code is gone by then. Measured before it existed: the refresh
/// handler passed the presented token's issue time, so <c>auth_time</c> moved forward on every
/// rotation — a session authenticated thirty days ago reported one minutes old, which silently
/// defeats every relying party enforcing <c>max_age</c> or step-up authentication.
/// </para>
/// </remarks>
public sealed record GrantRecord(
    string GrantId,
    SubjectId Subject,
    ClientIdentifier ClientId,
    ScopeSet Scope,
    IReadOnlyList<string> Resources,
    DateTimeOffset CreatedAt,
    DateTimeOffset AuthTime,
    DateTimeOffset? RevokedAt = null,
    string? UserAgent = null)
{
    /// <summary>Whether this grant can still produce tokens.</summary>
    public bool IsActive => RevokedAt is null;
}

/// <summary>
/// An issued authorization code.
/// </summary>
/// <param name="CodeHash">The primary key. The plaintext is never stored (N-16).</param>
/// <param name="GrantId">The grant this code will produce tokens for.</param>
/// <param name="ClientId">
/// Which client the code was issued to. Checked at redemption, because a code redeemed by a
/// different client than requested it is an injection attempt.
/// </param>
/// <param name="RedirectUriUsed">
/// The redirect URI the authorization request carried. RFC 6749 §4.1.3 requires it to match if the
/// token request sends one.
/// </param>
/// <param name="CodeChallenge">The PKCE challenge, stored so redemption can verify it.</param>
/// <param name="ChallengeMethod">Always S256 here; stored so the record is self-describing.</param>
/// <param name="PkceWasRequested">
/// Whether the authorization request carried a challenge at all.
/// </param>
/// <param name="Scope">Scopes for the tokens this code produces.</param>
/// <param name="Resources">The resources requested at authorization time.</param>
/// <param name="Nonce">The OIDC nonce, echoed into the ID token.</param>
/// <param name="AuthTime">When the user authenticated.</param>
/// <param name="IssuedAt">When the code was issued.</param>
/// <param name="ExpiresAt">When it expires. Short — a code is meant to be redeemed immediately.</param>
/// <param name="RedeemedAt">
/// When it was redeemed, or <see langword="null"/>.
/// </param>
/// <remarks>
/// <para>
/// <b>A redeemed row is retained until <paramref name="ExpiresAt"/>, not deleted.</b> That is what
/// makes N-07 possible: when a code is presented twice, the second presentation must be validated
/// <i>fully</i> — client binding, redirect URI, PKCE — before anything is revoked. Deleting the row
/// on first use leaves nothing to validate against, so the only available response to a replay is
/// "revoke the grant", and that is a denial of service: an attacker who sniffed a code but has no
/// verifier could kill the legitimate client's tokens at will.
/// </para>
/// <para>
/// <paramref name="PkceWasRequested"/> is stored rather than inferred from
/// <paramref name="CodeChallenge"/> being non-null, because the check at redemption is a strict
/// XOR in both directions: a verifier arriving for a code issued without a challenge is as much a
/// protocol violation as a missing verifier for one issued with a challenge. OAuth 2.1 §3.2.4 names
/// the first case explicitly.
/// </para>
/// </remarks>
public sealed record AuthorizationCodeRecord(
    Sha256Hash CodeHash,
    string GrantId,
    ClientIdentifier ClientId,
    string RedirectUriUsed,
    string? CodeChallenge,
    CodeChallengeMethod ChallengeMethod,
    bool PkceWasRequested,
    ScopeSet Scope,
    IReadOnlyList<string> Resources,
    string? Nonce,
    DateTimeOffset AuthTime,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RedeemedAt = null);

/// <summary>
/// An issued refresh token.
/// </summary>
/// <param name="TokenHash">The primary key. The plaintext is never stored.</param>
/// <param name="GrantId">The grant this token refreshes.</param>
/// <param name="FamilyId">
/// Every token descended from one authorization code shares a family id.
/// </param>
/// <param name="Generation">How many rotations deep this token is. Diagnostics only.</param>
/// <param name="PredecessorHash">The token this one replaced.</param>
/// <param name="SuccessorHash">
/// The token that replaced this one, set when it is consumed. Load-bearing for the grace window:
/// a concurrent retry inside the window is answered with the successor that already exists rather
/// than by minting a second one.
/// </param>
/// <param name="IssuedAt">When it was issued.</param>
/// <param name="ExpiresAt">When it expires.</param>
/// <param name="ConsumedAt">When it was rotated away, or <see langword="null"/>.</param>
public sealed record RefreshTokenRecord(
    Sha256Hash TokenHash,
    string GrantId,
    string FamilyId,
    int Generation,
    Sha256Hash? PredecessorHash,
    Sha256Hash? SuccessorHash,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? ConsumedAt = null);

/// <summary>
/// The outcome of presenting an authorization code for redemption. A closed set of three.
/// </summary>
/// <remarks>
/// <para>
/// This was a <see cref="bool"/>, and the <see langword="false"/> case carried two meanings that
/// have opposite correct responses. "A fully valid second presentation" is the attacker replay
/// §4.1.3 says SHOULD revoke every token descended from the code. "The same request arrived twice"
/// is an HTTP retry after a lost response, a proxy retry, or a double-click — and revoking there
/// destroys the session the first delivery just created.
/// </para>
/// <para>
/// Measured before this type existed: fifty unforced double-submits, and the winner's grant was
/// revoked fifty times out of fifty. A sequential duplicate did the same. The code path had a
/// <see cref="bool"/> where the refresh path already had four cases and a grace window; this gives
/// it the same shape for the same reason.
/// </para>
/// </remarks>
public abstract record CodeRedemption
{
    private CodeRedemption() { }

    /// <summary>This call redeemed it. Issue the tokens.</summary>
    public sealed record Redeemed : CodeRedemption;

    /// <summary>
    /// Already redeemed, within the grace window. Deny, but <b>do not revoke</b>.
    /// </summary>
    /// <remarks>
    /// §4.1.3 makes denying the second request a MUST regardless — the tokens went to the first
    /// caller and cannot be handed out again. What the window changes is the blast radius: a retry
    /// arriving moments later is far more likely to be the same client than an attacker who
    /// obtained the code, the client authentication and the verifier.
    /// </remarks>
    public sealed record ReplayedWithinGrace : CodeRedemption;

    /// <summary>
    /// Already redeemed, and long enough ago to be a replay. Deny <b>and</b> revoke.
    /// </summary>
    /// <remarks>
    /// §4.1.3: the server "SHOULD revoke (when possible) all access tokens and refresh tokens
    /// previously issued based on that authorization code". Reaching here means every other check
    /// passed, so the presenter holds the client authentication and the verifier — which is the
    /// evidence §7.5.2 requires before revoking anything.
    /// </remarks>
    public sealed record ReplayedOutsideGrace : CodeRedemption;
}

/// <summary>What to persist when minting a successor during rotation.</summary>
/// <param name="TokenHash">The successor's hash.</param>
/// <param name="ExpiresAt">The successor's expiry.</param>
public sealed record RefreshTokenSeed(Sha256Hash TokenHash, DateTimeOffset ExpiresAt);

/// <summary>
/// The outcome of presenting a refresh token. A closed set of four.
/// </summary>
/// <remarks>
/// Four cases because the protocol genuinely has four answers, and collapsing any two of them
/// breaks something specific:
/// <list type="bullet">
/// <item><description>
/// Merging <see cref="ReplayedWithinGrace"/> into <see cref="ReuseDetected"/> makes every racing
/// refresh a security incident. Claude refreshes both proactively (up to five minutes before
/// expiry) and reactively (on a 401), so the two genuinely race in normal operation — and the user
/// sees a forced logout that reads as an outage.
/// </description></item>
/// <item><description>
/// Merging <see cref="ReuseDetected"/> into <see cref="NotFound"/> discards the only replay signal
/// that exists. A stolen refresh token then works until it expires, silently.
/// </description></item>
/// </list>
/// The caller switches over all four with no default arm, so adding a fifth case is a compile error
/// at every call site rather than a branch someone forgets.
/// </remarks>
public abstract record RefreshRedemption
{
    private RefreshRedemption() { }

    /// <summary>Rotated normally. The successor is the new refresh token.</summary>
    public sealed record Rotated(RefreshTokenRecord Successor) : RefreshRedemption;

    /// <summary>
    /// Presented again within the grace window. Idempotent: the same successor is returned.
    /// </summary>
    /// <remarks>
    /// Not a security event. Two refreshes racing is what a correct client does when its proactive
    /// timer and a 401 coincide, and the response has to be the successor that already exists —
    /// minting a second one would fork the family, which is a known CVE class and defeats reuse
    /// detection entirely.
    /// </remarks>
    public sealed record ReplayedWithinGrace(RefreshTokenRecord Successor) : RefreshRedemption;

    /// <summary>
    /// A consumed token presented after the grace window. The whole family is revoked.
    /// </summary>
    /// <remarks>
    /// The only signal that a refresh token leaked. Either the legitimate client is replaying one
    /// it should have discarded, or someone else has a copy — and the server cannot tell which, so
    /// it must assume the worse one. RFC 9700 §2.2.2.
    /// </remarks>
    public sealed record ReuseDetected(string GrantId, string FamilyId) : RefreshRedemption;

    /// <summary>Unknown, expired or already revoked. <c>invalid_grant</c>.</summary>
    public sealed record NotFound : RefreshRedemption;
}
