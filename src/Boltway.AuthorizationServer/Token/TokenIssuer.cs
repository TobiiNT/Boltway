using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Tokens;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.OAuth.Tokens;

namespace Boltway.AuthorizationServer.Token;

/// <summary>What a successful token request produced.</summary>
/// <param name="AccessToken">The <c>at+jwt</c>.</param>
/// <param name="ExpiresAt">When it expires, for <c>expires_in</c>.</param>
/// <param name="Scope">The scopes actually granted.</param>
/// <param name="RefreshToken">A refresh token, when <c>offline_access</c> was granted.</param>
/// <param name="IdToken">An ID token, when <c>openid</c> was granted.</param>
public sealed record IssuedTokens(
    MintedToken AccessToken,
    DateTimeOffset ExpiresAt,
    ScopeSet Scope,
    OpaqueSecret? RefreshToken,
    string? IdToken);

/// <summary>
/// Mints the tokens a grant produces. Shared by both grant handlers.
/// </summary>
/// <remarks>
/// <para>
/// One place, because the authorization-code path and the refresh path must produce
/// <i>indistinguishable</i> tokens. A client that gets a differently-shaped token after a refresh —
/// a missing claim, a different audience, an ID token that appears only on first issue — breaks
/// hours after connecting, and the report is "it stopped working overnight".
/// </para>
/// <para>
/// The audience is a single <see cref="ResourceIdentifier"/> because
/// <see cref="AccessTokenDescriptor"/> takes one. That is a deliberate reading of RFC 8707 §2.2,
/// which permits an authorization server to refuse a request naming several resources: a token
/// valid at two resources is one that either of them can replay at the other, and the whole point
/// of resource indicators is that a compromised MCP server does not hold a token that works
/// elsewhere. A request that names more than one is refused rather than served with a multi-valued
/// <c>aud</c>.
/// </para>
/// </remarks>
public sealed class TokenIssuer(
    JwtTokenMinter minter,
    SigningKeyRing keyRing,
    IRefreshTokenStore refreshTokens,
    AuthorizationServerOptions options,
    TimeProvider timeProvider,
    IAccessTokenClaims? subjectClaims = null)
{
    private readonly JwtTokenMinter _minter = minter ?? throw new ArgumentNullException(nameof(minter));
    private readonly SigningKeyRing _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
    private readonly IRefreshTokenStore _refreshTokens = refreshTokens ?? throw new ArgumentNullException(nameof(refreshTokens));
    private readonly AuthorizationServerOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _time = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    // Optional, and null is the shipped default: an access token that says nothing about the
    // subject beyond its identifier is the correct thing to hand a resource server that only needs
    // to know the request is authorised. A deployment whose resource servers record *who* did
    // something registers one — see UserAccountClaims.
    private readonly IAccessTokenClaims? _subjectClaims = subjectClaims;

    /// <summary>
    /// The scope that makes a refresh token appear.
    /// </summary>
    /// <remarks>
    /// Claude appends this to its authorization request only when the metadata advertises it, and
    /// without a refresh token every connection ends when the first access token expires.
    /// </remarks>
    public const string OfflineAccessScope = "offline_access";

    /// <summary>Issue for a freshly redeemed authorization code: a new refresh family.</summary>
    public async Task<IssuedTokens> IssueForCodeAsync(
        GrantRecord grant,
        ClientRecord client,
        ResourceIdentifier audience,
        ScopeSet scope,
        string? nonce,
        DateTimeOffset authTime,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);

        var now = _time.GetUtcNow();
        OpaqueSecret? refresh = null;

        if (scope.Contains(OfflineAccessScope))
        {
            var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);

            await _refreshTokens.StoreAsync(
                new RefreshTokenRecord(
                    TokenHash: Sha256Hash.Of(secret),
                    GrantId: grant.GrantId,

                    // A family per code redemption. Reuse detection revokes a family, so scoping it
                    // to the grant instead would make one leaked token kill every session the user
                    // has with that client — including the ones on other devices that did nothing
                    // wrong.
                    FamilyId: Guid.NewGuid().ToString("N"),
                    Generation: 0,
                    PredecessorHash: null,
                    SuccessorHash: null,
                    IssuedAt: now,
                    ExpiresAt: now + _options.RefreshTokenLifetime),
                cancellationToken);

            refresh = secret;
        }

        return await MintAsync(grant, client, audience, scope, nonce, authTime, refresh, now, cancellationToken);
    }

    /// <summary>Issue for a rotated refresh token: the successor is already persisted by the store.</summary>
    /// <remarks>
    /// Asynchronous because the claims mapper is. It was synchronous when nothing on this path
    /// reached a store, and keeping it that way would have meant blocking on the mapper here and
    /// awaiting it on the code path — two ways of calling the same thing, which is how one of them
    /// ends up deadlocking on a synchronization context nobody remembered was there.
    /// </remarks>
    public Task<IssuedTokens> IssueForRefreshAsync(
        GrantRecord grant,
        ClientRecord client,
        ResourceIdentifier audience,
        ScopeSet scope,
        DateTimeOffset authTime,
        OpaqueSecret successor,
        CancellationToken cancellationToken = default) =>
        MintAsync(
            grant,
            client,
            audience,
            scope,

            // No nonce on a refresh. OIDC Core §12.2: the ID token from a refresh "MUST NOT have a
            // nonce Claim" unless the original request carried one — and echoing a stale nonce is
            // worse than omitting it, because the client's replay check compares against a value it
            // has long since discarded.
            nonce: null,
            authTime,
            successor,
            _time.GetUtcNow(),
            cancellationToken);

    /// <summary>Issue for a service account: no refresh token, no nonce, no ID token.</summary>
    /// <remarks>
    /// <para>
    /// A third entry point rather than a flag on one of the others, because what it omits is the
    /// part that would be wrong to reach by accident. <c>refresh: null</c> is not an optimisation
    /// here — RFC 6749 §4.4.3 says a refresh token SHOULD NOT be issued for this grant, and the
    /// reason applies exactly: the client already holds a credential that mints access tokens
    /// whenever it likes, so a refresh token is a second long-lived secret protecting nothing.
    /// </para>
    /// <para>
    /// It still goes through <see cref="MintAsync"/>, which is the point of that method existing.
    /// The access token a service account gets must be shaped exactly like the one a person gets —
    /// same claims mapper, same audience handling, same lifetime — because a resource server that
    /// had to tell them apart would be a resource server with two authorization paths, and the
    /// second one is always the one nobody tests.
    /// </para>
    /// </remarks>
    public Task<IssuedTokens> IssueForClientCredentialsAsync(
        GrantRecord grant,
        ClientRecord client,
        ResourceIdentifier audience,
        ScopeSet scope,
        DateTimeOffset authTime,
        CancellationToken cancellationToken = default) =>
        MintAsync(
            grant,
            client,
            audience,
            scope,

            // No nonce: a nonce binds an ID token to an authorization request that a browser made,
            // and there was no browser and no request to bind to.
            nonce: null,
            authTime,
            refresh: null,
            _time.GetUtcNow(),
            cancellationToken);

    private async Task<IssuedTokens> MintAsync(
        GrantRecord grant,
        ClientRecord client,
        ResourceIdentifier audience,
        ScopeSet scope,
        string? nonce,
        DateTimeOffset authTime,
        OpaqueSecret? refresh,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var expiresAt = now + _options.AccessTokenLifetime;
        var key = _keyRing.ActiveKey(_options.TokenSigningAlgorithm);

        // Here rather than in either caller, because this method exists to make the two paths
        // produce indistinguishable tokens. A mapper called only on the authorization-code path
        // would give a client a token carrying a name for an hour and then, after the first
        // refresh, one without — the "it stopped working overnight" failure this class's remarks
        // are about, in the shape that is hardest to attribute.
        var extra = _subjectClaims is null
            ? null
            : await _subjectClaims.ForAsync(grant.Subject, scope, cancellationToken);

        var access = _minter.MintAccessToken(
            new AccessTokenDescriptor(
                Issuer: _options.ValidatedIssuer,
                Audience: audience,
                Subject: grant.Subject,
                ClientId: client.ClientId,
                GrantId: grant.GrantId,
                Scope: scope,
                IssuedAt: now,
                ExpiresAt: expiresAt,
                JwtId: Guid.NewGuid().ToString("N"),
                AuthTime: authTime,

                // Not passed to the ID token below. The two go to different holders — an access
                // token to the resource server, an ID token to the client — and a mapper written
                // for one is not consent to release the same claims to the other. OIDC's own
                // channel for that is the `profile`/`email` claims in an ID token or /userinfo,
                // and neither is what this seam is.
                Extra: extra),
            key);

        string? idToken = null;

        // OIDC only when the user asked for it. Both vendors' MCP clients omit `openid` entirely,
        // and minting an ID token they did not request would hand them a second credential to
        // mishandle for no benefit.
        if (scope.Contains("openid"))
        {
            idToken = _minter.MintIdToken(
                new IdTokenDescriptor(
                    Issuer: _options.ValidatedIssuer,
                    Audience: client.ClientId,
                    Subject: grant.Subject,
                    IssuedAt: now,
                    ExpiresAt: expiresAt,
                    AuthTime: authTime,
                    Nonce: nonce,

                    // OIDC Core §3.1.3.6: at_hash is REQUIRED when an ID token is issued alongside
                    // an access token in this flow. It is what lets the client detect an access
                    // token substituted for one issued to a different session.
                    AccessTokenHash: JwtTokenMinter.ComputeAccessTokenHash(access.Wire)),
                key).Wire;
        }

        return new IssuedTokens(access, expiresAt, scope, refresh, idToken);
    }
}
