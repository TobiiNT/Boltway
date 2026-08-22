using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Token;

/// <summary>What a grant handler produced.</summary>
public abstract record GrantOutcome
{
    private GrantOutcome() { }

    /// <summary>Tokens.</summary>
    public sealed record Issued(IssuedTokens Tokens) : GrantOutcome;

    /// <summary>An OAuth error, always delivered as JSON from the token endpoint.</summary>
    /// <param name="Rejection">
    /// Why, in both forms. This grant is where the response is least informative on purpose — ten
    /// distinct causes answer "The authorization code is invalid" — so the reason has to travel
    /// with the failure rather than be reconstructed at the endpoint from the description.
    /// </param>
    public sealed record Failed(Rejection Rejection) : GrantOutcome
    {
        /// <summary>The OAuth error the client is told.</summary>
        public OAuthErrorCode Code => Rejection.Error;

        /// <summary>What the client is told, in words.</summary>
        public string Description => Rejection.Description;
    }
}

/// <summary>
/// The <c>authorization_code</c> grant. RFC 6749 §4.1.3.
/// </summary>
/// <remarks>
/// <para>
/// <b>The order of the checks below is the requirement, not a convention</b>, and it is not the
/// order §4.1.3 lists them in. Redemption is last, after every other check has passed, because
/// OAuth 2.1 §7.5.2 says an authorization server "SHOULD NOT revoke any issued tokens when
/// receiving a replayed authorization code that contains invalid parameters. If it were to do so,
/// this would create a denial of service opportunity for an attacker who is able to obtain an
/// authorization code but unable to obtain the client authentication or code_verifier".
/// </para>
/// <para>
/// So a <see langword="false"/> from <c>TryRedeemAsync</c> at the end means something precise: a
/// <i>fully valid</i> second presentation, which is the only case that justifies revoking the
/// grant. Fold any check in after it and the revocation becomes an attacker-triggerable weapon.
/// </para>
/// </remarks>
public sealed class AuthorizationCodeGrant(
    IAuthorizationCodeStore codes,
    IGrantStore grants,
    IRefreshTokenStore refreshTokens,
    IResourceRegistry resources,
    TokenIssuer issuer,
    TimeProvider timeProvider)
{
    private readonly IAuthorizationCodeStore _codes = codes ?? throw new ArgumentNullException(nameof(codes));
    private readonly IGrantStore _grants = grants ?? throw new ArgumentNullException(nameof(grants));
    private readonly IRefreshTokenStore _refreshTokens = refreshTokens ?? throw new ArgumentNullException(nameof(refreshTokens));
    private readonly IResourceRegistry _resources = resources ?? throw new ArgumentNullException(nameof(resources));
    private readonly TokenIssuer _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
    private readonly TimeProvider _time = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>
    /// How long after redemption a second presentation of a code is a retry rather than a replay.
    /// </summary>
    /// <remarks>
    /// Much shorter than the refresh window, because it covers a different thing. The refresh
    /// window exists because a correct client genuinely races its own proactive and reactive
    /// refreshes; this one only has to cover a transport-level retry of a single request that has
    /// already been delivered once.
    /// </remarks>
    public static TimeSpan RetryWindow { get; } = TimeSpan.FromSeconds(10);

    /// <summary>Exchange a code.</summary>
    public async Task<GrantOutcome> HandleAsync(
        OAuthParameters parameters, ClientRecord client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);

        if (!parameters.TrySingle("code", out var rawCode))
        {
            return Invalid(ReasonCode.RepeatedParameter, "parameter=code", OAuthErrorCode.InvalidRequest,
                "The 'code' parameter appeared more than once.");
        }

        if (string.IsNullOrEmpty(rawCode))
        {
            return Invalid(ReasonCode.AuthorizationCodeMissing, null, OAuthErrorCode.InvalidRequest,
                "The 'code' parameter is required.");
        }

        // The `ck_ac_` prefix check refuses a refresh token presented as a code before any storage
        // is touched — a wrong-purpose credential should not become a database lookup.
        if (!OpaqueSecret.TryParse(rawCode, TokenPurpose.AuthorizationCode, out var code))
        {
            // The value is not recorded, and this is the case where the temptation is strongest —
            // it did not parse, so "it is probably not a real secret". It might be: the commonest
            // cause of this branch is a client sending a refresh token here, and that is a live
            // credential. The prefix check is what the diagnosis needs and the prefix is the part
            // that is not secret.
            return Invalid(
                ReasonCode.AuthorizationCodeMalformed,
                $"client_id={client.ClientId.Value}; presented_prefix={TokenPrefix(rawCode)}");
        }

        var record = await _codes.FindAsync(Sha256Hash.Of(code), cancellationToken);

        if (record is null)
        {
            return Invalid(ReasonCode.AuthorizationCodeUnknown, $"client_id={client.ClientId.Value}");
        }

        // §4.1.3 and §3.2.4: a code "issued to another client" is invalid_grant. This is a code
        // injection attempt, so the answer says nothing about whose code it is.
        if (record.ClientId != client.ClientId)
        {
            return Invalid(
                ReasonCode.AuthorizationCodeWrongClient,
                $"issued_to={record.ClientId.Value}; presented_by={client.ClientId.Value}");
        }

        if (!parameters.TrySingle("redirect_uri", out var redirectUri))
        {
            return Invalid(ReasonCode.RepeatedParameter, "parameter=redirect_uri", OAuthErrorCode.InvalidRequest,
                "The 'redirect_uri' parameter appeared more than once.");
        }

        // Accept if sent, enforce if sent, never require. OAuth 2.1 §10.2 makes accepting it a MUST
        // — "A client following only the OAuth 2.1 recommendations will not send the redirect_uri in
        // the token request" — and enforcing it a MUST when it is there.
        //
        // Compared against the value the authorization request carried, never against the client's
        // registered set. Claude Code registers portless http://localhost/callback and redirects to
        // http://localhost:3118/callback, so comparing with the registration fails every one of its
        // exchanges.
        if (redirectUri is not null
            && !string.Equals(redirectUri, record.RedirectUriUsed, StringComparison.Ordinal))
        {
            // Both strings, in the log only. This is the check Claude Code trips when a portless
            // registration meets an ephemeral port, and the difference is one substring — which is
            // unreadable from "The authorization code is invalid" and obvious from these two.
            return Invalid(
                ReasonCode.AuthorizationCodeRedirectUriMismatch,
                $"authorized={record.RedirectUriUsed}; presented={redirectUri}");
        }

        if (!parameters.TrySingle("code_verifier", out var rawVerifier))
        {
            return Invalid(ReasonCode.RepeatedParameter, "parameter=code_verifier", OAuthErrorCode.InvalidRequest,
                "The 'code_verifier' parameter appeared more than once.");
        }

        var pkce = VerifyPkce(record, rawVerifier);

        if (pkce is not null)
        {
            return pkce;
        }

        var now = _time.GetUtcNow();

        // Expiry after PKCE, and deliberately not inside TryRedeemAsync. Folding it into redemption
        // would send an expired code down the revoke-the-grant path, which is the denial of service
        // §7.5.2 describes.
        if (now >= record.ExpiresAt)
        {
            return Invalid(
                ReasonCode.AuthorizationCodeExpired,
                $"expired_at={record.ExpiresAt:O}; now={now:O}; late_by={now - record.ExpiresAt}");
        }

        var grant = await _grants.FindAsync(record.GrantId, cancellationToken);

        if (grant is null || !grant.IsActive)
        {
            return Invalid(
                ReasonCode.AuthorizationCodeGrantInactive,
                grant is null ? $"grant={record.GrantId}; not found" : $"grant={record.GrantId}; revoked");
        }

        var resolved = await ResourceNarrowing.ResolveAsync(
            parameters, record.Resources, client, _resources, cancellationToken);

        if (resolved.Error is { } resourceError)
        {
            return resourceError;
        }

        // ───────── everything has passed; only now is redemption safe ─────────

        var redemption = await _codes.RedeemAsync(record.CodeHash, now, RetryWindow, cancellationToken);

        switch (redemption)
        {
            case CodeRedemption.Redeemed:
                break;

            case CodeRedemption.ReplayedWithinGrace:
                // Denied — §4.1.3 makes that a MUST, and the tokens went to the first caller and
                // cannot be handed out twice — but NOT revoked. A second delivery moments later is
                // an HTTP retry after a lost response, a proxy retry or a double-click far more
                // often than it is an attacker who has also obtained the client authentication and
                // the verifier.
                //
                // Measured before this case existed, when redemption answered a bare bool: fifty
                // unforced double-submits revoked the winner's grant fifty times. The client saw an
                // authorization that succeeded and was dead on its next call.
                return Invalid(
                    ReasonCode.AuthorizationCodeReplayedWithinRetryWindow,
                    $"grant={record.GrantId}; retry_window={RetryWindow}");

            case CodeRedemption.ReplayedOutsideGrace:
                // §4.1.3: "SHOULD revoke (when possible) all access tokens and refresh tokens
                // previously issued based on that authorization code." Every other check has passed,
                // so whoever sent this holds the client authentication and the verifier — the
                // evidence §7.5.2 requires before revoking anything.
                await _grants.RevokeAsync(record.GrantId, now, cancellationToken);

                // Byte-identical to an unknown code on the wire. Confirming that a replay was
                // noticed tells a thief which of their codes was real — but this is the one refusal
                // in the grant that revokes a live session, so the log has to say so plainly or the
                // user's report ("it just signed me out") has nothing to match against.
                return Invalid(
                    ReasonCode.AuthorizationCodeReplayed,
                    $"grant={record.GrantId} revoked: every check passed on a second presentation outside the {RetryWindow} retry window");

            default:
                throw new InvalidOperationException($"Unhandled redemption {redemption.GetType().Name}.");
        }

        var tokens = await _issuer.IssueForCodeAsync(
            grant, client, resolved.Resource!, record.Scope, record.Nonce, grant.AuthTime, cancellationToken);

        return new GrantOutcome.Issued(tokens);
    }

    /// <summary>
    /// PKCE, as a strict XOR in both directions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §4.1.3: "verify that the <c>code_verifier</c> parameter is present if and only if a
    /// <c>code_challenge</c> parameter was present in the authorization request", and "If there was
    /// no <c>code_challenge</c> in the authorization request associated with the authorization code
    /// in the token request, the authorization server MUST reject the token request."
    /// </para>
    /// <para>
    /// <b>All three failures return <c>invalid_grant</c>, including the "verifier with no stored
    /// challenge" case that §3.2.4's general enumeration assigns to <c>invalid_request</c>.</b> Two
    /// reasons. RFC 7636 §4.6 names <c>invalid_grant</c> for the mismatch, and §4.1.3 — the
    /// grant-specific section — says only "MUST reject" without naming a code, so the general
    /// enumeration does not override it. And returning a <i>different</i> code for "no challenge was
    /// stored" than for "wrong verifier" is a distinguishing oracle for exactly the downgrade
    /// attacker PKCE exists to stop.
    /// </para>
    /// </remarks>
    private static GrantOutcome.Failed? VerifyPkce(AuthorizationCodeRecord record, string? rawVerifier)
    {
        var presented = !string.IsNullOrEmpty(rawVerifier);

        if (presented != record.PkceWasRequested)
        {
            return Invalid(
                ReasonCode.PkceVerifierPresenceMismatch,
                $"code_verifier presented={presented}; challenge stored={record.PkceWasRequested}");
        }

        if (!record.PkceWasRequested)
        {
            // Unreachable while N-02 holds — this server never issues a code without a challenge —
            // so arriving here means a corrupted record or a downgrade attempt.
            return null;
        }

        if (!CodeVerifier.TryParse(rawVerifier, out var verifier))
        {
            // The length, never the value. A code_verifier IS the secret PKCE turns on, and the
            // grammar failure is entirely described by how long it was.
            return Invalid(
                ReasonCode.PkceVerifierMalformed,
                $"code_verifier_length={rawVerifier!.Length}");
        }

        // TryParse rather than a rehydrate-without-checking, so a corrupted stored challenge fails
        // closed. Re-validating a value that was validated on the way in costs a base64url decode
        // and removes the case where a truncated column produces a challenge that matches nothing —
        // or, worse, one that matches something.
        if (!CodeChallenge.TryParse(record.CodeChallenge, record.ChallengeMethod, out var challenge))
        {
            return Invalid(
                ReasonCode.PkceStoredChallengeUnusable,
                $"stored challenge does not re-parse; method={record.ChallengeMethod}");
        }

        return challenge.Matches(verifier)
            ? null
            : Invalid(ReasonCode.PkceVerifierMismatch, $"method={record.ChallengeMethod}");
    }

    /// <summary>
    /// The one description every refusal in this grant shares.
    /// </summary>
    /// <remarks>
    /// Ten conditions, one sentence, and that is the requirement rather than laziness: telling a
    /// caller which check failed tells a thief holding a stolen code whether the code was real,
    /// whether it belonged to this client, and whether it had expired. The <see cref="ReasonCode"/>
    /// and the detail carry all ten apart in the log, where the audience already has the database.
    /// </remarks>
    private const string Indistinguishable = "The authorization code is invalid.";

    private static GrantOutcome.Failed Invalid(
        ReasonCode reason,
        string? detail = null,
        OAuthErrorCode code = OAuthErrorCode.InvalidGrant,
        string description = Indistinguishable) =>
        new(Rejection.Of(reason, code, description, detail));

    /// <summary>
    /// The kind-prefix of a presented credential, and never more of it.
    /// </summary>
    /// <remarks>
    /// <c>OpaqueSecret</c>'s wire form is <c>{prefix}{43 base64url characters}</c>, and the prefix
    /// is the part that is a fact about the kind rather than about the value. Everything after the
    /// last underscore of the prefix is 256 bits of entropy and is not written anywhere.
    /// </remarks>
    private static string TokenPrefix(string presented)
    {
        var underscore = presented.IndexOf('_', StringComparison.Ordinal);

        if (underscore < 0 || underscore + 1 >= presented.Length)
        {
            return "none";
        }

        var second = presented.IndexOf('_', underscore + 1);

        return second < 0 || second > 8 ? "none" : presented[..(second + 1)];
    }
}

/// <summary>
/// The <c>refresh_token</c> grant. RFC 6749 §6, OAuth 2.1 §4.3.
/// </summary>
public sealed class RefreshTokenGrant(
    IRefreshTokenStore refreshTokens,
    IGrantStore grants,
    IResourceRegistry resources,
    TokenIssuer issuer,
    RefreshTokenDeriver deriver,
    AuthorizationServerOptions options,
    TimeProvider timeProvider,
    Diagnostics.AuthorizationServerMetrics? metrics = null,
    IServiceProvider? services = null)
{
    // Optional and last, like `metrics`, so a host constructing this by hand keeps working. It is
    // only used to reach the entitlement policy and the directory, and a null one means the filter
    // does not run — the same "no policy registered, no narrowing" behaviour ScopeEntitlement has.
    private readonly IServiceProvider _services = services ?? EmptyServices.Instance;

    // Optional, and last in the list, so a host that does not register metrics constructs this
    // exactly as before. `reuse` is the row worth an alert: RFC 9700 §2.2.2 says a replayed refresh
    // token is either a client replaying one it should have discarded or somebody else holding a
    // copy, and the server cannot tell which — so it is counted rather than inferred later from a
    // log line whose retention nobody checked.
    private readonly Diagnostics.AuthorizationServerMetrics? _metrics = metrics;

    private readonly RefreshTokenDeriver _deriver = deriver ?? throw new ArgumentNullException(nameof(deriver));

    private readonly IRefreshTokenStore _refreshTokens = refreshTokens ?? throw new ArgumentNullException(nameof(refreshTokens));
    private readonly IGrantStore _grants = grants ?? throw new ArgumentNullException(nameof(grants));
    private readonly IResourceRegistry _resources = resources ?? throw new ArgumentNullException(nameof(resources));
    private readonly TokenIssuer _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
    private readonly AuthorizationServerOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _time = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>
    /// How long after consumption a repeat presentation is a retry rather than a reuse.
    /// </summary>
    /// <remarks>
    /// Not optional. Claude refreshes both proactively — up to five minutes before expiry — and
    /// reactively on a 401, so the two race in normal operation. Without a window the loser of that
    /// race is reported as a stolen token and the user is logged out, which reads as an outage.
    /// </remarks>
    public static TimeSpan GraceWindow { get; } = TimeSpan.FromSeconds(45);

    /// <summary>Rotate a refresh token.</summary>
    public async Task<GrantOutcome> HandleAsync(
        OAuthParameters parameters, ClientRecord client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(client);

        if (!parameters.TrySingle("refresh_token", out var raw))
        {
            return Failed(
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'refresh_token' parameter appeared more than once.",
                "parameter=refresh_token");
        }

        if (string.IsNullOrEmpty(raw))
        {
            return Failed(
                ReasonCode.RefreshTokenMissing,
                OAuthErrorCode.InvalidRequest,
                "The 'refresh_token' parameter is required.");
        }

        if (!OpaqueSecret.TryParse(raw, TokenPurpose.RefreshToken, out var presented))
        {
            return Dead(ReasonCode.RefreshTokenMalformed, $"client_id={client.ClientId.Value}");
        }

        var hash = Sha256Hash.Of(presented);
        var record = await _refreshTokens.FindAsync(hash, cancellationToken);

        if (record is null)
        {
            // Unknown, and that is all this branch knows. It is also where a rotated-away token
            // lands after its grace window closes and its row is gone, which is the difference
            // between a user who signed out and a deployment whose store is losing rows — so the
            // reason is separate from ReuseDetected below rather than merged into one "dead".
            return Dead(ReasonCode.RefreshTokenUnknown, $"client_id={client.ClientId.Value}");
        }

        var grant = await _grants.FindAsync(record.GrantId, cancellationToken);

        if (grant is null || !grant.IsActive)
        {
            return Dead(
                ReasonCode.RefreshTokenGrantInactive,
                grant is null ? $"grant={record.GrantId}; not found" : $"grant={record.GrantId}; revoked");
        }

        // §6: "ensure that the refresh token was issued to the authenticated client". Checked
        // before redemption, not after — redeeming first would consume the legitimate user's token
        // on a request the wrong client made, which is the same denial of service the
        // authorization-code path orders its checks to avoid.
        if (grant.ClientId != client.ClientId)
        {
            return Dead(
                ReasonCode.RefreshTokenWrongClient,
                $"issued_to={grant.ClientId.Value}; presented_by={client.ClientId.Value}");
        }

        var scope = ResolveScope(parameters, grant, out var scopeError);

        if (scopeError is not null)
        {
            return scopeError;
        }

        // The entitlement filter, again. Applying it only at /authorize would mean a consent granted
        // while somebody was entitled keeps minting the scope after they are not, for as long as the
        // refresh family lives — which is the longest-lived thing this server issues.
        var entitled = await Authorize.ScopeEntitlement
            .FilterAsync(_services, grant.Subject, scope, cancellationToken)
            .ConfigureAwait(false);

        if (entitled.Values.Count == 0)
        {
            // X-42. The account can hold none of what this grant covers, so there is no narrower
            // token to issue — unlike the ordinary case, where filtering just returns less.
            return Dead(
                ReasonCode.ScopeNotAllowedForClient,
                $"subject={grant.Subject.Value}; requested={scope.ToWireString()}");
        }

        scope = entitled;

        // The reference set is the GRANT's resources, not the narrower set the previous exchange
        // used. RFC 8707 §2.2: "any refresh token that is returned is bound to the full original
        // grant". Storing the narrowed set on the refresh token would permanently downgrade a
        // client that once asked for less.
        var resolved = await ResourceNarrowing.ResolveAsync(
            parameters, grant.Resources, client, _resources, cancellationToken);

        if (resolved.Error is { } resourceError)
        {
            return resourceError;
        }

        var now = _time.GetUtcNow();

        // Derived from the family and the generation rather than generated, so that a second racer
        // landing on ReplayedWithinGrace can compute the *same* plaintext from the record the store
        // hands back. Only the hash is ever stored, so a generated successor is unrecoverable by
        // anyone but the caller that made it — which is why the grace path used to answer
        // invalid_grant to a client that was doing nothing wrong.
        var successor = _deriver.Derive(record.FamilyId, record.Generation + 1);

        var redemption = await _refreshTokens.RedeemAsync(
            hash,
            new RefreshTokenSeed(Sha256Hash.Of(successor), now + _options.RefreshTokenLifetime),
            now,
            GraceWindow,
            cancellationToken);

        // All four cases, no default arm — a fifth would be a compile error here rather than a
        // branch someone forgets.
        switch (redemption)
        {
            case RefreshRedemption.Rotated:
                _metrics?.RefreshRotation.Add(1, new KeyValuePair<string, object?>("result", "rotated"));

                // grant.AuthTime, not the presented token's IssuedAt. Using the token's issue time
                // moved auth_time forward on every rotation, so a session authenticated a month ago
                // reported one minutes old — which silently defeats any relying party enforcing
                // max_age or step-up authentication.
                return new GrantOutcome.Issued(
                    await _issuer.IssueForRefreshAsync(
                        grant, client, resolved.Resource!, scope, grant.AuthTime, successor, cancellationToken));

            case RefreshRedemption.ReplayedWithinGrace grace:
            {
                _metrics?.RefreshRotation.Add(1, new KeyValuePair<string, object?>("result", "grace_replay"));

                // N-08: "two concurrent redemptions ⇒ one successor, BOTH callers get it." The store
                // returned the successor that already exists rather than minting a second one, and
                // the deriver reconstructs its plaintext from the same record — so the loser of the
                // race receives a working token instead of being told its credential is dead.
                //
                // Claude refreshes proactively and reactively, so this race happens in normal
                // operation, and the reactive request is racing because it just took a 401 and needs
                // a token now. Answering invalid_grant there is answering the one caller that cannot
                // act on it.
                var replayed = _deriver.Derive(grace.Successor.FamilyId, grace.Successor.Generation);

                // ...but only if the reconstruction actually reconstructs. On the Rotated branch the
                // derived value IS the seed, so it matches by construction. Here it is recomputed
                // from scratch under whatever key this process holds, and nothing has so far
                // compared it to the hash the store has. An adversarial review measured what that
                // costs: with the derivation key differing between instances, the loser of the race
                // got HTTP 200, a working access token, and a refresh token whose hash is in no row.
                // The client then discards its previous token because rotation told it to, the
                // parent is already consumed, and the family is unrecoverable — with nothing logged,
                // because the server never sees the dud again.
                //
                // Three ways in, all live: a key generated per process rather than configured, a key
                // rotated with no overlap, and any family whose successor predates the deriver and
                // is therefore still a random value. So this check is not defence in depth; it is
                // the only thing standing between a misconfiguration and silent, permanent,
                // unattributable logouts.
                //
                // Failing closed means invalid_grant, which is a credential the client can act on:
                // it re-runs the authorization flow and the user is signed in again. A corpse is not
                // something any client can act on. Constant-time via Sha256Hash.Matches, though the
                // timing here leaks nothing an attacker could use — the comparison is against a
                // value they would already have to hold.
                if (!grace.Successor.TokenHash.Matches(replayed))
                {
                    // The one refusal in this file that is almost certainly the operator's fault
                    // rather than the caller's, which is why it does not share a reason with the
                    // others. Every route into it is a deployment mistake — a derivation key
                    // generated per process, a key rotated with no overlap, a family predating the
                    // deriver — and the symptom without this line is users reporting random,
                    // permanent, unattributable logouts.
                    return Dead(
                        ReasonCode.RefreshTokenSuccessorUnrecoverable,
                        $"family={grace.Successor.FamilyId}; generation={grace.Successor.Generation}; "
                        + "the derived successor does not match the stored hash, so this instance's "
                        + "RefreshTokenDerivationKey disagrees with the one that wrote the row");
                }

                return new GrantOutcome.Issued(
                    await _issuer.IssueForRefreshAsync(
                        grant, client, resolved.Resource!, scope, grant.AuthTime, replayed, cancellationToken));
            }

            case RefreshRedemption.ReuseDetected reuse:
                _metrics?.RefreshRotation.Add(1, new KeyValuePair<string, object?>("result", "reuse"));

                // The only signal that a refresh token leaked. Either the legitimate client replayed
                // one it should have discarded or someone else has a copy, and the server cannot
                // tell which — so it assumes the worse one. RFC 9700 §2.2.2.
                await _refreshTokens.RevokeFamilyAsync(reuse.FamilyId, now, cancellationToken);
                await _grants.RevokeAsync(reuse.GrantId, now, cancellationToken);
                return Dead(
                    ReasonCode.RefreshTokenReuseDetected,
                    $"family={reuse.FamilyId} and grant={reuse.GrantId} revoked; grace_window={GraceWindow}");

            case RefreshRedemption.NotFound:
                return Dead(ReasonCode.RefreshTokenUnknown, $"the row disappeared between find and redeem; grant={grant.GrantId}");

            default:
                throw new InvalidOperationException($"Unhandled redemption {redemption.GetType().Name}.");
        }
    }

    /// <summary>
    /// Narrow the scope, or refuse to widen it.
    /// </summary>
    /// <remarks>
    /// §6: the requested scope "MUST NOT include any scope not originally granted by the resource
    /// owner, and if omitted is treated as equal to the scope originally granted". Widening is
    /// <c>invalid_scope</c> and never <c>invalid_grant</c> — a client reads the latter as "the
    /// refresh token is dead" and discards a live credential.
    /// </remarks>
    private static ScopeSet ResolveScope(OAuthParameters parameters, GrantRecord grant, out GrantOutcome? error)
    {
        error = null;

        if (!parameters.TrySingle("scope", out var raw))
        {
            error = Failed(
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'scope' parameter appeared more than once.",
                "parameter=scope");
            return ScopeSet.Empty;
        }

        if (string.IsNullOrEmpty(raw))
        {
            return grant.Scope;
        }

        if (!ScopeSet.TryParse(raw, out var requested, out _))
        {
            error = Failed(
                ReasonCode.RefreshTokenScopeMalformed,
                OAuthErrorCode.InvalidScope,
                "The 'scope' parameter contains an invalid value.",
                $"scope={raw}");
            return ScopeSet.Empty;
        }

        if (requested.Except(grant.Scope).Count > 0)
        {
            error = Failed(
                ReasonCode.RefreshTokenScopeWidened,
                OAuthErrorCode.InvalidScope,
                "The requested scope exceeds the scope of this grant.",
                $"granted={grant.Scope.ToWireString()}; widened_by={string.Join(' ', requested.Except(grant.Scope))}");
            return ScopeSet.Empty;
        }

        return requested;
    }

    /// <summary>
    /// Unknown, expired, revoked and forged are one indistinguishable answer.
    /// </summary>
    /// <remarks>
    /// The code must be exactly <c>invalid_grant</c>. Anthropic's integration guidance is explicit
    /// that a client branches on this string — "not <c>invalid_request</c> or a custom code" — and a
    /// client that cannot recognise a dead refresh token has no recovery path but to sit there
    /// failing.
    /// </remarks>
    private static GrantOutcome.Failed Dead(ReasonCode reason, string? detail = null) =>
        Failed(reason, OAuthErrorCode.InvalidGrant, "The refresh token is invalid, expired or revoked.", detail);

    private static GrantOutcome.Failed Failed(
        ReasonCode reason, OAuthErrorCode code, string description, string? detail = null) =>
        new(Rejection.Of(reason, code, description, detail));
}

/// <summary>The resource resolved for a token request, or why it could not be.</summary>
/// <param name="Resource">The audience the access token will carry.</param>
/// <param name="Error">Set when resolution failed.</param>
public readonly record struct NarrowedResource(ResourceIdentifier? Resource, GrantOutcome.Failed? Error);

/// <summary>
/// RFC 8707 §2.2 narrowing, shared by both grants.
/// </summary>
/// <remarks>
/// One implementation because the two grants differ only in which set they narrow <i>from</i> — the
/// code's resources for an exchange, the grant's for a refresh — and every other rule is the same.
/// Two copies would drift on the one that matters: never widening.
/// </remarks>
public static class ResourceNarrowing
{
    /// <summary>Resolve the requested resource against the set this grant permits.</summary>
    public static async ValueTask<NarrowedResource> ResolveAsync(
        OAuthParameters parameters,
        IReadOnlyList<string> permitted,
        ClientRecord client,
        IResourceRegistry registry,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(permitted);

        var requested = parameters.All("resource");

        // More than one is refused rather than served with a multi-valued `aud`. RFC 8707 §3 says an
        // authorization server "may be unwilling or unable to fulfill a token request with multiple
        // resources", and a token valid at two resources is one either can replay at the other —
        // which is the property resource indicators exist to remove.
        if (requested.Count > 1)
        {
            return Failed(
                ReasonCode.ResourceTooMany,
                "Only one 'resource' may be requested at the token endpoint.",
                $"requested={requested.Count}");
        }

        if (requested.Count == 0)
        {
            // Nothing requested: the grant must name exactly one, or there is no unambiguous
            // audience and guessing would mint a token for a resource nobody asked for.
            if (permitted.Count != 1)
            {
                return Failed(
                    ReasonCode.ResourceDefaultUnavailable,
                    "The 'resource' parameter is required: this grant covers more than one resource.",
                    $"grant covers {permitted.Count}: {string.Join(' ', permitted)}");
            }

            return await ResolveOneAsync(permitted[0], client, registry, cancellationToken);
        }

        // Never widen. The requested value has to be in the set the user consented to, compared
        // ordinally against the canonical strings stored at consent time.
        if (!permitted.Contains(requested[0], StringComparer.Ordinal))
        {
            return Failed(
                ReasonCode.ResourceUnavailable,
                "The requested 'resource' is not available to this client.",
                $"requested={requested[0]}; grant covers {string.Join(' ', permitted)}");
        }

        return await ResolveOneAsync(requested[0], client, registry, cancellationToken);
    }

    private static async ValueTask<NarrowedResource> ResolveOneAsync(
        string canonical, ClientRecord client, IResourceRegistry registry, CancellationToken cancellationToken)
    {
        if (!RequestedResource.TryParse(canonical, out var parsed))
        {
            return Failed(
                ReasonCode.ResourceMalformed,
                "The requested 'resource' is not available to this client.",
                $"resource={canonical}");
        }

        var resolved = await registry.ResolveAsync(parsed, client, cancellationToken);

        // The registry is the only source of a ResourceIdentifier, so a token cannot be minted for
        // a resource that was not resolved here. Unknown and not-permitted return the same null and
        // therefore the same words — distinguishing them enumerates the customer's internal service
        // topology.
        return resolved is null
            ? Failed(
                ReasonCode.ResourceUnavailable,
                "The requested 'resource' is not available to this client.",
                $"client_id={client.ClientId.Value}; resource={canonical}; the registry declined it")
            : new NarrowedResource(resolved, null);
    }

    private static NarrowedResource Failed(ReasonCode reason, string description, string? detail = null) =>
        new(null, new GrantOutcome.Failed(Rejection.Of(reason, OAuthErrorCode.InvalidTarget, description, detail)));
}

/// <summary>A provider that resolves nothing, for a handler constructed without one.</summary>
internal sealed class EmptyServices : IServiceProvider
{
    internal static EmptyServices Instance { get; } = new();

    public object? GetService(Type serviceType) => null;
}
