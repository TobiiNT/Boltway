using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>An authorization code, and the grant it will produce tokens for.</summary>
/// <param name="Code">
/// The plaintext, which exists only here and in the redirect. Nothing persists it - the store
/// holds <see cref="Sha256Hash"/> - so a database read cannot yield a usable code.
/// </param>
/// <param name="GrantId">The grant the code redeems against.</param>
public readonly record struct IssuedAuthorizationCode(OpaqueSecret Code, string GrantId);

/// <summary>
/// Stage 11: turn a validated, consented request into an authorization code.
/// </summary>
/// <remarks>
/// <para>
/// Everything the token endpoint will need to make a decision is written here, because at
/// redemption the authorization request is gone. In particular <c>redirect_uri_used</c> and the
/// PKCE challenge are stored rather than recomputed: RFC 6749 §4.1.3 requires the token request's
/// <c>redirect_uri</c> to equal the one the authorization request carried, and "the one it carried"
/// has no other source.
/// </para>
/// <para>
/// The grant is written before the code. If the process dies between the two, the result is a grant
/// with no code - inert, and swept by expiry. The other order would leave a code pointing at a
/// grant that does not exist, which the token endpoint would have to treat as a server error on an
/// otherwise valid request.
/// </para>
/// </remarks>
public sealed class AuthorizationCodeIssuer(
    IGrantStore grants,
    IAuthorizationCodeStore codes,
    TimeProvider timeProvider,
    NewDeviceNotice? devices = null)
{
    private readonly IGrantStore _grants = grants ?? throw new ArgumentNullException(nameof(grants));
    private readonly IAuthorizationCodeStore _codes = codes ?? throw new ArgumentNullException(nameof(codes));
    private readonly TimeProvider _time = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <summary>Issue a code for a request that has passed validation, authentication and consent.</summary>
    /// <param name="context">The validated request, with <see cref="AuthorizeContext.Subject"/> set.</param>
    /// <param name="lifetime">How long the code is valid.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<IssuedAuthorizationCode> IssueAsync(
        AuthorizeContext context, TimeSpan lifetime, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // These are programming errors rather than protocol errors - a caller reaching stage 11
        // without them has skipped a stage - so they throw rather than producing an OAuth error.
        var subject = context.Subject ?? throw new InvalidOperationException(
            "A code cannot be issued before the user is authenticated (stage 9).");
        var redirect = context.Redirect ?? throw new InvalidOperationException(
            "A code cannot be issued before the redirect URI is validated (stage 3).");
        var client = context.Client ?? throw new InvalidOperationException(
            "A code cannot be issued before the client is resolved (stage 2).");

        var now = _time.GetUtcNow();
        var authTime = context.AuthTime ?? now;

        var grant = new GrantRecord(
            GrantId: Guid.NewGuid().ToString("N"),
            Subject: subject,
            ClientId: client.ClientId,
            Scope: context.Scope,
            Resources: [.. context.Resources.Select(r => r.Canonical)],
            CreatedAt: now,

            // Carried on the grant, not only on the code, because the refresh path needs it after
            // the code is gone. Without it that path had nothing correct to pass and used the
            // presented token's issue time, so auth_time crept forward on every rotation.
            AuthTime: authTime,
            RevokedAt: null,

            // Stamped once, here, and never again. A refresh does not restamp it: the page asks
            // which device approved, not which one is holding the token now.
            UserAgent: context.UserAgent);

        // Before the write, because afterwards the grant being written is in its own history and
        // every device looks familiar. NewDeviceNotice says what that costs.
        var notice = devices is null
            ? null
            : await devices.PrepareAsync(subject, client, context.UserAgent, now, cancellationToken);

        await _grants.StoreAsync(grant, cancellationToken);

        // After it, because a message announcing an authorization that failed to store is a message
        // about something that did not happen. Optional at both ends: a deployment with no sender
        // configured never reaches either call, and neither can fail this method.
        if (notice is not null)
        {
            await devices!.SendAsync(notice, cancellationToken);
        }

        var code = OpaqueSecret.Generate(TokenPurpose.AuthorizationCode);

        var record = new AuthorizationCodeRecord(
            CodeHash: Sha256Hash.Of(code),
            GrantId: grant.GrantId,
            ClientId: client.ClientId,
            RedirectUriUsed: redirect.Value,
            CodeChallenge: context.Challenge?.Value,
            ChallengeMethod: context.Challenge?.Method ?? CodeChallengeMethod.None,

            // Stored, not inferred from the challenge being non-null. The check at redemption is a
            // strict XOR in both directions: a verifier arriving for a code issued without a
            // challenge is as much a protocol violation as a missing verifier for one issued with
            // it, and only a recorded fact can tell those apart from "the challenge column is null
            // because something went wrong".
            PkceWasRequested: context.Challenge is not null,

            Scope: context.Scope,
            Resources: [.. context.Resources.Select(r => r.Canonical)],
            Nonce: context.Nonce,
            AuthTime: authTime,
            IssuedAt: now,
            ExpiresAt: now + lifetime);

        await _codes.StoreAsync(record, cancellationToken);

        return new IssuedAuthorizationCode(code, grant.GrantId);
    }
}
