using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Token;

/// <summary>Knobs for <see cref="ClientAssertionAuthenticator"/>.</summary>
public sealed class ClientAssertionOptions
{
    /// <summary>
    /// The longest an assertion's own validity window may be.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Five minutes. RFC 7523 §3 requires an <c>exp</c> and says nothing about how far out it may
    /// be, so a client is free to mint one valid for a year - and a year-long assertion is a bearer
    /// credential in everything but name, since anyone who captures it can authenticate as that
    /// client until it expires.
    /// </para>
    /// <para>
    /// It also bounds the replay store. A row lives until its assertion expires, so the longest
    /// acceptable lifetime is exactly how long the store must remember, and without a ceiling the
    /// client picks the size of this server's table.
    /// </para>
    /// </remarks>
    public TimeSpan MaxLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Cap on the length of a <c>jti</c> this server will store.</summary>
    /// <remarks>
    /// The value is the client's own opaque string and goes straight into a keyed column. Refused
    /// with its own message rather than truncated: a truncated identifier collides with every other
    /// one sharing its prefix, which reads to the client as a replay it did not make.
    /// </remarks>
    public int MaxJwtIdLength { get; set; } = 256;

    /// <summary>Clock tolerance on the assertion's <c>exp</c> and <c>nbf</c>.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Authenticates a client by a signed assertion. RFC 7523 §3, OIDC Core §9.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists, dated.</b> On 2026-08-17 both of ChatGPT's live client documents were
/// measured declaring <c>token_endpoint_auth_method: private_key_jwt</c> beside a plural offering
/// <c>none</c>. This server prefers <c>none</c> and therefore still connects - that is what
/// <c>The_live_chatgpt_document_is_a_public_client</c> pins - so this is not a lockout fix. It is
/// the difference between serving a client the weaker of the two methods it offered and serving it
/// the one it named first. LESSONS #8 is what happens when the plural is the only thing read.
/// </para>
/// <para>
/// <b>Two audiences are accepted and the reason is interop, not laxity.</b> RFC 7523 §3 asks for a
/// value identifying the authorization server; OIDC Core §9 says the token endpoint URL and notes
/// that a server "MAY accept" its issuer identifier. Real clients send one or the other. Accepting
/// both costs nothing here because there is exactly one endpoint that takes assertions - the
/// cross-endpoint replay a broad audience would open needs a second one to replay to - and refusing
/// one spelling produces a failure the client cannot diagnose from an <c>invalid_client</c>.
/// <b>Which spelling ChatGPT actually sends has not been measured</b>; no assertion from it has been
/// captured, and this is the honest reason both are accepted rather than a preference.
/// </para>
/// <para>
/// <b>A <c>jti</c> is required, which is stricter than the RFC.</b> §3 makes it optional and the
/// replay check a MAY. Without one there is no way to tell a second presentation from a first, so
/// accepting an assertion that carries none means accepting a credential whose reuse this server
/// cannot detect - silently, on the endpoint where reuse is the point.
/// </para>
/// </remarks>
public sealed class ClientAssertionAuthenticator(
    ClientKeySource keys,
    IClientAssertionReplayStore replays,
    AuthorizationServerOptions options,
    TimeProvider time,
    ClientAssertionOptions? assertionOptions = null)
{
    /// <summary>RFC 7521 §4.2's registered assertion type. Compared ordinally.</summary>
    public const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static readonly JsonWebTokenHandler Handler = new();

    private readonly ClientKeySource _keys = keys ?? throw new ArgumentNullException(nameof(keys));
    private readonly IClientAssertionReplayStore _replays = replays ?? throw new ArgumentNullException(nameof(replays));
    private readonly AuthorizationServerOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ClientAssertionOptions _assertion = assertionOptions ?? new ClientAssertionOptions();

    /// <summary>Verify the assertion in this request, or say why not.</summary>
    /// <param name="client">The client the <c>client_id</c> resolved to.</param>
    /// <param name="parameters">The form body.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async ValueTask<ClientAuthentication> AuthenticateAsync(
        ClientRecord client, OAuthParameters parameters, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(parameters);

        if (!parameters.TrySingle("client_assertion_type", out var assertionType)
            || !string.Equals(assertionType, JwtBearerAssertionType, StringComparison.Ordinal))
        {
            return Refuse(
                ReasonCode.ClientAssertionTypeUnsupported,
                "This client must authenticate with a JWT client assertion.",
                $"client_id={client.ClientId.Value}; client_assertion_type={assertionType ?? "absent"}");
        }

        if (!parameters.TrySingle("client_assertion", out var assertion) || string.IsNullOrEmpty(assertion))
        {
            return Refuse(
                ReasonCode.ClientCredentialsMissing,
                "This client must authenticate with a JWT client assertion.",
                $"client_id={client.ClientId.Value}; client_assertion absent");
        }

        // Fetched before the first validation attempt, and again only on an unknown `kid`. The
        // second fetch is what keeps a client's own key rotation from failing every authentication
        // until this cache expires; ClientKeySource bounds how often it can be provoked.
        var fetched = await _keys.GetAsync(client, refreshBecauseKeyUnknown: false, cancellationToken);

        if (fetched.Keys.Count == 0)
        {
            return Refuse(
                ReasonCode.ClientAssertionKeysUnavailable,
                "Client authentication failed.",
                $"client_id={client.ClientId.Value}; {fetched.Detail}");
        }

        var result = await Handler.ValidateTokenAsync(assertion, Parameters(client, fetched.Keys));

        if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            // The one failure worth a second attempt: the client signed with a key published after
            // this cache was filled. Every other failure is about the assertion rather than the key
            // set, and refetching for those would make the token endpoint an amplifier - an
            // attacker-shaped assertion naming a random `kid` costs nothing to produce.
            var refreshed = await _keys.GetAsync(client, refreshBecauseKeyUnknown: true, cancellationToken);

            if (refreshed.Keys.Count > 0)
            {
                result = await Handler.ValidateTokenAsync(assertion, Parameters(client, refreshed.Keys));
            }
        }

        if (!result.IsValid)
        {
            return Refuse(
                ReasonCode.ClientAssertionInvalid,
                "Client authentication failed.",
                $"client_id={client.ClientId.Value}; {result.Exception?.GetType().Name ?? "invalid"}");
        }

        var identity = result.ClaimsIdentity;

        // §3 point 2: the subject is the client too. TokenValidationParameters has no place to
        // express it, so it is checked here rather than being left to the reader to notice.
        var subject = identity.FindFirst("sub")?.Value;

        if (!string.Equals(subject, client.ClientId.Value, StringComparison.Ordinal))
        {
            return Refuse(
                ReasonCode.ClientAssertionInvalid,
                "Client authentication failed.",
                $"client_id={client.ClientId.Value}; sub={subject ?? "absent"}");
        }

        if (!TryReadExpiry(identity, out var expiresAt))
        {
            return Refuse(
                ReasonCode.ClientAssertionInvalid,
                "Client authentication failed.",
                $"client_id={client.ClientId.Value}; exp unreadable");
        }

        // RequireExpirationTime has already refused an assertion with no `exp`, and ValidateLifetime
        // has refused one that has passed. This is the other end: how far out it may be.
        if (expiresAt - _time.GetUtcNow() > _assertion.MaxLifetime + _assertion.ClockSkew)
        {
            return Refuse(
                ReasonCode.ClientAssertionInvalid,
                "Client authentication failed.",
                $"client_id={client.ClientId.Value}; exp beyond {_assertion.MaxLifetime}");
        }

        var jwtId = identity.FindFirst("jti")?.Value;

        if (string.IsNullOrEmpty(jwtId) || jwtId.Length > _assertion.MaxJwtIdLength)
        {
            return Refuse(
                ReasonCode.ClientAssertionIdentifierUnusable,
                "The client assertion must carry a 'jti' this server can record.",
                $"client_id={client.ClientId.Value}; jti={(jwtId is null ? "absent" : $"{jwtId.Length} chars")}");
        }

        // Last, and after every other check, so a replay row is never written for an assertion that
        // was going to be refused anyway - otherwise a malformed assertion burns the identifier a
        // later valid one would use, and the client sees a replay it did not make.
        if (!await _replays.TryClaimAsync(client.ClientId, jwtId, expiresAt, cancellationToken))
        {
            return Refuse(
                ReasonCode.ClientAssertionReplayed,
                "Client authentication failed.",
                $"client_id={client.ClientId.Value}; jti already used");
        }

        return new ClientAuthentication.Authenticated(client, ClientAuthMethod.PrivateKeyJwt);
    }

    /// <summary>The two spellings of this server's identity an assertion may name.</summary>
    private TokenValidationParameters Parameters(
        ClientRecord client, IReadOnlyList<SecurityKey> signingKeys) =>
        Rfc9068ValidationParameters.ForClientAssertion(
            client.ClientId,
            [
                _options.ValidatedIssuer.Value + AuthorizationServerPaths.Token,
                _options.ValidatedIssuer.Value,
            ],
            signingKeys,
            _assertion.ClockSkew);

    private static bool TryReadExpiry(System.Security.Claims.ClaimsIdentity identity, out DateTimeOffset expiresAt)
    {
        expiresAt = default;

        var raw = identity.FindFirst("exp")?.Value;

        if (!long.TryParse(raw, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var seconds))
        {
            return false;
        }

        expiresAt = DateTimeOffset.FromUnixTimeSeconds(seconds);

        return true;
    }

    /// <summary>
    /// A refusal, always carrying <c>invalid_client</c> and never the Authorization header's 401.
    /// </summary>
    /// <remarks>
    /// <c>UsedAuthorizationHeader: false</c> throughout: an assertion travels in the request body,
    /// which RFC 7235 has no challenge form for, so §5.2's 401 does not apply and the answer is 400.
    /// <c>ClientAuthentication.Failed</c> already documents that for this method.
    /// </remarks>
    private static ClientAuthentication.Failed Refuse(ReasonCode code, string description, string detail) =>
        new ClientAuthentication.Failed(
            Rejection.Of(code, OAuthErrorCode.InvalidClient, description, detail),
            UsedAuthorizationHeader: false);
}
