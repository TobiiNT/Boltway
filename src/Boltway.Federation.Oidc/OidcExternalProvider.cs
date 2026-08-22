using System.Text;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Federation;
using Boltway.OAuth.Net;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.Federation.Oidc;

/// <summary>
/// An OpenID Connect relying party, pointed at one upstream.
/// </summary>
/// <remarks>
/// <para>
/// <b>This server is an OAuth client here, and every rule it enforces on its own clients applies to
/// it.</b> PKCE with S256, a <c>state</c> bound to the browser, a <c>nonce</c> bound to the ID
/// token, and one exact redirect URI sent identically at both legs. Those are not extras on the
/// upstream side: a relying party that skips PKCE on the leg it controls has the same code-injection
/// exposure it refuses to let its own clients have.
/// </para>
/// <para>
/// The division of labour with the authorization server is recorded on
/// <see cref="IExternalIdentityProvider"/>. Briefly: the server mints the three unguessable values
/// and compares <c>state</c> and <c>nonce</c>; this class composes the URL, exchanges the code, and
/// validates the ID token.
/// </para>
/// <para>
/// It is <c>sealed</c>. A subclass overriding <see cref="CompleteAsync"/> would be a second
/// validation path, and the shape a provider is meant to take is a different
/// <see cref="OidcProviderOptions"/> — which is what <c>Boltway.Federation.Google</c> is.
/// </para>
/// </remarks>
public sealed class OidcExternalProvider : IExternalIdentityProvider, IDisposable
{
    private readonly OidcProviderOptions _options;
    private readonly IUpstreamEndpointClient _http;
    private readonly UpstreamMetadataCache _metadata;
    private readonly JsonWebTokenHandler _handler = new();

    /// <summary>Construct over validated options.</summary>
    /// <param name="options">
    /// The provider's configuration. Must already have been through
    /// <see cref="OidcProviderOptions.TryValidate"/>.
    /// </param>
    /// <param name="http">The guarded upstream transport.</param>
    /// <param name="time">The clock the metadata caches count on.</param>
    /// <exception cref="ArgumentException">The options do not validate.</exception>
    public OidcExternalProvider(OidcProviderOptions options, IUpstreamEndpointClient http, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(time);

        // Re-validated here rather than trusted, because this constructor is public and a customer
        // may reach it without going through the registration extension. Options validation sets
        // the parsed fields this class reads, so skipping it is not a style lapse — it leaves
        // ValidatedIssuer empty and every ID token comparison against the empty string.
        if (!options.TryValidate(out var errors))
        {
            throw new ArgumentException(
                "This upstream provider is not configured usably:" + Environment.NewLine
                + string.Join(Environment.NewLine, errors.Select(e => "  - " + e)),
                nameof(options));
        }

        _options = options;
        _http = http;
        _metadata = new UpstreamMetadataCache(options, http, time);
    }

    /// <inheritdoc />
    public string Scheme => _options.Scheme;

    /// <inheritdoc />
    public string Issuer => _options.Issuer;

    /// <inheritdoc />
    public string DisplayName => _options.DisplayName;

    /// <summary>
    /// Whether this provider can run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Answers <see cref="ProviderAvailability.Available"/> for every client. This provider carries
    /// no per-client restriction, which is A-10 rather than an omission: "no two-tier connection
    /// model — every configured identity source is usable by every valid client unless explicitly
    /// restricted". A deployment that needs a restriction wraps this class or writes its own, and
    /// A-11 is what makes the wrapper's refusal show up as a disabled control with a reason instead
    /// of a missing button.
    /// </para>
    /// <para>
    /// It also does <b>not</b> probe the upstream. A liveness check here would put an outbound
    /// request on every render of the login page, keyed on nothing, and the honest answer it could
    /// give — "reachable a moment ago" — is not the question. An upstream that is down produces a
    /// specific failure on the callback, which is logged with a correlation id.
    /// </para>
    /// </remarks>
    public ValueTask<ProviderAvailability> GetAvailabilityAsync(
        ExternalProviderContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(ProviderAvailability.Available);

    /// <inheritdoc />
    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// The discovered authorization endpoint's origin, so the policy and the redirect come from the
    /// same metadata and cannot disagree.
    /// </para>
    /// <para>
    /// <b>Falling back to the issuer's origin is the load-bearing half.</b> Discovery is a network
    /// fetch behind a cache, so the first render after a restart — or any render once the cache has
    /// expired and the fetch fails — would otherwise answer null, ship a strict policy, and leave
    /// the button silently doing nothing. That is the exact defect this method exists to close,
    /// reached through the back door, and it is invisible: the page is correct, the redirect is
    /// correct, the browser declines. Observed as a deploy verifier passing a check for a *bare*
    /// policy nine minutes after a container restart, when it had failed on the widened one before.
    /// </para>
    /// <para>
    /// The issuer is configuration rather than a fetch, so it is available at every render. It is a
    /// lower bound and not a guess: an upstream whose authorization endpoint sits on a different
    /// origin from its issuer is served no worse than by the null this replaces, and the common
    /// configuration — Google, Okta, Entra, Auth0 — puts both on one host. Naming a source the
    /// browser never navigates to costs nothing; failing to name one it does costs the flow.
    /// </para>
    /// </remarks>
    public async ValueTask<string?> GetChallengeOriginAsync(CancellationToken cancellationToken)
    {
        var endpoints = await _metadata.GetEndpointsAsync(cancellationToken);

        if (endpoints.Value is { } resolved)
        {
            return new Uri(resolved.Authorization.Value).GetLeftPart(UriPartial.Authority);
        }

        return Uri.TryCreate(_options.Issuer, UriKind.Absolute, out var issuer)
            ? issuer.GetLeftPart(UriPartial.Authority)
            : null;
    }

    /// <inheritdoc />
    public async ValueTask<ExternalChallenge> BeginAsync(
        ExternalLoginContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var endpoints = await _metadata.GetEndpointsAsync(cancellationToken);

        if (endpoints.Value is null)
        {
            // Thrown rather than returned, because ExternalChallenge has no failure case: the type
            // exists to be a validated redirect target. The server's endpoint catches this and turns
            // it into a logged rejection — it cannot become a 500, because the exception boundary is
            // the same one every interaction page sits behind.
            throw new UpstreamProviderException(
                ExternalFailureKind.ProviderUnavailable, endpoints.Detail!);
        }

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["response_type"] = "code",
            ["client_id"] = _options.ValidatedClientId.Value,
            ["redirect_uri"] = context.CallbackUrl,
            ["scope"] = string.Join(' ', _options.Scopes),
            ["state"] = context.State,
            ["nonce"] = context.Nonce,
            ["code_challenge"] = context.CodeChallenge,
            ["code_challenge_method"] = "S256",
        };

        foreach (var (name, value) in _options.AuthorizationParameters)
        {
            // Options validation refuses any key that collides with the eight above, so this cannot
            // overwrite `state`, `nonce` or the challenge.
            parameters[name] = value;
        }

        return ExternalChallenge.To(WithQuery(endpoints.Value.Authorization.Value, parameters));
    }

    /// <summary>
    /// Append parameters to a URL's <b>query</b>, preserving one that is already there.
    /// </summary>
    /// <remarks>
    /// The same three failures <c>AuthorizeResults.Build</c> records, one layer over. An
    /// authorization endpoint may legitimately carry a query string — several enterprise products
    /// put a tenant or a policy there — so concatenating <c>"?…"</c> would produce a second
    /// <c>?</c>, which is a legal character inside a query and therefore fails silently. And every
    /// value here needs percent-encoding: a display name or a hosted-domain hint containing
    /// <c>&amp;</c> would otherwise inject a parameter.
    /// </remarks>
    private static string WithQuery(string url, IReadOnlyDictionary<string, string> parameters)
    {
        var builder = new StringBuilder(url);
        var separator = url.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        foreach (var (name, value) in parameters)
        {
            builder.Append(separator)
                .Append(Uri.EscapeDataString(name))
                .Append('=')
                .Append(Uri.EscapeDataString(value));

            separator = '&';
        }

        return builder.ToString();
    }

    /// <inheritdoc />
    public async ValueTask<ExternalLoginResult> CompleteAsync(
        ExternalCallbackContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // RFC 9207 §2.4: when the authorization response carries `iss`, a client MUST validate it.
        // An upstream that does not send it is conformant and common, so its absence is not a
        // failure — but a value that disagrees with the configured issuer is a mix-up attack in
        // progress and is refused before the code is spent.
        if (context.Parameters.TryGetValue("iss", out var declaredIssuer)
            && !string.Equals(declaredIssuer, _options.ValidatedIssuer.Value, StringComparison.Ordinal))
        {
            return new ExternalLoginResult.Failed(
                ExternalFailureKind.IdentityTokenRejected,
                $"authorization response `iss` is '{Trim(declaredIssuer)}', configured issuer is "
                + $"'{_options.ValidatedIssuer.Value}' (RFC 9207 mix-up)");
        }

        var endpoints = await _metadata.GetEndpointsAsync(cancellationToken);

        if (endpoints.Value is null)
        {
            return new ExternalLoginResult.Failed(ExternalFailureKind.ProviderUnavailable, endpoints.Detail!);
        }

        var exchange = await ExchangeCodeAsync(endpoints.Value, context, cancellationToken);

        if (exchange is not FetchOutcome.Ok ok)
        {
            return new ExternalLoginResult.Failed(
                ExternalFailureKind.TokenExchangeFailed, UpstreamMetadataCache.Describe(exchange));
        }

        string? idToken;

        try
        {
            using var document = JsonDocument.Parse(ok.Body);

            idToken = document.RootElement.ValueKind is JsonValueKind.Object
                && document.RootElement.TryGetProperty("id_token", out var member)
                && member.ValueKind is JsonValueKind.String
                    ? member.GetString()
                    : null;
        }
        catch (JsonException)
        {
            return new ExternalLoginResult.Failed(
                ExternalFailureKind.TokenExchangeFailed, "token response is not JSON");
        }

        if (string.IsNullOrEmpty(idToken))
        {
            return new ExternalLoginResult.Failed(
                ExternalFailureKind.IdentityTokenMissing,
                "the token response carried no id_token; check that `openid` is in the requested scope");
        }

        return await ValidateAsync(idToken, cancellationToken);
    }

    /// <summary>The credentialed POST. Split out so the exchange is one readable block above.</summary>
    /// <remarks>
    /// The secret is not a parameter here and is not read here: it goes across as the
    /// <see cref="UpstreamClientSecret"/> off the options, and only
    /// <c>Boltway.OAuth.Net</c> can turn that back into characters.
    /// </remarks>
    private Task<FetchOutcome> ExchangeCodeAsync(
        UpstreamEndpoints endpoints, ExternalCallbackContext context, CancellationToken cancellationToken) =>
        _http.PostFormAsync(
            new UpstreamFormRequest(
                endpoints.Token,
                FetchPurpose.UpstreamTokenExchange,
                [
                    new("grant_type", "authorization_code"),
                    new("code", context.Code),

                    // Byte for byte the value sent at the start. OAuth 2.1 §4.1.3 requires it, and
                    // a mismatch here is one of the two things that make a stolen code useless.
                    new("redirect_uri", context.CallbackUrl),

                    new("code_verifier", context.CodeVerifier),
                ])
            {
                ClientId = _options.ValidatedClientId.Value,
                ClientSecret = _options.ClientSecret,
                AuthMethod = _options.ClientAuthMethod,
            },
            cancellationToken);

    /// <summary>Validate the ID token, refetching keys once if it names a <c>kid</c> we do not hold.</summary>
    private async ValueTask<ExternalLoginResult> ValidateAsync(string idToken, CancellationToken cancellationToken)
    {
        var attempt = await ValidateOnceAsync(idToken, refreshKeys: false, cancellationToken);

        // One retry, and only for the one failure a key rotation produces. Retrying on a bad
        // signature would let anyone with a forged token drive an outbound fetch per request; the
        // minimum-refresh floor inside the cache is the second bound on the same thing.
        if (attempt.Result is ExternalLoginResult.Failed && attempt.KeyUnknown)
        {
            attempt = await ValidateOnceAsync(idToken, refreshKeys: true, cancellationToken);
        }

        return attempt.Result;
    }

    private async ValueTask<(ExternalLoginResult Result, bool KeyUnknown)> ValidateOnceAsync(
        string idToken, bool refreshKeys, CancellationToken cancellationToken)
    {
        var keys = await _metadata.GetKeysAsync(refreshKeys, cancellationToken);

        if (keys.Value is null)
        {
            return (new ExternalLoginResult.Failed(ExternalFailureKind.ProviderUnavailable, keys.Detail!), false);
        }

        var parameters = Rfc9068ValidationParameters.ForUpstreamIdToken(
            _options.ValidatedIssuer,
            _options.ValidatedClientId,
            keys.Value,
            [.. _options.IdTokenTypeHeaders],
            _options.ClockSkew);

        var result = await _handler.ValidateTokenAsync(idToken, parameters);

        if (!result.IsValid)
        {
            var unknownKey = result.Exception is SecurityTokenSignatureKeyNotFoundException;

            return (
                new ExternalLoginResult.Failed(
                    ExternalFailureKind.IdentityTokenRejected,

                    // The exception type and message, exactly as the resource server's validator
                    // records them and for the same reason: "wrong key", "wrong issuer", "expired"
                    // and "wrong audience" are one refusal to the user and four different mornings
                    // for whoever is on call. It reaches the log and never a response.
                    $"{result.Exception?.GetType().Name}: {Trim(result.Exception?.Message)}"),
                unknownKey);
        }

        var identity = result.ClaimsIdentity;
        var subject = identity.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(subject))
        {
            // OIDC Core §2 makes `sub` REQUIRED. Without it there is nothing to key an account on,
            // and inventing one from `email` is the exact takeover this integration refuses.
            return (
                new ExternalLoginResult.Failed(
                    ExternalFailureKind.IdentityTokenRejected, "the ID token carries no `sub` claim"),
                false);
        }

        var claims = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var name in SurfacedClaims)
        {
            if (identity.FindFirst(name)?.Value is { Length: > 0 } value)
            {
                claims[name] = value;
            }
        }

        return (
            new ExternalLoginResult.Authenticated(
                new ExternalPrincipal(
                    _options.ValidatedIssuer.Value,
                    subject,

                    // Uncompared. The value it must equal is in the browser's pending-request
                    // cookie, which this assembly cannot see — the comparison is the server's, in
                    // one place, for every provider.
                    identity.FindFirst("nonce")?.Value,
                    claims)),
            false);
    }

    /// <summary>
    /// The claims carried out of the ID token, and nothing else.
    /// </summary>
    /// <remarks>
    /// An allow-list rather than the whole claim set. Two reasons, and the second is the one that
    /// matters: a copied claim set is unbounded attacker-influenced data on its way into a log line
    /// and possibly into an account record; and an allow-list makes it obvious, on one line, that
    /// <c>email</c> is here for display and provisioning and is <b>never</b> read as an identity —
    /// which is the rule the whole account-resolution design rests on.
    /// </remarks>
    private static readonly string[] SurfacedClaims = ["email", "email_verified", "name", "picture", "hd"];

    private static string Trim(string? value) =>
        value is null ? "<none>" : value.Length <= 200 ? value : value[..200];

    /// <summary>Release the metadata cache's single-flight gates.</summary>
    /// <remarks>
    /// It does <b>not</b> dispose the <see cref="IUpstreamEndpointClient"/>: that is registered in
    /// the container, is shared by every provider, and disposing something this class did not create
    /// is how one provider's shutdown breaks another's.
    /// </remarks>
    public void Dispose() => _metadata.Dispose();
}

/// <summary>A provider that cannot run at all, thrown out of <see cref="OidcExternalProvider.BeginAsync"/>.</summary>
/// <remarks>
/// The start of a federated sign-in has no failure return value — <see cref="ExternalChallenge"/> is
/// a redirect target and there is no such thing as a redirect to nowhere — so the one failure it can
/// have travels as an exception. The authorization server's federation endpoints catch it and turn
/// it into a logged rejection with a correlation id, so it never surfaces as an unhandled 500.
/// </remarks>
public sealed class UpstreamProviderException : Exception
{
    /// <summary>Construct with a kind and a detail for the log.</summary>
    public UpstreamProviderException(ExternalFailureKind kind, string detail)
        : base(detail) => Kind = kind;

    /// <summary>Construct with a message.</summary>
    public UpstreamProviderException(string message)
        : base(message) => Kind = ExternalFailureKind.ProviderUnavailable;

    /// <summary>Construct with a message and an inner cause.</summary>
    public UpstreamProviderException(string message, Exception innerException)
        : base(message, innerException) => Kind = ExternalFailureKind.ProviderUnavailable;

    /// <summary>Construct with no detail. Present for the framework; prefer the other constructors.</summary>
    public UpstreamProviderException()
        : this("The upstream identity provider cannot be used.") { }

    /// <summary>Which failure this is.</summary>
    public ExternalFailureKind Kind { get; }
}
