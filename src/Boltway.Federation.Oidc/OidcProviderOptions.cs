using Boltway.OAuth.Net;
using Boltway.OAuth.Tokens;

namespace Boltway.Federation.Oidc;

/// <summary>
/// One upstream OpenID Connect provider, as an operator configures it.
/// </summary>
/// <remarks>
/// <para>
/// The whole of "add Facebook" is an instance of this class. Everything below is either a value the
/// upstream publishes or a credential it issued; there is no per-provider code path, and
/// <c>Boltway.Federation.Google</c> is a file that fills three of these fields in.
/// </para>
/// <para>
/// <b>Validated once, at startup, by <see cref="TryValidate"/>.</b> The alternative - checking each
/// field where it is used - means a deployment learns its issuer is malformed at the moment a user
/// clicks the button, which is the failure mode this whole codebase is a reaction to.
/// </para>
/// </remarks>
public sealed class OidcProviderOptions
{
    /// <summary>
    /// The route segment: <c>/external/{scheme}/start</c>.
    /// </summary>
    /// <remarks>
    /// Constrained to <c>[a-z0-9-]{1,32}</c> by <see cref="TryValidate"/> so it needs no escaping in
    /// a path - the A-18 rule, applied to a value that becomes part of a URL. It is also the key
    /// this server's <c>ExternalLogin</c> rows are <i>not</i> stored under: those use the issuer, so
    /// renaming a scheme does not orphan anybody's account.
    /// </remarks>
    public string Scheme { get; set; } = string.Empty;

    /// <summary>What the button says. Plain text; the renderer encodes it.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// The upstream's issuer identifier, exactly as it appears in its ID tokens.
    /// </summary>
    /// <remarks>
    /// The one field that must be right. It is compared byte for byte against the <c>iss</c> claim
    /// of every ID token, against the <c>issuer</c> member of the discovery document, and it is the
    /// first half of the key that maps an upstream identity to a local account. A deployment that
    /// changes it orphans every existing federated login, which is why nothing derives it from
    /// anything else.
    /// </remarks>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>This server's client identifier at the upstream.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// The secret, or <see langword="null"/> for an upstream that issues none.
    /// </summary>
    /// <remarks>
    /// An <see cref="UpstreamClientSecret"/> rather than a <see cref="string"/>, so the value cannot
    /// be read back out by anything except the code that writes it onto the socket. Configuration
    /// binding sets it through <see cref="SetClientSecret"/>.
    /// </remarks>
    public UpstreamClientSecret? ClientSecret { get; private set; }

    /// <summary>Set the secret from a configured string.</summary>
    /// <param name="secret">The secret, or <see langword="null"/> / empty to clear it.</param>
    public void SetClientSecret(string? secret) =>
        ClientSecret = string.IsNullOrEmpty(secret) ? null : new UpstreamClientSecret(secret);

    /// <summary>How to present the secret at the token endpoint.</summary>
    public UpstreamClientAuthMethod ClientAuthMethod { get; set; } = UpstreamClientAuthMethod.ClientSecretPost;

    /// <summary>
    /// The discovery document URL, or empty to derive it from <see cref="Issuer"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Derived as <c>{issuer}/.well-known/openid-configuration</c>, which is OIDC Discovery §4's
    /// append form. RFC 8414 §3.1's <i>insertion</i> form -
    /// <c>https://host/.well-known/openid-configuration/tenant</c> - is <b>not</b> tried, and that is
    /// a stated limitation rather than an oversight: probing several spellings would mean several
    /// outbound requests against an upstream that is almost always reachable at the first one. An
    /// issuer with a path whose provider serves only the insertion form is configured here
    /// explicitly.
    /// </para>
    /// <para>
    /// Ignored entirely when <see cref="AuthorizationEndpoint"/>, <see cref="TokenEndpoint"/> and
    /// <see cref="JwksUri"/> are all set - in which case this server makes no discovery request at
    /// all.
    /// </para>
    /// </remarks>
    public string DiscoveryUri { get; set; } = string.Empty;

    /// <summary>The upstream's authorization endpoint, or empty to discover it.</summary>
    public string AuthorizationEndpoint { get; set; } = string.Empty;

    /// <summary>The upstream's token endpoint, or empty to discover it.</summary>
    public string TokenEndpoint { get; set; } = string.Empty;

    /// <summary>The upstream's JWKS URI, or empty to discover it.</summary>
    public string JwksUri { get; set; } = string.Empty;

    /// <summary>
    /// The scopes requested at the upstream.
    /// </summary>
    /// <remarks>
    /// <c>openid</c> is required and is added by <see cref="TryValidate"/> if it is missing - without
    /// it the upstream is not obliged to return an ID token at all, and an ID token is the only
    /// thing this integration consumes. The default asks for nothing else: an email address is not
    /// needed to identify a user here, because identity is
    /// <c>(issuer, subject)</c>, and asking for a claim this server refuses to make decisions on
    /// would be asking for data it has no use for.
    /// </remarks>
    public IList<string> Scopes { get; } = ["openid"];

    /// <summary>
    /// Extra parameters added to the upstream authorization request.
    /// </summary>
    /// <remarks>
    /// For the provider-specific knobs that are not worth a field: Google's <c>hd</c> for a hosted
    /// domain, <c>prompt</c>, <c>access_type</c>. Any key that collides with a parameter this
    /// provider sets is rejected at startup rather than silently overriding <c>state</c> or
    /// <c>nonce</c>.
    /// </remarks>
    public IDictionary<string, string> AuthorizationParameters { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// The <c>typ</c> header values accepted on an upstream ID token.
    /// </summary>
    /// <remarks>
    /// See <c>Rfc9068ValidationParameters.ForUpstreamIdToken</c>: the check cannot be switched off,
    /// and an upstream that omits <c>typ</c> is not supported. Google, Entra, Okta, Auth0 and
    /// Keycloak all set <c>JWT</c>.
    /// </remarks>
    public IList<string> IdTokenTypeHeaders { get; } = [TokenTypes.IdToken];

    /// <summary>Clock tolerance when validating an upstream ID token.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long a fetched key set is used before it is fetched again.
    /// </summary>
    /// <remarks>
    /// Bounded rather than indefinite so a key an upstream has retired stops being accepted within a
    /// known window. It is not the rotation mechanism - see
    /// <see cref="JwksMinimumRefreshInterval"/>, which is what handles a key appearing early.
    /// </remarks>
    public TimeSpan JwksCacheLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The shortest interval between two key-set fetches provoked by an unknown <c>kid</c>.
    /// </summary>
    /// <remarks>
    /// An upstream that rotates publishes the new key before it signs with it, but not every one
    /// does, and a token naming a <c>kid</c> we have not seen is the signal to refetch. Without a
    /// floor that signal is attacker-controlled: anyone who can reach the callback with a
    /// syntactically valid JWT naming a random <c>kid</c> makes this server fetch the upstream's
    /// JWKS, once per request. The floor turns that into once per interval.
    /// </remarks>
    public TimeSpan JwksMinimumRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long a discovery document is used before it is fetched again.</summary>
    public TimeSpan DiscoveryCacheLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>The parsed issuer. Set by <see cref="TryValidate"/>.</summary>
    public UpstreamIssuer ValidatedIssuer { get; private set; }

    /// <summary>The parsed client identifier. Set by <see cref="TryValidate"/>.</summary>
    public UpstreamAudience ValidatedClientId { get; private set; }

    /// <summary>The parsed discovery URL, or <see langword="null"/> when nothing is discovered.</summary>
    public AbsoluteHttpsUrl? ValidatedDiscoveryUri { get; private set; }

    /// <summary>The parsed authorization endpoint, or <see langword="null"/> to discover it.</summary>
    public AbsoluteHttpsUrl? ValidatedAuthorizationEndpoint { get; private set; }

    /// <summary>The parsed token endpoint, or <see langword="null"/> to discover it.</summary>
    public AbsoluteHttpsUrl? ValidatedTokenEndpoint { get; private set; }

    /// <summary>The parsed JWKS URI, or <see langword="null"/> to discover it.</summary>
    public AbsoluteHttpsUrl? ValidatedJwksUri { get; private set; }

    /// <summary>Parameters a caller may not override, because this provider sets them.</summary>
    private static readonly string[] ReservedAuthorizationParameters =
    [
        "response_type", "client_id", "redirect_uri", "scope",
        "state", "nonce", "code_challenge", "code_challenge_method",
    ];

    /// <summary>
    /// Check everything, collecting every problem rather than the first.
    /// </summary>
    /// <param name="errors">Every problem found.</param>
    /// <returns>Whether the configuration is usable.</returns>
    public bool TryValidate(out IReadOnlyList<string> errors)
    {
        List<string> problems = [];

        if (!IsUsableScheme(Scheme))
        {
            problems.Add(
                $"Scheme '{Scheme}' is not usable as a route segment. It must be 1-32 characters of "
                + "[a-z0-9-], because it becomes part of /external/{scheme}/start.");
        }

        if (string.IsNullOrWhiteSpace(DisplayName))
        {
            problems.Add("DisplayName is what the sign-in button says and cannot be empty.");
        }

        if (!UpstreamIssuer.TryParse(Issuer, out var issuer))
        {
            problems.Add(
                $"Issuer '{Issuer}' is not an https URL without query or fragment. It is compared "
                + "byte for byte against the `iss` of every ID token, so it must be exactly what the "
                + "upstream publishes.");
        }
        else
        {
            ValidatedIssuer = issuer;
        }

        if (!UpstreamAudience.TryParse(ClientId, out var clientId))
        {
            problems.Add("ClientId is empty, over-long, or contains a character outside printable ASCII.");
        }
        else
        {
            ValidatedClientId = clientId;
        }

        ValidatedAuthorizationEndpoint = Endpoint(nameof(AuthorizationEndpoint), AuthorizationEndpoint, problems);
        ValidatedTokenEndpoint = Endpoint(nameof(TokenEndpoint), TokenEndpoint, problems);
        ValidatedJwksUri = Endpoint(nameof(JwksUri), JwksUri, problems);

        var discovers = ValidatedAuthorizationEndpoint is null
            || ValidatedTokenEndpoint is null
            || ValidatedJwksUri is null;

        if (discovers)
        {
            var candidate = string.IsNullOrWhiteSpace(DiscoveryUri)
                ? (issuer.IsPresent ? issuer.Value.TrimEnd('/') + "/.well-known/openid-configuration" : string.Empty)
                : DiscoveryUri;

            if (!AbsoluteHttpsUrl.TryCreate(candidate, out var discovery))
            {
                // Only reported when something actually has to be discovered. A deployment that
                // configured all three endpoints explicitly never makes this request, and demanding
                // a valid discovery URL from it would be demanding a value nothing reads.
                problems.Add(
                    $"DiscoveryUri '{candidate}' is not an absolute https URL, and at least one of "
                    + "AuthorizationEndpoint, TokenEndpoint and JwksUri is unset — so this provider "
                    + "has to discover them.");
            }
            else
            {
                ValidatedDiscoveryUri = discovery;
            }
        }
        else
        {
            ValidatedDiscoveryUri = null;
        }

        if (!Scopes.Contains("openid", StringComparer.Ordinal))
        {
            // Added rather than rejected: an upstream is not obliged to return an ID token without
            // it, and an ID token is the only thing this integration reads. A deployment that
            // removed it has not expressed a preference this code should honour.
            Scopes.Insert(0, "openid");
        }

        foreach (var scope in Scopes)
        {
            // RFC 6749 §3.3's grammar, the same one A-13 applies to this server's own scopes. A
            // space inside a value would silently become two scopes on the upstream request.
            if (string.IsNullOrEmpty(scope) || scope.Any(c => c is < '\x21' or '\x22' or '\x5c' or > '\x7e'))
            {
                problems.Add($"Scope '{scope}' is outside RFC 6749 §3.3's grammar.");
            }
        }

        foreach (var name in AuthorizationParameters.Keys)
        {
            if (ReservedAuthorizationParameters.Contains(name, StringComparer.Ordinal))
            {
                problems.Add(
                    $"AuthorizationParameters may not contain '{name}': this provider sets it. "
                    + "Overriding `state`, `nonce` or `code_challenge` would remove the binding "
                    + "between the browser and the upstream round trip.");
            }
        }

        if (IdTokenTypeHeaders.Count == 0)
        {
            problems.Add(
                "IdTokenTypeHeaders is empty, which would leave the `typ` header unchecked. There is "
                + "deliberately no way to express that.");
        }

        if (JwksMinimumRefreshInterval <= TimeSpan.Zero)
        {
            problems.Add(
                "JwksMinimumRefreshInterval must be positive: it is what stops an unknown `kid` in an "
                + "unauthenticated callback from causing one outbound JWKS fetch per request.");
        }

        errors = problems;
        return problems.Count == 0;
    }

    private static AbsoluteHttpsUrl? Endpoint(string name, string configured, List<string> problems)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return null;
        }

        if (!AbsoluteHttpsUrl.TryCreate(configured, out var url))
        {
            problems.Add($"{name} '{configured}' is not an absolute https URL without a fragment.");
            return null;
        }

        return url;
    }

    /// <summary>Whether a scheme is safe as a bare path segment.</summary>
    internal static bool IsUsableScheme(string? scheme) =>
        !string.IsNullOrEmpty(scheme)
        && scheme.Length <= 32
        && scheme.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');
}
