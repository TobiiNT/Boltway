using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Tokens;

namespace Boltway.AuthorizationServer.Metadata;

/// <summary>
/// Builds the discovery document from live configuration.
/// </summary>
/// <remarks>
/// A pure function of <see cref="AuthorizationServerOptions"/>, and that is the whole design. The
/// alternative — a document template with holes punched in it — is how a disabled feature keeps its
/// advertisement: nobody remembers that turning off introspection also has to delete two keys. Here
/// a disabled feature has no value to write, so the key cannot survive it.
/// </remarks>
public static class MetadataBuilder
{
    /// <summary>Claims an ID token from this server can carry.</summary>
    /// <remarks>
    /// <para>
    /// OIDC Discovery §3 calls this list RECOMMENDED and notes it need not be exhaustive. It is
    /// held here rather than in configuration because it is a fact about what the token minter
    /// writes, not a preference — a claim listed here that no code emits is a promise to an RP that
    /// nothing keeps.
    /// </para>
    /// <para>
    /// It said that while listing five claims nothing emits. <c>name</c>,
    /// <c>preferred_username</c>, <c>email</c>, <c>email_verified</c> and <c>updated_at</c> were all
    /// advertised; <c>JwtTokenMinter.MintIdToken</c> writes <c>iss</c>, <c>aud</c>, <c>sub</c>,
    /// <c>iat</c>, <c>exp</c>, <c>nonce</c>, <c>auth_time</c> and <c>at_hash</c> plus whatever a
    /// caller puts in <c>Extra</c>, and <c>TokenIssuer.Mint</c> never passes <c>Extra</c>. So the
    /// list contradicted the rule stated directly above it. An RP that reads <c>claims_supported</c>
    /// to decide it need not call a directory would get nulls forever.
    /// </para>
    /// <para>
    /// The first eight are what a maximal ID token carries — <c>openid</c> with a <c>nonce</c>, a
    /// <c>max_age</c> so <c>auth_time</c> applies, and an access token alongside so <c>at_hash</c>
    /// does. The rest are what <c>/userinfo</c> answers for a fully populated account asked with
    /// <c>email</c> granted.
    /// </para>
    /// <para>
    /// <b>Both surfaces, because the field is about the provider and not about one endpoint.</b>
    /// OIDC Discovery §3 defines this as the claims the OP MAY supply values for, and after
    /// <c>/userinfo</c> shipped the list stayed ID-token-only — so an RP reading it found no
    /// <c>email</c> and concluded this server could not supply one, while <c>/userinfo</c> sat there
    /// ready to answer. That is the same defect the paragraph above describes, in the direction that
    /// is harder to notice: the earlier one produced nulls an RP could see, this one produces a call
    /// an RP never makes.
    /// </para>
    /// <para>
    /// <c>role</c> is not a claim any specification registers, and it belongs here for exactly that
    /// reason — advertising a claim the OP can supply is what the field is for, and an RP that maps
    /// a directory onto its own permissions has no other way to discover it.
    /// <c>The_advertised_claims_are_exactly_what_the_two_token_surfaces_emit</c> measures both and
    /// compares the union in both directions, so this list cannot drift from either. Restore a name
    /// here when a claims mapper emits it.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> ClaimsSupported { get; } =
    [
        "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
        "preferred_username", "email", "email_verified", "role",
    ];

    /// <summary>Build the document. <paramref name="options"/> must already have validated.</summary>
    /// <exception cref="InvalidOperationException">
    /// The options did not validate. Building a document from unvalidated configuration is how an
    /// issuer derived from a request, or a scope with a trailing space, reaches the wire.
    /// </exception>
    public static AuthorizationServerMetadata Build(AuthorizationServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.TryValidate(out var errors))
        {
            throw new InvalidOperationException(
                "The authorization server is misconfigured and cannot publish metadata:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, errors.Select(e => "  - " + e)));
        }

        var issuer = options.ValidatedIssuer.Value;
        var cimd = options.RegistrationProfile is ClientRegistrationProfile.ClientIdMetadataDocument;

        // Every endpoint URL is the issuer plus a constant. Concatenation rather than `new Uri(base,
        // relative)`: the Uri constructor resolves the relative reference, which would silently
        // change "/token" against an issuer that ever grew a path — and it re-serializes the
        // authority, which is the normalization N-13 exists to keep away from the issuer string.
        string Url(string path) => issuer + path;

        // Assertion-based client authentication is the trigger for the *_signing_alg_values_supported
        // keys. RFC 8414 §2 makes them MUST-be-present when private_key_jwt or client_secret_jwt is
        // offered, and forbids `none` as a value in any of them.
        var assertionAuth = options.TokenEndpointAuthMethods.Contains(ClientAuthMethod.PrivateKeyJwt);
        var authMethods = Wire(options.TokenEndpointAuthMethods);
        var signingAlgs = assertionAuth ? SigningAlgorithms.All : null;

        // The revocation and introspection endpoints do not accept `none`: unlike /token, where a
        // public client has no secret to present, both of these read or destroy the state of a
        // token, and an unauthenticated caller who can do that has a denial-of-service primitive
        // (RFC 7009 §5) or a token-status oracle (RFC 7662 §4).
        var confidentialAuth = authMethods.Where(m => !string.Equals(m, "none", StringComparison.Ordinal)).ToList();

        return new AuthorizationServerMetadata
        {
            Issuer = issuer,
            AuthorizationEndpoint = Url(AuthorizationServerPaths.Authorize),
            TokenEndpoint = Url(AuthorizationServerPaths.Token),
            JwksUri = Url(AuthorizationServerPaths.Jwks),

            UserInfoEndpoint = options.UserInfoEnabled ? Url(AuthorizationServerPaths.UserInfo) : null,
            RevocationEndpoint = options.RevocationEnabled ? Url(AuthorizationServerPaths.Revoke) : null,
            IntrospectionEndpoint = options.IntrospectionEnabled ? Url(AuthorizationServerPaths.Introspect) : null,
            EndSessionEndpoint = options.EndSessionEnabled ? Url(AuthorizationServerPaths.EndSession) : null,

            // The two mutually exclusive keys, from the one enum that cannot hold both. There is no
            // "and refuse to boot if both" check here because the check has nothing to find.
            RegistrationEndpoint = cimd ? null : Url(AuthorizationServerPaths.Register),
            ClientIdMetadataDocumentSupported = cimd ? true : null,

            ScopesSupported = NullIfEmpty(options.ValidatedScopes.Values),
            ResponseTypesSupported = ["code"],
            // `query` only. `form_post` was listed here and no code reads `response_mode` or
            // renders a self-submitting form, which is N-06 exactly: an advertised capability that
            // does not exist. Neither vendor sends `response_mode`, so dropping it costs nothing.
            ResponseModesSupported = ["query"],
            GrantTypesSupported = [.. options.GrantTypesSupported],

            TokenEndpointAuthMethodsSupported = authMethods,
            TokenEndpointAuthSigningAlgValuesSupported = signingAlgs,

            RevocationEndpointAuthMethodsSupported =
                options.RevocationEnabled ? NullIfEmpty(confidentialAuth) : null,
            RevocationEndpointAuthSigningAlgValuesSupported =
                options.RevocationEnabled ? signingAlgs : null,
            IntrospectionEndpointAuthMethodsSupported =
                options.IntrospectionEnabled ? NullIfEmpty(confidentialAuth) : null,
            IntrospectionEndpointAuthSigningAlgValuesSupported =
                options.IntrospectionEnabled ? signingAlgs : null,

            CodeChallengeMethodsSupported = ["S256"],
            AuthorizationResponseIssParameterSupported = true,

            SubjectTypesSupported = ["public"],
            // What this server issues, not what it accepts. Filling this from the verifier
            // allow-list advertised ES256 that TokenIssuer never mints — N-06 through a
            // category error rather than through a stale list.
            IdTokenSigningAlgValuesSupported = SigningAlgorithms.Issued,
            ClaimsSupported = ClaimsSupported,
            ClaimTypesSupported = ["normal"],

            ClaimsParameterSupported = false,
            RequestParameterSupported = false,
            RequestUriParameterSupported = false,
            RequireRequestUriRegistration = false,

            ProtectedResources = NullIfEmpty(options.ProtectedResources),
            ServiceDocumentation = NullIfEmpty(options.ServiceDocumentation),
            OpPolicyUri = NullIfEmpty(options.PolicyUri),
            OpTosUri = NullIfEmpty(options.TermsOfServiceUri),
            UiLocalesSupported = NullIfEmpty(options.UiLocalesSupported),

            ResourceIndicatorsSupported = true,
        };
    }

    private static IReadOnlyList<string> Wire(IEnumerable<ClientAuthMethod> methods) =>
    [
        .. methods.Select(m => m switch
        {
            ClientAuthMethod.None => "none",
            ClientAuthMethod.ClientSecretBasic => "client_secret_basic",
            ClientAuthMethod.ClientSecretPost => "client_secret_post",
            ClientAuthMethod.PrivateKeyJwt => "private_key_jwt",
            _ => throw new ArgumentOutOfRangeException(nameof(methods), m, "Unknown client authentication method."),
        }),
    ];

    // RFC 8414 §3.2: a zero-element array is omitted, not written as []. System.Text.Json will
    // write [] for an empty list however the ignore condition is set, so emptiness has to become
    // null before the serializer sees it.
    private static string[]? NullIfEmpty(IEnumerable<string> values)
    {
        var copied = values.ToArray();
        return copied.Length == 0 ? null : copied;
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;
}
