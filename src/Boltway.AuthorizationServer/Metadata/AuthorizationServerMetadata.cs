using System.Text.Json.Serialization;

namespace Boltway.AuthorizationServer.Metadata;

/// <summary>
/// The discovery document, as one superset object.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8414 §2 ("Additional authorization server metadata parameters MAY also be used") and OIDC
/// Discovery §3 ("Additional OpenID Provider Metadata parameters MAY also be used") both permit the
/// superset, so <c>/.well-known/oauth-authorization-server</c> and
/// <c>/.well-known/openid-configuration</c> serve the <b>same bytes</b>. Two documents built from
/// one configuration is two documents that can drift, and a client that reads one and validates
/// against the other is the failure that drift produces.
/// </para>
/// <para>
/// Every collection is nullable and every optional string is nullable, because RFC 8414 §3.2 says
/// a zero-element array must be omitted rather than emitted as <c>[]</c> — and
/// <c>System.Text.Json</c> will happily write <c>[]</c> for an empty list. Nullability is what makes
/// <see cref="JsonIgnoreCondition.WhenWritingNull"/> do that job, so the type itself carries the
/// rule instead of a serializer setting somewhere else carrying it.
/// </para>
/// <para>
/// The four <c>*_supported</c> booleans below are <b>not</b> nullable, deliberately. Their spec
/// defaults are <c>true</c> for <c>request_uri_parameter_supported</c> and unstated elsewhere, so
/// silence advertises a feature this server does not have. They are always written.
/// </para>
/// </remarks>
public sealed record AuthorizationServerMetadata
{
    /// <summary>RFC 8414 §2 REQUIRED. The configured string, verbatim.</summary>
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    /// <summary>RFC 8414 §2 REQUIRED.</summary>
    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; init; }

    /// <summary>RFC 8414 §2 REQUIRED.</summary>
    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    /// <summary>OIDC Discovery §3 REQUIRED. No <c>at+jwt</c> validator works without it.</summary>
    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    /// <summary>OIDC Discovery §3 RECOMMENDED. Present because we serve OIDC RPs.</summary>
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; init; }

    /// <summary>RFC 7009 §5.</summary>
    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    /// <summary>RFC 7662.</summary>
    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; init; }

    /// <summary>OIDC RP-Initiated Logout §2.1.</summary>
    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; init; }

    /// <summary>
    /// RFC 7591. Present <b>only</b> in the dynamic-registration profile.
    /// </summary>
    /// <remarks>
    /// N-06 / A-05: never alongside <see cref="ClientIdMetadataDocumentSupported"/>. With both
    /// advertised a live measurement showed Claude choosing DCR, against the priority order the MCP
    /// specification states.
    /// </remarks>
    [JsonPropertyName("registration_endpoint")]
    public string? RegistrationEndpoint { get; init; }

    /// <summary>RFC 8414 §2 RECOMMENDED.</summary>
    [JsonPropertyName("scopes_supported")]
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>RFC 8414 §2 REQUIRED. <c>code</c> only — OAuth 2.1 §10.1 removes implicit.</summary>
    [JsonPropertyName("response_types_supported")]
    public required IReadOnlyList<string> ResponseTypesSupported { get; init; }

    /// <summary>RFC 8414 §2 OPTIONAL, published explicitly.</summary>
    [JsonPropertyName("response_modes_supported")]
    public IReadOnlyList<string>? ResponseModesSupported { get; init; }

    /// <summary>
    /// OIDC Discovery OPTIONAL. Every <c>prompt</c> value <c>/authorize</c> acts on, and no other.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Published because the alternative is a capability nobody can discover.</b> N-06 refuses
    /// to advertise what is not served, and every other honesty check here runs in that direction.
    /// This is the same rule pointing the other way: <c>/authorize</c> honours four prompt values
    /// and named none of them, so a client reading discovery to decide whether it may ask for a
    /// silent refresh found no answer and had to assume no.
    /// </para>
    /// <para>
    /// Under-advertising is the cheap direction to be wrong in — nothing breaks, nothing goes red,
    /// and the only cost is a client taking the long way round — which is exactly why it survived
    /// while the expensive direction was guarded four ways.
    /// </para>
    /// </remarks>
    [JsonPropertyName("prompt_values_supported")]
    public IReadOnlyList<string>? PromptValuesSupported { get; init; }

    /// <summary>
    /// RFC 8414 §2 OPTIONAL, and published explicitly for a reason.
    /// </summary>
    /// <remarks>
    /// The spec default is <c>["authorization_code", "implicit"]</c>, so an OAuth 2.1 server that
    /// stays silent here advertises a grant it removed.
    /// </remarks>
    [JsonPropertyName("grant_types_supported")]
    public required IReadOnlyList<string> GrantTypesSupported { get; init; }

    /// <summary>
    /// RFC 8414 §2 OPTIONAL, published explicitly.
    /// </summary>
    /// <remarks>
    /// The spec default is <c>["client_secret_basic"]</c>, which would lock out every public client.
    /// <c>none</c> is what Claude's CIMD selection gate looks for and <c>private_key_jwt</c> is what
    /// ChatGPT's live metadata declares; omitting either locks out one vendor.
    /// </remarks>
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public required IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; }

    /// <summary>RFC 8414 §2: MUST be present when an assertion-based auth method is offered.</summary>
    [JsonPropertyName("token_endpoint_auth_signing_alg_values_supported")]
    public IReadOnlyList<string>? TokenEndpointAuthSigningAlgValuesSupported { get; init; }

    /// <summary>RFC 8414 §2.</summary>
    [JsonPropertyName("revocation_endpoint_auth_methods_supported")]
    public IReadOnlyList<string>? RevocationEndpointAuthMethodsSupported { get; init; }

    /// <summary>RFC 8414 §2.</summary>
    [JsonPropertyName("revocation_endpoint_auth_signing_alg_values_supported")]
    public IReadOnlyList<string>? RevocationEndpointAuthSigningAlgValuesSupported { get; init; }

    /// <summary>RFC 8414 §2.</summary>
    [JsonPropertyName("introspection_endpoint_auth_methods_supported")]
    public IReadOnlyList<string>? IntrospectionEndpointAuthMethodsSupported { get; init; }

    /// <summary>RFC 8414 §2.</summary>
    [JsonPropertyName("introspection_endpoint_auth_signing_alg_values_supported")]
    public IReadOnlyList<string>? IntrospectionEndpointAuthSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// RFC 8414 §2. <c>S256</c> and nothing else.
    /// </summary>
    /// <remarks>
    /// "If omitted, the authorization server does not support PKCE", and MCP escalates that to
    /// clients MUST refuse to proceed. <c>plain</c> is never listed: OAuth 2.1 and RFC 9700 §2.1.1
    /// both remove it, and under <c>plain</c> the challenge is the verifier.
    /// </remarks>
    [JsonPropertyName("code_challenge_methods_supported")]
    public required IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; }

    /// <summary>
    /// draft-ietf-oauth-client-id-metadata-document §6. A JSON boolean, never the string.
    /// </summary>
    /// <remarks>Gate #1 for CIMD selection by both vendors. Absent in the DCR profile.</remarks>
    [JsonPropertyName("client_id_metadata_document_supported")]
    public bool? ClientIdMetadataDocumentSupported { get; init; }

    /// <summary>
    /// RFC 9207 §3. Always <see langword="true"/> here.
    /// </summary>
    /// <remarks>
    /// MUST be true if <c>iss</c> is emitted, and it is emitted on every authorization response
    /// including error redirects — an error response is as useful to a mix-up attack as a
    /// successful one. A client that sees this flag and then a response without <c>iss</c> is
    /// required to reject it.
    /// </remarks>
    [JsonPropertyName("authorization_response_iss_parameter_supported")]
    public required bool AuthorizationResponseIssParameterSupported { get; init; }

    /// <summary>OIDC Discovery §3 REQUIRED.</summary>
    [JsonPropertyName("subject_types_supported")]
    public required IReadOnlyList<string> SubjectTypesSupported { get; init; }

    /// <summary>OIDC Discovery §3 REQUIRED; RS256 MUST be included.</summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>OIDC Discovery §3 RECOMMENDED.</summary>
    [JsonPropertyName("claims_supported")]
    public IReadOnlyList<string>? ClaimsSupported { get; init; }

    /// <summary>OIDC Discovery §3 OPTIONAL.</summary>
    [JsonPropertyName("claim_types_supported")]
    public IReadOnlyList<string>? ClaimTypesSupported { get; init; }

    /// <summary>OIDC Discovery §3. Written even when false — see the type remarks.</summary>
    [JsonPropertyName("claims_parameter_supported")]
    public required bool ClaimsParameterSupported { get; init; }

    /// <summary>OIDC Discovery §3. Written even when false — see the type remarks.</summary>
    [JsonPropertyName("request_parameter_supported")]
    public required bool RequestParameterSupported { get; init; }

    /// <summary>
    /// OIDC Discovery §3, whose default is <b><c>true</c></b>. Written even when false.
    /// </summary>
    [JsonPropertyName("request_uri_parameter_supported")]
    public required bool RequestUriParameterSupported { get; init; }

    /// <summary>OIDC Discovery §3. Written even when false — see the type remarks.</summary>
    [JsonPropertyName("require_request_uri_registration")]
    public required bool RequireRequestUriRegistration { get; init; }

    /// <summary>
    /// RFC 9728 §4 OPTIONAL. A partial list is explicitly permitted.
    /// </summary>
    /// <remarks>
    /// Cheap defence in depth — a client cross-checks it against the resource's own metadata. Since
    /// partial lists are legal, a client that does not find its resource here must not treat the
    /// absence as a refusal.
    /// </remarks>
    [JsonPropertyName("protected_resources")]
    public IReadOnlyList<string>? ProtectedResources { get; init; }

    /// <summary>RFC 8414 §2 OPTIONAL. Emitted only when configured.</summary>
    [JsonPropertyName("service_documentation")]
    public string? ServiceDocumentation { get; init; }

    /// <summary>RFC 8414 §2 OPTIONAL. Emitted only when configured.</summary>
    [JsonPropertyName("op_policy_uri")]
    public string? OpPolicyUri { get; init; }

    /// <summary>RFC 8414 §2 OPTIONAL. Emitted only when configured.</summary>
    [JsonPropertyName("op_tos_uri")]
    public string? OpTosUri { get; init; }

    /// <summary>OIDC Discovery §3 OPTIONAL. Generated from the resource files that exist (N-06).</summary>
    [JsonPropertyName("ui_locales_supported")]
    public IReadOnlyList<string>? UiLocalesSupported { get; init; }

    /// <summary>
    /// Non-standard, and emitted anyway.
    /// </summary>
    /// <remarks>
    /// RFC 8707 registers no metadata field at all, so this is neither in that RFC nor in the IANA
    /// registry. It is widely emitted in practice and harmless as a courtesy signal — but nothing
    /// in this server may rely on a client reading it, because the absence of a discovery field is
    /// precisely why a client cannot detect a server that ignores <c>resource</c> (U-06).
    /// </remarks>
    [JsonPropertyName("resource_indicators_supported")]
    public bool? ResourceIndicatorsSupported { get; init; }
}
