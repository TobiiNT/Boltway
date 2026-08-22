using System.Text.Json.Serialization;

namespace Boltway.ResourceServer.Metadata;

/// <summary>
/// The RFC 9728 §2 protected resource metadata document.
/// </summary>
/// <remarks>
/// <para>
/// Every optional member is nullable, and every collection is a nullable array rather than a list.
/// That is what makes <see cref="JsonIgnoreCondition.WhenWritingNull"/> omit an empty
/// <c>scopes_supported</c> instead of writing <c>[]</c> — and the difference is behavioural, not
/// cosmetic: the MCP scope-selection strategy says a client uses every scope in
/// <c>scopes_supported</c> when the challenge carries none, "omitting the <c>scope</c> parameter if
/// <c>scopes_supported</c> is undefined". An empty array is defined, and a client that dutifully
/// requests the empty set gets a token with no authority at all.
/// </para>
/// <para>
/// Members RFC 9728 defines that this document never carries, each for a reason:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>jwks_uri</c> — these would be the <i>resource's own</i> keys, for signing responses back to a
/// client. Putting the authorization server's JWKS here is a common misreading, and one this server
/// cannot make because it has no field to put it in.
/// </description></item>
/// <item><description>
/// <c>dpop_bound_access_tokens_required</c> and <c>dpop_signing_alg_values_supported</c> — DPoP is
/// deferred (D-02). Advertising either invites proofs this server would reject, and setting the
/// first to <see langword="true"/> breaks both Claude and ChatGPT, since neither sends DPoP.
/// <b>That last clause is a measurement, not a rule</b>, and the word "today" used to stand where
/// the tripwire now does: <c>CimdClientResolverTests.No_captured_vendor_document_asks_for_dpop</c>
/// reads the dated live captures and goes red when a vendor starts advertising RFC 9449 §5.2's
/// <c>dpop_bound_access_tokens</c>. Read that test's verdict before trusting this sentence — a
/// comment cannot notice when it expires, which is what LESSONS #8 is about.
/// </description></item>
/// <item><description>
/// <c>tls_client_certificate_bound_access_tokens</c> — mTLS is deferred (D-03) and RFC 9728 §2 says
/// the default when omitted is <see langword="false"/>, which is the truth.
/// </description></item>
/// <item><description>
/// <c>signed_metadata</c> — §3.3 makes signed values take precedence over the plain members, so
/// emitting it means committing to a signing key and its rotation for the metadata document itself.
/// </description></item>
/// <item><description>
/// <c>resource_signing_alg_values_supported</c> and <c>authorization_details_types_supported</c> —
/// nothing here signs responses, and RAR is not implemented (D-05).
/// </description></item>
/// </list>
/// </remarks>
internal sealed record ProtectedResourceMetadata
{
    /// <summary>
    /// RFC 9728 §2 REQUIRED. The identifier, verbatim.
    /// </summary>
    /// <remarks>
    /// §3.3: this "MUST be identical to the protected resource's resource identifier value into
    /// which the well-known URI path suffix was inserted to create the URL used to retrieve the
    /// metadata", and if it is not, the client "MUST NOT" use the document. So this is the
    /// configured string and nothing derived from the request that fetched it.
    /// </remarks>
    [JsonPropertyName("resource")]
    public required string Resource { get; init; }

    /// <summary>
    /// OPTIONAL in RFC 9728 §2, REQUIRED by the MCP authorization specification.
    /// </summary>
    /// <remarks>
    /// Exactly one entry. Claude reads the first and does not fall back to later ones (C-27), and
    /// this server pins a single <c>ValidIssuer</c> when it verifies a token, so a second entry
    /// would advertise an authorization server whose tokens this resource refuses.
    /// </remarks>
    [JsonPropertyName("authorization_servers")]
    public required string[] AuthorizationServers { get; init; }

    /// <summary>RFC 9728 §2 RECOMMENDED. Omitted entirely when empty — see the type's remarks.</summary>
    [JsonPropertyName("scopes_supported")]
    public string[]? ScopesSupported { get; init; }

    /// <summary>
    /// RFC 9728 §2 OPTIONAL. Always <c>["header"]</c>.
    /// </summary>
    /// <remarks>
    /// The registry also defines <c>body</c> and <c>query</c>. Neither is offered: the MCP
    /// specification forbids a token in the query string, and the middleware answers a query-string
    /// token with <c>400 invalid_request</c> (X-35), so advertising the method would be a promise
    /// the request path breaks.
    /// </remarks>
    [JsonPropertyName("bearer_methods_supported")]
    public required string[] BearerMethodsSupported { get; init; }

    /// <summary>RFC 9728 §2 RECOMMENDED. Shown in some consent user interfaces.</summary>
    [JsonPropertyName("resource_name")]
    public string? ResourceName { get; init; }

    /// <summary>RFC 9728 §2 OPTIONAL.</summary>
    [JsonPropertyName("resource_documentation")]
    public string? ResourceDocumentation { get; init; }

    /// <summary>RFC 9728 §2 OPTIONAL.</summary>
    [JsonPropertyName("resource_policy_uri")]
    public string? ResourcePolicyUri { get; init; }

    /// <summary>RFC 9728 §2 OPTIONAL.</summary>
    [JsonPropertyName("resource_tos_uri")]
    public string? ResourceTosUri { get; init; }
}

/// <summary>
/// The serializer for the metadata document.
/// </summary>
/// <remarks>
/// Source-generated, so the shape of the JSON is fixed at compile time. Reflection-based
/// serialization works today and fails silently under trimming, and this assembly is meant to be
/// published into a customer's trimmed or AOT-compiled host.
/// </remarks>
[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    GenerationMode = JsonSourceGenerationMode.Serialization)]
[JsonSerializable(typeof(ProtectedResourceMetadata))]
internal sealed partial class ProtectedResourceMetadataJsonContext : JsonSerializerContext;
