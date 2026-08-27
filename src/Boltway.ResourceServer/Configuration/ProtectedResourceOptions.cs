using Microsoft.IdentityModel.Tokens;

namespace Boltway.ResourceServer.Configuration;

/// <summary>
/// What this resource server is, and which authorization server it trusts.
/// </summary>
/// <remarks>
/// <para>
/// Every string here is emitted or compared verbatim. Nothing on this type is normalized, trimmed
/// or lower-cased on the way in, because RFC 9728 §6 forbids normalization and §3.3 makes the
/// <c>resource</c> value a byte-for-byte identity check: a client that fetched the metadata from a
/// URL built out of <c>https://mcp.example.com/mcp</c> must find exactly those bytes in the
/// document, or it is required to discard what it just fetched.
/// </para>
/// <para>
/// The practical form of that, from Anthropic's own documentation, is that
/// <see cref="Resource"/> "must match your MCP server URL exactly as the user enters it in Claude,
/// including any path component" (C-28). A trailing slash is a different resource.
/// </para>
/// </remarks>
public sealed class ProtectedResourceOptions
{
    /// <summary>
    /// This resource's identifier - the value that appears in an access token's <c>aud</c>.
    /// </summary>
    /// <remarks>
    /// An <c>https</c> URL, path included (A-22). No proprietary namespace and no separate
    /// "expose an API" ceremony: an MCP server lives at <c>https://mcp.example.com/mcp</c> and
    /// that whole string is the identifier. Comparing an incoming <c>aud</c> to this value's
    /// <i>origin</i> is the shipped real-world bug that broke ChatGPT custom connectors, and it is
    /// unreachable here because the comparison is done by
    /// <c>Rfc9068ValidationParameters.ForAccessToken</c> over the full canonical string.
    /// </remarks>
    public string? Resource { get; set; }

    /// <summary>
    /// The issuer identifier of the authorization server that issues tokens for this resource.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One value, used for two things that must agree: it is the expected <c>iss</c> on every
    /// access token, and it is the single entry in the metadata document's
    /// <c>authorization_servers</c>. Deriving both from one setting is what makes "the AS we
    /// advertise is the AS we accept tokens from" true by construction.
    /// </para>
    /// <para>
    /// There is deliberately no way to list a second authorization server. RFC 9728 permits an
    /// array and Claude reads only the first entry (C-27), so a second entry would be advertised
    /// to clients while <c>ForAccessToken</c> - which pins exactly one <c>ValidIssuer</c> - went on
    /// rejecting its tokens. Advertising an authorization server whose tokens this server refuses
    /// is a worse failure than not supporting multiple issuers, because it presents as a
    /// successful sign-in followed by a permanent 401.
    /// </para>
    /// </remarks>
    public string? AuthorizationServer { get; set; }

    /// <summary>
    /// Scopes this resource defines. RFC 9728 §2 RECOMMENDED, and Claude's fallback scope source.
    /// </summary>
    /// <remarks>
    /// Read when a <c>401</c> challenge carries no <c>scope</c> parameter: the MCP scope-selection
    /// strategy says to use the <c>scope</c> from the challenge if present, and otherwise every
    /// scope in <c>scopes_supported</c>. Empty means the list is omitted from the document
    /// entirely, and a client then requests no scope at all - which is the correct behaviour for a
    /// resource with no scopes and a silent under-authorization for one that has them but did not
    /// say so.
    /// <para>
    /// <b>Do not put <c>offline_access</c> here.</b> It is an authorization-server concern; the MCP
    /// specification says a protected resource SHOULD NOT list it.
    /// </para>
    /// </remarks>
    public IList<string> ScopesSupported { get; } = [];

    /// <summary>Human-readable name for this resource. RFC 9728 §2 RECOMMENDED.</summary>
    public string? ResourceName { get; set; }

    /// <summary>Developer documentation URL. RFC 9728 §2 OPTIONAL.</summary>
    public string? ResourceDocumentation { get; set; }

    /// <summary>Data-use policy URL. RFC 9728 §2 OPTIONAL.</summary>
    public string? ResourcePolicyUri { get; set; }

    /// <summary>Terms-of-service URL. RFC 9728 §2 OPTIONAL.</summary>
    public string? ResourceTosUri { get; set; }

    /// <summary>
    /// Clock tolerance when validating a token's lifetime.
    /// </summary>
    /// <remarks>
    /// Thirty seconds, not the library's five-minute default. The default silently extends every
    /// token's life by five minutes, which is longer than some access tokens are meant to live.
    /// </remarks>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Whether an endpoint is protected unless it says otherwise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Defaults to <see langword="true"/>, so forgetting to annotate an endpoint produces a
    /// <c>401</c> rather than an unauthenticated read. The opt-out is the framework's own
    /// <c>AllowAnonymous</c>, which the metadata endpoints carry.
    /// </para>
    /// <para>
    /// A request that matched <b>no</b> endpoint is never challenged, whatever this is set to. A
    /// 401 on an unrouted path would turn every stray probe into an authentication prompt, and it
    /// would do so on exactly the paths a client probes during discovery - so the fail-closed
    /// posture would be paid for in the one place where a clean 404 is what lets a client move on
    /// to its next probe.
    /// </para>
    /// </remarks>
    public bool RequireBearerByDefault { get; set; } = true;

    /// <summary>
    /// The public keys that verify an access token's signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Supplied by the host rather than fetched here. Fetching them means an outbound HTTP client
    /// with SSRF hardening, a clamped-TTL cache and a circuit breaker, all of which live in
    /// <c>Boltway.OAuth.Net</c> - so a JWKS-backed source belongs there, and
    /// <c>Boltway.OAuth.Net.JwksKeySource</c> is it. Assign its <c>CurrentKeys</c> to
    /// <see cref="SigningKeySource"/> below rather than filling this list, unless the keys are
    /// already in this process (an authorization server hosting its own protected resource points
    /// the source at its own key ring, and fetches nothing).
    /// </para>
    /// <para>
    /// Each key must carry a <c>KeyId</c>: the verifier is configured with
    /// <c>TryAllIssuerSigningKeys = false</c> and matches on the token's <c>kid</c>, so an
    /// unlabelled key matches nothing and every signature check fails with a message that reads
    /// like a missing key rather than an unnamed one.
    /// </para>
    /// </remarks>
    public IList<SecurityKey> SigningKeys { get; } = [];

    /// <summary>
    /// Where the verification keys come from, read once per validation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><see cref="SigningKeys"/> is a mutable list that requests read while something else
    /// writes it, and this is the way out.</b> Anything keeping it current - a JWKS refresher, a key
    /// ring in the same process - has to call <c>Add</c> and <c>Remove</c> on the very instance the
    /// validator hands to <c>Rfc9068ValidationParameters</c>. Measured: nothing synchronises the two.
    /// A rotation is therefore a structural modification of a <c>List&lt;T&gt;</c> during
    /// enumeration, and the failure it produces is a rejected token that was perfectly good - on the
    /// day a key rotates, which is the day nobody is looking at the resource server.
    /// </para>
    /// <para>
    /// A source is read fresh on every validation, so a producer publishes a <i>new</i> list instead
    /// of editing a shared one, and the swap is a reference assignment rather than a race. Set this
    /// and <see cref="SigningKeys"/> is not consulted at all.
    /// </para>
    /// <para>
    /// <b>An authorization server hosting its own protected resource points this at its key ring</b>
    /// - the public halves, <c>SigningKeyRing.PublicVerificationKeys()</c> - rather than fetching
    /// its own JWKS over its own edge, which would make startup depend on the component most likely
    /// to be broken when it matters.
    /// </para>
    /// <para>
    /// Default <see langword="null"/>, meaning "use <see cref="SigningKeys"/>", so nothing that
    /// works today changes.
    /// </para>
    /// </remarks>
    public Func<IReadOnlyList<SecurityKey>>? SigningKeySource { get; set; }

    /// <summary>The keys to verify with, right now.</summary>
    internal IReadOnlyList<SecurityKey> CurrentSigningKeys() =>
        SigningKeySource is { } source ? source() : (IReadOnlyList<SecurityKey>)SigningKeys.AsReadOnly();
}
