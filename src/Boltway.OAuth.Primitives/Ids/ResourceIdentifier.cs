using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.OAuth.Primitives.Ids;

/// <summary>
/// A registered protected resource. RFC 8707, and the value that becomes an access token's
/// <c>aud</c>.
/// </summary>
/// <remarks>
/// <para>
/// N-01's chokepoint. There is no public constructor, and the one public factory
/// (<see cref="TryRegister"/>) is the registration path - so within the authorization server the
/// only way to obtain one is <c>IResourceRegistry.ResolveAsync</c>, which returns
/// <see langword="null"/> for a resource that is unknown or not permitted. "Accept the
/// <c>resource</c> parameter and ignore it" and "stamp a default audience" therefore have no code
/// path in this server: the token minter's descriptor requires one of these, and the only thing
/// that can produce one is a registry.
/// </para>
/// <para>
/// <b>What enforces that is a test, not the type.</b> <see cref="TryRegister"/> is public because it
/// has to be - <c>IResourceRegistry</c> is a public interface a customer must be able to implement -
/// so the restriction on who may call it is an IL-level architecture rule over call sites
/// (<c>Only_a_resource_registry_mints_a_resource_identifier</c>), which is a build gate rather than
/// a property of the type system. Stated plainly because the previous version of this paragraph
/// claimed a stronger guarantee than the code had, twice, and both times an audit caught it.
/// </para>
/// <para>
/// That matters more than it looks. RFC 8707 registers no discovery metadata field, so a client
/// <i>cannot tell</i> whether a server honours <c>resource</c> or silently ignores it. An
/// authorization server that ignores it issues tokens valid at every resource the user has access
/// to; a user who connects one malicious MCP server then hands its operator a token that works at
/// all the others. The client did everything right and has no way to detect the problem.
/// </para>
/// </remarks>
public sealed class ResourceIdentifier : IEquatable<ResourceIdentifier>
{
    private ResourceIdentifier(string canonical)
    {
        Canonical = canonical;
        UrlSafeToken = Base64Url.Encode(Sha256Hash.OfString(canonical).Value);
    }

    /// <summary>
    /// Exactly the registered string. This is what goes in <c>aud</c>, byte for byte.
    /// </summary>
    /// <remarks>
    /// Never <c>new Uri(x).ToString()</c>. A resource identifier may carry a path - A-22 requires
    /// it, because an MCP server lives at <c>https://mcp.example.com/mcp</c> - and comparing
    /// <c>aud</c> to the request's <i>origin</i> instead of the full identifier is a shipped
    /// real-world bug that broke ChatGPT custom connectors.
    /// </remarks>
    public string Canonical { get; }

    /// <summary>
    /// base64url of SHA-256 of <see cref="Canonical"/>. The only form safe in a route or cache key.
    /// </summary>
    /// <remarks>
    /// A resource identifier is a URL, so it contains <c>:</c> and <c>/</c>. Interpolating one into
    /// a path, a filename or a cache key is a traversal waiting to happen; this is the form that
    /// cannot be.
    /// </remarks>
    public string UrlSafeToken { get; }

    /// <summary>
    /// Register a resource. <b>Only an <c>IResourceRegistry</c> implementation may call this.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// The history here is worth keeping, because both of the obvious mechanisms were tried and
    /// both were wrong in a way that only measurement showed.
    /// </para>
    /// <para>
    /// It was <c>public</c> in the first draft, which made the "no other way to get one" claim above
    /// false while the comment asserted it anyway. So it was made <c>internal</c> with
    /// <c>InternalsVisibleTo</c> granted to the assemblies that needed it. That was worse in two
    /// directions at once. First, the grant is per-assembly and indiscriminate: the one added for
    /// this method also exposed <c>RedirectMatch.Exact</c>, and a probe compiled that forged a
    /// validated redirect - <c>internal</c> is a keyword, not a boundary. Second, and only found by
    /// an operability review that tried to build a host, the server assembly was never on the grant
    /// list, so <b>no assembly a customer could own was able to construct one</b>. The chokepoint
    /// was airtight in the wrong direction: <c>IResourceRegistry</c> is public and required, and
    /// nobody outside this repository could implement it. The measured symptom was
    /// <c>CS0117: 'ResourceIdentifier' does not contain a definition for 'TryRegister'</c>.
    /// </para>
    /// <para>
    /// So it is public again, and the invariant is held by the mechanism that actually held for
    /// <c>RedirectMatch.Exact</c>: an IL-level architecture test over call sites
    /// (<c>Only_a_resource_registry_mints_a_resource_identifier</c>). That rule can only see
    /// assemblies in this solution, and that is the correct scope - the risk N-01 exists to stop is
    /// <i>this library</i> stamping a house default audience on the customer's behalf, silently and
    /// undetectably. A customer's own registry deciding which resources exist is not a threat, it is
    /// the definition of the role.
    /// </para>
    /// </remarks>
    public static bool TryRegister(string? canonical, out ResourceIdentifier? resource, out string? error)
    {
        resource = null;
        error = null;

        if (string.IsNullOrWhiteSpace(canonical))
        {
            error = "A resource identifier is required.";
            return false;
        }

        if (!Uri.TryCreate(canonical, UriKind.Absolute, out var uri))
        {
            error = $"'{canonical}' is not an absolute URI.";
            return false;
        }

        // RFC 8707 §2: the resource MUST NOT include a fragment. A path is fine and a query is
        // discouraged but legal.
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            error = $"RFC 8707 §2: a resource identifier must not have a fragment; '{canonical}' does.";
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            error = $"A resource identifier must be https; '{canonical}' is '{uri.Scheme}'.";
            return false;
        }

        // Claude sends the RFC 8707 `resource` parameter in canonical form - scheme and host
        // lowercased, a default port dropped, no trailing slash, the path kept - regardless of what
        // the user typed into the connector dialog, and its own documentation says to expect exactly
        // that. Everything downstream of this factory compares ordinally, on purpose: the registry
        // lookup, the `resource` echoed by protected-resource metadata, and the `aud` check on every
        // request. A registration that differs from its own canonical form therefore can never match
        // a compliant client, and nothing reports the mismatch - discovery serves a document naming
        // a resource no request will ever ask for, and the failure surfaces as `invalid_target` at
        // somebody's sign-in. Refused here instead, where the operator who wrote the string is the
        // one reading the message.
        var expected = CanonicalFormOf(canonical);
        if (!string.Equals(canonical, expected, StringComparison.Ordinal))
        {
            error = $"'{canonical}' is not in canonical form; register '{expected}'. Clients send "
                + "the RFC 8707 resource in canonical form — lowercase scheme and host, no default "
                + "port, no trailing slash — and every comparison against it is ordinal, so a "
                + "registration that differs from that form never matches. Use the same string "
                + "everywhere the resource is named: here, the resource server's configuration, and "
                + "the URL users enter in their client.";
            return false;
        }

        resource = new ResourceIdentifier(canonical);
        return true;
    }

    /// <summary>
    /// The RFC 8707 form a compliant client sends: lowercase scheme and host, default port
    /// dropped, no trailing slash on the path, everything else kept as written.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Built to be <i>compared</i> with the configured string - never to replace it. Normalizing
    /// silently would move the mismatch instead of removing it: the operator's string still sits in
    /// the resource server's configuration and in every client dialog, and those comparisons are
    /// ordinal too. The one string has to be right everywhere, so the wrong one is refused with the
    /// right one in the message.
    /// </para>
    /// <para>
    /// Raw-string surgery, the same discipline as <c>RedirectUriParts</c>: <see cref="Uri"/> never
    /// produces a compared byte (N-03 - its accessors percent-decode and resolve dot segments,
    /// mapping several distinct strings onto one). The transformations applied are exactly the ones
    /// clients document applying and no others, so an exotic identifier is compared as written
    /// rather than as this library guesses a client might rewrite it.
    /// </para>
    /// </remarks>
    private static string CanonicalFormOf(string raw)
    {
        var schemeEnd = raw.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0)
        {
            // No authority marker. Nothing documented to canonicalize, so compare as written.
            return raw;
        }

        var scheme = raw[..schemeEnd].ToLowerInvariant();

        var authorityStart = schemeEnd + 3;
        var authorityEnd = raw.Length;
        for (var i = authorityStart; i < raw.Length; i++)
        {
            if (raw[i] is '/' or '?')
            {
                authorityEnd = i;
                break;
            }
        }

        var authority = raw[authorityStart..authorityEnd];
        var rest = raw[authorityEnd..];

        // Userinfo is kept as written: it is case-sensitive, so lowercasing it would change it.
        var userinfo = string.Empty;
        var at = authority.LastIndexOf('@');
        if (at >= 0)
        {
            userinfo = authority[..(at + 1)];
            authority = authority[(at + 1)..];
        }

        // Bracket-aware: an IPv6 literal contains colons that are not the port separator.
        string host, port;
        var close = authority.StartsWith('[') ? authority.IndexOf(']') : -1;
        if (close >= 0)
        {
            host = authority[..(close + 1)];
            port = authority[(close + 1)..];
        }
        else
        {
            var colon = authority.IndexOf(':');
            host = colon < 0 ? authority : authority[..colon];
            port = colon < 0 ? string.Empty : authority[colon..];
        }

        host = host.ToLowerInvariant();
        if (port is ":" or ":443")
        {
            port = string.Empty;
        }

        var query = string.Empty;
        var question = rest.IndexOf('?');
        if (question >= 0)
        {
            query = rest[question..];
            rest = rest[..question];
        }

        return scheme + "://" + userinfo + host + port + rest.TrimEnd('/') + query;
    }

    /// <inheritdoc />
    public bool Equals(ResourceIdentifier? other) =>
        other is not null && string.Equals(Canonical, other.Canonical, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as ResourceIdentifier);

    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Canonical);

    /// <inheritdoc />
    public override string ToString() => Canonical;

    /// <summary>Ordinal equality on the canonical identifier.</summary>
    public static bool operator ==(ResourceIdentifier? left, ResourceIdentifier? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Ordinal inequality on the canonical identifier.</summary>
    public static bool operator !=(ResourceIdentifier? left, ResourceIdentifier? right) => !(left == right);
}

/// <summary>
/// A <c>resource</c> value as it arrived on a request, before it is known to be registered.
/// </summary>
/// <remarks>
/// Deliberately a different type from <see cref="ResourceIdentifier"/>. A request carries a string
/// someone asked for; a <see cref="ResourceIdentifier"/> is a resource this server actually has.
/// Keeping them apart is what stops "the client asked for it" from being mistaken for "we granted
/// it" at a call site.
/// </remarks>
public readonly struct RequestedResource : IEquatable<RequestedResource>
{
    private RequestedResource(string value) => Value = value;

    /// <summary>The raw request value.</summary>
    public string Value { get; }

    /// <summary>Parse a <c>resource</c> parameter. Shape only - says nothing about registration.</summary>
    public static bool TryParse(string? raw, out RequestedResource resource)
    {
        resource = default;

        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 2048)
        {
            return false;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        resource = new RequestedResource(raw);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(RequestedResource other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is RequestedResource other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(RequestedResource left, RequestedResource right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(RequestedResource left, RequestedResource right) => !left.Equals(right);
}
