namespace Boltway.OAuth.Net;

/// <summary>
/// An absolute <c>https</c> URL that is permitted to be fetched.
/// </summary>
/// <remarks>
/// <para>
/// The only type <see cref="ISafeHttpFetcher"/> accepts, and it has exactly one constructor. That
/// is the whole design: <c>file://</c>, <c>gopher://</c>, <c>ftp://</c>, <c>data:</c> and
/// <c>javascript:</c> cannot reach the fetcher because there is no way to build one of these from
/// them, rather than because the fetcher remembers to check.
/// </para>
/// <para>
/// It matters because the URLs this server fetches are attacker-supplied by design. A CIMD
/// <c>client_id</c> <i>is</i> a URL, sent by whoever is starting an authorization flow, and the
/// server dereferences it. So does <c>jwks_uri</c>, and <c>logo_uri</c>, each read out of a document
/// that was itself fetched from an attacker-chosen host.
/// </para>
/// </remarks>
public readonly struct AbsoluteHttpsUrl : IEquatable<AbsoluteHttpsUrl>
{
    /// <summary>Length cap. Bounds a log line and a cache key.</summary>
    public const int MaxLength = 2048;

    /// <summary>
    /// Longest host accepted, per RFC 1035. Enforced here so DNS never sees an over-long name.
    /// </summary>
    public const int MaxHostLength = 253;

    private AbsoluteHttpsUrl(string value, string host, int port)
    {
        Value = value;
        Host = host;
        Port = port;
    }

    /// <summary>The URL exactly as supplied.</summary>
    public string Value { get; }

    /// <summary>The host, for resolution and for the RFC 6890 check.</summary>
    public string Host { get; }

    /// <summary>The port, defaulted to 443.</summary>
    public int Port { get; }

    /// <summary>
    /// Parse. Rejects anything that is not an absolute <c>https</c> URL with no fragment and no
    /// userinfo.
    /// </summary>
    /// <remarks>
    /// A fragment is refused because it is never sent to the server, so a <c>client_id</c> that
    /// differs only by fragment would be two identities for one fetch. Userinfo is refused because
    /// credentials in a URL the server dereferences would be sent to whoever the host resolves to.
    /// </remarks>
    public static bool TryCreate(string? raw, out AbsoluteHttpsUrl url)
    {
        url = default;

        if (string.IsNullOrEmpty(raw) || raw.Length > MaxLength)
        {
            return false;
        }

        // Control characters and whitespace, before Uri sees the string: Uri trims surrounding
        // whitespace, so a value carrying CR or LF would validate here and then be handed to
        // something that splits on it.
        foreach (var c in raw)
        {
            if (c < '\x21' || c == '\x7f')
            {
                return false;
            }
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || string.IsNullOrEmpty(uri.Host)
            || uri.IdnHost.Length > MaxHostLength)
        {
            return false;
        }

        // IdnHost, not Host. HttpClient uses the punycode form for SNI, the Host header and its
        // connection-pool key, so storing the Unicode form means the name we RESOLVE and check is
        // not the name the connection uses. Measured consequences of the mismatch: a legitimate
        // internationalised client_id was always Blocked(DnsFailed), because glibc does no IDNA;
        // and `https://ⓔⓥⓘⓛ.example/` reused the pooled connection opened for
        // `https://evil.example/`.
        url = new AbsoluteHttpsUrl(raw, uri.IdnHost, uri.Port is -1 ? 443 : uri.Port);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(AbsoluteHttpsUrl other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is AbsoluteHttpsUrl other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(AbsoluteHttpsUrl left, AbsoluteHttpsUrl right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(AbsoluteHttpsUrl left, AbsoluteHttpsUrl right) => !left.Equals(right);
}
