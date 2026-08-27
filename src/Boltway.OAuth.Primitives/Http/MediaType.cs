namespace Boltway.OAuth.Primitives.Http;

/// <summary>
/// A parsed <c>Content-Type</c>, reduced to its type and subtype.
/// </summary>
/// <remarks>
/// <para>
/// This type exists because of a measurement. Both vendors publish a client metadata document, and
/// on 2026-08-03 they served it with different headers:
/// </para>
/// <code>
/// claude.ai    Content-Type: application/json
/// chatgpt.com  Content-Type: application/json; charset=utf-8
/// </code>
/// <para>
/// A fetcher that compares the header to <c>"application/json"</c> by string equality therefore
/// accepts every Claude document and rejects every ChatGPT one - and the resulting failure surfaces
/// as <c>invalid_client</c>, which reads as the client's fault. RFC 9110 §8.3 has said all along
/// that parameters are part of the field and not part of the media type; this is the type that
/// makes the code agree.
/// </para>
/// <para>
/// Used by both halves of the product: the authorization server's CIMD fetcher and the resource
/// server's metadata fetcher parse Content-Type through the same compiled code, so the two cannot
/// drift apart on it.
/// </para>
/// </remarks>
public readonly struct MediaType : IEquatable<MediaType>
{
    private MediaType(string type, string subType)
    {
        Type = type;
        SubType = subType;
    }

    /// <summary>The type, lowercased. RFC 9110 §8.3.1: case-insensitive.</summary>
    public string Type { get; }

    /// <summary>The subtype, lowercased.</summary>
    public string SubType { get; }

    /// <summary>Whether this is any flavour of JSON, including <c>+json</c> structured suffixes.</summary>
    /// <remarks>
    /// RFC 6839 requires a non-empty base before a <c>+json</c> structured suffix, so
    /// <c>application/+json</c> is not JSON - it is malformed.
    /// </remarks>
    public bool IsJson =>
        string.Equals(Type, "application", StringComparison.Ordinal)
        && (string.Equals(SubType, "json", StringComparison.Ordinal)
            || (SubType.Length > 5 && SubType[0] != '+' && SubType.EndsWith("+json", StringComparison.Ordinal)));

    /// <summary>Whether this is <c>application/x-www-form-urlencoded</c>, the <c>/token</c> input.</summary>
    public bool IsFormUrlEncoded =>
        string.Equals(Type, "application", StringComparison.Ordinal)
        && string.Equals(SubType, "x-www-form-urlencoded", StringComparison.Ordinal);

    /// <summary>
    /// Parse a <c>Content-Type</c> header value, discarding parameters.
    /// </summary>
    public static bool TryParse(string? header, out MediaType mediaType)
    {
        mediaType = default;

        if (string.IsNullOrWhiteSpace(header))
        {
            return false;
        }

        // Everything from the first ';' is parameters: charset, boundary, profile. Not our business.
        var semicolon = header.IndexOf(';', StringComparison.Ordinal);
        var essence = (semicolon >= 0 ? header[..semicolon] : header).Trim();

        var slash = essence.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0 || slash == essence.Length - 1)
        {
            return false;
        }

        var type = essence[..slash];
        var subType = essence[(slash + 1)..];

        if (type.Length == 0 || subType.Length == 0 || !IsToken(type) || !IsToken(subType))
        {
            return false;
        }

        mediaType = new MediaType(type.ToLowerInvariant(), subType.ToLowerInvariant());
        return true;
    }

    /// <summary>
    /// RFC 9110 §5.6.2 <c>token</c>: <c>1*tchar</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without this, a parsed media type could carry anything the splitter did not eat - including
    /// CR and LF. <c>Content-Type</c> is attacker-controlled on every <c>/token</c> and
    /// <c>/register</c> request, so the moment a 415 body, a log line or a diagnostic header
    /// interpolated the parsed value, that was log injection or response splitting, out of the very
    /// type whose job is to be the trusted parse of that header.
    /// </para>
    /// <para>
    /// It also rejects several things that merely looked parseable: <c>application/json/evil</c>,
    /// <c>application / json</c>, <c>application/js on</c>, and a comma-joined Accept-style list
    /// such as <c>text/html, application/json</c>.
    /// </para>
    /// </remarks>
    /// <summary>
    /// RFC 7230 §3.2.6 <c>token</c>: one or more <c>tchar</c>.
    /// </summary>
    /// <remarks>
    /// <c>internal</c> rather than private so <see cref="WwwAuthenticate"/> uses this definition
    /// instead of its own. tchar appears in several header grammars and two copies of it would
    /// eventually disagree by one character, which is precisely the kind of difference that decides
    /// whether an injected value parses.
    /// </remarks>
    internal static bool IsToken(string value)
    {
        foreach (var c in value)
        {
            var ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
                or '!' or '#' or '$' or '%' or '&' or '\'' or '*'
                or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';

            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc />
    public bool Equals(MediaType other) =>
        string.Equals(Type, other.Type, StringComparison.Ordinal)
        && string.Equals(SubType, other.SubType, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is MediaType other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Type, SubType);

    /// <inheritdoc />
    public override string ToString() => Type is null ? "<none>" : $"{Type}/{SubType}";

    /// <summary>Equality on type and subtype.</summary>
    public static bool operator ==(MediaType left, MediaType right) => left.Equals(right);

    /// <summary>Inequality on type and subtype.</summary>
    public static bool operator !=(MediaType left, MediaType right) => !left.Equals(right);
}
