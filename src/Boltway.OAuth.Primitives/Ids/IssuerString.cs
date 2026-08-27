namespace Boltway.OAuth.Primitives.Ids;

/// <summary>
/// The authorization server's issuer identifier. One immutable configured byte string.
/// </summary>
/// <remarks>
/// <para>
/// N-13. This exact string appears in five places that must agree byte for byte: the two discovery
/// documents, every access token's <c>iss</c>, every ID token's <c>iss</c>, the RFC 9207 <c>iss</c>
/// response parameter, and the prefix of the URL the metadata was fetched from. Clients compare it
/// with Simple String Comparison and the MCP specification forbids them from normalizing, so
/// <c>https://as.example.com</c> and <c>https://as.example.com/</c> are two different issuers.
/// </para>
/// <para>
/// <b>Never derived from the request.</b> Building it from <c>Request.Scheme</c> and
/// <c>Request.Host</c> is the standard way to get this wrong and it has two distinct failure modes:
/// behind a reverse proxy the scheme is <c>http</c>, so every token is issued under an issuer no
/// client will accept; and with host-header injection an attacker chooses the issuer, so tokens are
/// minted under a name they control. An architecture test bans <c>HttpRequest.Host</c> and
/// <c>HttpRequest.Scheme</c> from the server assembly for exactly this reason.
/// </para>
/// </remarks>
public readonly struct IssuerString : IEquatable<IssuerString>
{
    private IssuerString(string value) => Value = value;

    /// <summary>The issuer, exactly as configured. Emitted verbatim, never reconstructed.</summary>
    public string Value { get; }

    /// <summary>
    /// Parse a configured issuer. Rejects everything RFC 8414 §2 forbids.
    /// </summary>
    /// <remarks>
    /// A trailing slash is refused rather than trimmed. Trimming would be a normalization, and the
    /// operator who wrote the slash would then see a different string in the metadata than the one
    /// they configured - which is exactly the class of surprise this type exists to prevent.
    /// </remarks>
    public static bool TryCreate(string? raw, out IssuerString issuer, out string? error)
    {
        issuer = default;
        error = null;

        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "The issuer is required.";
            return false;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            error = $"'{raw}' is not an absolute URL.";
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            error = $"The issuer must be https; '{raw}' is '{uri.Scheme}'.";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            error = $"RFC 8414 §2: the issuer must have no query or fragment; '{raw}' has one.";
            return false;
        }

        if (raw.EndsWith('/'))
        {
            error =
                $"'{raw}' ends with a slash. Clients compare the issuer with Simple String " +
                "Comparison and must not normalize it, so a trailing slash makes this a different " +
                "issuer from the one without. Configure it without the slash.";
            return false;
        }

        issuer = new IssuerString(raw);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(IssuerString other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is IssuerString other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<unset>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(IssuerString left, IssuerString right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(IssuerString left, IssuerString right) => !left.Equals(right);
}
