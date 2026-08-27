namespace Boltway.OAuth.Tokens;

/// <summary>
/// The issuer identifier of an upstream identity provider.
/// </summary>
/// <remarks>
/// <para>
/// A distinct type from <c>IssuerString</c>, which is <i>this</i> server's issuer. They are both
/// "an https URL naming an OAuth issuer" and they are never interchangeable: one is the value this
/// server stamps into every token it signs (N-13), the other is a value it compares tokens
/// <i>from somebody else</i> against. A single type would let a call site validate an upstream's ID
/// token against our own issuer, which accepts nothing, or - worse in the other direction - mint a
/// token under an upstream's name.
/// </para>
/// <para>
/// Compared with <see cref="StringComparison.Ordinal"/> everywhere. OIDC Discovery §4.3 makes the
/// issuer comparison exact: "The <c>issuer</c> value returned MUST be identical to the Issuer URL
/// that was directly used to retrieve the configuration information."
/// </para>
/// </remarks>
public readonly struct UpstreamIssuer : IEquatable<UpstreamIssuer>
{
    /// <summary>Length cap, so a configured value cannot be unbounded in a log line or a cache key.</summary>
    public const int MaxLength = 512;

    private UpstreamIssuer(string value) => Value = value;

    /// <summary>The issuer, exactly as configured and exactly as compared.</summary>
    public string Value { get; }

    /// <summary>Whether this was ever set.</summary>
    public bool IsPresent => !string.IsNullOrEmpty(Value);

    /// <summary>
    /// Parse an issuer.
    /// </summary>
    /// <remarks>
    /// RFC 8414 §2 and OIDC Discovery §3: an issuer identifier is an <c>https</c> URL with no query
    /// and no fragment. A path is permitted - several enterprise products put the tenant there, and
    /// refusing one would make this unusable against them.
    /// </remarks>
    public static bool TryParse(string? raw, out UpstreamIssuer issuer)
    {
        issuer = default;

        if (string.IsNullOrEmpty(raw) || raw.Length > MaxLength)
        {
            return false;
        }

        // Before Uri sees the string, which trims surrounding whitespace: a value carrying CR or LF
        // would otherwise validate here and later be spliced into a URL or a log line.
        foreach (var c in raw)
        {
            if (c < '\x21' || c == '\x7f')
            {
                return false;
            }
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || string.IsNullOrEmpty(uri.Host))
        {
            return false;
        }

        issuer = new UpstreamIssuer(raw);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(UpstreamIssuer other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is UpstreamIssuer other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(UpstreamIssuer left, UpstreamIssuer right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(UpstreamIssuer left, UpstreamIssuer right) => !left.Equals(right);
}

/// <summary>
/// This server's client identifier at an upstream identity provider - the <c>aud</c> of an ID token
/// it issued to us.
/// </summary>
/// <remarks>
/// A third audience type beside <c>ResourceIdentifier</c> and <c>ClientIdentifier</c>, and the
/// reason is the same one recorded on <c>Rfc9068ValidationParameters.ForIdToken</c>: the compiler
/// refusing to swap two audiences at a call site is worth more than a comment saying not to. This
/// one differs from both - it is issued by a third party, it is opaque (Google's are
/// <c>&lt;digits&gt;-&lt;hash&gt;.apps.googleusercontent.com</c>, which is not a URL), and it is
/// never emitted by this server in anything.
/// </remarks>
public readonly struct UpstreamAudience : IEquatable<UpstreamAudience>
{
    /// <summary>Length cap.</summary>
    public const int MaxLength = 512;

    private UpstreamAudience(string value) => Value = value;

    /// <summary>The identifier, exactly as the upstream issued it.</summary>
    public string Value { get; }

    /// <summary>Whether this was ever set.</summary>
    public bool IsPresent => !string.IsNullOrEmpty(Value);

    /// <summary>
    /// Parse.
    /// </summary>
    /// <remarks>
    /// Deliberately permissive about the shape, because it is not ours to constrain: providers issue
    /// GUIDs, hostnames and opaque strings. What is refused is anything that could not survive being
    /// compared, logged or spliced - the empty string, an over-long value, and any character outside
    /// printable ASCII, which covers the control characters that turn one log line into two.
    /// </remarks>
    public static bool TryParse(string? raw, out UpstreamAudience audience)
    {
        audience = default;

        if (string.IsNullOrEmpty(raw) || raw.Length > MaxLength)
        {
            return false;
        }

        foreach (var c in raw)
        {
            if (c is < ' ' or > '~')
            {
                return false;
            }
        }

        audience = new UpstreamAudience(raw);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(UpstreamAudience other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is UpstreamAudience other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(UpstreamAudience left, UpstreamAudience right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(UpstreamAudience left, UpstreamAudience right) => !left.Equals(right);
}
