using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.OAuth.Primitives.Ids;

/// <summary>How a client came to have its identifier.</summary>
/// <remarks>
/// Stored on the client record, never re-derived from the shape of the identifier. Deciding "is
/// this CIMD?" by testing for an <c>https://</c> prefix would let a dynamically registered client
/// that chose a URL-shaped id be treated as a CIMD client, which is a different trust model
/// entirely — the CIMD draft warns about exactly this.
/// </remarks>
public enum ClientIdKind
{
    /// <summary>Not set.</summary>
    Unknown = 0,

    /// <summary>The identifier is a URL naming a client metadata document. CIMD.</summary>
    ClientIdMetadataDocument = 1,

    /// <summary>Issued by this server through RFC 7591 dynamic registration.</summary>
    Dynamic = 2,

    /// <summary>Configured by an administrator.</summary>
    PreRegistered = 3,
}

/// <summary>
/// A client identifier: a URL for a CIMD client, an opaque string otherwise.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="string"/>, not a GUID. Both vendors identify themselves with a URL —
/// <c>https://claude.ai/oauth/mcp-oauth-client-metadata</c> and
/// <c>https://chatgpt.com/oauth/client.json</c> — so a schema that assumed a GUID would not be able
/// to store either of the two clients this server exists to serve.
/// </para>
/// <para>
/// That has a consequence worth naming (A-18): these values contain <c>:</c> and <c>/</c>. Putting
/// one in a route, a filename, a log path or a cache key without encoding is a traversal or a
/// collision, so <see cref="UrlSafeToken"/> exists and the management endpoints route on it.
/// </para>
/// </remarks>
public readonly struct ClientIdentifier : IEquatable<ClientIdentifier>
{
    /// <summary>Length cap, generous enough for a URL-shaped identifier.</summary>
    public const int MaxLength = 512;

    private ClientIdentifier(string value, ClientIdKind kind)
    {
        Value = value;
        Kind = kind;
        UrlSafeToken = Base64Url.Encode(Sha256Hash.OfString(value).Value);
    }

    /// <summary>The identifier, exactly as issued or as sent. The comparison input.</summary>
    public string Value { get; }

    /// <summary>How this identifier was obtained. Stored, never inferred from <see cref="Value"/>.</summary>
    public ClientIdKind Kind { get; }

    /// <summary>base64url of SHA-256 of the identifier. The only form safe in a route or cache key.</summary>
    public string UrlSafeToken { get; }

    /// <summary>A CIMD client, identified by the URL of its metadata document.</summary>
    public static ClientIdentifier ForCimd(string url) => new(url, ClientIdKind.ClientIdMetadataDocument);

    /// <summary>A client registered through RFC 7591.</summary>
    public static ClientIdentifier ForDynamic(string generated) => new(generated, ClientIdKind.Dynamic);

    /// <summary>A client configured by an administrator.</summary>
    public static ClientIdentifier ForPreRegistered(string configured) => new(configured, ClientIdKind.PreRegistered);

    /// <summary>
    /// Parse a <c>client_id</c> from a request, with the kind still unknown.
    /// </summary>
    /// <remarks>
    /// The kind comes from resolving the client, not from the request: whoever sent it does not get
    /// to say what kind of client they are. There is deliberately no constructor taking both a
    /// value and a kind from untrusted input.
    /// </remarks>
    public static bool TryParseFromRequest(string? raw, out ClientIdentifier clientId)
    {
        clientId = default;

        if (string.IsNullOrEmpty(raw) || raw.Length > MaxLength)
        {
            return false;
        }

        // RFC 6749 Appendix A.1: client_id is *VSCHAR, %x20-7E. Rejecting control characters here
        // keeps them out of every log line and cache key downstream.
        foreach (var c in raw)
        {
            if (c is < '\x20' or > '\x7e')
            {
                return false;
            }
        }

        clientId = new ClientIdentifier(raw, ClientIdKind.Unknown);
        return true;
    }

    /// <summary>Whether this identifier is URL-shaped, so a CIMD resolution could be attempted.</summary>
    /// <remarks>
    /// A question about the <i>shape</i>, asked when choosing which resolver to try. It is not the
    /// same question as <see cref="Kind"/>, which records what the client turned out to be.
    /// </remarks>
    public bool LooksLikeCimdUrl =>
        Value is not null && Value.StartsWith("https://", StringComparison.Ordinal);

    /// <inheritdoc />
    public bool Equals(ClientIdentifier other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ClientIdentifier other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(ClientIdentifier left, ClientIdentifier right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(ClientIdentifier left, ClientIdentifier right) => !left.Equals(right);
}

/// <summary>
/// The end user's identifier: the <c>sub</c> claim.
/// </summary>
/// <remarks>
/// A ULID, rendered as 26 characters of Crockford base32 — charset <c>[0-9A-HJKMNP-TV-Z]</c>. That
/// choice does A-18's work by construction: no <c>|</c>, <c>/</c>, <c>.</c> or <c>@</c>, so the
/// value is safe as a path segment, a filename, a cache key and a column name with no sanitiser
/// anywhere. It is a deliberate improvement on the <c>auth0|&lt;hex&gt;</c> shape, which forced the
/// connector this project came out of to write both a sanitiser and a collision-disambiguation
/// path — and a sanitiser that maps several inputs onto one identifier is a collision waiting for
/// the wrong two users.
/// </remarks>
public readonly struct SubjectId : IEquatable<SubjectId>
{
    private SubjectId(string value) => Value = value;

    /// <summary>The <c>sub</c> claim value.</summary>
    public string Value { get; }

    /// <summary>Wrap a stored subject identifier.</summary>
    public static SubjectId FromStorage(string value) => new(value);

    /// <inheritdoc />
    public bool Equals(SubjectId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is SubjectId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality.</summary>
    public static bool operator ==(SubjectId left, SubjectId right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(SubjectId left, SubjectId right) => !left.Equals(right);
}
