using System.Diagnostics.CodeAnalysis;
using Boltway.OAuth.Net;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>
/// A <c>client_id</c> that satisfies the Client Identifier URL rules of CIMD §3.
/// </summary>
/// <remarks>
/// <para>
/// Two values, deliberately kept apart. <see cref="Value"/> is the raw <c>client_id</c> string and
/// is the <b>only</b> comparison input: §3 and §4 both require simple string comparison as defined
/// in RFC 3986 §6.2.1, so <c>https://example.com/c</c> and <c>https://example.com:443/c</c> are
/// different clients even though they name the same resource. <see cref="Url"/> is the fetch
/// target, and its type is the proof that the fetcher can never be pointed at a scheme this server
/// does not speak.
/// </para>
/// <para>
/// The dot-segment rule is the one that would look like pedantry and is not. Measured on .NET 10,
/// building an <c>HttpRequestMessage</c> for these URLs:
/// </para>
/// <code>
/// https://example.com/a/../b       -> https://example.com/b
/// https://example.com/a/%2e%2e/b   -> https://example.com/b
/// https://example.com/a/./b        -> https://example.com/a/b
/// </code>
/// <para>
/// So a <c>client_id</c> carrying a dot segment is fetched from a URL that is not the
/// <c>client_id</c>, and the document found there is some other client's. §4's self-reference check
/// would then refuse it - the failure is closed either way - but it would be refused with
/// "your <c>client_id</c> does not match", which sends the reader looking at the wrong file.
/// Refusing here names the actual rule.
/// </para>
/// </remarks>
public readonly struct CimdClientIdUrl : IEquatable<CimdClientIdUrl>
{
    /// <summary>The only scheme §3 permits, as the literal prefix an ordinal test uses.</summary>
    public const string HttpsPrefix = "https://";

    private CimdClientIdUrl(string value, AbsoluteHttpsUrl url)
    {
        Value = value;
        Url = url;
    }

    /// <summary>The <c>client_id</c> exactly as it arrived. The comparison input, per §3.</summary>
    public string Value { get; }

    /// <summary>The same URL, in the one type the fetcher accepts.</summary>
    public AbsoluteHttpsUrl Url { get; }

    /// <summary>
    /// Apply every §3 rule, naming the one that failed.
    /// </summary>
    /// <param name="raw">The <c>client_id</c> as sent.</param>
    /// <param name="parsed">The parsed URL, when this returns <see langword="true"/>.</param>
    /// <param name="failure">
    /// Which §3 rule refused it, in words, when this returns <see langword="false"/>. A-07: the
    /// description has to identify the check, because <c>invalid_client</c> with no detail is the
    /// diagnosis this project exists as a reaction to.
    /// </param>
    /// <remarks>
    /// <para>
    /// §3's list, and what each maps to below:
    /// </para>
    /// <list type="bullet">
    /// <item><description>MUST use the https scheme - the ordinal prefix test.</description></item>
    /// <item><description>MUST NOT contain a userinfo component - the <c>@</c> scan of the authority.</description></item>
    /// <item><description>MAY contain a port - no check; <see cref="AbsoluteHttpsUrl"/> keeps it.</description></item>
    /// <item><description>MUST contain a path component - the delimiter test.</description></item>
    /// <item><description>MUST NOT contain single- or double-dot path components - <c>HasDotSegment</c>.</description></item>
    /// <item><description>MUST NOT contain a fragment - the <c>#</c> scan.</description></item>
    /// </list>
    /// <para>
    /// §3 also says a Client Identifier URL <b>SHOULD NOT</b> contain a query component. That is a
    /// SHOULD NOT and it is not enforced: refusing a query would refuse a client the specification
    /// permits, and neither of the four vendor documents captured on 2026-08-03 uses one, so there
    /// is no measurement saying the stricter reading is needed. §3's "NOT RECOMMENDED" against a
    /// path of <c>/</c> is left alone for the same reason.
    /// </para>
    /// </remarks>
    public static bool TryParse(
        string? raw, out CimdClientIdUrl parsed, [NotNullWhen(false)] out string? failure)
    {
        parsed = default;

        if (string.IsNullOrEmpty(raw))
        {
            failure = "The 'client_id' is empty.";
            return false;
        }

        if (!raw.StartsWith(HttpsPrefix, StringComparison.Ordinal))
        {
            failure = "A client metadata document URL must use the https scheme (CIMD section 3).";
            return false;
        }

        // A fragment is never sent to the origin server, so a client_id that differs only by
        // fragment would be two identities sharing one document.
        if (raw.Contains('#', StringComparison.Ordinal))
        {
            failure = "A client metadata document URL must not contain a fragment (CIMD section 3).";
            return false;
        }

        // Cut the authority out of the raw string rather than reading Uri.Host: this is a rule about
        // the characters the client sent, and Uri is a normalizing type.
        var rest = raw.AsSpan(HttpsPrefix.Length);
        var delimiter = rest.IndexOfAny('/', '?');
        var authority = delimiter < 0 ? rest : rest[..delimiter];

        if (authority.Contains('@'))
        {
            failure = "A client metadata document URL must not contain a userinfo component (CIMD section 3).";
            return false;
        }

        // No delimiter at all is `https://host`; a `?` first is `https://host?q`. Neither has a path
        // component, and §3 requires one.
        if (delimiter < 0 || rest[delimiter] != '/')
        {
            failure = "A client metadata document URL must contain a path component (CIMD section 3).";
            return false;
        }

        var afterAuthority = rest[delimiter..];
        var queryStart = afterAuthority.IndexOf('?');
        var path = queryStart < 0 ? afterAuthority : afterAuthority[..queryStart];

        if (HasDotSegment(path))
        {
            failure = "A client metadata document URL must not contain '.' or '..' path segments (CIMD section 3).";
            return false;
        }

        // Last, because it is the one check that cannot say which rule it enforced. Everything it
        // would catch on its own - control characters, an over-long host, a malformed authority -
        // has no more specific §3 sentence to quote.
        if (!AbsoluteHttpsUrl.TryCreate(raw, out var url))
        {
            failure = "The 'client_id' is not a well-formed absolute https URL (CIMD section 3).";
            return false;
        }

        parsed = new CimdClientIdUrl(raw, url);
        failure = null;
        return true;
    }

    /// <summary>Whether any segment of <paramref name="path"/> is <c>.</c> or <c>..</c>.</summary>
    private static bool HasDotSegment(ReadOnlySpan<char> path)
    {
        var start = 0;

        for (var i = 0; i <= path.Length; i++)
        {
            if (i != path.Length && path[i] != '/')
            {
                continue;
            }

            if (i > start && IsDotSegment(path[start..i]))
            {
                return true;
            }

            start = i + 1;
        }

        return false;
    }

    /// <summary>
    /// Whether a single path segment is one or two dots, however they are spelled.
    /// </summary>
    /// <remarks>
    /// <c>%2e</c> counts as a dot. RFC 3986's dot-segment production is the literal characters, so
    /// this is stricter than the grammar - but <c>.</c> is unreserved, and .NET percent-decodes
    /// unreserved characters and then resolves the result: measured,
    /// <c>https://example.com/a/%2e%2e/b</c> is fetched as <c>https://example.com/b</c>, exactly as
    /// the unencoded spelling is. Accepting the encoded form would be accepting the same redirection
    /// under a different name.
    /// </remarks>
    private static bool IsDotSegment(ReadOnlySpan<char> segment)
    {
        var dots = 0;
        var i = 0;

        while (i < segment.Length)
        {
            if (segment[i] == '.')
            {
                i += 1;
            }
            else if (i + 2 < segment.Length
                     && segment[i] == '%'
                     && segment[i + 1] == '2'
                     && segment[i + 2] is 'e' or 'E')
            {
                i += 3;
            }
            else
            {
                return false;
            }

            dots++;

            if (dots > 2)
            {
                return false;
            }
        }

        return dots is 1 or 2;
    }

    /// <inheritdoc />
    public bool Equals(CimdClientIdUrl other) => string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is CimdClientIdUrl other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value ?? "<none>";

    /// <summary>Ordinal equality, per RFC 3986 §6.2.1.</summary>
    public static bool operator ==(CimdClientIdUrl left, CimdClientIdUrl right) => left.Equals(right);

    /// <summary>Ordinal inequality.</summary>
    public static bool operator !=(CimdClientIdUrl left, CimdClientIdUrl right) => !left.Equals(right);
}
