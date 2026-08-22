using System.Diagnostics.CodeAnalysis;

namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// The frozen result of parsing a redirect URI exactly once.
/// </summary>
/// <remarks>
/// <para>
/// This type exists so that <see cref="RedirectUriMatcher"/> can be written without a single
/// reference to <see cref="Uri"/>. That is not a stylistic preference: <see cref="Uri"/> is a
/// normalizing type, and every one of its normalizations maps several distinct byte strings onto
/// one — which is the same operation as widening a redirect allowlist.
/// </para>
/// <para>
/// The rule that follows, and it is absolute: <b>no value that a matching decision compares may
/// have passed through <see cref="Uri"/>.</b> <see cref="Uri"/> is used here only to <i>reject</i>
/// (is it absolute, does it carry a fragment, is the port in range) — never to produce a string
/// that is later compared. Every compared value is cut out of the raw request bytes.
/// </para>
/// <para>
/// Both halves of that rule were learned by measurement rather than reasoning. <c>Uri.Host</c>
/// collapses <c>127.1</c>, <c>0x7f.1</c> and <c>2130706433</c> onto <c>127.0.0.1</c>;
/// <c>GetComponents(UriComponents.Path, UriFormat.UriEscaped)</c> resolves dot segments and
/// percent-decodes unreserved characters, so <c>/a/../callback</c>, <c>/a/%2e%2e/callback</c> and
/// <c>/%63allback</c> all become <c>callback</c>. Each of those was a live match against a
/// registration that did not contain them.
/// </para>
/// </remarks>
internal readonly struct RedirectUriParts
{
    /// <summary>Length cap. Long enough for any real redirect, short enough to bound a log line.</summary>
    internal const int MaxLength = 2048;

    private RedirectUriParts(RedirectKind kind, string host, string pathAndQuery)
    {
        Kind = kind;
        Host = host;
        PathAndQuery = pathAndQuery;
    }

    internal RedirectKind Kind { get; }

    /// <summary>Host cut from the raw string, with any IPv6 brackets stripped.</summary>
    internal string Host { get; }

    /// <summary>
    /// Everything after the authority, cut from the raw string: path and query together.
    /// </summary>
    /// <remarks>
    /// Kept as one span rather than split, because splitting would need a second parse and the two
    /// are only ever compared together. Raw, so <c>%2e%2e</c> stays <c>%2e%2e</c> and <c>/a/../b</c>
    /// stays <c>/a/../b</c>. A fragment cannot appear: it is rejected upstream.
    /// </remarks>
    internal string PathAndQuery { get; }

    /// <summary>
    /// The three loopback hosts, compared as literal strings against the raw host.
    /// </summary>
    /// <remarks>
    /// String literals, and never <see cref="System.Net.IPAddress.IsLoopback"/>, which accepts the
    /// whole 127.0.0.0/8 block and parses alternate spellings into it. <c>localhost</c> is in the
    /// set because RFC 8252 permits registering it and Claude Code's published client metadata
    /// declares both <c>http://localhost/callback</c> and <c>http://127.0.0.1/callback</c>.
    /// </remarks>
    private static readonly string[] LoopbackHosts = ["127.0.0.1", "::1", "localhost"];

    internal static bool TryParse(string? raw, [NotNullWhen(true)] out RedirectUriParts? parts, out RedirectUriError error)
    {
        parts = null;

        if (string.IsNullOrEmpty(raw) || raw.Length > MaxLength)
        {
            error = RedirectUriError.Malformed;
            return false;
        }

        // Reject every character below '!' and DEL, BEFORE Uri sees the string.
        //
        // This is the highest-value check in the file. System.Uri TRIMS leading and trailing
        // whitespace — including CR, LF and TAB — and then validates what is left. So
        // "http://127.0.0.1:1/callback\r\n\r\n" parses as a clean URI, passes every rule below,
        // and matches a registration. The raw string is what gets written to the Location header,
        // and it still has the CRLF in it: response splitting on the authorization server's own
        // origin. On the registration side it is worse, because it needs no loopback and reaches
        // the exact-match path — any client that can self-register through DCR or CIMD could store
        // a CRLF-bearing redirect URI and then drive a victim through /authorize.
        //
        // A redirect URI legally contains none of these characters. Rejecting the whole range is
        // cheaper than enumerating the dangerous ones and cannot miss one.
        foreach (var c in raw)
        {
            if (c < '\x21' || c == '\x7f')
            {
                error = RedirectUriError.Malformed;
                return false;
            }
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            error = RedirectUriError.NotAbsolute;
            return false;
        }

        // RFC 6749 §3.1.2.
        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            error = RedirectUriError.HasFragment;
            return false;
        }

        // Userinfo is refused for its own sake — a credential in a redirect URI is a phishing
        // primitive, because the host a human reads is not the host the browser connects to. It
        // also happens to close a parser-disagreement hole: in
        // "http://127.0.0.1:1\r\n@evil.example/cb", Uri strips the CRLF and sees evil.example while
        // raw extraction sees 127.0.0.1. The control-character check above now catches that case
        // first, so this check is no longer load-bearing for it, but both stay.
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            error = RedirectUriError.HasUserInfo;
            return false;
        }

        if (!TrySplitRaw(raw, out var scheme, out var authority, out var pathAndQuery, out var hasAuthority))
        {
            error = RedirectUriError.NotAbsolute;
            return false;
        }

        var host = StripBrackets(HostOf(authority));
        var isLoopbackHost = IsLoopbackHost(host);

        RedirectKind kind;
        if (string.Equals(scheme, "https", StringComparison.Ordinal))
        {
            kind = RedirectKind.Https;
        }
        else if (string.Equals(scheme, "http", StringComparison.Ordinal) && isLoopbackHost)
        {
            // http is tolerated only here. RFC 8252 §8.3: loopback traffic never leaves the machine.
            kind = RedirectKind.Loopback;
        }
        else if (IsPrivateUseScheme(scheme, hasAuthority))
        {
            kind = RedirectKind.PrivateUseScheme;
        }
        else
        {
            error = RedirectUriError.SchemeNotAllowed;
            return false;
        }

        // -1 means no port and no default for the scheme. An explicit :0 is refused: to a listener
        // it means "any port", which would make one registration match everything.
        if (uri.Port is 0 or < -1 or > 65535)
        {
            error = RedirectUriError.PortOutOfRange;
            return false;
        }

        parts = new RedirectUriParts(kind, host, pathAndQuery);
        error = RedirectUriError.None;
        return true;
    }

    /// <summary>
    /// Cut a raw URI into lowercased scheme, authority, and the path+query remainder.
    /// </summary>
    /// <remarks>
    /// Lowercasing the scheme is the one normalization applied to a comparison input, and it is
    /// safe: RFC 3986 §6.2.2.1 makes the scheme case-insensitive, the set of legal scheme characters
    /// is ASCII, and the classification it feeds (https / http / private-use) is a closed set. It is
    /// done here rather than read from <c>Uri.Scheme</c> so that the raw string remains the source.
    /// </remarks>
    private static bool TrySplitRaw(
        string raw,
        out string scheme,
        out string authority,
        out string pathAndQuery,
        out bool hasAuthority)
    {
        scheme = string.Empty;
        authority = string.Empty;
        pathAndQuery = string.Empty;
        hasAuthority = false;

        var schemeEnd = raw.IndexOf(':', StringComparison.Ordinal);
        if (schemeEnd <= 0)
        {
            return false;
        }

        scheme = raw[..schemeEnd].ToLowerInvariant();

        hasAuthority = raw.Length >= schemeEnd + 3 && raw.AsSpan(schemeEnd + 1, 2) is "//";
        var authorityStart = hasAuthority ? schemeEnd + 3 : schemeEnd + 1;

        if (!hasAuthority)
        {
            // A private-use scheme such as com.example.app:/oauth2redirect has no authority.
            pathAndQuery = raw[authorityStart..];
            return true;
        }

        var authorityEnd = raw.Length;
        for (var i = authorityStart; i < raw.Length; i++)
        {
            if (raw[i] is '/' or '?' or '#')
            {
                authorityEnd = i;
                break;
            }
        }

        authority = raw[authorityStart..authorityEnd];
        pathAndQuery = raw[authorityEnd..];
        return true;
    }

    /// <summary>Strip the port from a raw authority, leaving the host.</summary>
    private static string HostOf(string authority)
    {
        if (authority.Length == 0)
        {
            return string.Empty;
        }

        // An IPv6 literal is bracketed and contains colons that are not the port separator.
        if (authority[0] == '[')
        {
            var close = authority.IndexOf(']', StringComparison.Ordinal);
            return close < 0 ? authority : authority[..(close + 1)];
        }

        var colon = authority.IndexOf(':', StringComparison.Ordinal);
        return colon < 0 ? authority : authority[..colon];
    }

    /// <summary>
    /// Is this one of the three loopback host strings?
    /// </summary>
    /// <remarks>
    /// Ordinal, not <c>OrdinalIgnoreCase</c>, so that classification and comparison use the same
    /// rule. Case-insensitive classification here would put <c>http://LOCALHOST:1/cb</c> into the
    /// loopback branch and then fail its host comparison against <c>localhost</c> — failing closed,
    /// but for a reason no reader could predict. A registration is lowercased on write, so an
    /// uppercase host can only arrive on a request, and a request is never normalized.
    /// </remarks>
    private static bool IsLoopbackHost(string host)
    {
        foreach (var candidate in LoopbackHosts)
        {
            if (string.Equals(host, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// RFC 8252 §7.1 private-use scheme: a reverse-DNS name the app controls.
    /// </summary>
    /// <remarks>
    /// Requires at least two dot-separated non-empty labels and forbids an <c>//</c> authority.
    /// "Contains a dot" alone would admit <c>co.uk:/cb</c> and, worse, <c>http.s://host/cb</c> —
    /// which reads as a typo of <c>https</c> and would be classified as a private-use scheme.
    /// Matching stays exact for this kind either way, so this is tightening the door rather than
    /// closing a hole.
    /// </remarks>
    private static bool IsPrivateUseScheme(string scheme, bool hasAuthority)
    {
        // Tests whether an authority MARKER was present, not whether it was non-empty. "file://"
        // and "a.b://" carry an empty authority, which is still an authority — RFC 8252 §7.1
        // private-use schemes are of the form scheme:/path with no "//" at all.
        if (hasAuthority)
        {
            return false;
        }

        var labels = scheme.Split('.');
        if (labels.Length < 2)
        {
            return false;
        }

        foreach (var label in labels)
        {
            if (label.Length == 0)
            {
                return false;
            }
        }

        return true;
    }

    private static string StripBrackets(string host) =>
        host.Length >= 2 && host[0] == '[' && host[^1] == ']'
            ? host[1..^1]
            : host;

    /// <summary>
    /// Lowercase the scheme and authority in place, leaving path and query bytes untouched.
    /// </summary>
    /// <remarks>
    /// RFC 3986 §6.2.2.1 makes scheme and host case-insensitive and everything after them
    /// case-sensitive, so this is the one normalization safe to apply — and it is applied at
    /// registration only, never to a request. Done by string surgery rather than by rebuilding
    /// through <see cref="Uri"/>: reconstruction would also elide an explicitly written default
    /// port, and <c>https://claude.ai:443/cb</c> is not the same registered string as
    /// <c>https://claude.ai/cb</c>.
    /// </remarks>
    internal static string LowercaseSchemeAndAuthority(string raw)
    {
        if (!TrySplitRaw(raw, out var scheme, out var authority, out var pathAndQuery, out var hasAuthority))
        {
            return raw;
        }

        // Preserve the "//" whenever it was there. Collapsing "file:///etc/passwd" to
        // "file:/etc/passwd" is a normalization that changes what the URI MEANS — an empty
        // authority is not the absence of one — and normalize-on-write must only ever change case.
        // It also produced a misleading rejection: the collapsed form does not parse at all, so the
        // reported reason became NotAbsolute for a URI that is absolute and should have been
        // refused for its scheme.
        return hasAuthority
            ? scheme + "://" + authority.ToLowerInvariant() + pathAndQuery
            : scheme + ":" + pathAndQuery;
    }
}
