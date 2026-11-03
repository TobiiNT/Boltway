namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// Why a redirect URI was refused. Every value names one rule, so a rejection can say which.
/// </summary>
/// <remarks>
/// These reach the operator (at registration) and the developer (at request time) through
/// <c>error_description</c>. A-12 requires that <c>curl</c> alone be a sufficient debugging tool,
/// and "invalid redirect URI" with no reason is exactly the Auth0 behaviour the field report is
/// about.
/// </remarks>
public enum RedirectUriError
{
    /// <summary>No error.</summary>
    None = 0,

    /// <summary>Empty, whitespace, or over the length cap.</summary>
    Malformed,

    /// <summary>Not an absolute URI. RFC 6749 §3.1.2 requires one.</summary>
    NotAbsolute,

    /// <summary>Carries a fragment. RFC 6749 §3.1.2: the endpoint URI MUST NOT include a fragment.</summary>
    HasFragment,

    /// <summary>
    /// Carries userinfo (<c>https://user:pass@host/</c>). A credential in a redirect URI is a
    /// phishing primitive: the host a human reads is not the host the browser connects to.
    /// </summary>
    HasUserInfo,

    /// <summary>
    /// Scheme is not <c>https</c>, not <c>http</c>-on-a-loopback-host, and not a dotted private-use
    /// scheme. Notably <c>http</c> on a public host is refused: it would put the authorization code
    /// on the wire in clear text.
    /// </summary>
    SchemeNotAllowed,

    /// <summary>Port outside 1-65535, or explicitly 0. Port 0 means "any port" to a listener.</summary>
    PortOutOfRange,

    /// <summary>
    /// The query names a parameter the authorization response uses: <c>code</c>, <c>state</c>,
    /// <c>iss</c>, <c>error</c>, <c>error_description</c> or <c>error_uri</c>. OAuth 2.1 -17 §2.3:
    /// the redirect URI's query "MUST NOT include any parameters defined for use in the
    /// authorization response". Checked at registration only; a response appended to such a URI
    /// would carry the parameter twice, and which copy a client reads is its library's choice.
    /// </summary>
    QueryHasResponseParameter,
}
