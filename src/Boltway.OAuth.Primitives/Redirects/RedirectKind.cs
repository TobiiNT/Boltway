namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// How a redirect URI is allowed to be matched.
/// </summary>
/// <remarks>
/// This is stored, never re-derived at match time. Re-deriving "is this loopback?" from the
/// requested string would let the request decide which matching rule applies to it, which is the
/// whole attack: <c>https://claude.ai:1337/api/mcp/auth_callback</c> must not become port-agnostic
/// just because someone asked nicely.
/// </remarks>
public enum RedirectKind
{
    /// <summary>An <c>https</c> URI. Matched by exact ordinal string comparison, RFC 3986 §6.2.1.</summary>
    Https = 0,

    /// <summary>
    /// An <c>http</c> URI on a loopback host. Matched ignoring the port, RFC 8252 §7.3, because the
    /// native app cannot know which ephemeral port it will get until it binds one.
    /// </summary>
    Loopback = 1,

    /// <summary>
    /// A private-use scheme such as <c>com.example.app:/oauth</c>, RFC 8252 §7.1. Matched exactly.
    /// Only permitted when the scheme contains a dot, which is how RFC 8252 keeps app-defined
    /// schemes from colliding with registered ones.
    /// </summary>
    PrivateUseScheme = 2,
}
