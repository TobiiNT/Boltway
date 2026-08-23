using Microsoft.AspNetCore.Http;

namespace Boltway.Mcp;

/// <summary>Who the transport authenticated, and what they may do.</summary>
public sealed class CallerPrincipal
{
    /// <summary>
    /// Stable handle for the person. What a connector attributes this request's writes to —
    /// though whether it actually does is the connector's to deliver, not this library's to
    /// claim. See <see cref="Email"/>.
    /// </summary>
    public required string Actor { get; init; }

    /// <summary>
    /// Address to attribute a downstream write to, when the store records one — git wants a
    /// name and an email on every commit.
    ///
    /// <para>
    /// Null means unknown, and a connector should then leave the field unset rather than
    /// synthesise something plausible. An invented author is worse than an absent one: it
    /// is indistinguishable from a real one, so the trail stops being evidence for every
    /// entry rather than just this one.
    /// </para>
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Whatever role vocabulary the connector uses. This library does not interpret it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This was a single string, and widening it was a change to both halves at once.</b> The
    /// authorization server's <c>IUserStore</c> said so from the other side: it stored one role
    /// because <c>FromClaims</c> read the claim with <c>FindFirst</c>, which takes one value and
    /// ignores the rest, so a set stored there would have produced tokens whose second and third
    /// roles were dropped by the only consumer shipped here — a rule existing on one surface and
    /// not the other. Both halves moved together.
    /// </para>
    /// <para>
    /// Empty for a caller holding none, never null. A connector deciding what that means — a floor,
    /// a refusal, an empty view — is the connector's decision and not this library's.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>
    /// What those roles stand for, if the authorization server resolved them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uninterpreted here, like everything else about a role. A server that keeps role definitions
    /// can put the resolved set in the token, which saves the resource server a lookup it would
    /// otherwise have to make on every call — and costs the freshness of one, because a token
    /// carries what was true when it was minted.
    /// </para>
    /// <para>
    /// <b>Empty means "the token said nothing", not "this caller may do nothing".</b> A connector
    /// with its own role table falls back to that table when this is empty, which is the same
    /// arrangement a static-token deployment has always had. Treating empty as a refusal would make
    /// every connector break the day it pointed at a server that does not publish permissions.
    /// </para>
    /// </remarks>
    public IReadOnlySet<string> Permissions { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// The scopes the access token actually carried.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>RequireScope</c> on an endpoint answers "may this request reach the server at all". It
    /// cannot answer "may this request write", because one MCP endpoint carries every tool: a
    /// required scope there is the intersection of what the tools need, so the widest scope a
    /// connector advertises is enforced by nothing. That gap is not visible from the endpoint —
    /// the metadata document lists the scope, the consent screen shows it, the user agrees to it,
    /// and withdrawing it takes no capability away. Carrying the granted set here is what lets a
    /// connector gate a tool on it.
    /// </para>
    /// <para>
    /// <b>Empty means the token carried no <c>scope</c> claim, not that this caller was granted
    /// nothing.</b> The static-token path has no authorization server and therefore no scopes at
    /// all, so a connector reading this must fall back rather than refuse — the same shape as
    /// <see cref="Permissions"/>, and for the same reason.
    /// </para>
    /// </remarks>
    public IReadOnlySet<string> Scopes { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// The caller's own credential for whatever the connector writes to.
    ///
    /// Carrying the caller's token rather than a service account's is what makes an audit
    /// trail worth having: a store where every change is authored by the connector has a
    /// log, not an audit trail.
    /// </summary>
    public string? DownstreamToken { get; init; }

    /// <summary>Anything else the authenticator learned. This library does not interpret it.</summary>
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Refuses a request, and says what would fix it. Thrown by an authenticator; turned into
/// an RFC 9728 challenge by the middleware, never into a JSON-RPC error — a client that
/// cannot find the authorization server has no way to recover from one.
/// </summary>
public sealed class UnauthorizedException(string message, string? scope = null) : Exception(message)
{
    /// <summary>The scope the caller lacked, surfaced in the challenge when known.</summary>
    public string? Scope { get; } = scope;
}

/// <summary>
/// The seam between a transport credential and an identity.
///
/// Deliberately the whole interface. A connector starts with a static token map, moves to
/// OAuth introspection, and later to a signed JWT, without anything above this changing.
/// </summary>
public interface IConnectorAuthenticator
{
    /// <summary>Resolve the caller, or throw <see cref="UnauthorizedException"/>.</summary>
    Task<CallerPrincipal> AuthenticateAsync(HttpContext context, CancellationToken ct = default);
}

/// <summary>
/// Bearer tokens resolved by a delegate.
///
/// <para>
/// Useful as a stepping stone before an authorization server exists, and the cost of
/// stopping there is specific rather than vague: with one shared static token every write
/// is authored by the same identity, so the trail records the tool and not the person.
/// That is exactly the property the audit trail was for.
/// </para>
/// </summary>
public sealed class BearerAuthenticator(Func<string, CancellationToken, Task<CallerPrincipal?>> resolve)
    : IConnectorAuthenticator
{
    /// <summary>A static map, for getting a connector deployed and learned from.</summary>
    public static BearerAuthenticator FromTokens(IReadOnlyDictionary<string, CallerPrincipal> tokens) =>
        new((token, _) => Task.FromResult(tokens.TryGetValue(token, out var principal) ? principal : null));

    /// <summary>
    /// Parse <c>DEV_TOKENS="tokenA:ada:editor:ada@example.com,tokenB:bob:editor"</c>.
    /// Entries that are not <c>token:actor[:role[:email]]</c> are skipped rather than
    /// guessed at. A missing email stays null — see <see cref="CallerPrincipal.Email"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, CallerPrincipal> ParseTokenMap(string? spec, string? downstreamToken = null)
    {
        var map = new Dictionary<string, CallerPrincipal>(StringComparer.Ordinal);

        foreach (var entry in (spec ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split(':');
            if (parts.Length < 2 || parts[0].Length == 0 || parts[1].Length == 0) continue;

            map[parts[0]] = new CallerPrincipal
            {
                Actor = parts[1],
                // Still one role on this path, and the entry format is unchanged. A static token is
                // pasted by hand into an environment variable; making it carry a set would be a
                // second syntax to get right for a path that exists to be simple, and the connector's
                // own table resolves the one it does carry.
                Roles = parts.Length > 2 && parts[2].Length > 0 ? [parts[2]] : [],
                Email = parts.Length > 3 && parts[3].Length > 0 ? parts[3] : null,
                DownstreamToken = downstreamToken,
            };
        }

        return map;
    }

    /// <inheritdoc />
    public async Task<CallerPrincipal> AuthenticateAsync(HttpContext context, CancellationToken ct = default)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedException("No bearer token");

        var token = header[7..].Trim();
        if (token.Length == 0) throw new UnauthorizedException("Empty bearer token");

        return await resolve(token, ct) ?? throw new UnauthorizedException("Token not recognised");
    }
}
