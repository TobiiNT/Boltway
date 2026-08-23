using System.Security.Claims;
using Boltway.ResourceServer.Bearer;
using Microsoft.AspNetCore.Http;

using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.Mcp;

/// <summary>
/// Turns an access token validated by <c>Boltway.ResourceServer</c> into a
/// <see cref="CallerPrincipal"/>, so an MCP connector can move off static tokens without
/// anything above the seam changing.
///
/// <para>
/// <strong>It does not authenticate and it never challenges.</strong> That is the point.
/// <c>UseBoltwayProtectedResource()</c> already validated the signature, the audience
/// and the scopes, and it writes the 401 — the one that carries the vendor-researched
/// challenge shape. A second authenticator producing a second 401 is exactly the
/// duplication this library exists to prevent, so this one only reads what that middleware
/// left behind.
/// </para>
///
/// <para>
/// Wire it after the resource-server middleware and give the MCP endpoint a required scope:
/// </para>
///
/// <code>
/// app.UseRouting();
/// app.UseBoltwayProtectedResource();                 // validates, and owns the 401
/// app.UseConnectorCaller("/mcp", bindState);              // maps the result onto the caller
/// app.MapProtectedResourceMetadata();
/// app.MapMcp("/mcp").RequireScope("docs:read");             // what makes the gate apply
/// </code>
/// </summary>
public sealed class ResourceServerAuthenticator(Func<ClaimsPrincipal, CallerPrincipal> map)
    : IConnectorAuthenticator
{
    /// <summary>
    /// Read the standard claims: <c>preferred_username</c> then <c>sub</c> for the handle,
    /// <c>email</c> for the address, and whichever claim the authorization server puts a
    /// role in.
    /// </summary>
    /// <param name="roleClaim">
    /// Claim holding the roles. Every value is read, not the first: a JWT array claim arrives as one
    /// claim per element, and taking one of them would drop the rest where nobody would see it.
    /// Absent means the caller holds none, which is a state for the connector to interpret.
    /// </param>
    /// <param name="permissionsClaim">
    /// Claim holding what those roles stand for, space-separated. Absent means the authorization
    /// server does not publish them — not that this caller holds none — so a connector with its own
    /// role table falls back to it.
    /// </param>
    /// <param name="downstreamToken">
    /// The credential the connector writes with. An access token minted for <em>this</em>
    /// resource is not one the store upstream would accept, so a connector that needs the
    /// caller's own credential downstream has to obtain it separately — passing this token
    /// through would fail in a way that looks like the caller's fault.
    /// </param>
    public static ResourceServerAuthenticator FromClaims(
        string roleClaim = "role", string? downstreamToken = null, string permissionsClaim = "permissions") =>
        new(principal => new CallerPrincipal
        {
            Actor = principal.FindFirst("preferred_username")?.Value
                ?? principal.FindFirst("sub")?.Value
                // Not an UnauthorizedException, for the same reason as below: a token that
                // validated and carries no `sub` is the authorization server breaking its
                // contract with this one. Challenging would tell the caller to sign in again
                // for a problem that re-authenticating cannot touch.
                ?? throw new InvalidOperationException(
                    "A validated access token carried no `sub` and no `preferred_username`, so there is nobody to " +
                    "attribute this request to. The authorization server has to put an identifier in the token."),
            // Every value, not the first. `FindFirst` here was the reason the authorization server
            // stored one role for a year: it would have dropped the second and third silently, on
            // the surface furthest from anybody who could notice.
            //
            // A JWT array claim arrives as one Claim per element, so `FindAll` covers both shapes —
            // the array a multi-role server emits and the bare string an older one does.
            Roles = [.. principal.FindAll(roleClaim).Select(c => c.Value)],

            // Space-separated, the same shape as `scope`, and absent means the server does not
            // publish them rather than that this caller holds none.
            Permissions = new HashSet<string>(
                principal.FindFirst(permissionsClaim)?.Value
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    ?? [],
                StringComparer.Ordinal),
            // Parsed by the same reader the endpoint gate uses, so a connector gating a tool on
            // a scope and the middleware gating the route on one cannot disagree about what the
            // claim said. A malformed claim yields the empty set here rather than throwing: the
            // token already validated, and this is the read that decides how much authority it
            // carries — less, never more.
            Scopes = ScopeSet.TryParse(principal.FindFirst("scope")?.Value, out var granted, out _)
                ? new HashSet<string>(granted.Values, StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal),
            Email = principal.FindFirst("email")?.Value,
            DownstreamToken = downstreamToken,
            Claims = principal.Claims
                .GroupBy(c => c.Type, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal),
        });

    /// <summary>
    /// Turn a validated principal into a caller, without a request.
    /// </summary>
    /// <param name="principal">The claims a validated token carried.</param>
    /// <returns>The caller those claims describe.</returns>
    /// <remarks>
    /// The pure half of this class, public so it can be tested as one and so a connector supplying
    /// its own mapping can check it against the shipped one. Reading claims is where a resource
    /// server quietly drops half of what a token said, and that is not a thing to find out through
    /// an HTTP fixture.
    /// </remarks>
    public CallerPrincipal Map(ClaimsPrincipal principal) => map(principal);

    /// <inheritdoc />
    public Task<CallerPrincipal> AuthenticateAsync(HttpContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var token = context.GetBearerToken();
        if (token is null)
        {
            // Deliberately not an UnauthorizedException. A missing feature here does not mean
            // the caller failed to authenticate — it means the resource-server middleware
            // never gated this endpoint, so *nothing* checked the token. Answering 401 would
            // present a wiring bug as the caller's problem and leave it in production; the
            // alternative, treating the request as anonymous, would let everyone through.
            throw new InvalidOperationException(
                "No validated access token on this request. Call UseBoltwayProtectedResource() before " +
                "UseConnectorCaller(), and give the MCP endpoint a required scope — MapMcp(\"/mcp\").RequireScope(...) " +
                "— since the gate is applied per endpoint and an ungated one is never challenged.");
        }

        return Task.FromResult(map(token.Principal));
    }
}
