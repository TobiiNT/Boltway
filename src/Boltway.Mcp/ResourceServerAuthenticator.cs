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
/// and the scopes, and it writes the 401 - the one that carries the vendor-researched
/// challenge shape. A second authenticator producing a second 401 is exactly the
/// duplication this library exists to prevent, so this one only reads what that middleware
/// left behind.
/// </para>
///
/// <para>
/// Wire it after the resource-server middleware:
/// </para>
///
/// <code>
/// app.UseRouting();
/// app.UseBoltwayProtectedResource();          // validates, and owns the 401
/// app.UseConnectorCaller("/mcp", bindState);  // maps the result onto the caller
/// app.MapProtectedResourceMetadata();
/// app.MapMcp("/mcp").RequireBearer();         // gated, and no required scope - see below
/// </code>
///
/// <para>
/// <b><c>RequireBearer()</c>, not <c>RequireScope(...)</c>, and the difference is not a
/// preference.</b> For a release the last line of this example ended in <c>RequireScope</c>
/// instead, annotated "what makes the gate apply". It does not: one MCP endpoint carries every
/// tool, so a scope required there is the intersection of what the tools need - see
/// <see cref="CallerPrincipal.Scopes"/>, which says the same thing from the other side.
/// </para>
///
/// <para>
/// The expensive half is what it does instead. <c>RequireScope</c> declares two things at once, and
/// the second is the one nobody expects: it also fills the <c>scope</c> parameter of the <c>401</c>
/// challenge, and the MCP scope-selection strategy reads that <em>before</em> the metadata
/// document. So naming one scope there tells every client to ask for that scope <em>and nothing
/// else</em>, for the whole server. A connector that did this advertised a second scope in both
/// RFC 9728 documents, showed it on its consent screen and enforced it in its tools, and no token
/// its authorization server ever minted carried it - reads worked, health was green, and it
/// surfaced only when the tools began enforcing, at which point every write stopped at once and
/// re-consenting could not help.
/// </para>
///
/// <para>
/// Naming both scopes is not the fix either: <c>RequireScope</c> requires <em>every</em> scope
/// listed, so a genuine read-only grant would be refused its reads. Declare none, leave the
/// challenge carrying the resource's whole <c>ScopesSupported</c>, and gate each tool on
/// <see cref="CallerPrincipal.Grants"/> - which is the only place a single endpoint can make a
/// per-tool decision anyway.
/// </para>
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
    /// server does not publish them - not that this caller holds none - so a connector with its own
    /// role table falls back to it.
    /// </param>
    /// <param name="downstreamToken">
    /// The credential the connector writes with. An access token minted for <em>this</em>
    /// resource is not one the store upstream would accept, so a connector that needs the
    /// caller's own credential downstream has to obtain it separately - passing this token
    /// through would fail in a way that looks like the caller's fault.
    /// </param>
    public static ResourceServerAuthenticator FromClaims(
        string roleClaim = "role", string? downstreamToken = null, string permissionsClaim = "permissions") =>
        new(principal =>
        {
            // Read once, and keep both halves of the answer. The claim's *presence* and its
            // *readability* are two different facts, and the parse below throws the first away -
            // it returns the same empty set for a claim that granted nothing, a claim that could
            // not be read, and no claim at all. A connector cannot recover the difference
            // afterwards, so it is recorded here where it is still known.
            var scopeClaim = principal.FindFirst("scope")?.Value;
            var readable = ScopeSet.TryParse(scopeClaim, out var granted, out _);

            return new CallerPrincipal
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
            // A JWT array claim arrives as one Claim per element, so `FindAll` covers both shapes -
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
            // carries - less, never more.
            //
            // "Less, never more" holds for this property and stopped holding one call further out,
            // which is what ScopeClaim below is for: a connector falling back on an empty set
            // grants more than the token said whenever the emptiness came from a claim it could
            // not read.
            Scopes = readable
                ? new HashSet<string>(granted.Values, StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal),

            // Absent beats readability: TryParse answers true for null, so the null check has to
            // come first or a token with no claim at all would be reported as one that granted
            // nothing - the refusal, instead of the fall-back.
            ScopeClaim = scopeClaim is null
                ? ScopeClaimState.Absent
                : readable ? ScopeClaimState.Readable : ScopeClaimState.Unreadable,
            Email = principal.FindFirst("email")?.Value,

            // Read as properties rather than left for a connector to pull out of Claims by string
            // key: every one is the same lookup, and a key typed wrong there is silently null on
            // the surface whose whole job is saying who did what.
            //
            // Verbatim, all three. ClientId in particular reaches a consumer's commit history, so
            // anything this reader tidied would rewrite what that history means.
            ClientId = principal.FindFirst("client_id")?.Value,
            TokenId = principal.FindFirst("jti")?.Value,
            GrantId = principal.FindFirst("gid")?.Value,

            DownstreamToken = downstreamToken,
            Claims = principal.Claims
                .GroupBy(c => c.Type, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal),
            };
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
            // the caller failed to authenticate - it means the resource-server middleware
            // never gated this endpoint, so *nothing* checked the token. Answering 401 would
            // present a wiring bug as the caller's problem and leave it in production; the
            // alternative, treating the request as anonymous, would let everyone through.
            throw new InvalidOperationException(
                "No validated access token on this request. Call UseBoltwayProtectedResource() before " +
                "UseConnectorCaller(), and gate the MCP endpoint — MapMcp(\"/mcp\").RequireBearer() — since " +
                "an endpoint the bearer middleware does not gate is never challenged. Use RequireBearer " +
                "rather than RequireScope: a required scope on an MCP route also fills the 401 challenge's " +
                "`scope`, which tells every client to ask for that and nothing else. See the remarks on " +
                "ResourceServerAuthenticator.");
        }

        return Task.FromResult(map(token.Principal));
    }
}
