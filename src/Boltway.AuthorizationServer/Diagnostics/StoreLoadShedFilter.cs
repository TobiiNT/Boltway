using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>
/// Turns a store that cannot be reached into a load-shed, for a whole group of routes. X-43.
/// </summary>
/// <remarks>
/// <para>
/// <b>A filter rather than a <c>catch</c> in each handler, and rather than middleware.</b> The
/// protocol endpoints each hold their own <c>catch</c> because each had one thing to decide:
/// <c>/authorize</c> re-codes an existing boundary, <c>/token</c> wraps one exchange. These do not.
/// There are forty-odd of them across six files, every one answers the same way, and forty copies of
/// a <c>catch</c> is forty chances for the next route to be added without one - which is the shape
/// A-09 was found in and the reason this server has a chokepoint at all.
/// </para>
/// <para>
/// <b>It is not the second response writer the architecture rule forbids.</b> A filter returns an
/// <see cref="IResult"/> and the framework executes it, so the response is still written by
/// <see cref="RejectionResult.ExecuteAsync"/> - logged, counted and stamped by the same code as
/// every 400. Middleware would have to write a status itself, which is the difference. The rule is
/// about who writes, not about where the <c>catch</c> sits.
/// </para>
/// <para>
/// <b>A response that has already started is rethrown, not answered.</b> The same call
/// <c>AuthorizeEndpoint</c>'s boundary makes and for the same reason: bytes are on the wire, so a
/// second write either fails or produces a body the caller cannot parse. Letting the host abort the
/// connection is the only honest outcome, and it is rarer than it looks here - these handlers build
/// their response and return it rather than streaming.
/// </para>
/// </remarks>
/// <param name="surface">Which surface to record. Decides nothing about the response.</param>
/// <param name="rendered">
/// Whether the caller is a person. <see langword="true"/> renders the deployment's error page;
/// <see langword="false"/> answers the status alone, which is what a script in a page needs and all
/// it can use. The two are separate arguments rather than derived from the surface so that a route
/// group can be moved without silently changing what its callers receive.
/// </param>
internal sealed class StoreLoadShedFilter(OAuthSurface surface, bool rendered) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        try
        {
            return await next(context);
        }
        catch (Exception unreachable)
            when (TransientStoreFailure.Describes(unreachable) && !context.HttpContext.Response.HasStarted)
        {
            return rendered
                ? StoreLoadShed.Page(context.HttpContext, surface, unreachable)
                : StoreLoadShed.Answer(context.HttpContext, surface, unreachable);
        }
    }
}

/// <summary>Attaching the filter to a group of routes.</summary>
internal static class StoreLoadShedRoutes
{
    /// <summary>
    /// A group carrying no prefix and one filter, so every route mapped into it sheds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The empty prefix is the point: this adds a behaviour to a set of routes without moving any of
    /// them, so the paths in <c>AuthorizationServerPaths</c> stay the paths that are served and
    /// nothing about routing changes. What the group buys is that the behaviour is declared once,
    /// where the routes are mapped, rather than remembered forty times.
    /// </para>
    /// <para>
    /// Declared at the top of each <c>MapX</c> method rather than centrally, because which answer a
    /// surface owes its caller is a fact about that surface. A central table of route-group to
    /// answer-shape would be the same decision moved away from the only place it can be checked
    /// against what the handlers actually return.
    /// </para>
    /// </remarks>
    /// <param name="endpoints">The builder the routes would otherwise be mapped onto.</param>
    /// <param name="surface">Which surface to record on the log line.</param>
    /// <param name="rendered">Whether these routes answer a person or a script. See the filter.</param>
    internal static RouteGroupBuilder ShedsOnStoreFailure(
        this IEndpointRouteBuilder endpoints, OAuthSurface surface, bool rendered)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup(string.Empty);

        group.AddEndpointFilter(new StoreLoadShedFilter(surface, rendered));

        return group;
    }
}
