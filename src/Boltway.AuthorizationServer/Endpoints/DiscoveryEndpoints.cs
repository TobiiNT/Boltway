using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Metadata;
using Boltway.OAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// The discovery endpoints: E-01, E-02 and E-07, plus the 404 that protects them.
/// </summary>
/// <remarks>
/// <para>
/// These are the first three requests any client makes, and every failure mode here presents as
/// "the connector does not work" with nothing in a log to say why. Three are worth naming.
/// </para>
/// <para>
/// A global authorization fallback policy returns <c>401</c> from the discovery documents - a
/// documented and repeatedly observed real-world connector failure, hence <c>AllowAnonymous</c> on
/// every route below rather than a note in a readme.
/// </para>
/// <para>
/// A SPA fallback turns an unmatched <c>/.well-known/*</c> into <c>200 text/html</c>. MCP clients
/// probe several URLs in sequence and move on at a <c>404</c>, so an HTML 200 does not degrade
/// gracefully - it ends discovery with a parse error. Two catch-alls below claim both shapes of
/// well-known path so no later fallback can.
/// </para>
/// <para>
/// CORS headers are written by the results rather than by <c>RequireCors</c>, and that is a fix
/// rather than a style. <c>RequireCors</c> attaches metadata that the CORS <i>middleware</i> acts
/// on, and a host that never calls <c>UseCors()</c> gets
/// <c>"contains CORS metadata, but a middleware was not found"</c> - a <b>500 on every discovery
/// document</b>, while the 404 catch-all keeps working. Measured, and invisible to a test fixture
/// that happens to call <c>UseCors()</c>. Writing the one header the documents need removes the
/// dependency: these are simple cross-origin GETs, so no preflight is involved.
/// </para>
/// </remarks>
public static class DiscoveryEndpoints
{
    /// <summary>Map E-01, E-02, E-07 and the <c>/.well-known</c> catch-alls.</summary>
    public static IEndpointRouteBuilder MapOAuthDiscovery(
        this IEndpointRouteBuilder endpoints, MetadataDocument document, SigningKeyRing keyRing)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(keyRing);

        // RFC 8414 §2 and OIDC Discovery §3 both permit a superset, so these two serve the same
        // bytes from the same object.
        foreach (var path in DocumentPaths)
        {
            endpoints
                .MapMethods(path, ProbeMethods, () => Document(document))
                .AllowAnonymous()
                .WithName("boltway-discovery-" + path.Replace('/', '_'));
        }

        endpoints
            .MapMethods(AuthorizationServerPaths.Jwks, ProbeMethods, () => Jwks(keyRing))
            .AllowAnonymous()
            .WithName("boltway-jwks");

        // Both shapes of well-known path that this server does not serve.
        //
        // RFC 8414 §3.1 *inserts* the well-known segment before an issuer path
        // (/.well-known/oauth-authorization-server/tenant1), while OIDC Discovery §4.1 *appends* it
        // after (/tenant1/.well-known/openid-configuration). The two need two routes, and only the
        // insertion form was covered at first - so the appending form fell through to whatever the
        // host had, which in a SPA is 200 text/html. Measured against a realistic fixture before
        // this second route existed.
        //
        // Both answer 404 because this server requires a path-less issuer, so no issuer exists for
        // which either URL is correct. Serving the document there would break RFC 8414 §3.3 - "the
        // issuer value returned MUST be identical to the [issuer] into which the well-known URI
        // string was inserted" - and a conforming client is then required to reject what it just
        // fetched. A 404 lets it try the next probe instead of failing on a document it must not
        // trust.
        foreach (var (template, name) in NotFoundRoutes)
        {
            endpoints
                .MapMethods(template, ProbeMethods, NotFound)
                .AllowAnonymous()
                .WithName(name);
        }

        return endpoints;
    }

    private static readonly string[] ProbeMethods = ["GET", "HEAD"];

    /// <summary>
    /// The well-known paths that get a bare 404.
    /// </summary>
    /// <remarks>
    /// The appended forms are enumerated by depth because a route template cannot hold a catch-all
    /// anywhere but the end - <c>{**prefix}/.well-known/{**rest}</c> is not expressible. One and two
    /// segments is the whole reachable set: this server refuses a path-bearing issuer at startup, so
    /// its own metadata can never point a client at a deeper one, and the shapes covered here are
    /// the ones a customer or a gateway constructs by hand. A three-segment prefix would fall
    /// through to the host's fallback, which is a real limit and is why it is written down rather
    /// than left as an apparent guarantee.
    /// </remarks>
    private static readonly (string Template, string Name)[] NotFoundRoutes =
    [
        ("/.well-known/{**rest}", "boltway-wellknown-notfound"),
        ("/{t1}/.well-known/{**rest}", "boltway-wellknown-appended-1-notfound"),
        ("/{t1}/{t2}/.well-known/{**rest}", "boltway-wellknown-appended-2-notfound"),
    ];

    /// <summary>
    /// Every path that serves the discovery document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>HEAD</c> is declared explicitly rather than left to the framework's fallback, and the
    /// reason is measured. ASP.NET Core routes a HEAD request to a GET endpoint only when
    /// <i>nothing</i> handles HEAD - and the <c>/.well-known/{**rest}</c> catch-all does, so it won
    /// every HEAD probe and answered 404. The guard against one discovery failure had created
    /// another, and only a HEAD request against a running server could show it.
    /// </para>
    /// <para>
    /// The trailing-slash spellings are <b>not</b> listed. Registering them explicitly looks like
    /// belt and braces and is in fact a bug: a route template treats a trailing slash as
    /// insignificant, so <c>".../openid-configuration"</c> and <c>".../openid-configuration/"</c>
    /// are the same template, and mapping both makes every request to either an
    /// <c>AmbiguousMatchException</c> - a 500 on the first request any client makes. Measured, and
    /// one test asserts the slash variant still resolves.
    /// </para>
    /// </remarks>
    private static readonly string[] DocumentPaths =
    [
        AuthorizationServerPaths.OAuthAuthorizationServerMetadata,
        AuthorizationServerPaths.OpenIdConfiguration,
    ];

    private static CachedJsonResult Document(MetadataDocument document) =>
        new(document.Json, document.ETag, MaxAgeSeconds);

    private static CachedJsonResult Jwks(SigningKeyRing keyRing)
    {
        // Rendered per request rather than cached, because the published set changes on its own:
        // a key enters it when its publish lead time starts and leaves it when retention ends, and
        // a cache would have to be invalidated by a clock. Rendering costs a few microseconds and
        // removes the failure where a client fetches a JWKS that no longer contains the kid it
        // just saw.
        var json = Encoding.UTF8.GetBytes(JsonWebKeySet.Render(keyRing.PublishedKeys()));
        var etag = '"' + Convert.ToHexStringLower(SHA256.HashData(json)) + '"';

        return new CachedJsonResult([.. json], etag, MaxAgeSeconds);
    }

    private static WellKnownNotFoundResult NotFound() => new();

    /// <summary>
    /// Five minutes.
    /// </summary>
    /// <remarks>
    /// Claude caches discovery globally by URL with roughly a five-minute staleness window, so this
    /// matches the behaviour rather than fighting it. The consequence worth knowing: a metadata
    /// change takes about five minutes to propagate, and a transient discovery failure inside that
    /// window does not break live connections - so a failure observed there is usually not the one
    /// being chased.
    /// </remarks>
    private const int MaxAgeSeconds = 300;
}

/// <summary>Headers every discovery response carries, whatever its status.</summary>
internal static class DiscoveryHeaders
{
    /// <summary>
    /// Allow any origin to read the response.
    /// </summary>
    /// <remarks>
    /// Written directly rather than through the CORS middleware - see the remarks on
    /// <see cref="DiscoveryEndpoints"/>. Skipped when something already set it: a host running a
    /// global CORS policy would otherwise produce the header twice, and two
    /// <c>Access-Control-Allow-Origin</c> values is a CORS failure in every browser, so "helpfully"
    /// adding ours would break the case it was meant to serve.
    /// </remarks>
    internal static void AllowAnyOrigin(HttpResponse response)
    {
        if (!response.Headers.ContainsKey(HeaderNames.AccessControlAllowOrigin))
        {
            response.Headers[HeaderNames.AccessControlAllowOrigin] = "*";
        }
    }
}

/// <summary>A JSON body with a strong ETag and a conditional-GET short circuit.</summary>
internal sealed class CachedJsonResult(ImmutableArray<byte> json, string etag, int maxAgeSeconds) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var response = httpContext.Response;
        DiscoveryHeaders.AllowAnyOrigin(response);
        response.Headers.ETag = etag;
        response.Headers.CacheControl = $"public, max-age={maxAgeSeconds}";

        if (Matches(httpContext.Request.Headers[HeaderNames.IfNoneMatch], etag))
        {
            response.StatusCode = StatusCodes.Status304NotModified;
            return;
        }

        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "application/json";
        response.ContentLength = json.Length;

        // HEAD is answered by this same endpoint, and writing a body to a HEAD response is a
        // protocol error the framework hides by discarding it. Returning early makes the
        // Content-Length above the whole answer, which is what a probe issuing HEAD is asking for.
        if (HttpMethods.IsHead(httpContext.Request.Method))
        {
            return;
        }

        json.AsSpan().CopyTo(response.BodyWriter.GetSpan(json.Length));
        response.BodyWriter.Advance(json.Length);
        await response.BodyWriter.FlushAsync(httpContext.RequestAborted);
    }

    /// <summary>
    /// RFC 9110 §13.1.2 <c>If-None-Match</c> matching, for a strong validator.
    /// </summary>
    /// <remarks>
    /// The header is a comma-separated <i>list</i>, and it may arrive either as several header
    /// lines or as one line carrying several tags. Comparing each whole header value against the
    /// tag handles the first and silently fails the second - a client sending
    /// <c>If-None-Match: "a", "b"</c> would be answered 200 with a full body every time.
    /// Splitting covers both spellings.
    /// </remarks>
    private static bool Matches(StringValues ifNoneMatch, string etag)
    {
        foreach (var header in ifNoneMatch)
        {
            if (header is null)
            {
                continue;
            }

            foreach (var range in header.AsSpan().Split(','))
            {
                var candidate = header.AsSpan()[range].Trim();

                // A weak tag never matches a strong validator, and it is not stripped to make it
                // match: `W/"x"` is a promise about semantic equivalence, and this resource's tag
                // is a promise about bytes.
                if (candidate.SequenceEqual("*") || candidate.SequenceEqual(etag))
                {
                    return true;
                }
            }
        }

        return false;
    }
}

/// <summary>A bare 404 for an unmatched well-known path.</summary>
/// <remarks>
/// No body, no HTML, and <c>no-store</c> so a client that later fixes its configuration is not
/// served this from a cache. An MCP client probes sequentially and moves on at a 404; anything
/// richer than this risks being parsed.
/// </remarks>
internal sealed class WellKnownNotFoundResult : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        // The 404 is CORS-readable too. A browser-based prober that cannot read the status sees a
        // network error instead, which is a different diagnosis from "this server does not serve
        // that document".
        DiscoveryHeaders.AllowAnyOrigin(httpContext.Response);
        httpContext.Response.StatusCode = StatusCodes.Status404NotFound;
        httpContext.Response.Headers.CacheControl = "no-store";
        httpContext.Response.ContentLength = 0;

        return Task.CompletedTask;
    }
}
