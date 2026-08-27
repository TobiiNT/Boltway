using System.Collections.Immutable;
using Boltway.ResourceServer.Configuration;
using Boltway.ResourceServer.Metadata;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Boltway.ResourceServer.Endpoints;

/// <summary>
/// E-22 and E-23: the RFC 9728 metadata document, at both shapes a client probes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Which one is normative.</b> RFC 9728 §3.1 <i>inserts</i> the well-known segment between the
/// host and the path, so for a resource identified as <c>https://mcp.example.com/mcp</c> the
/// normative URL is <c>https://mcp.example.com/.well-known/oauth-protected-resource/mcp</c>. That
/// is E-23, it is the URL every challenge from this server points at, and it is the only one whose
/// §3.3 identity check succeeds for a path-bearing resource.
/// </para>
/// <para>
/// <b>Which one is the compatibility probe.</b> E-22, the root form, is normative only when the
/// resource identifier has no path at all. It is served regardless because it is what Claude falls
/// back to when a challenge carries no <c>resource_metadata</c> (it probes the path-inserted form
/// first, then this one), and because OpenAI's documentation shows only this shape. A client
/// applying §3.3 strictly will fetch this, find a <c>resource</c> that is not the identifier it
/// inserted into, and discard it; that is the specified behaviour and it is why the root form is a
/// fallback rather than the answer.
/// </para>
/// <para>
/// <b>U-01 is closed, and the answer is the opposite of what the documentation implied.</b> This
/// used to record "whether ChatGPT ever probes the path-inserted form is unverified", reasoning
/// from OpenAI's docs showing only the root shape. Measured 2026-08-17 against a live ChatGPT
/// connector linking to a deployment: it fetched
/// <c>/.well-known/oauth-protected-resource/mcp</c> twice, from <c>Python/3.12 aiohttp/3.13.5</c>,
/// and requested the root form <b>zero</b> times. So the path-inserted form is not the one in
/// doubt — it is the one ChatGPT actually uses, and a server that served only the shape OpenAI
/// documents would fail every ChatGPT connection. Serving both still costs one route; what changed
/// is which of the two is load-bearing.
/// </para>
/// <para>
/// <b>CORS is written by hand, not by <c>RequireCors</c>.</b> This is a fix rather than a style.
/// <c>RequireCors</c> attaches metadata that the CORS <i>middleware</i> acts on, and a host that
/// never calls <c>UseCors()</c> gets "contains CORS metadata, but a middleware was not found" — a
/// <b>500 on the discovery document</b>, which is the one response that must work before anything
/// else can. It is measured on the authorization-server side and invisible to any test fixture that
/// happens to call <c>UseCors()</c>. These are simple cross-origin GETs, so no preflight is
/// involved and one response header is the whole requirement.
/// </para>
/// <para>
/// <b>Anonymous, explicitly.</b> A global authorization fallback policy that 401s the metadata
/// document deadlocks the entire flow — the client cannot discover where to authenticate because
/// discovering that requires authenticating — and it is a repeatedly observed real-world connector
/// failure. <c>AllowAnonymous</c> here is also what this server's own bearer middleware keys off.
/// </para>
/// <para>
/// <b>And <c>AllowAnonymous</c> is only <i>this</i> pipeline's word for it.</b> A host that runs
/// authentication of its own alongside this library — an MCP connector with its own caller model is
/// the common shape — has a second vocabulary for "no credential needed", and neither middleware
/// reads the other's. The endpoints below carry the framework's marker; a host middleware keyed on
/// its own marker refuses them, and the symptom is a client that cannot discover where to
/// authenticate while every other route behaves. <b>Measured on a real deployment on 2026-08-26</b>:
/// both well-known forms answering <c>401</c>, keys fetched, tokens validating, and a suite of 402
/// unit tests green — because none of them is about a pipeline.
/// </para>
/// <para>
/// So a host with its own authentication middleware marks these endpoints in <i>its</i> vocabulary
/// too. Mapping them inside a route group and putting that marker on the group covers whatever this
/// package maps here, including anything a later version adds, and covers nothing else.
/// <c>Boltway.ResourceServer.Testing</c>'s <c>ProtectedResourceContract</c> is this paragraph as a
/// test a deployment can run against its own wiring.
/// </para>
/// </remarks>
public static class ProtectedResourceMetadataEndpoints
{
    private static readonly string[] ProbeMethods = ["GET", "HEAD"];

    /// <summary>
    /// One hour.
    /// </summary>
    /// <remarks>
    /// RFC 9728 §7.10 asks for caching directives on this document and the research distillation
    /// settles on an hour. It is longer than the authorization server's five minutes on purpose:
    /// that number tracks Claude's ~5-minute global discovery cache so a metadata change propagates
    /// predictably, whereas this document names a resource whose identifier and authorization
    /// server are deployment constants. A conditional GET makes the difference cheap anyway.
    /// </remarks>
    private const int MaxAgeSeconds = 3600;

    /// <summary>Map E-22 and E-23.</summary>
    public static IEndpointRouteBuilder MapProtectedResourceMetadata(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var resource = endpoints.ServiceProvider.GetRequiredService<ProtectedResource>();

        // E-22, the root form.
        endpoints
            .MapMethods(WellKnownResourceUri.Suffix, ProbeMethods, () => Document(resource))
            .AllowAnonymous()
            .WithName("boltway-prm-root");

        // E-23, the path-inserted form. A catch-all is mandatory: a plain route for the suffix
        // alone 404s the "/mcp" variant, which is the URL a conformant client constructs first and
        // the one this server's own challenges point at.
        //
        // The catch-all matches every suffix and then checks it, rather than being registered at
        // the one path this resource occupies. Two reasons, and both are about what a client does
        // next. A path this server does not serve gets a bare 404, so a client moves on to its next
        // probe instead of parsing whatever a SPA fallback would have returned; and a 404 is a
        // better answer than a 200 carrying another resource's document, which §3.3 requires the
        // client to discard anyway — with the difference that a discarded 200 usually ends
        // discovery while a 404 does not.
        endpoints
            .MapMethods(WellKnownResourceUri.Suffix + "/{*rest}", ProbeMethods, (HttpContext context) =>
                PathMatchesThisResource(context, resource)
                    ? Document(resource)
                    : (IResult)NotFound())
            .AllowAnonymous()
            .WithName("boltway-prm-inserted");

        return endpoints;
    }

    /// <summary>
    /// Whether the requested path is the one this resource's identifier inserts to.
    /// </summary>
    /// <remarks>
    /// Ordinal, on <see cref="HttpRequest.Path"/>, which ASP.NET Core has already decoded once —
    /// the same decoding a client's own URL went through. No normalization beyond that: RFC 9728 §6
    /// forbids it, and a trailing slash is a different resource identifier, so
    /// <c>/.well-known/oauth-protected-resource/mcp/</c> is not this resource unless the configured
    /// identifier ends in one too.
    /// </remarks>
    private static bool PathMatchesThisResource(HttpContext context, ProtectedResource resource) =>
        string.Equals(context.Request.Path.Value, resource.MetadataPath, StringComparison.Ordinal);

    private static CachedJsonResult Document(ProtectedResource resource) =>
        new(resource.Json, resource.ETag, MaxAgeSeconds);

    private static WellKnownNotFoundResult NotFound() => new();
}

/// <summary>Headers every metadata response carries, whatever its status.</summary>
internal static class MetadataHeaders
{
    /// <summary>
    /// Allow any origin to read the response.
    /// </summary>
    /// <remarks>
    /// Skipped when something already set it. A host running a global CORS policy would otherwise
    /// produce the header twice, and two <c>Access-Control-Allow-Origin</c> values is a CORS failure
    /// in every browser — so "helpfully" adding ours would break exactly the case it was meant to
    /// serve.
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
        MetadataHeaders.AllowAnyOrigin(response);
        response.Headers.ETag = etag;
        response.Headers.CacheControl = $"public, max-age={maxAgeSeconds}";

        if (Matches(httpContext.Request.Headers[HeaderNames.IfNoneMatch], etag))
        {
            response.StatusCode = StatusCodes.Status304NotModified;
            return;
        }

        response.StatusCode = StatusCodes.Status200OK;

        // Exactly "application/json". RFC 9728 §3.2 requires it, and the observed intolerance is
        // for `text/json` and `text/plain` rather than for a charset parameter — but there is
        // nothing to gain by adding one, so none is added.
        response.ContentType = "application/json";
        response.ContentLength = json.Length;

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
    /// <para>
    /// The header is a comma-separated <i>list</i>, and it may arrive either as several header lines
    /// or as one line carrying several tags. Comparing each whole header value against the tag
    /// handles the first and silently fails the second, so a client sending
    /// <c>If-None-Match: "a", "b"</c> would be answered <c>200</c> with a full body every time.
    /// </para>
    /// <para>
    /// <c>internal</c> rather than <c>private</c> so a test can reach it, and that is not a
    /// convenience. <b>Measured:</b> an HTTP-level test cannot exercise the one-line spelling at
    /// all — <c>If-None-Match</c> is a known header, so <c>HttpClient</c> parses the list and hands
    /// the server two header values before the request leaves the process. A test driven through
    /// the client passes whether this splits on commas, splits on spaces, or does not split at
    /// all, which is to say it proves nothing about the line it is pointed at.
    /// </para>
    /// </remarks>
    internal static bool Matches(StringValues ifNoneMatch, string etag)
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
                // match: `W/"x"` promises semantic equivalence, and this resource's tag promises
                // bytes.
                if (candidate.SequenceEqual("*") || candidate.SequenceEqual(etag))
                {
                    return true;
                }
            }
        }

        return false;
    }
}

/// <summary>A bare 404 for a well-known path this resource does not occupy.</summary>
/// <remarks>
/// No body and <c>no-store</c>, so a client that later fixes its configuration is not served this
/// from a cache. An MCP client probes sequentially and moves on at a 404; anything richer risks
/// being parsed.
/// </remarks>
internal sealed class WellKnownNotFoundResult : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        // Readable cross-origin too: a browser-based prober that cannot read the status sees a
        // network error instead, which is a different diagnosis from "this server does not serve
        // that document".
        MetadataHeaders.AllowAnyOrigin(httpContext.Response);
        httpContext.Response.StatusCode = StatusCodes.Status404NotFound;
        httpContext.Response.Headers.CacheControl = "no-store";
        httpContext.Response.ContentLength = 0;

        return Task.CompletedTask;
    }
}
