using System.Collections.Concurrent;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// Re-serves a client's <c>logo_uri</c> from this origin, so the consent page never hotlinks it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a proxy at all.</b> A client's <c>logo_uri</c> is a URL the client chose. Pointing an
/// <c>&lt;img&gt;</c> at it would tell whoever hosts it who is looking at a consent page for which
/// application and when — a disclosure the user never agreed to and cannot see. <c>N-14</c> says
/// proxy rather than hotlink, and the page's <c>default-src 'self'</c> enforces it whether or not
/// the renderer remembers.
/// </para>
/// <para>
/// <b>What this is not.</b> It is not verification. Anyone can publish a logo at their own URL, the
/// same way anyone can publish <c>{"client_name":"Claude"}</c>, so an image served from here is a
/// self-assertion that has been re-hosted and nothing more. The renderer's job is to keep it inside
/// the sentence that says so; this file's job is to make sure the bytes cannot hurt anybody.
/// </para>
/// <para>
/// <b>The rule that matters most here is the one about SVG.</b> An SVG can carry script, and script
/// in a document served from this origin runs with this origin's cookies — the session that is
/// mid-authorization. In an <c>&lt;img&gt;</c> it would not execute, but nothing stops somebody
/// opening this URL directly, and then it is a document. So the accepted set is raster only, the
/// declared type has to match the bytes, and the response carries <c>nosniff</c> and a policy of
/// its own. Refusing SVG costs a few clients a logo; serving one costs the origin.
/// </para>
/// </remarks>
public static class ClientLogoEndpoint
{
    /// <summary>
    /// How much of a logo is worth reading, in bytes.
    /// </summary>
    /// <remarks>
    /// A cap on bytes <i>read</i>, not on a declared <c>Content-Length</c>, which is
    /// <see cref="SafeFetchRequest"/>'s own distinction and the reason a lying header cannot spend
    /// this server's memory. 64 KB is generous for an icon and small enough that a few hundred
    /// cached ones are not a leak.
    /// </remarks>
    public const int MaxBytes = 64 * 1024;

    /// <summary>How long a fetched logo is served before it is fetched again.</summary>
    /// <remarks>
    /// The remote <c>Cache-Control</c> is respected within this bound rather than trusted: a host
    /// answering <c>max-age=0</c> would otherwise make every consent-page view an outbound request,
    /// which is the timing disclosure the proxy exists to prevent, arriving by the back door.
    /// </remarks>
    public static readonly TimeSpan CacheFor = TimeSpan.FromHours(6);

    /// <summary>How many clients' logos are held at once.</summary>
    public const int MaxCached = 256;

    /// <summary>
    /// The types served, and the bytes each has to start with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Raster only, and matched against the body rather than believed from the header. A host can
    /// declare <c>image/png</c> and serve anything; with <c>nosniff</c> on the way out a browser
    /// would refuse to render the mismatch rather than execute it, so this check is the second
    /// line — but it is the one that turns "the browser declined to show a logo" into "this server
    /// never stored it".
    /// </para>
    /// <para>
    /// <b>No <c>image/svg+xml</c>, and that absence is the point of the list.</b> See the type's
    /// remarks. There is no configuration to add it, deliberately: a deployment that wanted it would
    /// be turning one client's document into script on this origin.
    /// </para>
    /// </remarks>
    private static readonly (string SubType, byte[] Magic)[] Accepted =
    [
        ("png", [0x89, 0x50, 0x4E, 0x47]),
        ("jpeg", [0xFF, 0xD8, 0xFF]),
        ("gif", [0x47, 0x49, 0x46, 0x38]),

        // WebP is RIFF....WEBP: the four bytes at offset 8 are what separate it from every other
        // RIFF container, and they are checked below rather than here because this table compares
        // prefixes.
        ("webp", [0x52, 0x49, 0x46, 0x46]),
    ];

    private static readonly ConcurrentDictionary<string, Entry> Cache = new(StringComparer.Ordinal);

    /// <summary>Map <c>GET /client-logo</c>.</summary>
    public static IEndpointRouteBuilder MapClientLogo(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet(AuthorizationServerPaths.ClientLogo, GetAsync)
            .AllowAnonymous().WithName("boltway-client-logo");

        return endpoints;
    }

    /// <summary>How many logos are cached. For the tests.</summary>
    internal static int CachedCount => Cache.Count;

    /// <summary>Empty the cache. For the tests, which must not share one.</summary>
    internal static void Forget() => Cache.Clear();

    /// <summary>
    /// The image, or nothing.
    /// </summary>
    /// <remarks>
    /// <b>Every failure is the same 404.</b> A client with no logo, a client that does not resolve,
    /// a host that timed out and a body that was not an image all answer identically, because the
    /// alternative is an endpoint that reports on other people's infrastructure to anonymous
    /// callers: "this client_id exists but its logo host is down" is a fact about somebody else's
    /// deployment, offered to whoever asks. The page it serves degrades to no image either way.
    /// </remarks>
    private static async Task<IResult> GetAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (!http.Request.Query.TryGetValue("client_id", out var raw)
            || !ClientIdentifier.TryParseFromRequest(raw.ToString(), out var clientId))
        {
            return Results.NotFound();
        }

        var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();

        if (Cache.TryGetValue(clientId.Value, out var cached) && now < cached.ExpiresAt)
        {
            return Serve(cached);
        }

        // The same walk /authorize makes, so a logo is only ever served for a client this server
        // would actually have shown a consent page for. It resolves rather than reading a store
        // because the CIMD path has no store — A-08 — and the resolver's own cache means the usual
        // case, an image request arriving moments after the page that names it, makes no outbound
        // request of its own.
        var client = await ResolveAsync(http.RequestServices, clientId, cancellationToken);

        if (client?.LogoUri is not { Length: > 0 } logo
            || !AbsoluteHttpsUrl.TryCreate(logo, out var url))
        {
            return Results.NotFound();
        }

        var fetcher = http.RequestServices.GetService<ISafeHttpFetcher>();

        if (fetcher is null)
        {
            // A deployment that registered no fetcher has no CIMD either. Nothing to serve, and
            // nothing worth saying about it to an anonymous caller.
            return Results.NotFound();
        }

        var outcome = await fetcher.FetchAsync(
            new SafeFetchRequest(url, FetchPurpose.LogoUri, MaxBytes), cancellationToken);

        if (outcome is not FetchOutcome.Ok ok || !TryAccept(ok, out var type))
        {
            return Results.NotFound();
        }

        var entry = new Entry(ok.Body, type, now + Bounded(ok.MaxAge));

        Cache[clientId.Value] = entry;
        Evict();

        return Serve(entry);
    }

    /// <summary>The first resolver that answers, in the order the pipeline uses.</summary>
    private static async ValueTask<ClientRecord?> ResolveAsync(
        IServiceProvider services, ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        foreach (var resolver in services.GetServices<IClientResolver>())
        {
            if (!resolver.CanResolve(clientId))
            {
                continue;
            }

            var resolution = await resolver.ResolveAsync(clientId, cancellationToken);

            if (resolution.Client is { } client)
            {
                return client;
            }
        }

        return null;
    }

    /// <summary>
    /// Whether this body is one of the four, and what to call it on the way out.
    /// </summary>
    /// <remarks>
    /// The declared type has to be in the list <b>and</b> the bytes have to match it. Either alone
    /// is weaker than it looks: believing the header serves whatever a host sends under an
    /// <c>image/png</c> label, and sniffing alone re-labels a body the host called something else,
    /// which is this server deciding what somebody else's file is.
    /// </remarks>
    private static bool TryAccept(FetchOutcome.Ok ok, out string type)
    {
        type = string.Empty;

        // `MediaType` lowercases both halves when it parses, so these are ordinal comparisons
        // against values that have already been normalised rather than a case-insensitive guess.
        if (!string.Equals(ok.ContentType.Type, "image", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var (subType, magic) in Accepted)
        {
            if (!string.Equals(ok.ContentType.SubType, subType, StringComparison.Ordinal))
            {
                continue;
            }

            if (ok.Body.Length < magic.Length || !ok.Body.AsSpan(0, magic.Length).SequenceEqual(magic))
            {
                return false;
            }

            // RIFF is a container: AVI and WAV start with the same four bytes. Without this, a .wav
            // served as image/webp would be cached and handed back to a browser as an image.
            if (subType == "webp"
                && (ok.Body.Length < 12 || !ok.Body.AsSpan(8, 4).SequenceEqual("WEBP"u8)))
            {
                return false;
            }

            type = "image/" + subType;
            return true;
        }

        return false;
    }

    /// <summary>The remote's own freshness, kept inside this server's bounds.</summary>
    private static TimeSpan Bounded(TimeSpan? maxAge) =>
        maxAge is { } age && age > TimeSpan.Zero && age < CacheFor ? age : CacheFor;

    /// <summary>
    /// The bytes, with the headers that keep them inert.
    /// </summary>
    /// <remarks>
    /// <c>nosniff</c> so a browser renders it as the type declared here rather than as whatever it
    /// guesses, and a policy of its own so that a body that somehow reaches a document context
    /// loads nothing and runs nothing. Neither is the primary control — the accepted-types check
    /// is — and both are here because the primary control is the one that will be edited.
    /// </remarks>
    private static LogoResult Serve(Entry entry) => new(entry);

    /// <summary>Keep the cache bounded, oldest expiry first.</summary>
    private static void Evict()
    {
        if (Cache.Count <= MaxCached)
        {
            return;
        }

        foreach (var pair in Cache.OrderBy(e => e.Value.ExpiresAt).Take(Cache.Count - MaxCached))
        {
            _ = Cache.TryRemove(pair);
        }
    }

    /// <summary>One client's logo, as it will be served.</summary>
    internal sealed record Entry(byte[] Body, string ContentType, DateTimeOffset ExpiresAt);

    /// <summary>The result type, so the headers are written in one place.</summary>
    private sealed class LogoResult(Entry entry) : IResult
    {
        public async Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);

            var response = httpContext.Response;

            response.ContentType = entry.ContentType;
            response.ContentLength = entry.Body.Length;
            response.Headers["X-Content-Type-Options"] = "nosniff";
            response.Headers["Content-Security-Policy"] = "default-src 'none'; sandbox";
            response.Headers.CacheControl = "private, max-age=300";

            await response.Body.WriteAsync(entry.Body, httpContext.RequestAborted);
        }
    }
}
