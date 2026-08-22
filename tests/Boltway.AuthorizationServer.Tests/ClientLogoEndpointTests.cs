using System.Net;
using System.Text;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The logo proxy: what it will re-serve, and everything it will not.
/// </summary>
/// <remarks>
/// <para>
/// The endpoint exists so that the consent page never hotlinks a client's <c>logo_uri</c> — that
/// would tell whoever hosts the image who is looking at a consent page for which application and
/// when. Re-serving somebody else's bytes from this origin buys that privacy and takes on a
/// different risk, and these tests are about the second half.
/// </para>
/// <para>
/// <b>The SVG row is the one to keep.</b> An SVG can carry script; served from this origin and
/// opened directly it is a document, and that script runs with this origin's cookies — the session
/// that is part-way through an authorization. Every other refusal here is hygiene next to that one.
/// </para>
/// </remarks>
public sealed class ClientLogoEndpointTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string Logo = "https://cdn.example/logo.png";

    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];

    /// <summary>A client that published a logo, and a fetcher that answers for it.</summary>
    private static async Task<FlowFixture> FixtureAsync(FetchOutcome answer)
    {
        // Cleared per fixture: the cache is process-wide, so a test that seeded one body would
        // otherwise decide what the next test sees.
        ClientLogoEndpoint.Forget();

        return await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public) with { LogoUri = Logo };
            seed.Fetcher = new StubFetcher().Respond(Logo, answer);
        });
    }

    private static FetchOutcome.Ok Body(byte[] bytes, string contentType)
    {
        _ = MediaType.TryParse(contentType, out var parsed);
        return new FetchOutcome.Ok(bytes, parsed, ETag: null, MaxAge: null);
    }

    private static string Url(string clientId = ClientId) =>
        "/client-logo?client_id=" + Uri.EscapeDataString(clientId);

    /// <summary>A PNG the host declared as a PNG is re-served, from this origin.</summary>
    [Fact]
    public async Task A_png_is_served_back()
    {
        await using var fixture = await FixtureAsync(Body(Png, "image/png"));

        var response = await fixture.Client.GetAsync(Url());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("image/png", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(Png, await response.Content.ReadAsByteArrayAsync());
    }

    /// <summary>
    /// The response cannot become a document, whatever the bytes turn out to be.
    /// </summary>
    /// <remarks>
    /// <c>nosniff</c> so the browser renders it as the type declared here rather than as whatever it
    /// guesses from the body, and a policy of its own so that a body reaching a document context
    /// loads nothing and runs nothing. Both are defence behind the accepted-types check, and both
    /// are asserted because the check is the part that will be edited.
    /// </remarks>
    [Fact]
    public async Task The_response_carries_headers_that_keep_it_inert()
    {
        await using var fixture = await FixtureAsync(Body(Png, "image/png"));

        var response = await fixture.Client.GetAsync(Url());

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());

        var policy = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("default-src 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("sandbox", policy, StringComparison.Ordinal);
    }

    /// <summary>
    /// An SVG is refused, however it is labelled.
    /// </summary>
    /// <remarks>
    /// Both rows are the same attack arriving by different doors: declared as SVG, and declared as a
    /// PNG so that a type check alone would pass it. The second is why the bytes are compared
    /// against the declared type rather than the header being believed.
    /// </remarks>
    [Theory]
    [InlineData("image/svg+xml")]
    [InlineData("image/png")]
    public async Task An_svg_is_never_re_served(string declaredAs)
    {
        var svg = Encoding.UTF8.GetBytes(
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.cookie)</script></svg>");

        await using var fixture = await FixtureAsync(Body(svg, declaredAs));

        Assert.Equal(HttpStatusCode.NotFound, (await fixture.Client.GetAsync(Url())).StatusCode);
    }

    /// <summary>HTML declared as an image is refused on the same rule.</summary>
    [Fact]
    public async Task Html_wearing_an_image_content_type_is_refused()
    {
        var html = Encoding.UTF8.GetBytes("<!DOCTYPE html><script>alert(1)</script>");

        await using var fixture = await FixtureAsync(Body(html, "image/png"));

        Assert.Equal(HttpStatusCode.NotFound, (await fixture.Client.GetAsync(Url())).StatusCode);
    }

    /// <summary>
    /// A RIFF container that is not WebP is refused.
    /// </summary>
    /// <remarks>
    /// WAV and AVI open with the same four bytes as WebP, so a prefix check alone accepts them. Not
    /// dangerous in the way an SVG is — it is the case that shows the magic check is a real check
    /// rather than four bytes that happened to line up.
    /// </remarks>
    [Fact]
    public async Task A_riff_container_that_is_not_webp_is_refused()
    {
        var wav = Encoding.UTF8.GetBytes("RIFF____WAVEfmt ");

        await using var fixture = await FixtureAsync(Body(wav, "image/webp"));

        Assert.Equal(HttpStatusCode.NotFound, (await fixture.Client.GetAsync(Url())).StatusCode);
    }

    /// <summary>
    /// Everything that is not a served image is the same 404.
    /// </summary>
    /// <remarks>
    /// A client with no logo, an identifier nothing resolves, and a logo host that failed all answer
    /// identically. The alternative is an endpoint that reports on other people's infrastructure to
    /// anonymous callers — "this client_id exists and its CDN is down" is a fact about somebody
    /// else's deployment, handed to whoever asks.
    /// </remarks>
    [Fact]
    public async Task A_client_with_no_logo_and_an_unknown_client_answer_the_same()
    {
        ClientLogoEndpoint.Forget();

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public);
            seed.Fetcher = new StubFetcher();
        });

        Assert.Equal(HttpStatusCode.NotFound, (await fixture.Client.GetAsync(Url())).StatusCode);

        Assert.Equal(
            HttpStatusCode.NotFound,
            (await fixture.Client.GetAsync(Url("https://nobody.example/c.json"))).StatusCode);

        Assert.Equal(HttpStatusCode.NotFound, (await fixture.Client.GetAsync("/client-logo")).StatusCode);
    }

    /// <summary>A host that failed is a 404, not a 502 with its story in it.</summary>
    [Fact]
    public async Task A_logo_host_that_failed_is_not_reported()
    {
        await using var fixture = await FixtureAsync(new FetchOutcome.Timeout(TimeSpan.FromSeconds(5)));

        var response = await fixture.Client.GetAsync(Url());

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("cdn.example", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The second view of a consent page makes no second outbound request.
    /// </summary>
    /// <remarks>
    /// The proxy exists to stop a logo host learning who is looking at which consent page and when.
    /// Fetching per view would hand that host the same timing signal from this server's address
    /// instead of the user's — quieter, and the same disclosure.
    /// </remarks>
    [Fact]
    public async Task A_cached_logo_is_not_fetched_again()
    {
        ClientLogoEndpoint.Forget();

        var fetcher = new StubFetcher().Respond(Logo, Body(Png, "image/png"));

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public) with { LogoUri = Logo };
            seed.Fetcher = fetcher;
        });

        // Asserted, not assumed: if the first request 404s, the second one makes no fetch either
        // and "no second fetch" passes while nothing has ever been cached.
        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.GetAsync(Url())).StatusCode);
        Assert.Equal(1, fetcher.Calls);

        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.GetAsync(Url())).StatusCode);
        Assert.Equal(1, fetcher.Calls);
    }

    /// <summary>
    /// Serving a logo does not widen the consent page's policy.
    /// </summary>
    /// <remarks>
    /// The whole reason the image is same-origin is that <c>default-src 'self'</c> already covers
    /// it. If this ever needed an <c>img-src</c> the proxy would have stopped being a proxy, and
    /// this is the assertion that would say so.
    /// </remarks>
    [Fact]
    public async Task The_consent_pages_policy_is_unchanged_by_the_logo()
    {
        await using var fixture = await FixtureAsync(Body(Png, "image/png"));

        var response = await fixture.Client.GetAsync("/login?returnUrl=%2Fauthorize");
        var policy = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("default-src 'self'", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("img-src", policy, StringComparison.Ordinal);
    }
}
