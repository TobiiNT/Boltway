using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Boltway.ResourceServer.Endpoints;

namespace Boltway.ResourceServer.Tests;

/// <summary>E-22 and E-23, over HTTP.</summary>
public sealed class ProtectedResourceMetadataEndpointTests
{
    [Theory]
    [InlineData(Build.MetadataPath)]
    [InlineData(Build.RootMetadataPath)]
    public async Task Both_shapes_serve_the_document(string path)
    {
        // C-26 / U-01. Claude probes the path-inserted form first and the root form second; OpenAI
        // documents only the root form and whether it probes the other is unverified. Serving both
        // costs one route and removes the question, which was the design answer recorded for U-01
        // and which nothing implemented until now.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Both_shapes_serve_the_same_bytes()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var inserted = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));
        using var root = await fixture.Client.GetAsync(new Uri(Build.RootMetadataPath, UriKind.Relative));

        Assert.Equal(
            await inserted.Content.ReadAsByteArrayAsync(),
            await root.Content.ReadAsByteArrayAsync());

        // Same bytes means the same strong validator; two tags over one body would make a
        // conditional GET answer 304 against a body the client never received.
        Assert.Equal(inserted.Headers.ETag, root.Headers.ETag);
    }

    [Fact]
    public async Task The_resource_is_the_configured_string_verbatim()
    {
        // RFC 9728 §3.3: the value "MUST be identical to the protected resource's resource
        // identifier value into which the well-known URI path suffix was inserted", and a client
        // that finds otherwise "MUST NOT" use the document. So this is the one field where a
        // helpful normalization is a silent, total failure.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var document = await FetchDocumentAsync(fixture, Build.MetadataPath);

        Assert.Equal(Build.Resource, document.GetProperty("resource").GetString());
    }

    [Fact]
    public async Task The_authorization_server_is_first_and_alone()
    {
        // C-27: Claude reads only the first entry and does not fall back to later ones. This server
        // pins exactly one ValidIssuer when it verifies a token, so a second entry would advertise
        // an authorization server whose tokens this resource then refuses — a successful sign-in
        // followed by a permanent 401, which is worse than not supporting several.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var servers = (await FetchDocumentAsync(fixture, Build.MetadataPath))
            .GetProperty("authorization_servers");

        Assert.Equal(1, servers.GetArrayLength());
        Assert.Equal(Build.Issuer, servers[0].GetString());
    }

    [Fact]
    public async Task Bearer_methods_are_header_only()
    {
        // The MCP specification forbids a token in the query string and the middleware answers one
        // with 400 (X-35), so advertising `query` or `body` would be a promise the request path
        // breaks.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var methods = (await FetchDocumentAsync(fixture, Build.MetadataPath))
            .GetProperty("bearer_methods_supported");

        Assert.Equal(1, methods.GetArrayLength());
        Assert.Equal("header", methods[0].GetString());
    }

    [Fact]
    public async Task An_empty_scope_list_is_omitted_rather_than_written_as_an_empty_array()
    {
        // Behavioural, not cosmetic. The MCP scope-selection strategy uses every scope in
        // scopes_supported when the challenge carries none, "omitting the scope parameter if
        // scopes_supported is undefined" — so [] is defined, and a client that dutifully requests
        // the empty set gets a token with no authority at all.
        await using var fixture = await ResourceServerFixture.StartAsync(o => o.ScopesSupported.Clear());

        var document = await FetchDocumentAsync(fixture, Build.MetadataPath);

        Assert.False(document.TryGetProperty("scopes_supported", out _));
    }

    [Fact]
    public async Task Optional_members_that_are_not_configured_are_absent()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        var document = await FetchDocumentAsync(fixture, Build.MetadataPath);

        // Each of these would be a claim about a capability this server does not have. DPoP is
        // deferred and `dpop_bound_access_tokens_required: true` breaks both vendors outright;
        // `jwks_uri` here would be misread as the authorization server's keys; `signed_metadata`
        // takes precedence over the plain members under §3.3 and commits to a second signing key.
        foreach (var absent in new[]
                 {
                     "jwks_uri",
                     "signed_metadata",
                     "dpop_bound_access_tokens_required",
                     "dpop_signing_alg_values_supported",
                     "tls_client_certificate_bound_access_tokens",
                     "resource_signing_alg_values_supported",
                     "authorization_details_types_supported",
                     "resource_policy_uri",
                     "resource_tos_uri",
                 })
        {
            Assert.False(document.TryGetProperty(absent, out _), absent + " should not be advertised.");
        }
    }

    [Fact]
    public async Task The_document_is_anonymous_even_though_everything_else_is_protected()
    {
        // The deadlock this prevents: a global authorization policy 401s the discovery document, so
        // the client cannot find out where to authenticate without first authenticating. It is a
        // repeatedly observed real-world connector failure. Note the fixture leaves
        // RequireBearerByDefault on, which is what makes this assertion mean something.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var metadata = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));
        using var protectedEndpoint = await fixture.Client.GetAsync(new Uri("/protected", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, protectedEndpoint.StatusCode);
    }

    [Fact]
    public async Task A_bearer_token_is_not_needed_and_a_bad_one_does_not_matter()
    {
        // An anonymous endpoint is anonymous whatever the request carries. A middleware that
        // validated first and checked AllowAnonymous second would 401 the discovery document for
        // anyone holding a stale token, which is the population most in need of re-discovering it.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, Build.MetadataPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-real-token");

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData(Build.MetadataPath)]
    [InlineData(Build.RootMetadataPath)]
    public async Task Head_is_answered_with_the_headers_and_no_body(string path)
    {
        // Declared explicitly rather than left to the framework's fallback: ASP.NET Core routes
        // HEAD to a GET endpoint only when nothing handles HEAD, and this server maps both.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Head, path);
        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task A_conditional_get_with_the_current_tag_is_answered_304()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var first = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));
        var etag = first.Headers.ETag!.ToString();

        using var request = new HttpRequestMessage(HttpMethod.Get, Build.MetadataPath);
        request.Headers.TryAddWithoutValidation("If-None-Match", etag);

        using var second = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
    }

    [Fact]
    public async Task A_conditional_get_sending_several_tags_as_several_headers_still_matches()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var first = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));
        var etag = first.Headers.ETag!.ToString();

        using var request = new HttpRequestMessage(HttpMethod.Get, Build.MetadataPath);
        request.Headers.TryAddWithoutValidation("If-None-Match", "\"stale\", " + etag);

        using var second = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
    }

    [Theory]
    // One physical line carrying a list — the spelling RFC 9110 §13.1.2 permits and an HTTP client
    // will not let a test send. See the remarks on CachedJsonResult.Matches.
    [InlineData(true, "\"stale\", \"the-tag\"")]
    [InlineData(true, "\"the-tag\",\"stale\"")]
    [InlineData(true, "\"the-tag\"")]
    [InlineData(true, "*")]
    [InlineData(false, "\"stale\"")]
    [InlineData(false, "\"stale\", \"older\"")]
    // A weak tag never matches a strong validator: W/"x" promises semantic equivalence, and this
    // resource's tag promises bytes.
    [InlineData(false, "W/\"the-tag\"")]
    public void One_header_line_carrying_a_list_of_tags_is_split(bool expected, string header) =>
        Assert.Equal(expected, CachedJsonResult.Matches(header, "\"the-tag\""));

    [Fact]
    public void Several_header_lines_each_carrying_one_tag_are_also_read()
    {
        string[] lines = ["\"stale\"", "\"the-tag\""];

        Assert.True(CachedJsonResult.Matches(lines, "\"the-tag\""));
    }

    [Fact]
    public async Task A_weak_tag_does_not_match_a_strong_validator()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var first = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));
        var etag = first.Headers.ETag!.ToString();

        using var request = new HttpRequestMessage(HttpMethod.Get, Build.MetadataPath);
        request.Headers.TryAddWithoutValidation("If-None-Match", "W/" + etag);

        using var second = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    [Theory]
    [InlineData(Build.MetadataPath)]
    [InlineData(Build.RootMetadataPath)]
    public async Task The_document_is_readable_cross_origin(string path)
    {
        // Written by the result rather than by RequireCors. RequireCors attaches metadata the CORS
        // middleware acts on, and a host that never calls UseCors() gets "contains CORS metadata,
        // but a middleware was not found" — a 500 on the one document that has to work before
        // anything else can.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }

    [Fact]
    public async Task A_host_that_already_set_the_origin_header_does_not_get_it_twice()
    {
        // Two Access-Control-Allow-Origin values is a CORS failure in every browser, so
        // "helpfully" adding ours on top of a host's global policy breaks the case it was meant to
        // serve.
        await using var fixture = await ResourceServerFixture.StartAsync(corsEnabledByHost: true);

        using var response = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));

        Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task The_document_is_cacheable()
    {
        // RFC 9728 §7.10 asks for caching directives on this document.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));

        Assert.True(response.Headers.CacheControl!.Public);
        Assert.Equal(TimeSpan.FromHours(1), response.Headers.CacheControl.MaxAge);
    }

    [Theory]
    [InlineData("/.well-known/oauth-protected-resource/not-this-resource")]
    [InlineData("/.well-known/oauth-protected-resource/mcp/deeper")]
    [InlineData("/.well-known/oauth-protected-resource/mcp/")]
    public async Task A_path_this_resource_does_not_occupy_is_404_rather_than_someone_elses_document(string path)
    {
        // Two reasons, both about what the client does next. A 404 lets a sequential prober move on
        // to its next candidate; a 200 carrying a `resource` the client did not insert is a
        // document §3.3 requires it to discard, and a discarded 200 usually ends discovery. The
        // trailing-slash row is the C-28 trap: /mcp/ is a different resource identifier.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task The_404_is_readable_cross_origin_and_not_cached()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(
            new Uri("/.well-known/oauth-protected-resource/nope", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.True(response.Headers.CacheControl!.NoStore);
    }

    [Fact]
    public async Task A_resource_without_a_path_is_served_at_the_root_form()
    {
        // The other half of §3.1. With no path there is nothing to insert, so the root form is the
        // normative location and the catch-all serves nothing.
        await using var fixture = await ResourceServerFixture.StartAsync(
            o => o.Resource = "https://mcp.example.com");

        using var root = await fixture.Client.GetAsync(new Uri(Build.RootMetadataPath, UriKind.Relative));
        using var inserted = await fixture.Client.GetAsync(new Uri(Build.MetadataPath, UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, root.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, inserted.StatusCode);
    }

    private static async Task<JsonElement> FetchDocumentAsync(ResourceServerFixture fixture, string path)
    {
        using var response = await fixture.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }
}
