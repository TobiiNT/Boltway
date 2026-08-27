using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.Identity.Passwords;
using Boltway.OAuth.Tokens;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The discovery endpoints over real HTTP.
/// </summary>
/// <remarks>
/// Over a server rather than by calling the handlers, because every failure this file is about
/// lives in the pipeline rather than in the handler: a global authorization policy that 401s the
/// document, a fallback route that answers with HTML, a method matcher that does not route HEAD.
/// None of them are visible from a unit test of the delegate.
/// </remarks>
public sealed class DiscoveryEndpointTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(TestKeys.Ring());

                    // A fallback policy that requires an authenticated user. This is deliberately
                    // hostile: it is the single most common way a real deployment breaks its own
                    // discovery, and the endpoints are supposed to survive it.
                    services.AddAuthorization(o => o.FallbackPolicy =
                        new AuthorizationPolicyBuilder().RequireAssertion(_ => false).Build());


                    // Every seam MapBoltwayAuthorizationServer requires. This fixture used to
                    // register only the key ring, on the reasoning that a discovery-only host needs
                    // nothing else - which was true until the startup check began verifying the
                    // whole list before mapping any route. Discovery still has to survive the
                    // hostile pipeline below; that is what this file is about, and it is unchanged.
                    services.AddSingleton<IClientResolver>(new TestClientResolver([Build.Client()]));
                    services.AddSingleton<IResourceRegistry>(new TestResourceRegistry().Add(Build.Resource, "mcp:tools"));
                    services.AddBoltwayInMemoryStores();
                    services.AddScoped<IUserSession>(_ => new TestUserSession(null));
                    services.AddSingleton<IUserStore>(new InMemoryUserStore());
                    services.AddSingleton<IRoleStore>(new InMemoryRoleStore());
                    services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());

                    services.AddBoltwayAuthorizationServer(o =>
                    {
                        o.Issuer = Build.Issuer;
                        o.ScopesSupported.Add("openid");
                        o.ScopesSupported.Add("offline_access");
                        o.ScopesSupported.Add("mcp:tools");
                        o.RefreshTokenDerivationKey = Build.DerivationKey;
                    });
                })
                .Configure(app =>
                {
                    // Deliberately NO UseCors(). The discovery routes used to carry RequireCors
                    // metadata, which makes ASP.NET Core throw "contains CORS metadata, but a
                    // middleware was not found" at request time - a 500 on every document, in every
                    // host that had not thought to add the middleware. A fixture that called
                    // UseCors() hid that completely, so this one does not.
                    app.UseRouting();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapBoltwayAuthorizationServer();

                        // A catch-all that answers everything with HTML - the SPA fallback whose
                        // 200-with-markup terminates an MCP client's probe sequence with a parse
                        // error instead of letting it move on.
                        endpoints.MapFallback(context =>
                        {
                            context.Response.ContentType = "text/html";
                            return context.Response.WriteAsync("<html>app shell</html>");
                        }).AllowAnonymous();
                    });
                }))
            .StartAsync();

        _client = _host.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    private static readonly string[] DocumentUrls =
    [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/",
        "/.well-known/openid-configuration",
        "/.well-known/openid-configuration/",
    ];

    // Four spellings, two registered routes. The other two are the framework's trailing-slash
    // handling, which A_trailing_slash_resolves_to_the_same_document asserts separately.

    /// <summary>
    /// The discovery documents are anonymous even under a deny-everything fallback policy.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks.json")]
    public async Task Discovery_survives_a_global_authorization_policy(string url)
    {
        var response = await _client.GetAsync(url);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>
    /// Every spelling of the document URL returns the same bytes.
    /// </summary>
    /// <remarks>
    /// Byte equality, not JSON equivalence. RFC 8414 §3.3 makes the fetch URL part of the issuer
    /// check, and a client that fetched one spelling and validated against another would be
    /// comparing two documents this test would otherwise let differ.
    /// </remarks>
    [Fact]
    public async Task Every_document_url_returns_identical_bytes()
    {
        var bodies = new List<byte[]>();

        foreach (var url in DocumentUrls)
        {
            var response = await _client.GetAsync(url);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            bodies.Add(await response.Content.ReadAsByteArrayAsync());
        }

        foreach (var body in bodies)
        {
            Assert.Equal(bodies[0], body);
        }
    }

    /// <summary>HEAD returns the headers and no body.</summary>
    /// <remarks>
    /// Some client probes issue HEAD first. The framework's HEAD-to-GET fallback is <b>not</b> what
    /// makes this work: it applies only when no endpoint handles HEAD, and the
    /// <c>/.well-known/{**rest}</c> 404 catch-all does - so before HEAD was declared explicitly on
    /// the document routes, the catch-all won every HEAD probe and answered 404. This test is the
    /// one that found it.
    /// </remarks>
    [Theory]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks.json")]
    public async Task Head_is_answered_with_headers_and_no_body(string url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Head, url);
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(response.Headers.ETag);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    /// <summary>The document is cacheable for five minutes with a strong ETag.</summary>
    [Fact]
    public async Task The_document_carries_the_cache_headers_clients_expect()
    {
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");

        Assert.Equal(300, response.Headers.CacheControl?.MaxAge?.TotalSeconds);
        Assert.True(response.Headers.CacheControl?.Public);
        Assert.NotNull(response.Headers.ETag);
        Assert.False(response.Headers.ETag!.IsWeak);
    }

    /// <summary>A conditional request with the current ETag is answered 304.</summary>
    [Fact]
    public async Task A_matching_if_none_match_is_answered_304()
    {
        var first = await _client.GetAsync("/.well-known/oauth-authorization-server");
        var etag = first.Headers.ETag!.ToString();

        using var conditional = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-authorization-server");
        conditional.Headers.TryAddWithoutValidation("If-None-Match", etag);

        var second = await _client.SendAsync(conditional);

        Assert.Equal(HttpStatusCode.NotModified, second.StatusCode);
        Assert.Empty(await second.Content.ReadAsByteArrayAsync());
    }

    /// <summary>A stale ETag gets the body, so the 304 above is a decision and not a constant.</summary>
    [Fact]
    public async Task A_stale_if_none_match_is_answered_with_the_body()
    {
        using var conditional = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-authorization-server");
        conditional.Headers.TryAddWithoutValidation("If-None-Match", "\"stale\"");

        var response = await _client.SendAsync(conditional);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotEmpty(await response.Content.ReadAsByteArrayAsync());
    }

    /// <summary>
    /// An unmatched well-known path is a bare 404, not the application's HTML fallback.
    /// </summary>
    /// <remarks>
    /// The fallback in this fixture answers everything else with markup. An MCP client probes
    /// several URLs in sequence and moves on at a 404, so a 200 with HTML does not degrade - it
    /// ends discovery with a parse error on a document the client had no reason to doubt.
    /// </remarks>
    [Theory]
    [InlineData("GET", "/.well-known/oauth-authorization-server/tenant1")]
    [InlineData("GET", "/.well-known/openid-configuration/tenant1")]
    [InlineData("GET", "/.well-known/oauth-protected-resource")]
    [InlineData("GET", "/.well-known/something-else")]
    [InlineData("HEAD", "/.well-known/oauth-authorization-server/tenant1")]
    [InlineData("HEAD", "/.well-known/something-else")]
    public async Task An_unmatched_wellknown_path_is_a_bare_404(string method, string url)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), url);
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    /// <summary>
    /// A trailing slash resolves to the same document, without a second route being registered.
    /// </summary>
    /// <remarks>
    /// Registering <c>".../openid-configuration/"</c> alongside <c>".../openid-configuration"</c>
    /// is the same route template twice, which makes every request to either an
    /// <c>AmbiguousMatchException</c> - a 500 on the first request any client makes. This asserts
    /// the framework already handles the spelling, which is what makes the second registration
    /// both unnecessary and harmful.
    /// </remarks>
    [Theory]
    [InlineData("/.well-known/oauth-authorization-server/")]
    [InlineData("/.well-known/openid-configuration/")]
    public async Task A_trailing_slash_resolves_to_the_same_document(string url)
    {
        var withSlash = await _client.GetAsync(url);
        var without = await _client.GetAsync(url.TrimEnd('/'));

        Assert.Equal(HttpStatusCode.OK, withSlash.StatusCode);
        Assert.Equal(
            await without.Content.ReadAsByteArrayAsync(),
            await withSlash.Content.ReadAsByteArrayAsync());
    }

    /// <summary>
    /// The <b>appended</b> well-known form is a bare 404 too, not the host's HTML.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 8414 §3.1 <i>inserts</i> the well-known segment before an issuer path
    /// (<c>/.well-known/oauth-authorization-server/tenant1</c>) while OIDC Discovery §4.1
    /// <i>appends</i> it after (<c>/tenant1/.well-known/openid-configuration</c>). Only the
    /// insertion form was routed at first, so this shape fell through to the SPA fallback this
    /// fixture installs and came back <c>200 text/html</c> - the exact failure the 404 exists to
    /// prevent, arriving through the half of the rule nobody had covered.
    /// </para>
    /// <para>
    /// One- and two-segment prefixes only, and that is a stated limit rather than an oversight: a
    /// route template cannot carry a catch-all before a literal, and this server refuses a
    /// path-bearing issuer at startup, so nothing it publishes can send a client deeper.
    /// </remarks>
    [Theory]
    [InlineData("GET", "/tenant1/.well-known/oauth-authorization-server")]
    [InlineData("GET", "/tenant1/.well-known/openid-configuration")]
    [InlineData("GET", "/org/tenant1/.well-known/openid-configuration")]
    [InlineData("HEAD", "/tenant1/.well-known/openid-configuration")]
    public async Task An_appended_wellknown_path_is_a_bare_404(string method, string url)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), url);
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    /// <summary>
    /// The control for the test above: the fallback really would have answered with HTML.
    /// </summary>
    /// <remarks>
    /// Without this, the 404 test passes just as well against a fixture that has no fallback at
    /// all - which is to say it would be asserting nothing about the situation it names.
    /// </remarks>
    [Fact]
    public async Task The_fixture_really_does_have_an_html_fallback()
    {
        var response = await _client.GetAsync("/some/app/route");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>Discovery is CORS-enabled, because browser-based clients fetch it.</summary>
    [Fact]
    public async Task Discovery_allows_cross_origin_reads()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/oauth-authorization-server");
        request.Headers.Add("Origin", "https://claude.ai");

        var response = await _client.SendAsync(request);

        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }

    /// <summary>
    /// The authorization endpoint has no CORS headers.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §3.2 and RFC 9700 §2.6: CORS MUST NOT be supported at the authorization endpoint.
    /// This is why the policy is applied per endpoint rather than by <c>app.UseCors(policy)</c> -
    /// and since <c>/authorize</c> is not yet routed, what this asserts today is that the CORS
    /// middleware in the pipeline does not add headers to a route that did not ask for them.
    /// </remarks>
    [Fact]
    public async Task Cors_is_not_applied_to_routes_that_did_not_ask_for_it()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/some/app/route");
        request.Headers.Add("Origin", "https://claude.ai");

        var response = await _client.SendAsync(request);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    /// <summary>The JWKS publishes public members only.</summary>
    /// <remarks>
    /// Checked by scanning for every private JWK member name rather than by inspecting the one this
    /// key type happens to use, because the failure is catastrophic and the list is short.
    /// </remarks>
    [Fact]
    public async Task The_jwks_contains_no_private_key_material()
    {
        var body = await _client.GetStringAsync("/.well-known/jwks.json");

        foreach (var member in Boltway.OAuth.Tokens.JsonWebKeySet.PrivateMemberNames)
        {
            Assert.DoesNotContain($"\"{member}\"", body, StringComparison.Ordinal);
        }

        var keys = JsonDocument.Parse(body).RootElement.GetProperty("keys");
        Assert.True(keys.GetArrayLength() > 0, "An empty JWKS means no client can validate any token.");
    }

    /// <summary>The <c>jwks_uri</c> in the document is the URL that actually serves the key set.</summary>
    /// <remarks>
    /// A metadata document that points somewhere unserved is a working-looking deployment where
    /// every signature validation fails - and the client reports it as an invalid token, not as a
    /// missing key set.
    /// </remarks>
    [Fact]
    public async Task The_advertised_jwks_uri_is_live()
    {
        var body = await _client.GetStringAsync("/.well-known/oauth-authorization-server");
        var jwksUri = JsonDocument.Parse(body).RootElement.GetProperty("jwks_uri").GetString()!;

        Assert.StartsWith(Build.Issuer, jwksUri, StringComparison.Ordinal);

        var response = await _client.GetAsync(jwksUri[Build.Issuer.Length..]);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// The three endpoints without which there is no OAuth server are advertised and answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test used to also require <c>userinfo_endpoint</c>, <c>revocation_endpoint</c>,
    /// <c>introspection_endpoint</c> and <c>end_session_endpoint</c> to be advertised, on the
    /// reasoning that they were "step 6 and step 9 work … listed here so the gap is visible rather
    /// than implied". The intent was honest and the effect was not: none of the four was ever
    /// routed, so the assertion pinned four live N-06 violations in place and would have gone red
    /// on the commit that fixed them. Visibility is a job for a check that goes red while the gap
    /// exists, which is the opposite of what this was doing.
    /// </para>
    /// <para>
    /// <c>MetadataHonestyTests.Every_advertised_endpoint_answers</c> is that check. It cannot live
    /// here, because this fixture deliberately installs a <c>MapFallback</c> that answers everything
    /// with HTML - so nothing 404s in this host and a sweep would be vacuous.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_endpoints_the_flow_needs_are_advertised_and_answer()
    {
        var body = await _client.GetStringAsync("/.well-known/oauth-authorization-server");
        var root = JsonDocument.Parse(body).RootElement;

        foreach (var name in new[] { "jwks_uri", "authorization_endpoint", "token_endpoint" })
        {
            Assert.True(root.TryGetProperty(name, out var value), $"{name} should be advertised.");

            var path = value.GetString()![Build.Issuer.Length..];
            using var probe = await _client.GetAsync(path);

            // Not 404 rather than 200: /token is POST-only, so a GET is a 405 from the framework's
            // method matcher, and that is a routed endpoint disagreeing with the request.
            Assert.NotEqual(HttpStatusCode.NotFound, probe.StatusCode);
        }
    }
}

/// <summary>A key ring with one live RSA key, for tests that need JWKS to be non-empty.</summary>
internal static class TestKeys
{
    internal static SigningKeyRing Ring()
    {
        var rsa = RSA.Create(2048);
        var handle = new SigningKeyHandle("test-key", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));

        return new SigningKeyRing(
        [
            new ManagedSigningKey(
                handle,
                SigningKeyState.Active,
                DateTimeOffset.UtcNow.AddDays(-2),
                DateTimeOffset.UtcNow.AddDays(-1)),
        ]);
    }
}
