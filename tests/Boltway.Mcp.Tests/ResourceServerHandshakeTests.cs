using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Boltway.Mcp;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;
using Boltway.ResourceServer.Authorization;
using RsOptions = Boltway.ResourceServer.Configuration.ProtectedResourceOptions;
using Boltway.ResourceServer.DependencyInjection;
using Boltway.ResourceServer.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Boltway.Mcp.Tests;

/// <summary>
/// A connector authenticating against a real authorization server rather than a static token
/// map, driven end to end: the token is minted by the shipping minter, validated by the
/// shipping resource-server middleware, and read by a tool through the same
/// <c>ConnectorCaller</c> the static path uses.
///
/// <para>
/// What this pins is that moving off <c>BearerAuthenticator</c> changes nothing above the
/// seam — and that there is exactly <strong>one</strong> 401 in the process. Two challenge
/// shapes from one server is the duplication this package spends its documentation warning
/// about, so a test asserting the resource server's shape arrives is asserting mine did not.
/// </para>
/// </summary>
public sealed class ResourceServerHandshakeTests : IAsyncLifetime
{
    private const string Issuer = "https://auth.example.com";
    private const string Resource = "https://mcp.example.com/mcp";

    private static readonly RSA Rsa = RSA.Create(2048);
    private static readonly SigningKeyHandle Key = new("test-key", SigningAlgorithm.RS256, new RsaSecurityKey(Rsa));

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

                    // The discovery surface and the challenge come from the resource server.
                    services.AddBoltwayProtectedResource((RsOptions options) =>
                    {
                        options.Resource = Resource;
                        options.AuthorizationServer = Issuer;
                        options.ScopesSupported.Add("docs:read");
                        options.SigningKeys.Add(Key.Key);
                    });

                    // And this library contributes only the mapping onto a caller. Note the
                    // overload without ProtectedResourceOptions: nothing here publishes
                    // metadata or writes a 401, so requiring them would be a lie in the type.
                    services.AddBoltway(ResourceServerAuthenticator.FromClaims(downstreamToken: "gh-token"));

                    services.AddMcpServer(o => o.ServerInfo = new() { Name = "test", Version = "0.1.0" })
                        .WithHttpTransport()
                        .WithTools<WhoAmITool>();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseBoltwayProtectedResource();
                    app.UseConnectorCaller("/mcp", (_, principal) => $"state-for-{principal.Actor}");
                    app.UseEndpoints(e =>
                    {
                        // Called through its declaring type on purpose. Both packages export a
                        // `MapProtectedResourceMetadata` extension, and which one an unqualified
                        // call binds to depends on namespace resolution — this file sits in
                        // Boltway.Mcp.Tests, so Boltway.Mcp's won silently and the host
                        // failed at startup asking for options this arrangement does not have.
                        // A collision that resolves by proximity is the concrete cost of two
                        // implementations of one surface living in one repository.
                        ProtectedResourceMetadataEndpoints.MapProtectedResourceMetadata(e);
                        e.MapMcp("/mcp").RequireScope("docs:read");
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

    /// <summary>
    /// The audience, through the public path a customer's <c>IResourceRegistry</c> would take.
    /// The resource server's own <c>ProtectedResource</c> is internal, and reaching for it here
    /// would be testing a route no consumer of this package can use.
    /// </summary>
    private static ResourceIdentifier Audience(string canonical) =>
        ResourceIdentifier.TryRegister(canonical, out var id, out var error)
            ? id!
            : throw new InvalidOperationException(error);

    private static string Token(string subject = "ada", string? email = "ada@example.com", string scope = "docs:read")
    {
        var extra = new Dictionary<string, object?>(StringComparer.Ordinal) { ["preferred_username"] = subject };
        if (email is not null) extra["email"] = email;

        var now = DateTimeOffset.UtcNow;

        return new JwtTokenMinter().MintAccessToken(
            new AccessTokenDescriptor(
                IssuerString.TryCreate(Issuer, out var iss, out var e) ? iss : throw new InvalidOperationException(e),
                Audience(Resource),
                SubjectId.FromStorage("user-1"),
                ClientIdentifier.ForCimd("https://claude.ai/.well-known/oauth-client"),
                GrantId: "grant-1",
                ScopeSet.TryParse(scope, out var scopes, out _) ? scopes : throw new InvalidOperationException(scope),
                now,
                now.AddHours(1),
                JwtId: "jti-1",
                Extra: extra),
            Key).Wire;
    }

    private static HttpRequestMessage Call(string name, string? token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(
                """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"NAME","arguments":{}}}"""
                    .Replace("NAME", name, StringComparison.Ordinal),
                System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        if (token is not null) request.Headers.Add("Authorization", $"Bearer {token}");
        return request;
    }

    // -----------------------------------------------------------------------

    [Fact]
    public async Task A_token_from_the_authorization_server_reaches_the_tool_as_a_caller()
    {
        var body = await (await _client.SendAsync(Call("whoami", Token()))).Content.ReadAsStringAsync();

        // The identity is now attested by a signature chain rather than asserted from which
        // static string was presented. Nothing above the seam changed to get that.
        Assert.Contains("ada", body, StringComparison.Ordinal);
        Assert.Contains("state-for-ada", body, StringComparison.Ordinal);
        Assert.Contains("gh-token", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_only_401_is_the_resource_server_s()
    {
        var response = await _client.SendAsync(Call("whoami", token: null));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = response.Headers.WwwAuthenticate.ToString();

        // RFC 9728 §3.1 path insertion — the resource has a path, so the metadata URL is
        // /.well-known/oauth-protected-resource/mcp and not the root form. This library's own
        // challenge does not do that, so seeing it here is how we know whose 401 answered.
        Assert.Contains(
            "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\"",
            challenge, StringComparison.Ordinal);

        // And exactly one challenge, not two stapled together by two middlewares both
        // deciding they owned the refusal.
        Assert.Single(response.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task A_token_for_another_resource_does_not_open_this_one()
    {
        var now = DateTimeOffset.UtcNow;
        var wire = new JwtTokenMinter().MintAccessToken(
            new AccessTokenDescriptor(
                IssuerString.TryCreate(Issuer, out var iss, out _) ? iss : throw new InvalidOperationException(),
                Audience("https://other-mcp.example.com/mcp"),
                SubjectId.FromStorage("user-1"),
                ClientIdentifier.ForCimd("https://claude.ai/.well-known/oauth-client"),
                GrantId: "grant-1",
                ScopeSet.TryParse("docs:read", out var scopes, out _) ? scopes : throw new InvalidOperationException(),
                now, now.AddHours(1), JwtId: "jti-2"),
            Key).Wire;

        // A token this server would otherwise accept in every way except who it was minted
        // for. Audience binding is what stops one connector's token opening another's.
        var response = await _client.SendAsync(Call("whoami", wire));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_email_in_the_token_becomes_the_identity_a_write_is_attributed_to()
    {
        var withEmail = await (await _client.SendAsync(Call("email", Token()))).Content.ReadAsStringAsync();
        Assert.Contains("ada@example.com", withEmail, StringComparison.Ordinal);

        // An access token is not obliged to carry one, and most do not unless the
        // authorization server is configured to add it. Null rather than invented — a
        // connector then leaves the downstream author field unset and says so, which is
        // weaker evidence and visibly weaker.
        var without = await (await _client.SendAsync(Call("email", Token(email: null)))).Content.ReadAsStringAsync();
        var payload = JsonDocument.Parse(
                without.Split('\n').First(l => l.StartsWith("data:", StringComparison.Ordinal))[5..])
            .RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString()!;

        // No address at all, rather than one derived from the handle. `ada@` plus a guessed
        // domain would be indistinguishable from a real one, and a commit author that cannot
        // be told apart from a real one costs the whole trail its value, not just this entry.
        Assert.DoesNotContain('@', payload);
        Assert.False(JsonDocument.Parse(payload).RootElement.TryGetProperty("email", out var value)
            && value.ValueKind is not JsonValueKind.Null);
    }

    /// <summary>
    /// A path under the prefix that maps to nothing answers 404, not 500.
    ///
    /// <para>
    /// The caller middleware gates on a path prefix, so it saw every request under <c>/mcp</c>
    /// including the ones routing had already matched to nothing. It asked the authenticator for a
    /// caller, the resource server had deliberately set no token for an unrouted request, and the
    /// resulting <c>InvalidOperationException</c> reached the client as an empty 500 — with a
    /// message naming a wiring mistake in a pipeline that is wired the way this test wires it.
    /// Measured live before the fix: <c>GET /mcp/zzq7x4v-nope</c> returned <c>HTTP/2 500</c> with
    /// <c>content-length: 0</c>.
    /// </para>
    /// </summary>
    [Fact]
    public async Task An_unmapped_path_under_the_prefix_is_a_404_rather_than_a_500()
    {
        using var response = await _client.GetAsync(new Uri("/mcp/zzq7x4v-nope", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Control: an unmapped path outside the prefix was always a 404, so the assertion above is
    /// about the prefix branch rather than about routing in general.
    /// </summary>
    [Fact]
    public async Task An_unmapped_path_outside_the_prefix_is_also_a_404()
    {
        using var response = await _client.GetAsync(new Uri("/nope-unrouted", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Control, and the one that matters: the endpoint that does exist still refuses an
    /// unauthenticated caller. Skipping a request with no endpoint must not become skipping a
    /// request whose endpoint simply had no token.
    /// </summary>
    [Fact]
    public async Task The_mapped_endpoint_still_refuses_a_caller_with_no_token()
    {
        using var response = await _client.SendAsync(Call("tools/list", token: null));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
