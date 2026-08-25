using System.Diagnostics.CodeAnalysis;
using System.ComponentModel;
using System.Net;
using System.Text.Json;
using Boltway.Mcp;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using Xunit;

namespace Boltway.Mcp.Tests;

/// <summary>
/// The static-token path, driven through a real host rather than asserted about.
///
/// <para>
/// This connector publishes no RFC 9728 metadata and points at no authorization server,
/// because with static tokens there is not one. That is the whole change: it used to
/// publish a document with an empty <c>authorization_servers</c> list, which is a client
/// told it needs a token and handed nowhere to get one — LESSONS #8 exactly, produced by
/// the library written to prevent LESSONS #8. Discovery lives in
/// <c>Boltway.ResourceServer</c> now, and is exercised by
/// <see cref="ResourceServerHandshakeTests"/>.
/// </para>
/// </summary>
public sealed class StaticTokenTests : IAsyncLifetime
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
                    services.AddBoltway(BearerAuthenticator.FromTokens(
                        BearerAuthenticator.ParseTokenMap("good:ada:founder,other:bob", downstreamToken: "gh-token")));
                    services.AddMcpServer(o => o.ServerInfo = new() { Name = "test", Version = "0.1.0" })
                        .WithHttpTransport()
                        .WithTools<WhoAmITool>();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseConnectorAuth("/mcp", "test-connector",
                        (_, principal) => $"state-for-{principal.Actor}");
                    app.UseEndpoints(e => e.MapMcp("/mcp"));
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

    private static HttpRequestMessage Rpc(string method, string? token = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent($$"""{"jsonrpc":"2.0","id":1,"method":"{{method}}"}""",
                System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        if (token is not null) request.Headers.Add("Authorization", $"Bearer {token}");
        return request;
    }

    // -----------------------------------------------------------------------

    [Fact]
    public async Task A_refused_request_says_there_is_no_discovery_rather_than_implying_one()
    {
        var response = await _client.SendAsync(Rpc("ping"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = response.Headers.WwwAuthenticate.ToString();

        Assert.Contains("realm=\"test-connector\"", challenge, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", challenge, StringComparison.Ordinal);

        // No pointer, deliberately. There is no authorization server behind static tokens,
        // and a `resource_metadata` naming a document that lists no issuer is a dead end
        // that looks like a discovery chain — worse than an obvious failure, because
        // nothing reports it.
        Assert.DoesNotContain("resource_metadata", challenge, StringComparison.Ordinal);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("static tokens", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_way_of_arriving_unauthenticated_is_refused_the_same_way()
    {
        var noHeader = await _client.SendAsync(Rpc("ping"));
        var wrongToken = await _client.SendAsync(Rpc("ping", "nonsense"));

        var empty = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = new StringContent("{}") };
        empty.Headers.Add("Authorization", "Bearer ");
        var emptyToken = await _client.SendAsync(empty);

        foreach (var response in new[] { noHeader, wrongToken, emptyToken })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task The_challenge_is_readable_by_a_browser_client()
    {
        var response = await _client.SendAsync(Rpc("ping"));

        // Without this a browser cannot read the pointer, and a recoverable 401 becomes
        // unrecoverable for exactly one class of client.
        Assert.Contains("WWW-Authenticate",
            response.Headers.GetValues("Access-Control-Expose-Headers").First(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_valid_token_reaches_the_tool_with_its_identity_and_bound_state()
    {
        var response = await _client.SendAsync(Rpc("tools/list", "good"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(
                """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami","arguments":{}}}""",
                System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("Authorization", "Bearer good");

        var body = await (await _client.SendAsync(request)).Content.ReadAsStringAsync();
        Assert.Contains("ada", body, StringComparison.Ordinal);
        Assert.Contains("founder", body, StringComparison.Ordinal);
        Assert.Contains("state-for-ada", body, StringComparison.Ordinal);
        Assert.Contains("gh-token", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refusal_reaches_the_model_as_the_sentence_it_was_written_as()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(
                """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"refuse","arguments":{}}}""",
                System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("Authorization", "Bearer good");

        var body = await (await _client.SendAsync(request)).Content.ReadAsStringAsync();
        var result = JsonDocument.Parse(body[body.IndexOf('{', StringComparison.Ordinal)..]).RootElement.GetProperty("result");
        var text = result.GetProperty("content")[0].GetProperty("text").GetString()!;

        // isError, not a JSON-RPC error: a tool failure is content the model reads.
        Assert.True(result.GetProperty("isError").GetBoolean());

        // And the sentence survives the trip. The SDK appends the message only for an
        // McpException; every other exception type is reduced to the bare phrase below,
        // because an arbitrary exception message can carry a connection string.
        //
        // That default is right, and it means a refusal thrown as a plain Exception is
        // silently downgraded to noise: the server logs the sentence it went to the
        // trouble of writing and the model is told only that something went wrong. This
        // type derived from Exception for a release. Nothing reported it — the tool still
        // "failed", just uselessly.
        Assert.Contains("`doc-42` is outside the scope this token carries", text, StringComparison.Ordinal);
        Assert.Contains("ToolError [forbidden]", text, StringComparison.Ordinal);
        Assert.DoesNotContain("invoking 'refuse'.", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_static_token_learns_no_identity_claims()
    {
        var principal = BearerAuthenticator.ParseTokenMap("a:ada:founder")["a"];

        // Null rather than a stand-in. There is no authorization server on this path, so there is
        // no client, no token id and no grant id to learn — and a connector recording an invented
        // one would make every entry in its trail indistinguishable from a real attribution, not
        // only these.
        Assert.Null(principal.ClientId);
        Assert.Null(principal.TokenId);
        Assert.Null(principal.GrantId);
    }

    [Fact]
    public void A_static_token_reports_that_it_carries_no_scope_claim()
    {
        var principal = BearerAuthenticator.ParseTokenMap("a:ada:founder")["a"];

        // Absent rather than Unknown: this path is known to have no authorization server, so it
        // knows there is no claim. A connector gating a tool on a scope therefore falls back to its
        // own table here rather than refusing every call, which is what keeps DEV_TOKENS usable
        // after a connector starts enforcing scopes.
        Assert.Equal(ScopeClaimState.Absent, principal.ScopeClaim);
        Assert.Null(principal.Grants("docs:read"));
    }

    [Fact]
    public void ParseTokenMap_skips_malformed_entries_rather_than_guessing()
    {
        var map = BearerAuthenticator.ParseTokenMap("a:ada:founder:ada@example.com, b:bob , ,broken, :nope, c:");

        Assert.Equal(2, map.Count);
        Assert.Equal("ada", map["a"].Actor);
        Assert.Equal(["founder"], map["a"].Roles);
        Assert.Equal("ada@example.com", map["a"].Email);
        Assert.Equal("bob", map["b"].Actor);
        // Empty rather than a stand-in. What an absent role means is the connector's to decide, and
        // a library that picked `user` would be picking a vocabulary.
        Assert.Empty(map["b"].Roles);

        // Null, not a plausible-looking default. An invented author is indistinguishable
        // from a real one, so synthesising one costs the trail its value everywhere, not
        // only on the entry that was guessed.
        Assert.Null(map["b"].Email);
    }

}

[McpServerToolType]
public sealed class WhoAmITool(ConnectorCaller caller)
{
    [McpServerTool(Name = "whoami", ReadOnly = true)]
    [Description("Report the authenticated caller, their role, and the state bound to them.")]
    public object Who() => new
    {
        actor = caller.Actor,
        roles = caller.Roles,
        state = caller.StateAs<string>(),
        downstream = caller.Principal.DownstreamToken,
    };

    [McpServerTool(Name = "email", ReadOnly = true)]
    [Description("Report the address a downstream write would be attributed to, if any.")]
    public object Email() => new { email = caller.Principal.Email };

    [McpServerTool(Name = "refuse", ReadOnly = true)]
    [Description("Always refuses, so the shape of a refusal on the wire can be asserted.")]
    [SuppressMessage(
        "Performance",
        "CA1822:Mark members as static",
        Justification = "A tool on a per-caller tool type, discovered by reflection and resolved "
            + "through the container alongside its two siblings. Static would change how the SDK "
            + "binds it, on a test whose whole subject is the shape this produces on the wire — "
            + "and it only escapes the rule because refusing happens to need no caller state.")]
    public object Refuse() =>
        throw new ConnectorToolException("`doc-42` is outside the scope this token carries", "forbidden");
}
