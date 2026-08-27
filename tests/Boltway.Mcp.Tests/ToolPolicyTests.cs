using System.ComponentModel;
using System.Net;
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
/// A connector's own tool policy, applied to both places it has to hold.
/// </summary>
/// <remarks>
/// <para>
/// Driven through a real host rather than asserted about, because the property under test is that
/// <c>tools/list</c> and <c>tools/call</c> agree. Two filters that each work in isolation and
/// disagree with each other is the failure this is for: a listing that hides a tool while the call
/// still reaches it is a surface that looks gated and is not.
/// </para>
/// <para>
/// The policy here refuses one tool to one actor. What decides that is deliberately arbitrary -
/// this library ships no vocabulary, and a test that asserted one would be inventing the default
/// <see cref="IConnectorToolPolicy"/> exists to avoid.
/// </para>
/// </remarks>
public sealed class ToolPolicyTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;

    private sealed class ActorPolicy : IConnectorToolPolicy
    {
        public bool Allows(CallerPrincipal caller, string tool) =>
            tool != "closed" || caller.Actor == "ada";

        // One argument names a resource, and reaching it is the caller's own or nobody's. What
        // "theirs" means is this policy's to know - the library hands over the arguments and takes
        // no view.
        public bool AllowsArguments(
            CallerPrincipal caller, string tool, IReadOnlyDictionary<string, System.Text.Json.JsonElement>? arguments)
        {
            if (tool != "open" || arguments is null || !arguments.TryGetValue("owner", out var owner))
            {
                return true;
            }

            return owner.GetString() == caller.Actor;
        }
    }

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddBoltway(BearerAuthenticator.FromTokens(
                        BearerAuthenticator.ParseTokenMap("ada-token:ada:founder,bob-token:bob:member")));
                    services.AddSingleton<IConnectorToolPolicy, ActorPolicy>();
                    services.AddMcpServer(o => o.ServerInfo = new() { Name = "test", Version = "0.1.0" })
                        .WithHttpTransport()
                        .WithTools<GatedTools>()
                        .WithBoltwayToolPolicy();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseConnectorAuth("/mcp", "test-connector", (_, _) => null);
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

    private async Task<string> RpcAsync(string token, string body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("Authorization", $"Bearer {token}");

        var response = await _client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    private Task<string> ListAsync(string token) =>
        RpcAsync(token, """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""");

    private Task<string> CallAsync(string token, string tool) =>
        RpcAsync(token,
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\""
            + tool + "\",\"arguments\":{}}}");

    // -----------------------------------------------------------------------

    /// <summary>The listing carries what this caller may use, and nothing else.</summary>
    [Fact]
    public async Task The_listing_omits_a_tool_the_policy_refuses()
    {
        var listing = await ListAsync("bob-token");

        Assert.Contains("\"open\"", listing, StringComparison.Ordinal);
        Assert.DoesNotContain("\"closed\"", listing, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control, and the half a filtering bug would quietly take away: a caller the policy
    /// allows sees everything.
    /// </summary>
    [Fact]
    public async Task The_listing_keeps_every_tool_the_policy_allows()
    {
        var listing = await ListAsync("ada-token");

        Assert.Contains("\"open\"", listing, StringComparison.Ordinal);
        Assert.Contains("\"closed\"", listing, StringComparison.Ordinal);
    }

    /// <summary>
    /// <b>Hiding is not gating.</b> The tool is absent from this caller's listing and the call is
    /// still refused, because a caller that knows the name does not need the listing.
    /// </summary>
    /// <remarks>
    /// This is the test that makes shipping the two filters together worth doing. Either one alone
    /// passes a test written about itself: a listing filter looks like a gate, and a call gate
    /// leaves a model retrying an advertised tool that always refuses.
    /// </remarks>
    [Fact]
    public async Task A_tool_hidden_from_the_listing_is_also_refused_when_called()
    {
        var body = await CallAsync("bob-token", "closed");

        Assert.Contains("forbidden", body, StringComparison.Ordinal);

        // The refusal names what was refused. An empty result or an "unknown tool" would send
        // whoever is reading it to look for a registration bug.
        Assert.Contains("closed", body, StringComparison.Ordinal);
    }

    /// <summary>The other control: the same tool, a caller the policy allows, reaches the tool.</summary>
    [Fact]
    public async Task A_caller_the_policy_allows_reaches_the_tool()
    {
        var body = await CallAsync("ada-token", "closed");

        Assert.Contains("closed-ran", body, StringComparison.Ordinal);
        Assert.DoesNotContain("forbidden", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// A scope refusal names every scope the operation needs, not the missing subset.
    /// </summary>
    /// <remarks>
    /// Same rule as the <c>403</c> challenge, and the same measured reason: a client asks for the
    /// union of what it is told and what it already had, and does not reliably carry forward what
    /// an earlier step-up granted, so naming only the delta re-authorizes somebody into a narrower
    /// grant than they started with. Asserted on the message because the message is the whole
    /// channel - see <see cref="ToolRefusalReachTests"/> for why there is no challenge.
    /// </remarks>
    [Fact]
    public void A_scope_refusal_names_every_scope_the_operation_needs()
    {
        var refusal = new InsufficientScopeException("docs:read", "docs:write");

        Assert.Equal(["docs:read", "docs:write"], refusal.Required);
        Assert.Contains("docs:read docs:write", refusal.Message, StringComparison.Ordinal);

        // The code is what separates it from a role refusal, which re-authorizing cannot fix.
        Assert.Equal("insufficient_scope", refusal.Code);
    }

    /// <summary>
    /// An argument naming somebody else's resource is refused, on a tool the caller may otherwise use.
    /// </summary>
    /// <remarks>
    /// The gate <c>Allows</c> cannot express: the tool is the same tool either way, so a caller
    /// allowed to poll their own work and handed another caller's identifier is refused here or
    /// nowhere. Left to the tool body it would be a check each tool remembers separately, which is
    /// the arrangement one of them eventually forgets.
    /// </remarks>
    [Fact]
    public async Task An_argument_naming_someone_elses_resource_is_refused()
    {
        var body = await RpcAsync("bob-token",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"open\","
            + "\"arguments\":{\"owner\":\"ada\"}}}");

        Assert.Contains("forbidden", body, StringComparison.Ordinal);

        // A different sentence from the whole-tool refusal, so a caller can tell "not at all" from
        // "not to that".
        Assert.Contains("not with these arguments", body, StringComparison.Ordinal);
    }

    /// <summary>The control: the same tool, the caller's own resource, runs.</summary>
    [Fact]
    public async Task An_argument_naming_the_callers_own_resource_is_allowed()
    {
        var body = await RpcAsync("bob-token",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"open\","
            + "\"arguments\":{\"owner\":\"bob\"}}}");

        Assert.Contains("open-ran", body, StringComparison.Ordinal);
        Assert.DoesNotContain("forbidden", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// An argument gate refuses; it cannot hide. The listing has no arguments to judge by.
    /// </summary>
    [Fact]
    public async Task An_argument_gate_does_not_change_the_listing()
    {
        var listing = await ListAsync("bob-token");

        Assert.Contains("\"open\"", listing, StringComparison.Ordinal);
    }

    /// <summary>A tool nobody is refused still works, so the filter is not refusing everything.</summary>
    [Fact]
    public async Task An_open_tool_runs_for_a_caller_the_policy_narrows_elsewhere()
    {
        var body = await CallAsync("bob-token", "open");

        Assert.Contains("open-ran", body, StringComparison.Ordinal);
        Assert.DoesNotContain("forbidden", body, StringComparison.Ordinal);
    }
}

/// <summary>Two tools, so that a policy has something to tell apart.</summary>
[McpServerToolType]
public sealed class GatedTools
{
    [McpServerTool(Name = "open", ReadOnly = true)]
    [Description("Available to every caller.")]
    public static object Open(string? owner = null) => new { result = "open-ran", owner };

    [McpServerTool(Name = "closed", ReadOnly = true)]
    [Description("Available only to some callers.")]
    public static object Closed() => new { result = "closed-ran" };
}
