using System.ComponentModel;
using System.Net;
using Boltway.Mcp;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Server;
using Xunit;

namespace Boltway.Mcp.Tests;

/// <summary>
/// How far a per-tool refusal can reach — measured, because the answer decides a design.
/// </summary>
/// <remarks>
/// <para>
/// A tool refused for want of a scope wants to tell the caller which scope would fix it, in a form
/// they can act on. There are two channels for that and this file is why neither is taken.
/// </para>
/// <para>
/// The first is a tool-level challenge, <c>_meta["mcp/www_authenticate"]</c> on an
/// <c>isError</c> result. Measured 2026-08-25 and written up in
/// <c>spec/mcp-tool-challenge-2026-08-25.md</c>: it is SEP-1489, a sponsored draft, and the
/// substring <c>authenticat</c> occurs zero times in the <c>2025-11-25</c> schema and zero times in
/// the draft the <c>2026-07-28</c> release candidate is cut from. There is no such mechanism to
/// use yet.
/// </para>
/// <para>
/// The second is the HTTP challenge the resource server already writes well — and the tests below
/// are why it cannot be reached from a tool. Streamable HTTP requires a client to accept
/// <c>text/event-stream</c>, and the transport has opened that stream before any tool filter runs,
/// so the status line is already <c>200</c> and already sent. A per-tool refusal therefore cannot
/// become a <c>403</c>, whatever the connector does.
/// </para>
/// <para>
/// <b>These are measurements pinned as tests rather than notes.</b> If a future SDK buffers the
/// response, or a future revision defines the tool-level field, one of them goes red and the design
/// is worth reopening — which is the only way a closed door gets re-checked.
/// </para>
/// </remarks>
public sealed class ToolRefusalReachTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;
    private static bool? _startedWhenTheFilterRan;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddHttpContextAccessor();
                    services.AddBoltway(BearerAuthenticator.FromTokens(
                        BearerAuthenticator.ParseTokenMap("t:ada:founder")));
                    services.AddMcpServer(o => o.ServerInfo = new() { Name = "reach", Version = "0.1.0" })
                        .WithHttpTransport()
                        .WithTools<ReachTool>()
                        .WithRequestFilters(f => f.AddCallToolFilter(next => (context, ct) =>
                        {
                            // The accessor is the documented way to reach the request from a
                            // handler, and it works here — what has moved on by now is the
                            // response, not the context.
                            var http = context.Services?.GetService<IHttpContextAccessor>()?.HttpContext;
                            _startedWhenTheFilterRan = http?.Response.HasStarted;
                            return next(context, ct);
                        }));
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseConnectorAuth("/mcp", "reach", (_, _) => null);
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

    private async Task<HttpResponseMessage> CallAsync(string accept)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ping\",\"arguments\":{}}}",
                System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Accept.ParseAdd(accept);
        request.Headers.Add("Authorization", "Bearer t");
        return await _client.SendAsync(request);
    }

    /// <summary>
    /// Streamable HTTP has no buffered-JSON path a client can ask for, so there is no arrangement
    /// in which the response is still open when a tool runs.
    /// </summary>
    [Fact]
    public async Task A_client_that_will_not_take_an_event_stream_is_refused_the_transport()
    {
        var response = await CallAsync("application/json");

        Assert.Equal(HttpStatusCode.NotAcceptable, response.StatusCode);
    }

    /// <summary>
    /// <b>The response has already started by the time a tool filter runs.</b> So the status line
    /// is sent, and a per-tool refusal cannot be a <c>403</c> carrying a challenge.
    /// </summary>
    [Fact]
    public async Task A_tool_filter_runs_after_the_response_has_started()
    {
        var response = await CallAsync("application/json, text/event-stream");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(_startedWhenTheFilterRan, "the filter never saw an HttpContext at all");
    }
}

/// <summary>One tool, so there is something for the filter to run ahead of.</summary>
[McpServerToolType]
public sealed class ReachTool
{
    [McpServerTool(Name = "ping", ReadOnly = true)]
    [Description("Answers, so the filter above has a call to observe.")]
    public static object Ping() => new { ok = true };
}
