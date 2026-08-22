using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Boltway.Mcp.Tests;

/// <summary>
/// Whether "this request matched no endpoint" and "routing has not run yet" are distinguishable
/// from inside a middleware.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="BoltwayExtensions.UseConnectorCaller"/> has to skip a request that routed to
/// nothing — demanding a validated token for a path that is about to 404 is what turns a probe for
/// an unmapped subpath into a 500. But <c>GetEndpoint()</c> returning null also describes a
/// pipeline where routing has not run at all, and skipping there would leave every real request
/// unauthenticated. The two cases must be told apart by something, or the skip cannot be safe.
/// </para>
/// <para>
/// This is a measurement of ASP.NET Core's behaviour rather than of Boltway's, kept because
/// the answer is what the skip is built on and it is not written down anywhere the compiler checks.
/// </para>
/// </remarks>
public sealed class EndpointFeatureProbeTests
{
    private static async Task<(bool FeaturePresent, bool EndpointPresent)> Observe(
        bool routingFirst, string path)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRouting();

        var app = builder.Build();

        bool feature = false, endpoint = false;

        if (routingFirst) app.UseRouting();

        app.Use(async (context, next) =>
        {
            feature = context.Features.Get<IEndpointFeature>() is not null;
            endpoint = context.GetEndpoint() is not null;
            await next();
        });

        // Explicitly after the observer, which is the only way to get user middleware ahead of
        // routing in a WebApplication: leaving UseRouting out entirely does not do it.
        if (!routingFirst) app.UseRouting();

        app.MapGet("/mapped", () => "ok");

        await app.StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));
        await app.StopAsync();

        return (feature, endpoint);
    }

    /// <summary>Routing ran and matched: both are present.</summary>
    [Fact]
    public async Task A_matched_request_after_routing_has_both()
    {
        Assert.Equal((true, true), await Observe(routingFirst: true, "/mapped"));
    }

    /// <summary>
    /// Routing ran and matched nothing: the feature is absent too, not merely empty. So
    /// <c>IEndpointFeature</c> does not separate the two cases — measured, against the guess that
    /// an unmatched request would carry the feature with a null endpoint.
    /// </summary>
    [Fact]
    public async Task An_unmatched_request_after_routing_has_neither()
    {
        Assert.Equal((false, false), await Observe(routingFirst: true, "/nope"));
    }

    /// <summary>
    /// Middleware genuinely ahead of routing sees neither — the same pair as an unmatched request.
    /// Nothing in the context tells them apart, which is why the skip cannot be written as "no
    /// endpoint, therefore unrouted".
    /// </summary>
    [Fact]
    public async Task Before_routing_neither_is_present()
    {
        Assert.Equal((false, false), await Observe(routingFirst: false, "/mapped"));
    }

    /// <summary>
    /// And this is why the risk is narrower than it looks: in a <c>WebApplication</c>, omitting
    /// <c>UseRouting()</c> does not put middleware ahead of routing. The routing middleware is
    /// inserted at the front of the pipeline, so a matched request still carries its endpoint.
    /// Getting ahead of routing takes an explicit <c>UseRouting()</c> placed after the middleware.
    /// </summary>
    [Fact]
    public async Task Omitting_use_routing_does_not_put_middleware_ahead_of_routing()
    {
        Assert.Equal((true, true), await ObserveWithoutAnyUseRouting("/mapped"));
    }

    private static async Task<(bool, bool)> ObserveWithoutAnyUseRouting(string path)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRouting();

        var app = builder.Build();
        bool feature = false, endpoint = false;

        app.Use(async (context, next) =>
        {
            feature = context.Features.Get<IEndpointFeature>() is not null;
            endpoint = context.GetEndpoint() is not null;
            await next();
        });

        app.MapGet("/mapped", () => "ok");

        await app.StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.GetAsync(new Uri(path, UriKind.Relative));
        await app.StopAsync();

        return (feature, endpoint);
    }
}
