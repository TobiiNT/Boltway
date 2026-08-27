using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The theme a deployment configures is the theme the served page carries.
/// </summary>
/// <remarks>
/// <para>
/// The unit tests around <c>InteractionOptions</c> prove the renderer uses the options it is
/// handed. This file proves the options a deployment set are the ones it is handed, which is a
/// different claim and the one with a live failure mode: registering
/// <c>IInteractionRenderer</c> by type rather than by factory selects the parameterless
/// constructor, and every setting is then accepted, validated at startup, and silently ignored.
/// Nothing else in the suite would notice - the pages still render, just unthemed.
/// </para>
/// <para>
/// End to end through the real pipeline rather than against the container, because the seam being
/// checked is the whole path from <c>AddBoltwayAuthorizationServer</c> to bytes on the wire.
/// </para>
/// </remarks>
public sealed class InteractionThemeTests
{
    private static async Task<FlowFixture> ThemedAsync() =>
        await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
            seed.ConfigureOptions = options =>
            {
                options.Interaction.ProductName = "Northwind";
                options.Interaction.LogoPath = "/img/northwind.svg";
                options.Interaction.StylesheetPaths.Add("/css/authorization.css");
            };
        });

    [Fact]
    public async Task The_served_login_page_carries_the_configured_theme()
    {
        await using var fixture = await ThemedAsync();

        var page = await fixture.Client.GetStringAsync("/login?returnUrl=%2Fauthorize");

        Assert.Contains("<link rel=\"stylesheet\" href=\"/css/authorization.css\">", page, StringComparison.Ordinal);
        Assert.Contains("<img src=\"/img/northwind.svg\" alt=\"Northwind\">", page, StringComparison.Ordinal);
        Assert.Contains("Northwind", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The theme does not widen what the page is allowed to load.
    /// </summary>
    /// <remarks>
    /// A stylesheet reaching the page and the policy that governs it are set in two different files,
    /// and the theme is only safe because the paths are same-origin. If a future change let an
    /// absolute URL through, this is the assertion that says the page now asks for something
    /// <c>default-src 'self'</c> refuses.
    /// </remarks>
    [Fact]
    public async Task A_themed_page_still_sends_the_unmodified_policy()
    {
        await using var fixture = await ThemedAsync();

        var response = await fixture.Client.GetAsync("/login?returnUrl=%2Fauthorize");
        var policy = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("default-src 'self'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("unsafe-inline", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("http://", policy, StringComparison.Ordinal);
    }

    /// <summary>An unconfigured deployment serves the pages it served before these options existed.</summary>
    [Fact]
    public async Task An_unthemed_deployment_links_nothing()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public));

        var page = await fixture.Client.GetStringAsync("/login?returnUrl=%2Fauthorize");

        Assert.DoesNotContain("<link", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<img", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A stylesheet the browser would refuse stops the server instead.
    /// </summary>
    /// <remarks>
    /// The whole reason these paths are validated. Started, this deployment serves a login page that
    /// renders unstyled with the explanation only in a browser console - and the operator who set
    /// the path is the one person who could have fixed it in a second, at startup.
    /// </remarks>
    [Fact]
    public async Task A_deployment_pointing_at_a_cdn_refuses_to_start()
    {
        var failure = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(async () =>
            await FlowFixture.StartAsync(seed =>
            {
                seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
                seed.ConfigureOptions = options =>
                    options.Interaction.StylesheetPaths.Add("https://cdn.example.com/theme.css");
            }));

        Assert.Contains("StylesheetPaths[0]", failure.Message, StringComparison.Ordinal);
    }
}
