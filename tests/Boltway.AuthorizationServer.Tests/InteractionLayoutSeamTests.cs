using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A deployment's own page shell, from registration to bytes on the wire.
/// </summary>
/// <remarks>
/// <para>
/// <c>LayoutSeamTests</c> in the shipped contract package proves a layout composes with the
/// renderer. This proves a host can actually get one in: <c>TryAddSingleton</c> keeps a
/// registration made before <c>AddBoltwayAuthorizationServer</c>, and a seam that is only
/// reachable by constructing the renderer by hand is not a seam a deployment has.
/// </para>
/// <para>
/// The half worth measuring is the second test. The shell is the deployment's and the consent
/// controls are still the server's, and a shell arriving without them would be a page that looks
/// finished - which is the whole reason the renderer verifies rather than trusts.
/// </para>
/// </remarks>
public sealed class InteractionLayoutSeamTests
{
    private sealed class BrandedLayout : IInteractionLayout
    {
        public string Wrap(InteractionPage page)
        {
            ArgumentNullException.ThrowIfNull(page);

            return "<!DOCTYPE html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
                + "<title>Northwind</title></head><body class=\"northwind\">"
                + "<header id=\"northwind-header\">Northwind</header>"
                + page.Body
                + "<footer id=\"northwind-footer\">Quyền riêng tư</footer>"
                + "</body></html>";
        }
    }

    private static async Task<FlowFixture> BrandedAsync() =>
        await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
            seed.ConfigureServices = services => services.AddSingleton<IInteractionLayout, BrandedLayout>();
        });

    [Fact]
    public async Task A_layout_registered_before_the_server_is_the_one_that_serves()
    {
        await using var fixture = await BrandedAsync();

        var page = await fixture.Client.GetStringAsync("/login?returnUrl=%2Fauthorize");

        Assert.Contains("<header id=\"northwind-header\">Northwind</header>", page, StringComparison.Ordinal);
        Assert.Contains("<footer id=\"northwind-footer\">", page, StringComparison.Ordinal);
        Assert.Contains("lang=\"vi\"", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// The deployment got its shell and the server kept its page.
    /// </summary>
    /// <remarks>
    /// A custom shell that also silently replaced the sign-in form would be the seam failing at the
    /// only thing it promises. The username and password fields are the endpoint's wire contract -
    /// <c>PostLoginAsync</c> reads exactly those two names.
    /// </remarks>
    [Fact]
    public async Task The_servers_own_markup_is_still_inside_the_deployments_shell()
    {
        await using var fixture = await BrandedAsync();

        var page = await fixture.Client.GetStringAsync("/login?returnUrl=%2Fauthorize");

        Assert.Contains("name=\"username\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"password\"", page, StringComparison.Ordinal);

        var header = page.IndexOf("northwind-header", StringComparison.Ordinal);
        var form = page.IndexOf("name=\"username\"", StringComparison.Ordinal);
        var footer = page.IndexOf("northwind-footer", StringComparison.Ordinal);

        Assert.True(header < form && form < footer, "The server's markup is not inside the shell.");
    }

    /// <summary>
    /// A shell that drops the server's markup never reaches a user as a page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The production half of the render-time check. What must not happen is a <c>200</c> carrying a
    /// branded page with no sign-in form on it - a user staring at a header and a footer, and a
    /// server reporting success.
    /// </para>
    /// <para>
    /// <b>Measured before it was asserted:</b> the throw propagates out of <c>/login</c> rather than
    /// being caught and turned into an error page, because the exception boundary that produces
    /// <c>server_error</c> is on the authorize pipeline and this is the interaction endpoint. So a
    /// real host answers <c>500</c> from its own handler with this message in the log. That is the
    /// right outcome and it is pinned here rather than left as "either would do", because a test
    /// accepting two outcomes stops noticing when the one it gets changes.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_shell_that_drops_the_body_never_serves_a_page()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
            seed.ConfigureServices = services =>
                services.AddSingleton<IInteractionLayout>(new EmptyLayout());
        });

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Client.GetAsync("/login?returnUrl=%2Fauthorize"));

        Assert.Contains("did not include InteractionPage.Body", thrown.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(EmptyLayout), thrown.Message, StringComparison.Ordinal);
    }

    private sealed class EmptyLayout : IInteractionLayout
    {
        public string Wrap(InteractionPage page) => "<!DOCTYPE html><html><body>Northwind</body></html>";
    }

    /// <summary>The security headers are the server's, whoever wrote the shell.</summary>
    [Fact]
    public async Task A_custom_shell_does_not_change_the_policy()
    {
        await using var fixture = await BrandedAsync();

        var response = await fixture.Client.GetAsync("/login?returnUrl=%2Fauthorize");
        var policy = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("default-src 'self'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }
}
