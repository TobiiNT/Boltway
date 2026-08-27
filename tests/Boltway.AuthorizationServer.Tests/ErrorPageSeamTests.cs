using System.Net;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The error page goes through <see cref="IInteractionRenderer"/> - and survives it failing.
/// </summary>
/// <remarks>
/// <para>
/// It did not, for the whole history of the project: login and consent went through the seam and
/// this page was built inside <c>RejectionHtmlResult</c>. A deployment that implemented the renderer
/// restyled two pages of three and learned about the third from a screenshot.
/// </para>
/// <para>
/// The reason it was left out is real and is why the fallback exists: this page renders where
/// something has already gone wrong, including "the server threw", so the renderer is a second thing
/// that can fail while handling the first. That is an argument for catching, not for leaving one
/// page unthemeable and saying nothing about it.
/// </para>
/// </remarks>
public sealed class ErrorPageSeamTests
{
    [Fact]
    public async Task The_deployments_renderer_draws_it()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureServices = services =>
                services.AddSingleton<IInteractionRenderer, MarkedRenderer>());

        // GetAsync, not GetStringAsync: this page answers 500 by design - it is the landing place
        // for a request that arrived with nothing to speak for it - and GetStringAsync throws on a
        // non-success status before a test can look at what was rendered.
        var response = await fixture.Client.GetAsync(new Uri("/error", UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("this-came-from-the-deployment", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// A renderer that throws gets the built-in page, not a 500 and not an empty body.
    /// </summary>
    /// <remarks>
    /// The whole point of the fallback. Without it, a deployment with a broken renderer answers the
    /// error page by throwing inside the response that was already reporting an error - and what the
    /// user sees depends on how far the response had been written, which is the least debuggable
    /// failure available.
    /// </remarks>
    [Fact]
    public async Task A_renderer_that_throws_still_produces_the_page()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureServices = services =>
                services.AddSingleton<IInteractionRenderer, ThrowingRenderer>());

        var response = await fixture.Client.GetAsync(new Uri("/error", UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("This request could not be authorized", body, StringComparison.Ordinal);

        // And it is reported rather than swallowed: a renderer that throws on every error page is a
        // defect that would otherwise only ever be visible as pages that look slightly wrong.
        Assert.Contains(
            fixture.Logs.Events,
            entry => entry.Message.Contains("IInteractionRenderer threw", StringComparison.Ordinal));
    }

    /// <summary>
    /// The correlation id reaches the page, whichever renderer drew it.
    /// </summary>
    /// <remarks>
    /// It is what a support conversation is keyed on, and it is the one field on this page that
    /// cannot be reconstructed from anywhere else afterwards.
    /// </remarks>
    [Fact]
    public async Task The_correlation_id_is_on_the_page()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(new Uri("/error", UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("Reference:", body, StringComparison.Ordinal);
    }

    private sealed class MarkedRenderer : IInteractionRenderer
    {
        public string RenderConsent(ConsentViewModel model) => "<html><body>consent</body></html>";

        public string RenderLogin(LoginViewModel model) => "<html><body>login</body></html>";

        public string RenderError(ErrorViewModel model) =>
            "<html><body><p>this-came-from-the-deployment</p><p>"
            + System.Net.WebUtility.HtmlEncode(model.CorrelationId) + "</p></body></html>";
    }

    private sealed class ThrowingRenderer : IInteractionRenderer
    {
        public string RenderConsent(ConsentViewModel model) => throw new InvalidOperationException("no");

        public string RenderLogin(LoginViewModel model) => throw new InvalidOperationException("no");

        public string RenderError(ErrorViewModel model) => throw new InvalidOperationException("no");
    }
}
