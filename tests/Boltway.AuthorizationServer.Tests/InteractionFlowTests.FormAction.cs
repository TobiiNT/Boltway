using System.Net;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>form-action</c> on the pages that carry a form, and where its extra source comes from.
/// </summary>
/// <remarks>
/// <para>
/// Chrome and Safari apply <c>form-action</c> to the redirect a submission follows, not only to its
/// immediate target. Under a bare <c>form-action 'self'</c> the consent POST is allowed and the 303
/// it answers with is blocked — after the authorization code has been issued. So the server logs a
/// completed authorization, the client never sees the code, and nothing anywhere reports a failure.
/// </para>
/// <para>
/// It reached a deployment because <c>curl</c> does not enforce CSP: an end-to-end check that
/// followed every redirect by hand, including the one to the client, passed. These tests assert the
/// header rather than the flow for the same reason a browser is what found it — the flow passes
/// either way.
/// </para>
/// </remarks>
public sealed partial class InteractionFlowTests
{
    private static string Csp(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Content-Security-Policy", out var values)
            ? string.Join(' ', values)
            : throw new InvalidOperationException("The response carried no Content-Security-Policy.");

    [Fact]
    public async Task The_consent_page_names_the_client_in_form_action()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());
        var consent = await fixture.Client.GetAsync(start.Headers.Location!.ToString());

        Assert.Equal(HttpStatusCode.OK, consent.StatusCode);
        Assert.Contains("form-action 'self' https://claude.ai;", Csp(consent), StringComparison.Ordinal);
    }

    /// <summary>
    /// A loopback client's source carries the port it actually asked for.
    /// </summary>
    /// <remarks>
    /// The assertion that pins <i>which</i> URI the source is built from. RFC 8252 §7.3 registers
    /// <c>http://127.0.0.1/callback</c> with no port because a native app cannot know its ephemeral
    /// one until it binds; the request then arrives on 49321. A source derived from the registration
    /// would be <c>http://127.0.0.1</c>, which CSP reads as port 80 — so it would match nothing the
    /// app is listening on, and the sign-in would fail exactly as it did before any of this.
    /// </remarks>
    [Fact]
    public async Task A_loopback_client_gets_the_port_it_asked_for_rather_than_the_one_it_registered()
    {
        await using var fixture = await LoopbackClientAsync();

        var start = await fixture.Client.GetAsync(LoopbackAuthorizeUrl());
        var consent = await fixture.Client.GetAsync(start.Headers.Location!.ToString());

        Assert.Equal(HttpStatusCode.OK, consent.StatusCode);
        Assert.Contains("form-action 'self' http://127.0.0.1:49321;", Csp(consent), StringComparison.Ordinal);
    }

    /// <summary>
    /// A page reached without a client keeps the policy at <c>'self'</c>.
    /// </summary>
    /// <remarks>
    /// The half that stops this from being a widening with no floor. <c>/error</c> renders on our own
    /// origin with no authorization request behind it, and nothing should have added a source to it.
    /// </remarks>
    [Fact]
    public async Task A_page_with_no_client_behind_it_keeps_form_action_at_self()
    {
        await using var fixture = await PublicClientAsync();

        var error = await fixture.Client.GetAsync("/error");

        Assert.Contains("form-action 'self';", Csp(error), StringComparison.Ordinal);
    }
}
