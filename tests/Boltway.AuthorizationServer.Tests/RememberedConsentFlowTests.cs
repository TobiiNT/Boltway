using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Primitives.Pkce;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A browser application consents once, then renews silently.
/// </summary>
/// <remarks>
/// <para>
/// The case that needed both halves. A public client was sent to the consent page on every
/// authorization whatever the policy said, so a page renewing its token with <c>prompt=none</c>
/// in a hidden frame was answered <c>consent_required</c> every time: the token expired, the next
/// call failed, and the whole page went back through sign-in and consent. And the shipped policy
/// asks every time anyway, so even a client exempt from the guard would have been asked.
/// </para>
/// <para>
/// Driven over HTTP with the real consent page and the real consent store write, because the
/// property is "the record the approval wrote is the one the next request reads", and a seeded
/// policy decision would assert it without either. The control is the same flow without the flag.
/// </para>
/// </remarks>
public sealed partial class RememberedConsentFlowTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string Callback = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private static Task<FlowFixture> StartAsync(bool redirectProvesIdentity) =>
        FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public) with
            {
                RedirectProvesIdentity = redirectProvesIdentity,
            };
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";

            // After the fixture's own policy, so this is the one that resolves - the same position
            // a host registering it before AddBoltwayAuthorizationServer puts it in.
            seed.ConfigureServices = services =>
                services.AddSingleton<IConsentPolicy, RememberedConsentPolicy>();
        });

    private static string AuthorizeUrl(string extra = "") =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(ClientId)
        + "&redirect_uri=" + Uri.EscapeDataString(Callback)
        + "&code_challenge=" + Verifier.ComputeS256Challenge()
        + "&code_challenge_method=S256"
        + "&scope=" + Uri.EscapeDataString("mcp:tools")
        + "&resource=" + Uri.EscapeDataString(Build.Resource)
        + "&state=opaque-state"
        + extra;

    // Duplicated from InteractionFlowTests rather than shared, for the reason LoginFlowTests gives.
    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [GeneratedRegex("name=\"returnUrl\" value=\"([^\"]+)\"")]
    private static partial Regex ReturnUrlField();

    /// <summary>The first authorization, through the consent page, as a person would approve it.</summary>
    private static async Task ApproveOnceAsync(FlowFixture fixture)
    {
        var start = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);
        Assert.StartsWith("/consent?returnUrl=", start.Headers.Location!.ToString(), StringComparison.Ordinal);

        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        Assert.True(token.Success && returnUrl.Success, "The consent page rendered no form.");

        var approved = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("decision", "approve"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);
        Assert.StartsWith(Callback + "?", approved.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    private static System.Collections.Specialized.NameValueCollection QueryOf(HttpResponseMessage response) =>
        HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

    [Fact]
    public async Task A_client_whose_redirect_proves_identity_is_not_asked_a_second_time()
    {
        await using var fixture = await StartAsync(redirectProvesIdentity: true);
        await ApproveOnceAsync(fixture);

        var again = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.StartsWith(Callback + "?", again.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.NotNull(QueryOf(again)["code"]);
    }

    /// <summary>
    /// The silent renewal: <c>prompt=none</c> after one approval returns a code, not
    /// <c>consent_required</c>.
    /// </summary>
    [Fact]
    public async Task Prompt_none_after_one_approval_returns_a_code()
    {
        await using var fixture = await StartAsync(redirectProvesIdentity: true);
        await ApproveOnceAsync(fixture);

        var renewal = await fixture.Client.GetAsync(AuthorizeUrl("&prompt=none"));
        var query = QueryOf(renewal);

        Assert.Null(query["error"]);
        Assert.NotNull(query["code"]);
        Assert.Equal("opaque-state", query["state"]);
    }

    /// <summary>The control: without the flag, the same approval is asked for again.</summary>
    [Fact]
    public async Task Without_the_flag_the_same_client_is_asked_again()
    {
        await using var fixture = await StartAsync(redirectProvesIdentity: false);
        await ApproveOnceAsync(fixture);

        var again = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.StartsWith("/consent?returnUrl=", again.Headers.Location!.ToString(), StringComparison.Ordinal);

        var renewal = await fixture.Client.GetAsync(AuthorizeUrl("&prompt=none"));

        Assert.Equal("consent_required", QueryOf(renewal)["error"]);
    }

    /// <summary>A wider request than was approved is asked again, flag or not.</summary>
    [Fact]
    public async Task A_wider_request_than_was_approved_is_asked_again()
    {
        await using var fixture = await StartAsync(redirectProvesIdentity: true);
        await ApproveOnceAsync(fixture);

        var wider = await fixture.Client.GetAsync(
            AuthorizeUrl().Replace(
                "scope=" + Uri.EscapeDataString("mcp:tools"),
                "scope=" + Uri.EscapeDataString("mcp:tools offline_access"),
                StringComparison.Ordinal));

        Assert.StartsWith("/consent?returnUrl=", wider.Headers.Location!.ToString(), StringComparison.Ordinal);
    }
}
