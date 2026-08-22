using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Pkce;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The consent and login pages, and the flow a public client actually takes.
/// </summary>
/// <remarks>
/// Both vendors are public clients, and <c>PublicClientReconsentGuard</c> sends a public client to
/// the consent page on <b>every</b> authorization. So until these endpoints existed, neither Claude
/// nor ChatGPT could complete a single flow against this server — the redirect went to a route that
/// was not mapped.
/// </remarks>
public sealed partial class InteractionFlowTests
{
    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";

    private static async Task<FlowFixture> PublicClientAsync() =>
        await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public);
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
        });

    /// <summary>
    /// A client whose <c>client_id</c> host and redirect host differ.
    /// </summary>
    /// <remarks>
    /// The shape N-14 exists for, and the only one in which "the page shows both hosts" is a claim a
    /// test can distinguish. With the vendors' real configuration both hosts are <c>claude.ai</c>, so
    /// an assertion looking for that string passes whichever of the two was rendered — measured, and
    /// the reason dropping the redirect-host line from the page failed nothing.
    /// </remarks>
    private static async Task<FlowFixture> LoopbackClientAsync() =>
        await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public, "http://127.0.0.1/callback");
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
        });

    private static string LoopbackAuthorizeUrl() =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(ClientId)
        + "&redirect_uri=" + Uri.EscapeDataString("http://127.0.0.1:49321/callback")
        + "&code_challenge=" + Verifier.ComputeS256Challenge()
        + "&code_challenge_method=S256"
        + "&scope=" + Uri.EscapeDataString("mcp:tools offline_access")
        + "&resource=" + Uri.EscapeDataString(Build.Resource)
        + "&state=opaque-state";

    private static string AuthorizeUrl(string extra = "") =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(ClientId)
        + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")
        + "&code_challenge=" + Verifier.ComputeS256Challenge()
        + "&code_challenge_method=S256"
        + "&scope=" + Uri.EscapeDataString("mcp:tools offline_access")
        + "&resource=" + Uri.EscapeDataString(Build.Resource)
        + "&state=opaque-state"
        + extra;

    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [GeneratedRegex("name=\"returnUrl\" value=\"([^\"]+)\"")]
    private static partial Regex ReturnUrlField();

    /// <summary>Read the hidden fields the page rendered, as a browser would.</summary>
    private static (string Field, string Token, string ReturnUrl) FormFields(string html)
    {
        var token = AntiforgeryField().Match(html);
        var returnUrl = ReturnUrlField().Match(html);

        Assert.True(token.Success, "The page rendered no antiforgery field.");
        Assert.True(returnUrl.Success, "The page rendered no returnUrl field.");

        return (token.Groups[1].Value, token.Groups[2].Value, HttpUtility.HtmlDecode(returnUrl.Groups[1].Value));
    }

    /// <summary>
    /// A public client completes the whole flow, consent page included.
    /// </summary>
    /// <remarks>
    /// The test the fixture's own comment used to say was impossible. It exercises the property that
    /// forced the design: <c>POST /consent</c> issues the code itself rather than bouncing back to
    /// <c>/authorize</c>, which for a public client would find consent Required again and loop.
    /// </remarks>
    [Fact]
    public async Task A_public_client_completes_the_flow_through_the_consent_page()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);

        var consentUrl = start.Headers.Location!.ToString();
        Assert.StartsWith("/consent?returnUrl=", consentUrl, StringComparison.Ordinal);

        var page = await fixture.Client.GetStringAsync(consentUrl);
        var (field, token, returnUrl) = FormFields(page);

        var approved = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", returnUrl),
            new("decision", "approve"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);

        var callback = new Uri(approved.Headers.Location!.ToString());
        var query = HttpUtility.ParseQueryString(callback.Query);

        Assert.Equal("claude.ai", callback.Host);
        Assert.NotNull(query["code"]);
        Assert.Equal("opaque-state", query["state"]);
        Assert.Equal(Build.Issuer, query["iss"]);

        // And the code is real: it exchanges.
        var tokens = await fixture.Client.PostAsync("/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", query["code"]!),
            new("client_id", ClientId),
            new("code_verifier", Verifier.Value),
        ]));

        Assert.Equal(HttpStatusCode.OK, tokens.StatusCode);
    }

    /// <summary>Denying redirects to the client with <c>access_denied</c>, not to an error page.</summary>
    [Fact]
    public async Task Denying_consent_redirects_to_the_client_with_access_denied()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());
        var (field, token, returnUrl) = FormFields(page);

        var denied = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", returnUrl),
            new("decision", "deny"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, denied.StatusCode);

        var query = HttpUtility.ParseQueryString(new Uri(denied.Headers.Location!.ToString()).Query);

        Assert.Equal("access_denied", query["error"]);
        Assert.Equal("opaque-state", query["state"]);
        Assert.Equal(Build.Issuer, query["iss"]);
        Assert.Null(query["code"]);
    }

    /// <summary>
    /// The consent page names the <c>client_id</c> host and the redirect host. N-14.
    /// </summary>
    /// <remarks>
    /// The hostname is the entire mitigation for a self-asserted client name: anyone can publish
    /// <c>{"client_name":"Claude"}</c> at their own URL, and nobody else can publish it at
    /// <c>claude.ai</c>. The redirect host is the mitigation for the attack CIMD structurally
    /// cannot prevent — an attacker presenting the real client's metadata document and binding their
    /// own callback.
    /// </remarks>
    [Fact]
    public async Task The_consent_page_shows_both_hosts_and_the_scope_description()
    {
        await using var fixture = await LoopbackClientAsync();

        var start = await fixture.Client.GetAsync(LoopbackAuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());

        // Asserted against the rendered markup, not against the page text. Both hosts also appear
        // inside the hidden returnUrl field — it carries the whole authorization query — so a
        // substring search passes with the display lines deleted. Measured: dropping the
        // redirect-host line failed nothing until these assertions named the markup around it.
        Assert.Contains("<strong>claude.ai</strong>", page, StringComparison.Ordinal);
        Assert.Contains("<strong>127.0.0.1</strong>", page, StringComparison.Ordinal);

        Assert.Contains("Use the tools this server provides", page, StringComparison.Ordinal);
    }

    /// <summary>A loopback-only client gets the warning N-14 requires.</summary>
    /// <remarks>
    /// Its callback is a port any process on the user's machine could have bound, and the consent
    /// page is the only place that fact can be surfaced. Claude Code is the live case.
    /// </remarks>
    [Fact]
    public async Task A_loopback_only_client_is_flagged_on_the_consent_page()
    {
        await using var fixture = await LoopbackClientAsync();

        var start = await fixture.Client.GetAsync(LoopbackAuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());

        Assert.Contains("on your own device", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A private-use-scheme client gets the same warning, and a destination it can read.
    /// </summary>
    /// <remarks>
    /// RFC 8252 §7.1's other native-app shape, and it had neither. The flag tested only
    /// <c>RedirectKind.Loopback</c>, so no warning; and <c>Uri.Host</c> is empty for a URI with no
    /// authority, so the page rendered "the code will be sent to &lt;strong&gt;&lt;/strong&gt;" —
    /// measured. §8.4 is explicit that any application can register a private-use scheme and the
    /// operating system does not adjudicate, which is the same risk the loopback warning exists for.
    /// </remarks>
    [Fact]
    public async Task A_private_use_scheme_client_is_flagged_and_shows_its_scheme()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public, "com.example.app:/oauth2redirect");
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
        });

        var url = "/authorize?response_type=code"
            + "&client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString("com.example.app:/oauth2redirect")
            + "&code_challenge=" + Verifier.ComputeS256Challenge()
            + "&code_challenge_method=S256"
            + "&scope=" + Uri.EscapeDataString("mcp:tools offline_access")
            + "&resource=" + Uri.EscapeDataString(Build.Resource)
            + "&state=opaque-state";

        var start = await fixture.Client.GetAsync(url);
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());

        Assert.Contains("on your own device", page, StringComparison.Ordinal);

        // The destination line specifically, not merely the string somewhere on the page — the
        // hidden returnUrl field carries the whole authorization request, so "contains the scheme"
        // is satisfied by a page that displays nothing at all. That exact substitution has been
        // measured in this file twice.
        Assert.Contains(
            "sent to <strong>com.example.app</strong>", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A client disabled while the consent page was open cannot be approved.
    /// </summary>
    /// <remarks>
    /// The consent POST re-runs the whole pipeline rather than trusting the page that rendered, so
    /// every decision — client resolution included — is made against this request. Without that, an
    /// approval would complete against state that changed while the user was reading.
    /// </remarks>
    [Fact]
    public async Task A_client_disabled_while_the_page_was_open_cannot_be_approved()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());
        var (field, token, returnUrl) = FormFields(page);

        fixture.DisableClient(ClientId);

        var approved = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", returnUrl),
            new("decision", "approve"),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, approved.StatusCode);
    }

    /// <summary>
    /// A scope with no configured description shows the raw scope and says so. A-14.
    /// </summary>
    /// <remarks>
    /// Never a description derived by parsing the name — the failure that rule comes from is a page
    /// that assumed <c>action:resource</c> and rendered "read: story your read" as the thing a user
    /// was agreeing to.
    /// </remarks>
    [Fact]
    public async Task An_undescribed_scope_is_shown_raw_with_a_warning()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());

        Assert.Contains("offline_access", page, StringComparison.Ordinal);
        Assert.Contains("no description configured", page, StringComparison.Ordinal);
    }

    /// <summary>A consent POST with no antiforgery token is refused.</summary>
    /// <remarks>
    /// Without it, the consent form is a state-changing POST on our origin that any page can submit:
    /// the attacker crafts an authorization request for their own client, lures the user to a page
    /// that auto-submits <c>decision=approve</c>, and the browser supplies the session cookie.
    /// <c>state</c> protects the client and does nothing here. This is the check the minimal-API
    /// middleware would have skipped silently, because these handlers read the form by hand.
    /// </remarks>
    [Fact]
    public async Task A_consent_post_without_an_antiforgery_token_is_refused()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());
        var (_, _, returnUrl) = FormFields(page);

        var forged = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new("returnUrl", returnUrl),
            new("decision", "approve"),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
    }

    /// <summary>
    /// A <c>returnUrl</c> pointing off-origin is refused, on both pages and both methods.
    /// </summary>
    /// <remarks>
    /// The open-redirect case N-11 is about. These pages live on the one origin the user has been
    /// taught to type a password into, so a redirect off it is a phishing hand-off this server
    /// performed.
    /// </remarks>
    [Theory]
    [InlineData("/consent")]
    [InlineData("/login")]
    public async Task A_foreign_return_url_is_refused(string page)
    {
        await using var fixture = await PublicClientAsync();

        foreach (var hostile in new[] { "//evil.example", "https://evil.example", "/\\evil.example", "/logout" })
        {
            var response = await fixture.Client.GetAsync($"{page}?returnUrl={Uri.EscapeDataString(hostile)}");

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.DoesNotContain("evil.example", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    /// <summary>Every interactive page carries the N-15 headers.</summary>
    [Theory]
    [InlineData("/login")]
    [InlineData("/consent")]
    [InlineData("/error")]
    public async Task An_interactive_page_carries_the_security_headers(string path)
    {
        await using var fixture = await PublicClientAsync();

        var response = await fixture.Client.GetAsync($"{path}?returnUrl=%2Fauthorize");

        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    /// <summary>
    /// The consent POST re-validates the request rather than trusting the page.
    /// </summary>
    /// <remarks>
    /// A user can edit any hidden field before submitting. The scope that reaches the grant comes
    /// from re-running the pipeline over the <c>returnUrl</c>, so an edited <c>scope</c> field is a
    /// value that is read and then thrown away.
    /// </remarks>
    [Fact]
    public async Task A_tampered_scope_field_does_not_widen_the_grant()
    {
        await using var fixture = await PublicClientAsync();

        var start = await fixture.Client.GetAsync(AuthorizeUrl());
        var page = await fixture.Client.GetStringAsync(start.Headers.Location!.ToString());
        var (field, token, returnUrl) = FormFields(page);

        var approved = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", returnUrl),
            new("decision", "approve"),
            new("scope", "mcp:tools offline_access admin:everything"),
        ]));

        var code = HttpUtility.ParseQueryString(new Uri(approved.Headers.Location!.ToString()).Query)["code"]!;

        var tokens = await fixture.Client.PostAsync("/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("client_id", ClientId),
            new("code_verifier", Verifier.Value),
        ]));

        var body = await tokens.Content.ReadAsStringAsync();

        Assert.DoesNotContain("admin:everything", body, StringComparison.Ordinal);
    }
}
