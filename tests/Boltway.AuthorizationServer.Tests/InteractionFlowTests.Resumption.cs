using System.Net;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Interaction;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// What the consent POST re-checks, and what it used to skip.
/// </summary>
/// <remarks>
/// <para>
/// The consent page holds a URL, not a decision, and re-derives everything from it. That was true of
/// stages 1 to 8 — client resolution, exact redirect matching, PKCE, scope — and false of stages 9
/// and 10, which existed only in the authorization endpoint. Two adversarial probes reached an
/// authorization code through the gap, one past an explicit policy refusal and one past an
/// unsatisfied <c>max_age</c>.
/// </para>
/// <para>
/// These tests are written as the attack, not as the unit: start at <c>/authorize</c>, observe it
/// refuse, then post the same <c>returnUrl</c> to <c>/consent</c> and require the same refusal. A
/// test that called the resumption helper directly would pass over a wiring change that stopped
/// calling it.
/// </para>
/// </remarks>
public sealed partial class InteractionFlowTests
{
    /// <summary>
    /// A policy refusal cannot be converted into a code by going straight to the consent page.
    /// </summary>
    /// <remarks>
    /// <c>IConsentDecision.Denied</c> is documented as "Policy refuses. <c>access_denied</c>", and it
    /// is the seam a deployment uses for a client blocklist, a per-tenant allowlist or a risk
    /// engine. Measured before the fix: <c>/authorize</c> redirected with <c>access_denied</c>, and
    /// <c>GET /consent</c> on the same returnUrl rendered a full approve form whose POST returned
    /// <c>?code=bw_ac_…</c>. No CSRF and no interception needed — any signed-in user, one URL.
    /// </remarks>
    [Fact]
    public async Task A_denied_policy_cannot_be_bypassed_by_posting_to_the_consent_page()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public);
            seed.Consent = ConsentDecision.Denied;
        });

        // /authorize refuses, which is the behaviour the bypass contradicted.
        var start = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);
        Assert.Contains("error=access_denied", start.Headers.Location!.ToString(), StringComparison.Ordinal);

        // The attacker's move: skip /authorize and drive the consent page directly.
        var (field, token, returnUrl) = await ConsentFormAsync(fixture, ConsentDecision.Denied);

        var approve = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [field] = token,
                ["returnUrl"] = returnUrl,
                ["decision"] = "approve",
            }));

        var location = approve.Headers.Location?.ToString() ?? string.Empty;

        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
        Assert.Contains("error=access_denied", location, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unsatisfied <c>max_age</c> cannot be bypassed by posting to the consent page.
    /// </summary>
    /// <remarks>
    /// The seeded session authenticates at 11:00 and the clock reads 12:00, so <c>max_age=60</c> is
    /// an hour past. Measured before the fix: <c>/authorize</c> sent the user to <c>/login</c>, and
    /// posting the same returnUrl to <c>/consent</c> returned a code carrying the hour-old
    /// <c>auth_time</c> — so a relying party that asked for recent authentication was told it
    /// happened. OIDC Core §3.1.2.1 makes the re-authentication a MUST.
    /// </remarks>
    [Theory]
    [InlineData("&max_age=60")]
    [InlineData("&prompt=login")]
    public async Task A_request_needing_reauthentication_cannot_be_completed_at_the_consent_page(string extra)
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public);
        });

        var url = AuthorizeUrl(extra);

        // /authorize sends the user to sign in again.
        var start = await fixture.Client.GetAsync(url);

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);
        Assert.StartsWith("/login", start.Headers.Location!.ToString(), StringComparison.Ordinal);

        // Posting the request straight to /consent must reach the same conclusion. The antiforgery
        // pair is minted on the login page, which is where this user actually is.
        var (field, token) = await LoginFormTokenAsync(fixture, url);

        var approve = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [field] = token,
                ["returnUrl"] = url,
                ["decision"] = "approve",
            }));

        var location = approve.Headers.Location?.ToString() ?? string.Empty;

        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
        Assert.StartsWith("/login", location, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control: with a fresh session and a permitting policy, the same POST does issue a code.
    /// </summary>
    /// <remarks>
    /// Without this, both tests above are satisfied by a consent endpoint that refuses everything —
    /// which is a different bug with the same green tick, and one that would break both vendors.
    /// </remarks>
    [Fact]
    public async Task The_consent_post_still_issues_a_code_when_nothing_is_wrong()
    {
        await using var fixture = await PublicClientAsync();

        var (field, token, returnUrl) = await ConsentFormAsync(fixture, ConsentDecision.Required);

        var approve = await fixture.Client.PostAsync("/consent", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [field] = token,
                ["returnUrl"] = returnUrl,
                ["decision"] = "approve",
            }));

        Assert.Equal(HttpStatusCode.SeeOther, approve.StatusCode);
        Assert.Contains("code=", approve.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A self-asserted name is rendered readably, and exactly once.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The name was HTML-encoded by the model builder and again by the renderer, so
    /// <c>Acme &amp; "Claude"</c> displayed to the user as the literal text
    /// <c>Acme &amp;amp; &amp;quot;Claude&amp;quot;</c> and <c>Café</c> as <c>Caf&amp;#233;</c>. On
    /// the page whose job is to be read carefully, the field meant to be read carefully was
    /// mojibake. Nothing caught it because <c>Build.Client</c> never sets <c>ClientName</c>, so the
    /// entire self-asserted-name path was dead code across the whole suite.
    /// </para>
    /// <para>
    /// Both directions are asserted: the name arrives intact once decoded, and the raw
    /// <c>&lt;script&gt;</c> does not appear — encoding once is the requirement, not encoding less.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_self_asserted_name_is_encoded_once_and_stays_readable()
    {
        const string Name = "Acme & \"Claude\" <script>alert(1)</script> Café";

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public) with { ClientName = Name };
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
        });

        var page = await fixture.Client.GetStringAsync(
            "/consent?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

        // Not injected: the raw tag never reaches the document.
        Assert.DoesNotContain("<script>alert(1)</script>", page, StringComparison.Ordinal);

        // And not double-encoded: decoding the page once yields the name the client asserted. Under
        // the old behaviour this decoded to `Acme &amp; &quot;Claude&quot; …`, which is what the
        // user actually saw.
        var decoded = System.Net.WebUtility.HtmlDecode(page);

        Assert.Contains("Acme & \"Claude\"", decoded, StringComparison.Ordinal);
        Assert.Contains("Café", decoded, StringComparison.Ordinal);
    }

    /// <summary>
    /// The cap is on what the user sees, and the hostname survives a hostile name.
    /// </summary>
    /// <remarks>
    /// The cap exists so a name cannot push the client's real hostname off the screen. Double
    /// encoding expanded each <c>&lt;</c> to six rendered characters, so a name at the 64-character
    /// limit displayed as roughly 256 — about four times the intended budget, which is the failure
    /// the cap was written to prevent, arriving through the encoder instead of through the length.
    /// </remarks>
    [Fact]
    public async Task A_long_hostile_name_is_capped_and_does_not_displace_the_hostname()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public)
                with { ClientName = new string('<', 300) };
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
        });

        var page = await fixture.Client.GetStringAsync(
            "/consent?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

        // The name's own region, not the whole page. Counting document-wide conflates the cap with
        // the four tags of the paragraph that wraps the name, and the number then measures the
        // template.
        //
        // The longest run of encoded angle brackets, which is the name and nothing else. It used to
        // be the text between "It calls itself &ldquo;" and "&rdquo;", and that stopped matching the
        // moment those words became a translatable string — the quotation marks belong to a sentence
        // a deployment owns now, and they arrive as &#8220; rather than &ldquo;. A test anchored on
        // prose fails on the translation rather than on the defect, which is why the renderer
        // contract next door refuses to assert wording at all.
        var displayed = System.Net.WebUtility.HtmlDecode(
            System.Text.RegularExpressions.Regex.Matches(page, "(?:&lt;)+")
                .Select(m => m.Value)
                .OrderByDescending(v => v.Length)
                .FirstOrDefault() ?? string.Empty);

        Assert.True(
            displayed.Length <= ConsentModelBuilder.MaxClientNameLength,
            $"The name displayed as {displayed.Length} characters; the cap is "
            + $"{ConsentModelBuilder.MaxClientNameLength}. Under double encoding a name of angle "
            + "brackets rendered at roughly four times this, because each '<' became the six "
            + "characters '&lt;' — the cap held on the wire and not on the screen, and the screen is "
            + "what it is for.");

        // A control, since "short enough" is also satisfied by a page that dropped the name.
        Assert.Contains('<', displayed);

        // N-14's actual requirement: the identity is present, and ahead of the self-asserted name.
        var host = page.IndexOf("claude.ai", StringComparison.Ordinal);
        var name = page.IndexOf("&lt;", StringComparison.Ordinal);

        Assert.True(host >= 0 && name > host, "The client host must appear, and appear before the self-asserted name.");
    }

    private static string Between(string haystack, string start, string end)
    {
        var from = haystack.IndexOf(start, StringComparison.Ordinal);

        Assert.True(from >= 0, $"The page does not contain '{start}', so there is nothing to measure.");

        from += start.Length;

        var to = haystack.IndexOf(end, from, StringComparison.Ordinal);

        Assert.True(to > from, $"The page does not contain '{end}' after '{start}'.");

        return haystack[from..to];
    }

    /// <summary>
    /// Render the consent page and read its hidden fields.
    /// </summary>
    /// <param name="policy">
    /// What the fixture's policy answers. For the denied case the page is fetched from a *separate*
    /// fixture that permits, because a denied policy is exactly what stops the page rendering once
    /// the fix is in — and the returnUrl, which is all the POST actually carries, is identical
    /// either way. That is the point of the attack: the URL is not a capability.
    /// </param>
    private static async Task<(string Field, string Token, string ReturnUrl)> ConsentFormAsync(
        FlowFixture fixture, ConsentDecision policy)
    {
        if (policy is ConsentDecision.Denied)
        {
            await using var permissive = await PublicClientAsync();

            var page = await permissive.Client.GetStringAsync(
                "/consent?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

            var borrowed = FormFields(page);

            // The antiforgery pair has to come from the fixture the POST goes to — it is bound to
            // that host's data-protection keys — so only the returnUrl is borrowed.
            var (field, token, _) = await ConsentTokenFromLoginAsync(fixture);

            return (field, token, borrowed.ReturnUrl);
        }

        var html = await fixture.Client.GetStringAsync(
            "/consent?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

        return FormFields(html);
    }

    /// <summary>An antiforgery pair for this fixture, minted by any page that renders a form.</summary>
    private static async Task<(string Field, string Token, string ReturnUrl)> ConsentTokenFromLoginAsync(
        FlowFixture fixture)
    {
        var html = await fixture.Client.GetStringAsync(
            "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

        return FormFields(html);
    }

    private static async Task<(string Field, string Token)> LoginFormTokenAsync(FlowFixture fixture, string returnUrl)
    {
        var html = await fixture.Client.GetStringAsync("/login?returnUrl=" + Uri.EscapeDataString(returnUrl));
        var (field, token, _) = FormFields(html);

        return (field, token);
    }
}
