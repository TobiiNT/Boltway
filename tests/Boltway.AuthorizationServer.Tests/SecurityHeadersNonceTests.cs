using System.Text.RegularExpressions;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The opt-in CSP nonce, from the policy string to the bytes on the page.
/// </summary>
/// <remarks>
/// A nonce is worth having only if three things hold at once: the header names it, the page carries
/// the same one, and it is different next time. Any two without the third is a page that either
/// does not run or is not protected, so all three are measured here rather than assumed from the
/// generation code being correct.
/// </remarks>
public sealed partial class SecurityHeadersNonceTests
{
    [GeneratedRegex(@"'nonce-(?<value>[A-Za-z0-9+/_=-]+)'")]
    private static partial Regex NonceInPolicy();

    private static async Task<FlowFixture> NoncedAsync(Action<IServiceCollection>? services = null) =>
        await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
            seed.ConfigureOptions = o => o.Interaction.UseContentSecurityPolicyNonce = true;
            seed.ConfigureServices = services;
        });

    private static async Task<(string Policy, string Page)> LoginAsync(FlowFixture fixture)
    {
        var response = await fixture.Client.GetAsync("/login?returnUrl=%2Fauthorize");

        return (
            response.Headers.GetValues("Content-Security-Policy").Single(),
            await response.Content.ReadAsStringAsync());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Off, which is the default
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// With no nonce configured, the policy is exactly what it was before nonces existed.
    /// </summary>
    /// <remarks>
    /// The shipped pages have no inline content, so a nonce would be a token in a header that
    /// nothing uses - and a <c>script-src</c> naming it would replace the <c>default-src</c>
    /// fallback for scripts, which is a change to what the page may load made for no reason.
    /// </remarks>
    [Fact]
    public async Task An_unconfigured_deployment_sends_no_nonce_and_no_script_src()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public));

        var (policy, page) = await LoginAsync(fixture);

        Assert.DoesNotContain("nonce", policy, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("script-src", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("style-src", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("nonce", page, StringComparison.OrdinalIgnoreCase);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // On
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_nonced_deployment_names_the_nonce_in_both_script_and_style_src()
    {
        await using var fixture = await NoncedAsync();

        var (policy, _) = await LoginAsync(fixture);
        var nonce = NonceInPolicy().Match(policy).Groups["value"].Value;

        Assert.NotEmpty(nonce);
        Assert.Contains($"script-src 'self' 'nonce-{nonce}'", policy, StringComparison.Ordinal);
        Assert.Contains($"style-src 'self' 'nonce-{nonce}'", policy, StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>'self'</c> survives inside the two new directives.
    /// </summary>
    /// <remarks>
    /// Naming <c>script-src</c> replaces the <c>default-src</c> fallback for scripts entirely, so
    /// dropping <c>'self'</c> from it would stop the deployment's own stylesheet and script files
    /// loading the moment a nonce was switched on - an unstyled page with a perfectly working nonce,
    /// and nothing connecting the two.
    /// </remarks>
    [Fact]
    public async Task Turning_a_nonce_on_does_not_stop_same_origin_files_loading()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
            seed.ConfigureOptions = o =>
            {
                o.Interaction.UseContentSecurityPolicyNonce = true;
                o.Interaction.StylesheetPaths.Add("/css/authorization.css");
            };
        });

        var (policy, page) = await LoginAsync(fixture);

        Assert.Contains("style-src 'self' ", policy, StringComparison.Ordinal);
        Assert.Contains("script-src 'self' ", policy, StringComparison.Ordinal);
        Assert.Contains("/css/authorization.css", page, StringComparison.Ordinal);
    }

    /// <summary>The directives a nonce must never bring with it.</summary>
    /// <remarks>
    /// A nonce is the alternative to <c>'unsafe-inline'</c>, not a step toward it. With a nonce
    /// present a CSP2 browser ignores <c>'unsafe-inline'</c> anyway - so emitting both would be a
    /// policy that reads as permissive, behaves as strict, and misleads whoever audits it next.
    /// </remarks>
    [Fact]
    public async Task A_nonce_never_arrives_with_unsafe_inline_or_unsafe_eval()
    {
        await using var fixture = await NoncedAsync();

        var (policy, _) = await LoginAsync(fixture);

        Assert.DoesNotContain("unsafe-inline", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("unsafe-eval", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("strict-dynamic", policy, StringComparison.Ordinal);
    }

    /// <summary>The clickjacking directives are untouched by any of this.</summary>
    [Fact]
    public async Task A_nonce_changes_nothing_else_about_the_policy()
    {
        await using var fixture = await NoncedAsync();

        var (policy, _) = await LoginAsync(fixture);

        Assert.Contains("default-src 'self'", policy, StringComparison.Ordinal);
        Assert.Contains("form-action 'self'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("base-uri 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("object-src 'none'", policy, StringComparison.Ordinal);
    }

    /// <summary>
    /// A different nonce every response.
    /// </summary>
    /// <remarks>
    /// The property the whole mechanism rests on. A nonce reused across responses is a nonce an
    /// attacker who has seen one page can put on their own injected script - which is every
    /// protection gone, with the header still looking exactly right. These pages send
    /// <c>Cache-Control: no-store</c>, which is what stops a cache reintroducing the reuse that
    /// this proves the server does not.
    /// </remarks>
    [Fact]
    public async Task Every_response_gets_its_own_nonce()
    {
        await using var fixture = await NoncedAsync();

        List<string> seen = [];

        for (var i = 0; i < 5; i++)
        {
            var (policy, _) = await LoginAsync(fixture);
            seen.Add(NonceInPolicy().Match(policy).Groups["value"].Value);
        }

        Assert.DoesNotContain(string.Empty, seen);
        Assert.Equal(5, seen.Distinct(StringComparer.Ordinal).Count());

        // 16 bytes, base64url - 22 characters. Short of that is a generator someone shortened.
        Assert.All(seen, nonce => Assert.True(nonce.Length >= 22, $"'{nonce}' is {nonce.Length} characters."));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The page and the header agree
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The nonce a layout is handed is the nonce in the header of that same response.
    /// </summary>
    /// <remarks>
    /// The end of the plumbing, and the only part that cannot be checked without an HTTP round trip:
    /// <c>SecurityHeaders</c> mints it, the endpoint reads it onto the view model, the renderer
    /// copies it onto <c>InteractionPage</c>, and the layout writes it into an attribute - while the
    /// header is written separately, at commit time. Two values that must be one.
    /// </remarks>
    [Fact]
    public async Task The_nonce_on_the_page_is_the_nonce_in_the_header()
    {
        await using var fixture = await NoncedAsync(
            services => services.AddSingleton<IInteractionLayout, NoncedLayout>());

        var (policy, page) = await LoginAsync(fixture);
        var nonce = NonceInPolicy().Match(policy).Groups["value"].Value;

        Assert.NotEmpty(nonce);
        Assert.Contains($"<script nonce=\"{nonce}\">", page, StringComparison.Ordinal);
    }

    /// <summary>A layout that wants inline content only gets it when a deployment asked for a nonce.</summary>
    /// <remarks>
    /// With the option off the model carries <see langword="null"/>, so a layout written this way
    /// emits nothing inline rather than emitting a block the browser will refuse. That is the shape
    /// to copy: branch on the nonce, never assume it.
    /// </remarks>
    [Fact]
    public async Task The_same_layout_emits_nothing_inline_when_no_nonce_is_configured()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client("https://claude.ai/c.json", ClientType.Public);
            seed.ConfigureServices = services => services.AddSingleton<IInteractionLayout, NoncedLayout>();
        });

        var (_, page) = await LoginAsync(fixture);

        Assert.DoesNotContain("<script", page, StringComparison.Ordinal);
    }

    /// <summary>A layout of the kind the nonce exists for.</summary>
    private sealed class NoncedLayout : IInteractionLayout
    {
        public string Wrap(InteractionPage page)
        {
            ArgumentNullException.ThrowIfNull(page);

            var script = page.Nonce is null
                ? string.Empty
                : $"<script nonce=\"{page.Nonce}\">document.title=document.title;</script>";

            return "<!DOCTYPE html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
                + "<title>Northwind</title></head><body>"
                + page.Body
                + script
                + "</body></html>";
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The policy builder itself
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A widened <c>form-action</c> and a nonce compose rather than displacing each other.
    /// </summary>
    /// <remarks>
    /// They are set at different moments - the redirect origin is learned mid-pipeline and parked,
    /// the nonce is minted at the top of the handler - and both are read at commit time. A builder
    /// that handled one branch at a time would drop whichever was written second, and the symptom
    /// would be a sign-in that completes and delivers no code.
    /// </remarks>
    [Fact]
    public void The_policy_carries_a_widened_form_action_and_a_nonce_together()
    {
        var policy = SecurityHeaders.PolicyFor("https://claude.ai", "abc123");

        Assert.Contains("form-action 'self' https://claude.ai;", policy, StringComparison.Ordinal);
        Assert.Contains("script-src 'self' 'nonce-abc123'", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
    }

    [Fact]
    public void The_policy_with_neither_is_the_shipped_constant()
    {
        Assert.Equal(SecurityHeaders.ContentSecurityPolicy, SecurityHeaders.PolicyFor(null, null));
    }
}
