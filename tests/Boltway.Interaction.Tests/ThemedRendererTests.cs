using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;

using Boltway.Interaction.Testing;

namespace Boltway.Interaction.Tests;

/// <summary>
/// The whole contract, against a themed renderer.
/// </summary>
/// <remarks>
/// <b>This class is the argument for tier one existing.</b> The claim made for theme options is
/// that a deployment can rebrand these pages without taking on responsibility for N-14, and the
/// claim is only worth anything if something checks it. Running the same twenty-two assertions
/// against a renderer carrying a stylesheet, a logo and a product name is that check: no setting
/// here can drop the client hostname, reorder it behind the self-asserted name, lose the device
/// warning, or put something on the page the CSP will refuse.
/// </remarks>
public sealed class ThemedDefaultInteractionRendererTests : InteractionRendererContract
{
    /// <inheritdoc />
    protected override IInteractionRenderer NewRenderer()
    {
        var options = new InteractionOptions
        {
            ProductName = "Northwind",
            LogoPath = "/img/northwind.svg",
        };

        options.StylesheetPaths.Add("/css/base.css");
        options.StylesheetPaths.Add("/css/northwind.css");

        return new DefaultInteractionRenderer(options);
    }
}

/// <summary>The theme reaches the page, in the places it is supposed to and no others.</summary>
public sealed class ThemeRenderingTests
{
    private static readonly ConsentViewModel Model = new()
    {
        ClientHost = "claude.ai",
        RedirectHost = "claude.ai",
        RedirectsToThisDevice = false,
        ClientName = "Claude",
        ClientLogoUrl = null,
        Scopes = [new ConsentScope("docs:read", "Read the knowledge base", true)],
        Resources = [],
        ReturnUrl = "/authorize?client_id=x",
        AntiforgeryFieldName = "__RequestVerificationToken",
        AntiforgeryToken = "token",
        Nonce = null,
    };

    private static DefaultInteractionRenderer Themed(Action<InteractionOptions> configure)
    {
        var options = new InteractionOptions();
        configure(options);

        return new DefaultInteractionRenderer(options);
    }

    /// <summary>Stylesheets are linked in the order they were configured - for CSS, order is meaning.</summary>
    [Fact]
    public void Stylesheets_are_linked_in_configuration_order()
    {
        var html = Themed(options =>
        {
            options.StylesheetPaths.Add("/css/base.css");
            options.StylesheetPaths.Add("/css/override.css");
        }).RenderConsent(Model);

        var first = html.IndexOf("/css/base.css", StringComparison.Ordinal);
        var second = html.IndexOf("/css/override.css", StringComparison.Ordinal);

        Assert.True(first >= 0 && second >= 0, "A configured stylesheet is not linked at all.");
        Assert.True(first < second, "Stylesheets were linked out of configuration order.");
    }

    [Fact]
    public void An_unthemed_renderer_links_no_stylesheet_and_shows_no_logo()
    {
        var html = new DefaultInteractionRenderer().RenderConsent(Model);

        Assert.DoesNotContain("<link", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<img", html, StringComparison.Ordinal);
    }

    [Fact]
    public void The_product_name_is_in_the_title()
    {
        var html = Themed(options => options.ProductName = "Northwind").RenderConsent(Model);

        // Decoded, because the separator is non-ASCII and a correct renderer writes it as `&#183;`.
        // Asserting the raw character would be asserting the title was left unencoded.
        Assert.Contains("<title>Authorize access · Northwind</title>", Markup.Decoded(html), StringComparison.Ordinal);
    }

    /// <summary>
    /// The product name reaches the title and nothing else.
    /// </summary>
    /// <remarks>
    /// The reason it is a title and not a heading. The most prominent text on the consent page is
    /// the client hostname, by N-14, and a deployment name competing with it for that position would
    /// be this option quietly undoing the requirement - with the operator who set it having been
    /// given no reason to think it might.
    /// </remarks>
    [Fact]
    public void The_product_name_is_not_in_the_body()
    {
        var html = Themed(options => options.ProductName = "Northwind").RenderConsent(Model);

        var body = html[html.IndexOf("<body>", StringComparison.Ordinal)..];

        Assert.DoesNotContain("Northwind", body, StringComparison.Ordinal);
    }

    [Fact]
    public void A_logo_carries_the_product_name_as_its_alt_text()
    {
        var html = Themed(options =>
        {
            options.LogoPath = "/img/northwind.svg";
            options.ProductName = "Northwind";
        }).RenderConsent(Model);

        Assert.Contains("<img src=\"/img/northwind.svg\" alt=\"Northwind\">", html, StringComparison.Ordinal);
    }

    /// <summary>A logo with no product name announces nothing rather than something invented.</summary>
    [Fact]
    public void A_logo_without_a_product_name_has_empty_alt_text()
    {
        var html = Themed(options => options.LogoPath = "/img/northwind.svg").RenderConsent(Model);

        Assert.Contains("<img src=\"/img/northwind.svg\" alt=\"\">", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two cautions carry a stable hook a stylesheet can find them by.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Pinned here rather than in the contract, deliberately. The contract is for renderers this
    /// repository did not write and must not dictate their markup; this is the shipped renderer's
    /// own output, and a stylesheet ships with it that selects on exactly this.
    /// </para>
    /// <para>
    /// The class exists because CSS cannot find these paragraphs without it. `p:has(> strong:first-child)`
    /// was tried and measured wrong on the first render: `:first-child` counts elements and ignores
    /// the leading text node, so the paragraphs naming the client host and the redirect host matched
    /// too and the page came back with three warning boxes - which is the same as none, because the
    /// one N-14 asks for no longer stood out.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_device_warning_and_the_sign_in_error_carry_the_same_hook()
    {
        var renderer = new DefaultInteractionRenderer();

        var consent = renderer.RenderConsent(Model with { RedirectsToThisDevice = true });
        var login = renderer.RenderLogin(new LoginViewModel
        {
            ReturnUrl = "/authorize",
            Rejected = true,
            AntiforgeryFieldName = "__RequestVerificationToken",
            AntiforgeryToken = "token",
            Nonce = null,
            LocalPasswordsEnabled = true,
            ExternalProviders = [],
            PasswordRecoveryEnabled = false,
        });

        Assert.Contains("<p class=\"bw-warning\">", consent, StringComparison.Ordinal);
        Assert.Contains("<p class=\"bw-warning\">", login, StringComparison.Ordinal);

        // Exactly one on the consent page: the hostnames are information, not warnings, and a page
        // where everything is emphasised has emphasised nothing.
        Assert.Equal(1, consent.Split("bw-warning", StringSplitOptions.None).Length - 1);
    }

    /// <summary>A consent page with no device redirect has no warning to carry the hook.</summary>
    [Fact]
    public void A_web_redirect_gets_no_warning_box()
    {
        var html = new DefaultInteractionRenderer().RenderConsent(Model with { RedirectsToThisDevice = false });

        Assert.DoesNotContain("bw-warning", html, StringComparison.Ordinal);
    }

    [Fact]
    public void The_theme_reaches_the_login_page_too()
    {
        var html = Themed(options =>
        {
            options.StylesheetPaths.Add("/css/northwind.css");
            options.ProductName = "Northwind";
        }).RenderLogin(new LoginViewModel
        {
            ReturnUrl = "/authorize?client_id=x",
            Rejected = false,
            AntiforgeryFieldName = "__RequestVerificationToken",
            AntiforgeryToken = "token",
            Nonce = null,
            LocalPasswordsEnabled = true,
            ExternalProviders = [],
            PasswordRecoveryEnabled = false,
        });

        Assert.Contains("/css/northwind.css", html, StringComparison.Ordinal);
        Assert.Contains("<title>Sign in · Northwind</title>", Markup.Decoded(html), StringComparison.Ordinal);
    }
}
