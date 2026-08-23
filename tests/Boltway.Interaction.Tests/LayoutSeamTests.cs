using Boltway.AuthorizationServer.Interaction;

using Boltway.Interaction.Testing;

namespace Boltway.Interaction.Tests;

/// <summary>
/// A deployment's own shell, with the server still rendering the page inside it.
/// </summary>
/// <remarks>
/// <b>This class is the argument for tier two existing.</b> The layout below is the kind a real
/// deployment writes — a header, a nav, a footer, its own classes, nothing like the shipped shell —
/// and the whole renderer contract is run through it. Twenty-two assertions about N-14, A-11, A-14
/// and the CSP, none of which the layout author had to know about, all still true.
/// </remarks>
public sealed class BrandedLayoutRendererTests : InteractionRendererContract
{
    /// <inheritdoc />
    protected override IInteractionRenderer NewRenderer() => new DefaultInteractionRenderer(new BrandedLayout());

    /// <summary>A layout with nothing in common with the shipped one but the rule it obeys.</summary>
    private sealed class BrandedLayout : IInteractionLayout
    {
        public string Wrap(InteractionPage page)
        {
            ArgumentNullException.ThrowIfNull(page);

            return "<!DOCTYPE html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
                + "<link rel=\"stylesheet\" href=\"/assets/northwind.css\">"
                + $"<title>Northwind — {System.Net.WebUtility.HtmlEncode(page.Title)}</title></head>"
                + "<body class=\"northwind auth\">"
                + "<header class=\"northwind-header\"><img src=\"/assets/mark.svg\" alt=\"Northwind\"></header>"
                + $"<main class=\"card {page.Kind.ToString().ToLowerInvariant()}\">"
                + page.Body
                + "</main>"
                + "<footer class=\"northwind-footer\"><a href=\"/privacy\">Quyền riêng tư</a></footer>"
                + "</body></html>";
        }
    }
}

/// <summary>
/// What happens when a layout does not do the one thing a layout must.
/// </summary>
/// <remarks>
/// Without these, the middle tier would be the top tier with a smaller interface — a deployment
/// could ship a consent page with no client hostname, no scope list and no form, and the first
/// symptom would be a user who cannot connect. The check exists so the failure lands on the person
/// writing the layout, at the first render, in their own testing.
/// </remarks>
public sealed class LayoutGuardTests
{
    private static readonly ConsentViewModel Consent = new()
    {
        ClientHost = "evil.example",
        RedirectHost = "127.0.0.1",
        RedirectsToThisDevice = true,
        ClientName = "Claude",
        ClientLogoUrl = null,
        Scopes = [new ConsentScope("docs:read", "Read the knowledge base", true)],
        Resources = [],
        ReturnUrl = "/authorize?client_id=x",
        AntiforgeryFieldName = "__RequestVerificationToken",
        AntiforgeryToken = "token",
        Nonce = null,
    };

    private sealed class Layout(Func<InteractionPage, string?> wrap) : IInteractionLayout
    {
        public string Wrap(InteractionPage page) => wrap(page)!;
    }

    private static string Render(Func<InteractionPage, string?> wrap) =>
        new DefaultInteractionRenderer(new Layout(wrap)).RenderConsent(Consent);

    [Fact]
    public void A_layout_that_drops_the_body_is_refused()
    {
        var failure = Assert.Throws<InvalidOperationException>(() =>
            Render(page => "<!DOCTYPE html><html><body><h1>Northwind</h1></body></html>"));

        Assert.Contains("did not include InteractionPage.Body", failure.Message, StringComparison.Ordinal);
        Assert.Contains("Consent", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A layout that encodes the body is refused, and it is the likeliest mistake of the two.
    /// </summary>
    /// <remarks>
    /// Every other string a layout touches is plain text that must be encoded, so encoding this one
    /// too is the consistent thing to do and produces a page displaying the consent form's HTML to
    /// the user as literal text. The property's own documentation says verbatim; this is what says
    /// it when nobody read that.
    /// </remarks>
    [Fact]
    public void A_layout_that_encodes_the_body_is_refused()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Render(page => "<!DOCTYPE html><html><body>"
                + System.Net.WebUtility.HtmlEncode(page.Body)
                + "</body></html>"));
    }

    /// <summary>A layout that truncates the body — a template with a length cap on a slot.</summary>
    [Fact]
    public void A_layout_that_truncates_the_body_is_refused()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Render(page => "<!DOCTYPE html><html><body>" + page.Body[..40] + "</body></html>"));
    }

    [Fact]
    public void A_layout_returning_null_is_refused()
    {
        var failure = Assert.Throws<InvalidOperationException>(() => Render(_ => null));

        Assert.Contains("returned null", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>The message names the type, because a deployment may have more than one layout.</summary>
    [Fact]
    public void The_refusal_names_the_layout_that_caused_it()
    {
        var failure = Assert.Throws<InvalidOperationException>(() => Render(_ => "<html></html>"));

        Assert.Contains(typeof(Layout).FullName!, failure.Message, StringComparison.Ordinal);
    }

    /// <summary>A layout that wraps correctly is not refused, whatever else it adds.</summary>
    [Fact]
    public void A_layout_that_includes_the_body_is_accepted()
    {
        var html = Render(page => "<!DOCTYPE html><html><body><header>Northwind</header>"
            + page.Body
            + "<footer>·</footer></body></html>");

        Assert.Contains("evil.example", html, StringComparison.Ordinal);
        Assert.Contains("<header>Northwind</header>", html, StringComparison.Ordinal);
    }

    /// <summary>The kind reaches the layout, so a shell can differ between the two pages.</summary>
    [Fact]
    public void The_layout_is_told_which_page_it_is_wrapping()
    {
        List<InteractionPageKind> seen = [];

        var renderer = new DefaultInteractionRenderer(new Layout(page =>
        {
            seen.Add(page.Kind);
            return "<html><body>" + page.Body + "</body></html>";
        }));

        renderer.RenderConsent(Consent);
        renderer.RenderLogin(new LoginViewModel
        {
            ReturnUrl = "/authorize",
            Rejected = false,
            AntiforgeryFieldName = "__RequestVerificationToken",
            AntiforgeryToken = "token",
            Nonce = null,
            LocalPasswordsEnabled = true,
            ExternalProviders = [],
            PasswordRecoveryEnabled = false,
        });

        Assert.Equal([InteractionPageKind.Consent, InteractionPageKind.Login], seen);
    }
}
