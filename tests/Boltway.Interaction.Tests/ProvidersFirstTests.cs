using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;

namespace Boltway.Interaction.Tests;

/// <summary>
/// Which way in leads, and why the answer is in the markup rather than in a stylesheet.
/// </summary>
/// <remarks>
/// A deployment asked for the providers to come first — everyone there signs in with Google, so a
/// page opening with two empty text fields is friction on every visit. The reorder could have been
/// four lines of CSS on a flex container, and that is the version these tests exist to rule out:
/// <c>order</c> moves the boxes and leaves the tab order alone, so the eye and the keyboard would
/// disagree on the one page where somebody is typing a password they cannot see.
/// </remarks>
public sealed class ProvidersFirstTests
{
    private static LoginViewModel Login(bool passwords = true, bool providers = true) => new()
    {
        AntiforgeryFieldName = "__f",
        AntiforgeryToken = "tok",
        ReturnUrl = "/authorize?x=1",
        Rejected = false,
        LocalPasswordsEnabled = passwords,
        PasswordRecoveryEnabled = passwords,
        Nonce = null,
        ExternalProviders = providers
            ? [new LoginProviderOption("google", "Google", "/external/google", true, null)]
            : [],
    };

    private static string Render(bool providersFirst, LoginViewModel model)
    {
        var options = new InteractionOptions { ProvidersFirst = providersFirst };

        return new DefaultInteractionRenderer(options).RenderLogin(model);
    }

    private static (int Password, int Provider) Positions(string html) =>
        (html.IndexOf("action=\"/login\"", StringComparison.Ordinal),
         html.IndexOf("action=\"/external/google\"", StringComparison.Ordinal));

    /// <summary>The shipped order is unchanged, because it is what every deployment already has.</summary>
    [Fact]
    public void By_default_the_password_form_still_comes_first()
    {
        var (password, provider) = Positions(Render(providersFirst: false, Login()));

        Assert.True(password >= 0 && provider >= 0, "both methods render");
        Assert.True(password < provider, "password form precedes the provider button");
    }

    /// <summary>
    /// Turned on, the provider comes first <b>in the markup</b> — which is the whole point.
    /// </summary>
    /// <remarks>
    /// Asserted on source position rather than on anything visual, because source position is
    /// exactly what a stylesheet could not have changed. If this ever starts passing while the
    /// reorder lives in CSS, it is testing the wrong thing.
    /// </remarks>
    [Fact]
    public void Turned_on_the_provider_comes_first_in_the_markup()
    {
        var (password, provider) = Positions(Render(providersFirst: true, Login()));

        Assert.True(password >= 0 && provider >= 0, "both methods render");
        Assert.True(provider < password, "provider button precedes the password form");
    }

    /// <summary>
    /// The divider only exists when there are two things to divide.
    /// </summary>
    /// <remarks>
    /// "or use a password" under a page that has no password form is a sentence promising something
    /// that is not there, and a deployment with no provider has nothing above the form to separate
    /// it from.
    /// </remarks>
    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public void The_divider_is_drawn_only_with_both_methods(bool passwords, bool providers, bool expected)
    {
        var html = Render(providersFirst: true, Login(passwords, providers));

        Assert.Equal(expected, html.Contains("ck-or", StringComparison.Ordinal));
    }

    /// <summary>And never in the shipped order, where the form is already the first thing.</summary>
    [Fact]
    public void The_divider_is_not_drawn_in_the_default_order() =>
        Assert.DoesNotContain("ck-or", Render(providersFirst: false, Login()), StringComparison.Ordinal);

    /// <summary>
    /// Everything the page had, it still has — reordering is not an excuse to lose a control.
    /// </summary>
    /// <remarks>
    /// The forgot-password link is the one most at risk: it is emitted inside the password branch,
    /// so a reorder that moved the form and left the link behind would strand it above a provider
    /// button with nothing to explain it.
    /// </remarks>
    [Fact]
    public void Reordering_drops_nothing()
    {
        foreach (var first in new[] { false, true })
        {
            var html = Render(first, Login());

            Assert.Contains("action=\"/login\"", html, StringComparison.Ordinal);
            Assert.Contains("action=\"/external/google\"", html, StringComparison.Ordinal);
            Assert.Contains("href=\"/forgot\"", html, StringComparison.Ordinal);
            Assert.Contains("name=\"username\"", html, StringComparison.Ordinal);
            Assert.Contains("name=\"password\"", html, StringComparison.Ordinal);

            // Both forms still carry the antiforgery token; the provider POST needs it as much as
            // the password one, because it writes the state, nonce and PKCE verifier cookie.
            Assert.Equal(2, html.Split("name=\"__f\"", StringSplitOptions.None).Length - 1);
        }
    }

    /// <summary>
    /// The forgot link stays attached to the form it belongs to.
    /// </summary>
    /// <remarks>
    /// Its own remarks in the renderer say it is drawn "under the password form and only when there
    /// is one". Reordering must not turn that into "under whichever block happens to be last".
    /// </remarks>
    [Fact]
    public void The_forgot_link_stays_under_the_password_form()
    {
        var html = Render(providersFirst: true, Login());

        var password = html.IndexOf("action=\"/login\"", StringComparison.Ordinal);
        var forgot = html.IndexOf("href=\"/forgot\"", StringComparison.Ordinal);

        Assert.True(password < forgot, "the link follows the form it is about");
    }
}
