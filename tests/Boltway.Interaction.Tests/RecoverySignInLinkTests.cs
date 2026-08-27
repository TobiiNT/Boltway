using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;

namespace Boltway.Interaction.Tests;

/// <summary>
/// Where the recovery pages send somebody when they are finished.
/// </summary>
/// <remarks>
/// <para>
/// All three used to write <c>href="/login"</c> unconditionally, and <c>GET /login</c> with no
/// <c>returnUrl</c> answers <c>400</c> - it has no client and nowhere to go afterwards. So the last
/// thing a person saw at the end of a successful password reset was the error page: <i>"This page
/// was opened without a valid authorization request."</i>
/// </para>
/// <para>
/// Found by resetting a password on a running deployment and pressing the button the page offers,
/// which is the only way it could have been found - every test here passed, because none of them
/// asked where the link went.
/// </para>
/// </remarks>
public sealed class RecoverySignInLinkTests
{
    private static readonly DefaultInteractionRenderer Renderer = DefaultInteractionRenderer.Unthemed;

    private const string SignIn = "/login?returnUrl=%2Fme";

    private static ResetPasswordPageModel Reset(string? signInUrl, ResetPasswordState state) =>
        new(state, "token", 0, "__t", "value", null, signInUrl);

    private static ForgotPasswordPageModel Forgot(string? signInUrl, ForgotPasswordState state) =>
        new(state, "__t", "value", null, signInUrl);

    /// <summary>
    /// The regression, stated as the thing that must never appear again.
    /// </summary>
    /// <remarks>
    /// Asserted as an absence of the bare href rather than as a presence of the good one, because
    /// the defect was a link that existed and was wrong. A test that only checked "there is a link"
    /// passed against the broken page.
    /// </remarks>
    [Theory]
    [InlineData(ResetPasswordState.Done)]
    [InlineData(ResetPasswordState.Form)]
    [InlineData(ResetPasswordState.Expired)]
    public void The_reset_page_never_links_to_a_bare_login(ResetPasswordState state)
    {
        Assert.DoesNotContain("href=\"/login\"", Renderer.RenderResetPassword(Reset(SignIn, state)), StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"/login\"", Renderer.RenderResetPassword(Reset(null, state)), StringComparison.Ordinal);
    }

    /// <inheritdoc cref="The_reset_page_never_links_to_a_bare_login"/>
    [Theory]
    [InlineData(ForgotPasswordState.Form)]
    [InlineData(ForgotPasswordState.Sent)]
    [InlineData(ForgotPasswordState.Throttled)]
    public void The_forgot_page_never_links_to_a_bare_login(ForgotPasswordState state)
    {
        Assert.DoesNotContain("href=\"/login\"", Renderer.RenderForgotPassword(Forgot(SignIn, state)), StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"/login\"", Renderer.RenderForgotPassword(Forgot(null, state)), StringComparison.Ordinal);
    }

    /// <summary>Given somewhere to go, both pages say so.</summary>
    [Fact]
    public void A_destination_is_drawn_as_a_link()
    {
        Assert.Contains(
            "href=\"/login?returnUrl=%2Fme\"",
            Renderer.RenderResetPassword(Reset(SignIn, ResetPasswordState.Done)),
            StringComparison.Ordinal);

        Assert.Contains(
            "href=\"/login?returnUrl=%2Fme\"",
            Renderer.RenderForgotPassword(Forgot(SignIn, ForgotPasswordState.Sent)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// With nowhere to go, there is no link rather than a hopeful one.
    /// </summary>
    /// <remarks>
    /// A deployment can route password recovery without routing the self-service pages, and then
    /// no standalone destination exists at all - <c>/authorize</c> needs a request in flight and
    /// nothing else accepts a bare arrival. A link that lands on an error page is worse than no
    /// link: it spends the reader's trust before it fails, at the end of the flow where they have
    /// least of it left.
    /// </remarks>
    [Fact]
    public void No_destination_draws_no_link()
    {
        var reset = Renderer.RenderResetPassword(Reset(null, ResetPasswordState.Done));
        var forgot = Renderer.RenderForgotPassword(Forgot(null, ForgotPasswordState.Sent));

        Assert.DoesNotContain("<a href=", reset, StringComparison.Ordinal);
        Assert.DoesNotContain("<a href=", forgot, StringComparison.Ordinal);

        // And the page is still the page: the outcome it exists to report is unaffected.
        Assert.Contains("Your password", reset, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// The buttons that connect an upstream account to this one.
/// </summary>
/// <remarks>
/// <c>/me</c> had no way to link at all, so a deployment could configure Google, render the button
/// on the sign-in page, and leave every existing account unable to reach it - <c>UnknownIdentity</c>
/// is <c>Refuse</c> by default, so signing in with an unlinked identity is correctly refused and
/// there was nothing anywhere that would link one.
/// </remarks>
public sealed class AccountProviderLinkTests
{
    private static readonly DefaultInteractionRenderer Renderer = DefaultInteractionRenderer.Unthemed;

    private static AccountPageModel Account(params AccountProviderLink[] providers) =>
        new("ada", "ada@example.com", true, ["founder"], true, null, providers, "__t", "value",
            AuthorizationServerPaths.EndSession);

    /// <summary>A configured provider is offered, as a form.</summary>
    /// <remarks>
    /// A form and not a link, because linking changes the account: a <c>GET</c> that did it would be
    /// reachable from an <c>&lt;img&gt;</c> tag on any page - the logout-CSRF shape, which is why
    /// <c>/logout</c> asks too.
    /// </remarks>
    [Fact]
    public void A_configured_provider_is_offered_as_a_form()
    {
        var page = Renderer.RenderAccount(
            Account(new AccountProviderLink("google", "Google", "/external/google/link", Linked: false)));

        Assert.Contains("<form method=\"post\" action=\"/external/google/link\">", page, StringComparison.Ordinal);
        Assert.Contains("name=\"__t\" value=\"value\"", page, StringComparison.Ordinal);
        Assert.Contains("name=\"returnUrl\" value=\"/me\"", page, StringComparison.Ordinal);
    }

    /// <summary>No providers means no section, rather than an empty one.</summary>
    [Fact]
    public void No_providers_draws_no_section()
    {
        var page = Renderer.RenderAccount(Account());

        Assert.DoesNotContain("/external/", page, StringComparison.Ordinal);

        // The provider section's form specifically, not "any form on the page". This asserted the
        // latter, which was the same thing right up until the sign-out became a form too - and then
        // it failed for a reason that had nothing to do with providers.
        Assert.DoesNotContain("action=\"/external/", page, StringComparison.Ordinal);

        // And the page is still the page.
        Assert.Contains("ada", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A provider already connected says so instead of offering to connect it again.
    /// </summary>
    /// <remarks>
    /// The page could not say this at all until <c>ListExternalLoginsAsync</c> existed, so a user
    /// linked Google, the page came back identical, and the only way to find out whether it had
    /// worked was to sign out and try. Asserted as the button being gone as well as the sentence
    /// being there: leaving both would send somebody round the whole round trip to learn nothing
    /// changed.
    /// </remarks>
    [Fact]
    public void A_linked_provider_is_stated_rather_than_offered()
    {
        var page = Renderer.RenderAccount(
            Account(new AccountProviderLink("google", "Google", "/external/google/link", Linked: true)));

        Assert.DoesNotContain("action=\"/external/google/link\"", page, StringComparison.Ordinal);
        Assert.Contains("Google", page, StringComparison.Ordinal);

        // And it is a statement, not a control dressed as one.
        // The provider's own control, not "any button on the page". The line above already says
        // there is no form posting to this provider, and a form is the only thing that would give
        // it a button - whereas the page has a sign-out button of its own, which is not an offer to
        // link Google.
        Assert.DoesNotContain("/external/google/link", page, StringComparison.Ordinal);
    }

    /// <summary>Two providers are two buttons, each pointing at its own scheme.</summary>
    [Fact]
    public void Each_provider_gets_its_own_button()
    {
        var page = Renderer.RenderAccount(Account(
            new AccountProviderLink("google", "Google", "/external/google/link", Linked: false),
            new AccountProviderLink("okta", "Okta", "/external/okta/link", Linked: false)));

        Assert.Contains("action=\"/external/google/link\"", page, StringComparison.Ordinal);
        Assert.Contains("action=\"/external/okta/link\"", page, StringComparison.Ordinal);
    }
}
