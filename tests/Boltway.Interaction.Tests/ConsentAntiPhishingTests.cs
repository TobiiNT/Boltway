using Boltway.AuthorizationServer.Interaction;

namespace Boltway.Interaction.Tests;

/// <summary>
/// The consent page's anti-phishing contract, asserted on the shipped renderer's own output.
/// </summary>
/// <remarks>
/// <para>
/// The properties here are the ones the renderer's own comments describe as decisions rather than
/// styling: the self-asserted name never appears without the sentence saying
/// it is unverified, the client's own logo never precedes the one host a domain owner proved, and
/// the hostname the user's safety depends on leads the page. The existing render tests cover the
/// device warning and the theme; these cover the ordering and the unverified caveat, which no
/// setting and no future edit should be free to drop.
/// </para>
/// <para>
/// Unthemed on purpose. A themed renderer draws the <i>deployment's</i> product logo in the shell;
/// this file is about the <i>client's</i> self-asserted logo in the body, so the renderer carries
/// no product logo and the only <c>&lt;img&gt;</c> that can appear is the one under test.
/// </para>
/// </remarks>
public sealed class ConsentAntiPhishingTests
{
    private static ConsentViewModel Model(
        string? name = "Claude", string? logo = null, bool device = false,
        IReadOnlyList<ConsentScope>? scopes = null) => new()
    {
        ClientHost = "claude.ai",
        RedirectHost = "app.example.com",
        RedirectsToThisDevice = device,
        ClientName = name,
        ClientLogoUrl = logo,
        Scopes = scopes ?? [new ConsentScope("docs:read", "Read the knowledge base", true)],
        Resources = [],
        ReturnUrl = "/authorize?client_id=x",
        AntiforgeryFieldName = "__RequestVerificationToken",
        AntiforgeryToken = "token",
        Nonce = null,
    };

    private static string Render(ConsentViewModel model) =>
        new DefaultInteractionRenderer().RenderConsent(model);

    /// <summary>
    /// The self-asserted name never appears without the sentence that says it is unverified.
    /// </summary>
    /// <remarks>
    /// The caveat prints unconditionally and there is no verified branch — a decision, not an
    /// omission. Encoded here as "a name implies the caveat", because that is the shape it settles
    /// into: the answer to "when does it say verified" is never, until a party other than the
    /// application says so, and nothing on this page is that party.
    /// </remarks>
    [Fact]
    public void A_client_name_always_carries_the_unverified_caveat()
    {
        var html = Render(Model(name: "Claude"));

        Assert.Contains("It calls itself", html, StringComparison.Ordinal);
        Assert.Contains("is not verified.", html, StringComparison.Ordinal);
    }

    /// <summary>The only thing the page ever says about verification is that there is none.</summary>
    /// <remarks>
    /// Removes the one sentence that is allowed to mention verification, then asserts the word does
    /// not survive anywhere else. A "verified" branch added later — a badge, a checkmark caption, a
    /// reassuring aside — fails here rather than shipping a page that vouches for a name this server
    /// never checked.
    /// </remarks>
    [Fact]
    public void The_page_never_claims_a_name_is_verified()
    {
        var withCaveat = Render(Model(name: "Claude", logo: "/client-logo/abc"));

        var withoutTheCaveat = withCaveat.Replace(
            "That name is chosen by the application and is not verified.", string.Empty, StringComparison.Ordinal);

        Assert.DoesNotContain("verified", withoutTheCaveat, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>No name means no name paragraph, and nothing to caveat.</summary>
    /// <remarks>
    /// The caveat belongs to the name. A page with no <c>client_name</c> has no self-assertion to
    /// warn about, so it carries neither the claim nor the "unverified" line — printing the caveat
    /// beside nothing would teach a reader to skip it on the page where it matters.
    /// </remarks>
    [Fact]
    public void With_no_name_there_is_no_name_claim_and_no_caveat()
    {
        var html = Render(Model(name: null));

        Assert.DoesNotContain("ck-name", html, StringComparison.Ordinal);
        Assert.DoesNotContain("is not verified.", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The hostname leads, the name claim follows it, the redirect host follows that.
    /// </summary>
    /// <remarks>
    /// "Reversing that order is the whole attack" — the renderer's own words. A page led by the name
    /// and a logo, with the real host in small print, is a phishing surface this server would have
    /// endorsed. Document order is the contract, so it is asserted as document order.
    /// </remarks>
    [Fact]
    public void The_client_host_precedes_the_name_which_precedes_the_redirect()
    {
        var html = Render(Model(name: "Claude"));

        var host = html.IndexOf("ck-client", StringComparison.Ordinal);
        var name = html.IndexOf("ck-name", StringComparison.Ordinal);
        var redirect = html.IndexOf("ck-redirect", StringComparison.Ordinal);

        Assert.True(host >= 0 && name >= 0 && redirect >= 0, "all three paragraphs render");
        Assert.True(host < name, "the proven host leads the self-asserted name");
        Assert.True(name < redirect, "the name claim precedes where the code will go");
    }

    /// <summary>
    /// The client's logo sits inside the unverified sentence, after the host — never before it.
    /// </summary>
    /// <remarks>
    /// A logo is the same self-assertion the name is, in the form that is hardest to be sceptical
    /// of. So it lives after the one host a domain owner proved and inside the sentence that says
    /// nobody verified it: the logo appears between the client-host paragraph and the redirect, and
    /// the unverified caveat appears after the logo, in the same paragraph.
    /// </remarks>
    [Fact]
    public void The_client_logo_sits_after_the_host_and_inside_the_unverified_sentence()
    {
        var html = Render(Model(name: "Claude", logo: "/client-logo/abc"));

        var host = html.IndexOf("ck-client", StringComparison.Ordinal);
        var img = html.IndexOf("<img class=\"ck-client-logo\"", StringComparison.Ordinal);
        var redirect = html.IndexOf("ck-redirect", StringComparison.Ordinal);
        var caveat = html.IndexOf("is not verified.", StringComparison.Ordinal);

        Assert.True(img > 0, "the client logo renders");
        Assert.True(host < img, "the proven host comes before the self-asserted logo");
        Assert.True(img < redirect, "the logo is in the name paragraph, above the redirect");
        Assert.True(img < caveat, "the caveat follows the logo, so the logo is inside the sentence that disclaims it");
    }

    /// <summary>A logo with no name is not drawn at all.</summary>
    /// <remarks>
    /// The model sets the logo only when the name is set, and the renderer draws it only inside the
    /// name branch — so a logo can never appear as a bare mark with nothing beside it saying it is
    /// unverified. Both halves enforce the same rule; this pins the renderer's half, where a future
    /// edit could lift the logo out of the name branch and undo it.
    /// </remarks>
    [Fact]
    public void A_logo_without_a_name_is_not_drawn()
    {
        var html = Render(Model(name: null, logo: "/client-logo/abc"));

        // Unthemed, so no product logo either — any img here would be the disembodied client logo.
        Assert.DoesNotContain("<img", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// An undescribed scope shows its raw name and a warning, never a description guessed from it.
    /// </summary>
    /// <remarks>
    /// A-14: the page must not parse <c>docs:write</c> into "Write the knowledge base" and present the
    /// guess as if the server had described it. The raw token in a <c>code</c> element plus the
    /// configuration warning is the honest rendering — it says what was asked for and that nobody
    /// wrote down what it means.
    /// </remarks>
    [Fact]
    public void An_undescribed_scope_is_shown_raw_with_a_warning()
    {
        var html = Render(Model(scopes: [new ConsentScope("docs:write", string.Empty, false)]));

        Assert.Contains("<code>docs:write</code>", html, StringComparison.Ordinal);
        Assert.Contains("no description configured", html, StringComparison.Ordinal);
    }

    /// <summary>A described scope shows the description and not the raw token in a code element.</summary>
    /// <remarks>
    /// The other side of A-14: when the server does have a description, it is shown as prose, and the
    /// undescribed warning does not appear. Both directions are pinned so a regression in either —
    /// a raw token where a description exists, or a warning where one was configured — is caught.
    /// </remarks>
    [Fact]
    public void A_described_scope_shows_its_description_and_no_warning()
    {
        var html = Render(Model(scopes: [new ConsentScope("docs:read", "Read the knowledge base", true)]));

        Assert.Contains("Read the knowledge base", html, StringComparison.Ordinal);
        Assert.DoesNotContain("no description configured", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<code>docs:read</code>", html, StringComparison.Ordinal);
    }
}
