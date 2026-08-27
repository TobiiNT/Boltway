using System.Net;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// That the three tiers are actually seams, rather than interfaces nothing consults.
/// </summary>
/// <remarks>
/// An extension point is a claim, and the way it fails is not an exception - it is a deployment
/// writing an implementation, registering it, and getting the shipped page anyway. Each assertion
/// here is one of those claims, made by rendering through the seam and looking for what only the
/// replacement could have produced.
/// </remarks>
public sealed class SeamTests
{
    /// <summary>A layout that is unmistakably not the shipped one.</summary>
    private sealed class MarkedLayout : IAdminLayout
    {
        public List<AdminPageKind> Wrapped { get; } = [];

        public string Wrap(AdminPage page)
        {
            Wrapped.Add(page.Kind);

            return $"<!DOCTYPE html><html lang=\"xx\"><head><title>{AdminMarkup.Encode(page.Title)}</title>"
                 + $"</head><body data-kind=\"{page.Kind}\"><nav>ours</nav>{page.Body}</body></html>";
        }
    }

    /// <summary>A renderer replacing exactly one page and inheriting the rest.</summary>
    private sealed class OnePageReplaced : IAdminRenderer
    {
        public string RenderAudit(AuditViewModel model) => "<!DOCTYPE html><html lang=\"xx\"><body>our audit</body></html>";
    }

    /// <summary>A layout that drops the body, which is the one thing a layout can get wrong.</summary>
    private sealed class LosesTheBody : IAdminLayout
    {
        public string Wrap(AdminPage page) => "<!DOCTYPE html><html lang=\"xx\"><body></body></html>";
    }

    private static AccountsViewModel Accounts() =>
        new(Render.Json("""{"users":[{"handle":"ada","role":"founder"}]}"""), Render.Tokens, null, "ada");

    /// <summary>Every page goes through the registered layout, not just the first one written.</summary>
    /// <remarks>
    /// Six pages and six kinds. A renderer that wrapped five of them and hand-built the sixth is the
    /// ordinary way this kind of seam rots, and it is invisible until somebody opens that page.
    /// </remarks>
    [Fact]
    public void Every_page_goes_through_the_registered_layout()
    {
        var layout = new MarkedLayout();
        var renderer = new DefaultAdminRenderer(layout, AdminText.Default, ["founder"]);

        string[] pages =
        [
            renderer.RenderAccounts(Accounts()),
            renderer.RenderAccount(new AccountViewModel(Render.Account(), Render.Tokens, null, "ada")),
            renderer.RenderNewAccount(new NewAccountViewModel(Render.Tokens, null, "ada")),
            renderer.RenderAudit(new AuditViewModel(Render.Json("[]"), Render.Tokens, "ada")),
            renderer.RenderPassword(new PasswordViewModel("ada", "generated-value", Render.Tokens, "ada")),
            renderer.RenderRefusal(new RefusalViewModel(
                Render.Refusal(HttpStatusCode.Forbidden, "forbidden", "nope"), Render.Tokens,
                "ada")),
        ];

        foreach (var html in pages)
        {
            Assert.Contains("<nav>ours</nav>", html, StringComparison.Ordinal);
            Assert.DoesNotContain("/css/admin.css", html, StringComparison.Ordinal);
        }

        // And each announced which page it was, so a layout can branch without parsing its own output.
        Assert.Equal(
            [
                AdminPageKind.Accounts, AdminPageKind.Account, AdminPageKind.NewAccount,
                AdminPageKind.Audit, AdminPageKind.Password, AdminPageKind.Refused,
            ],
            layout.Wrapped);
    }

    /// <summary>
    /// A renderer overriding one page keeps the shipped five.
    /// </summary>
    /// <remarks>
    /// The reason every member has a default implementation. Requiring six to change one is the cost
    /// that stops a seam being used, and adding a seventh page in a later release would otherwise be
    /// a compile error in every deployment that had written the six.
    /// </remarks>
    [Fact]
    public void A_renderer_may_replace_one_page_and_inherit_the_rest()
    {
        IAdminRenderer renderer = new OnePageReplaced();

        Assert.Contains(
            "our audit",
            renderer.RenderAudit(new AuditViewModel(Render.Json("[]"), Render.Tokens, "ada")),
            StringComparison.Ordinal);

        // The five it did not write are the shipped pages, complete and styled by the shipped sheet.
        var accounts = renderer.RenderAccounts(Accounts());

        Assert.Contains("/css/admin.css", accounts, StringComparison.Ordinal);
        Assert.Contains("ada", accounts, StringComparison.Ordinal);
    }

    /// <summary>
    /// A default member renders in the shipped shell, and cannot reach the deployment's.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Documented behaviour rather than a defect, and asserted so it stays documented: a default
    /// interface member has no dependency injection, so it cannot see the layout a deployment
    /// registered. The only thing it can honestly produce is this app's page in this app's shell.
    /// </para>
    /// <para>
    /// The mismatch is the signal. A page that does not look like the others is how somebody finds
    /// out they have not written it - which is a better outcome than a page that looks right and is
    /// missing whatever their layout was for.
    /// </para>
    /// </remarks>
    [Fact]
    public void An_inherited_page_uses_the_shipped_shell_rather_than_silently_borrowing_one()
    {
        IAdminRenderer renderer = new OnePageReplaced();

        var accounts = renderer.RenderAccounts(Accounts());

        Assert.Contains("/css/admin.css", accounts, StringComparison.Ordinal);
        Assert.DoesNotContain("<nav>ours</nav>", accounts, StringComparison.Ordinal);
    }

    /// <summary>
    /// A layout that loses the page is told so, by name.
    /// </summary>
    /// <remarks>
    /// The one thing a layout can get wrong, and therefore the one thing that can be checked. An
    /// empty document is a page an operator reports as "the admin UI is broken" with nothing in any
    /// log; this names the layout and the page instead.
    /// </remarks>
    [Fact]
    public void A_layout_that_drops_the_body_is_refused()
    {
        var renderer = new DefaultAdminRenderer(new LosesTheBody(), AdminText.Default, null);

        var thrown = Assert.Throws<InvalidOperationException>(() => renderer.RenderAccounts(Accounts()));

        Assert.Contains(nameof(LosesTheBody), thrown.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(AdminPageKind.Accounts), thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The words and the roles belong to the renderer, so one instance serves every request.
    /// </summary>
    /// <remarks>
    /// They used to be arguments on every page, which is why eight call sites in <c>Program.cs</c>
    /// each restated them and why two pages were shipped that had simply been missed. Nothing here
    /// is per-request, so the app registers one and the endpoints pass only what the request carried.
    /// </remarks>
    [Fact]
    public void A_renderer_carries_the_deployments_words_and_roles_rather_than_taking_them_per_page()
    {
        var renderer = Render.With(
            Render.Text((AdminText.LanguageKey, "vi"), (AdminText.NavAudit, "Nhật ký")),
            ["founder"]);

        var audit = Render.Decoded(renderer.RenderAudit(new AuditViewModel(Render.Json("[]"), Render.Tokens, "ada")));
        var accounts = renderer.RenderAccounts(Accounts());

        Assert.Contains("Nhật ký", audit, StringComparison.Ordinal);
        Assert.Contains("<html lang=\"vi\">", audit, StringComparison.Ordinal);
        Assert.Contains("admin-badge", accounts, StringComparison.Ordinal);
    }
}
