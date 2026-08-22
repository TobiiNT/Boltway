using System.Net;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// The shell, which is the only part of the app present on every page — and was the only part
/// nothing asserted.
/// </summary>
/// <remarks>
/// <para>
/// The first assertions here exist because a screenshot of the running stack disagreed with the
/// code. The pages were rendered from a real <c>docker compose</c> deployment, signed into through
/// the real OIDC flow, and the header contained two links and nothing else: no sign-out, and a
/// <c>lang</c> of <c>en</c> over a page written in Vietnamese.
/// </para>
/// <para>
/// Neither was reachable by reading the source alone. The sign-out button needed the ID token's
/// claim set to see it was dead, and the <c>lang</c> attribute needed a translated deployment to
/// exist. That is the argument for these tests: what they pin is the <i>interaction</i> between the
/// shell and a deployment's configuration, which is where both hid.
/// </para>
/// </remarks>
public sealed class LayoutTests
{
    private static readonly string[] Shipped = [DefaultAdminLayout.ShippedStylesheet];

    private static string Wrap(
        AdminPageKind kind = AdminPageKind.Accounts,
        string title = "Accounts",
        string body = "<p>body</p>",
        string? operatorName = null,
        AdminText? text = null,
        IReadOnlyList<string>? stylesheets = null) =>
        new DefaultAdminLayout(text ?? AdminText.Default, stylesheets ?? Shipped)
            .Wrap(new AdminPage
            {
                Kind = kind,
                Title = title,
                Body = body,
                OperatorName = operatorName,
                Antiforgery = Render.Tokens,
            });

    /// <summary>
    /// The way out of the app does not depend on knowing who is in it.
    /// </summary>
    /// <remarks>
    /// This is the shipped defect. The button sat inside <c>if (operatorName is { Length: &gt; 0 })</c>,
    /// and this server's ID token carries no name claim of any kind — <c>claims_supported</c> is
    /// exactly <c>sub iss aud exp iat auth_time nonce at_hash</c> — so the condition was false on
    /// every request and the admin UI had no sign-out control at all.
    /// </remarks>
    [Fact]
    public void Sign_out_renders_when_there_is_no_name_to_show()
    {
        var html = Wrap(operatorName: null);

        Assert.Contains("action=\"/signout\"", html, StringComparison.Ordinal);
        Assert.Contains(">Sign out<", html, StringComparison.Ordinal);
    }

    /// <summary>And still renders when there is one, alongside it rather than instead of it.</summary>
    [Fact]
    public void A_name_is_shown_next_to_sign_out_rather_than_in_place_of_it()
    {
        var html = Wrap(operatorName: "ada");

        Assert.Contains("class=\"who\">ada</span>", html, StringComparison.Ordinal);
        Assert.Contains("action=\"/signout\"", html, StringComparison.Ordinal);
    }

    /// <summary>A name is a value an operator typed, so it is encoded like every other one.</summary>
    [Fact]
    public void A_name_containing_markup_is_encoded()
    {
        var html = Wrap(operatorName: "<script>alert(1)</script>");

        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>Told nothing, the page is English and says so.</summary>
    [Fact]
    public void The_default_language_is_english()
    {
        Assert.Contains("<html lang=\"en\">", Wrap(), StringComparison.Ordinal);
        Assert.Equal("en", AdminText.Default.Language);
    }

    /// <summary>
    /// A translated deployment's page declares the language its sentences are in.
    /// </summary>
    /// <remarks>
    /// Not cosmetic. A screen reader picks its phonology from this attribute, so a Vietnamese page
    /// claiming <c>en</c> is read aloud as mispronounced English; a browser offers to translate it
    /// from a language it is not in.
    /// </remarks>
    [Fact]
    public void A_translated_deployment_declares_its_language()
    {
        var html = Wrap(
            title: "Tài khoản",
            text: Render.Text((AdminText.LanguageKey, "vi"), (AdminText.NavAccounts, "Tài khoản")));

        Assert.Contains("<html lang=\"vi\">", html, StringComparison.Ordinal);
        Assert.Contains("Tài khoản", Render.Decoded(html), StringComparison.Ordinal);
    }

    /// <summary>
    /// The language is one setting with the words, so the two cannot drift apart.
    /// </summary>
    /// <remarks>
    /// It could have been an environment variable beside <c>ADMIN_TEXT_FILE</c>. Two settings that
    /// must agree is how a Vietnamese page ends up declaring itself English — the failure this was
    /// added to fix, arriving by a different route.
    /// </remarks>
    [Fact]
    public void The_language_travels_with_the_words()
    {
        Assert.Equal("vi", Render.Text((AdminText.LanguageKey, "vi")).Language);

        // And the reserved key is not a sentence: it never reaches a page as one, and it is not
        // something a deployment is asked to translate.
        Assert.DoesNotContain(AdminText.LanguageKey, AdminText.Keys);
    }

    /// <summary>
    /// The tab says the word, not the word's entities.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Found in the rendered HTML of a running deployment: <c>&lt;title&gt;T&amp;amp;#224;i
    /// khoản&lt;/title&gt;</c>. <see cref="AdminText"/>'s indexer encodes, the shell encodes what it
    /// is given, and the titles stopped being English literals — so <c>à</c> became <c>&amp;#224;</c>
    /// became the five characters a browser draws.
    /// </para>
    /// <para>
    /// Asserted on the decoded string, because that is what a browser puts in the tab. One decode is
    /// correct; the defect is a title that still holds an entity after it.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_translated_title_is_encoded_exactly_once()
    {
        var vietnamese = Render.Text((AdminText.LanguageKey, "vi"), (AdminText.NavAccounts, "Tài khoản"));

        var html = Render.With(vietnamese).RenderAccounts(
            new AccountsViewModel(Render.Json("""{"users":[]}"""), Render.Tokens, null, "ada"));

        var title = html[(html.IndexOf("<title>", StringComparison.Ordinal) + 7)..
                          html.IndexOf("</title>", StringComparison.Ordinal)];

        Assert.Equal("Tài khoản", WebUtility.HtmlDecode(title));
        Assert.DoesNotContain("&amp;", title, StringComparison.Ordinal);
    }

    /// <summary>
    /// A handle is not trusted in the title either, and that is why the title is plain text.
    /// </summary>
    /// <remarks>
    /// <c>&lt;/title&gt;</c> ends RCDATA, so a handle carrying one escapes the element. The fix for
    /// the double-encoded title could have been "stop encoding here and let callers encode" — this
    /// is the case that makes that the wrong fix, and the reason
    /// <see cref="AdminPage.Title"/> is documented as plain text rather than markup.
    /// </remarks>
    [Fact]
    public void A_title_that_tries_to_close_the_element_is_encoded()
    {
        var html = Wrap(title: "</title><script>alert(1)</script>");

        Assert.DoesNotContain("</title><script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;/title&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The rail says which page you are on, and says it the way assistive technology reads it.
    /// </summary>
    /// <remarks>
    /// The one piece of the shell no stylesheet could supply: the header was byte-identical on every
    /// page and CSS cannot read the URL, so a rail styled from that markup alone had hover and
    /// nothing else. It is the clearest single argument for this seam existing.
    /// </remarks>
    [Fact]
    public void The_current_section_is_marked_and_only_the_current_one()
    {
        var html = Wrap(AdminPageKind.Accounts);

        Assert.Contains("<a href=\"/\" aria-current=\"page\">", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<a href=\"/audit\" aria-current", html, StringComparison.Ordinal);
        Assert.Equal(1, html.Split("aria-current").Length - 1);
    }

    /// <summary>A page outside the navigation marks nothing rather than guessing.</summary>
    [Fact]
    public void A_page_with_no_section_marks_nothing() =>
        Assert.DoesNotContain("aria-current", Wrap(AdminPageKind.Refused), StringComparison.Ordinal);

    /// <summary>The audit page marks the audit link, not the accounts one.</summary>
    [Fact]
    public void Each_section_marks_its_own_link()
    {
        var html = Render.With().RenderAudit(new AuditViewModel(Render.Json("[]"), Render.Tokens, "ada"));

        Assert.Contains("<a href=\"/audit\" aria-current=\"page\">", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<a href=\"/\" aria-current", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The three pages reached from the account list mark it, because that is where they go back to.
    /// </summary>
    /// <remarks>
    /// Derived from the page kind rather than passed beside it. Two facts that must agree is how a
    /// page ends up highlighting the wrong link, which is the same shape of defect as a Vietnamese
    /// page declaring <c>lang="en"</c>.
    /// </remarks>
    [Theory]
    [InlineData(AdminPageKind.Account)]
    [InlineData(AdminPageKind.NewAccount)]
    [InlineData(AdminPageKind.Password)]
    public void The_pages_under_accounts_mark_accounts(AdminPageKind kind) =>
        Assert.Contains("<a href=\"/\" aria-current=\"page\">", Wrap(kind), StringComparison.Ordinal);

    /// <summary>Told nothing, the page links the stylesheet this app ships and serves.</summary>
    /// <remarks>
    /// Unlike the authorization server, whose unthemed pages link nothing at all. That is a library
    /// and ships no <c>wwwroot</c>; this is an application that does, so "configure nothing" here
    /// means the shipped look rather than no look.
    /// </remarks>
    [Fact]
    public void The_shipped_stylesheet_is_linked_by_default()
    {
        Assert.Contains(
            "<link rel=\"stylesheet\" href=\"/css/admin.css\">", Wrap(), StringComparison.Ordinal);

        Assert.Equal([DefaultAdminLayout.ShippedStylesheet], Options().StylesheetPaths);
    }

    /// <summary>
    /// A deployment's sheets are linked in the order it gave them.
    /// </summary>
    /// <remarks>
    /// A list rather than one path, because a deployment with a design system has a base sheet and
    /// an override, and concatenating them into one file to satisfy an API is work that buys
    /// nothing. Order is preserved, since for stylesheets order is meaning.
    /// </remarks>
    [Fact]
    public void Configured_stylesheets_are_linked_in_order()
    {
        var html = Wrap(stylesheets: ["/css/base.css", "/css/northwind.css"]);

        var first = html.IndexOf("/css/base.css", StringComparison.Ordinal);
        var second = html.IndexOf("/css/northwind.css", StringComparison.Ordinal);

        Assert.True(first >= 0 && second > first, "both sheets link, base first");
        Assert.DoesNotContain("/css/admin.css", html, StringComparison.Ordinal);
    }

    /// <summary>A path is an attribute value, so it is encoded like every other one.</summary>
    [Fact]
    public void A_stylesheet_path_is_encoded()
    {
        var html = Wrap(stylesheets: ["/css/a\">.css"]);

        Assert.DoesNotContain("href=\"/css/a\">.css\"", html, StringComparison.Ordinal);
        Assert.Contains("&quot;", html, StringComparison.Ordinal);
    }

    private static AdminBffOptions Options(params string[] stylesheets) => new()
    {
        Authority = "https://auth.example",
        AdminApi = "https://auth.example",
        ClientId = "admin-ui",
        ClientSecret = "unused-by-this-test",
        Resource = "https://auth.example/admin",
        StylesheetPaths = stylesheets.Length > 0 ? stylesheets : [DefaultAdminLayout.ShippedStylesheet],
    };

    /// <summary>
    /// A stylesheet the browser would refuse is refused at startup instead.
    /// </summary>
    /// <remarks>
    /// These pages send <c>default-src 'self'</c> with no <c>style-src</c> override, so a sheet on
    /// another origin never loads. The only trace of that is a line in a console nobody has open, on
    /// a page that renders unstyled in production — so it is caught here, in a message naming the
    /// setting.
    /// </remarks>
    [Theory]
    [InlineData("https://cdn.example/x.css")]   // another origin outright
    [InlineData("//cdn.example/x.css")]         // protocol-relative: looks like a path, is not
    [InlineData("/\\cdn.example/x.css")]        // the backslash a browser normalises to a slash
    [InlineData("css/admin.css")]               // relative, so it depends on the page's path
    [InlineData("")]
    public void A_stylesheet_that_is_not_a_path_on_this_origin_is_refused(string path)
    {
        Assert.False(Options(path).TryValidate(out var errors));
        Assert.Contains("ADMIN_STYLESHEETS[0]", errors.Single(), StringComparison.Ordinal);
    }

    /// <summary>Every problem, rather than the first one.</summary>
    [Fact]
    public void Validation_collects_every_problem()
    {
        Assert.False(Options("//a.example/x.css", "/css/ok.css", "//b.example/y.css")
            .TryValidate(out var errors));

        Assert.Equal(2, errors.Count);
        Assert.Contains("ADMIN_STYLESHEETS[0]", errors[0], StringComparison.Ordinal);
        Assert.Contains("ADMIN_STYLESHEETS[2]", errors[1], StringComparison.Ordinal);
    }

    /// <summary>The default validates, which is the case a deployment that sets nothing hits.</summary>
    [Fact]
    public void The_default_passes_validation()
    {
        Assert.True(Options().TryValidate(out var errors));
        Assert.Empty(errors);
    }
}
