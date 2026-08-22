using System.Net;
using System.Text.RegularExpressions;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// What has to hold of <b>any</b> <see cref="IAdminRenderer"/>, including a replacement.
/// </summary>
/// <remarks>
/// <para>
/// Inherit it, return the renderer under test from <see cref="Renderer"/>, and these run against it.
/// It asserts nothing about wording, markup or layout — a replacement renderer exists to change all
/// three. What it asserts is the set of properties that stop being true quietly: an unencoded value,
/// a document that is not a document, a page that lost the one thing it was rendered to show, and a
/// CSP the browser will enforce whether or not the renderer knows about it.
/// </para>
/// <para>
/// <b>It is also how a deployment finds out its override is not being called.</b> Every member of
/// <see cref="IAdminRenderer"/> has a default implementation, so a class whose override has a typo
/// in its signature compiles, becomes a new method nobody calls, and silently renders the shipped
/// page. Nothing in the compiler catches that. A subclass of this that also asserts its own wording
/// does.
/// </para>
/// <para>
/// <b>Why it is here rather than in a package.</b> The authorization server ships
/// <c>Boltway.Interaction.Testing</c> because it is a library and its renderer is implemented
/// in customer projects. This app is <c>IsPackable=false</c> and ships as a container image, so the
/// only way to replace this renderer today is to fork — and a fork has this file. Making the app
/// packable is what would turn this into a package, and that is a separate decision about a
/// published API surface rather than a detail of this one.
/// </para>
/// </remarks>
public abstract class AdminRendererContract
{
    /// <summary>The renderer under test.</summary>
    protected abstract IAdminRenderer Renderer { get; }

    /// <summary>A handle that is an injection attempt, used wherever a page renders one.</summary>
    private const string Hostile = "x\"><script>alert(1)</script>";

    private static readonly Regex Urls = new(
        "(?:href|src|action)=\"([^\"]*)\"", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));

    /// <summary>Every page, each rendered with something hostile in it.</summary>
    /// <remarks>
    /// One list, walked by every assertion below, so a page added to the interface is covered by all
    /// of them at once rather than by whichever ones somebody remembered.
    /// </remarks>
    private IEnumerable<(string Page, string Html)> EveryPage()
    {
        var account = Render.Json(
            $$"""
            {"handle":{{JsonString(Hostile)}},"email":{{JsonString(Hostile)}},"email_verified":true,
             "role":{{JsonString(Hostile)}},"subject":{{JsonString(Hostile)}},
             "realm":{{JsonString(Hostile)}},"has_password":true}
            """);

        yield return ("accounts", Renderer.RenderAccounts(new AccountsViewModel(
            Render.Json($$"""{"users":[{"handle":{{JsonString(Hostile)}},"role":"employee"}],"next":{{JsonString(Hostile)}}}"""),
            new AntiforgeryTokens("__t", Hostile), Hostile, Hostile)));

        yield return ("account", Renderer.RenderAccount(
            new AccountViewModel(account, new AntiforgeryTokens("__t", Hostile), Hostile, Hostile)));

        yield return ("new-account", Renderer.RenderNewAccount(
            new NewAccountViewModel(new AntiforgeryTokens("__t", Hostile), Hostile, Hostile)));

        yield return ("audit", Renderer.RenderAudit(new AuditViewModel(
            Render.Json(
                $$"""
                [{"at":"2026-08-13T08:00:00+00:00","actor_kind":{{JsonString(Hostile)}},
                  "action":{{JsonString(Hostile)}},"target_handle":{{JsonString(Hostile)}},
                  "outcome":{{JsonString(Hostile)}},"detail":{{JsonString(Hostile)}}}]
                """),
            new AntiforgeryTokens("__t", Hostile), Hostile)));

        yield return ("roles", Renderer.RenderRoles(new RolesViewModel(
            Render.Json(
                $$"""
                {"roles":[{"id":{{JsonString(Hostile)}},"name":{{JsonString(Hostile)}},
                           "permissions":[{{JsonString(Hostile)}}]}]}
                """),
            new AntiforgeryTokens("__t", Hostile), Hostile, Hostile)));

        yield return ("password", Renderer.RenderPassword(
            new PasswordViewModel(Hostile, Hostile, new AntiforgeryTokens("__t", Hostile), Hostile)));

        yield return ("refusal", Renderer.RenderRefusal(new RefusalViewModel(
            Render.Refusal(HttpStatusCode.Forbidden, Hostile, Hostile), new AntiforgeryTokens("__t", Hostile), Hostile)));
    }

    private static string JsonString(string value) => System.Text.Json.JsonSerializer.Serialize(value);

    /// <summary>Every page is a whole document, because every one of them is served as the response.</summary>
    /// <remarks>
    /// There is no outer template. A renderer returning a fragment produces a page a browser renders
    /// in quirks mode, which changes box sizing and is the kind of defect that looks like a CSS bug
    /// for a day.
    /// </remarks>
    [Fact]
    public void Every_page_is_a_complete_document()
    {
        foreach (var (page, html) in EveryPage())
        {
            Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.OrdinalIgnoreCase);
            Assert.EndsWith("</html>", html.TrimEnd(), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("<title>", html, StringComparison.OrdinalIgnoreCase);
            Assert.True(html.Contains("<html lang=\"", StringComparison.OrdinalIgnoreCase), page + " declares a language");
        }
    }

    /// <summary>
    /// Nothing an operator typed reaches the page as markup.
    /// </summary>
    /// <remarks>
    /// This app is a client, not the directory: it has validated none of these values. Handles,
    /// addresses, roles, audit details and the API's own refusal text all arrive from somewhere that
    /// accepted them, and "it came from our own API" is not a reason to trust a string.
    /// </remarks>
    [Fact]
    public void No_value_reaches_the_page_as_markup()
    {
        foreach (var (page, html) in EveryPage())
        {
            Assert.False(html.Contains("<script>", StringComparison.OrdinalIgnoreCase), page + " has no injected script");
            Assert.False(html.Contains("\"><script", StringComparison.OrdinalIgnoreCase), page + " has no attribute escape");
            Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The pages send <c>default-src 'self'</c>, so nothing inline and nothing off-origin.
    /// </summary>
    /// <remarks>
    /// The browser enforces this whether or not a renderer knows about it, which is what makes it
    /// worth asserting here: the failure is not an exception, it is a page that silently renders
    /// without the thing the renderer added.
    /// </remarks>
    [Fact]
    public void Nothing_is_inline_and_nothing_is_off_origin()
    {
        foreach (var (page, html) in EveryPage())
        {
            Assert.False(html.Contains("<style", StringComparison.OrdinalIgnoreCase), page + " has no inline style block");
            Assert.False(html.Contains(" style=\"", StringComparison.OrdinalIgnoreCase), page + " has no style attribute");
            Assert.False(html.Contains(" onclick=", StringComparison.OrdinalIgnoreCase), page + " has no event attribute");
            Assert.False(html.Contains("javascript:", StringComparison.OrdinalIgnoreCase), page + " has no javascript: url");

            foreach (Match match in Urls.Matches(html))
            {
                var url = match.Groups[1].Value;

                Assert.True(
                    url.StartsWith('/') || url.StartsWith('#'),
                    $"{page}: '{url}' must be a path on this origin — default-src 'self' refuses the rest, "
                    + "and a data: URI counts as the rest.");
            }
        }
    }

    /// <summary>
    /// The page rendered to show a credential once actually shows it.
    /// </summary>
    /// <remarks>
    /// The generated password exists nowhere else — the API returns it in the create and reset
    /// responses and never again. A renderer that dropped it leaves an operator with an account
    /// nobody can sign into and no error anywhere.
    /// </remarks>
    [Fact]
    public void The_password_page_carries_the_password()
    {
        var html = Renderer.RenderPassword(new PasswordViewModel("grace", "the-generated-value", Render.Tokens, "ada"));

        Assert.Contains("the-generated-value", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A refusal keeps the sentence naming the rule that was broken.
    /// </summary>
    /// <remarks>
    /// The admin API's refusals are written to say what an operator can act on — "`cli-acme` is
    /// outside your employee scope". A renderer replacing it with its own wording loses the only
    /// part of the page that was actionable, and this is the one page where there is nothing else to
    /// try.
    /// </remarks>
    [Fact]
    public void A_refusal_keeps_the_api_s_own_words()
    {
        var html = Renderer.RenderRefusal(new RefusalViewModel(
            Render.Refusal(HttpStatusCode.Forbidden, "forbidden", "`cli-acme` is outside your employee scope"), Render.Tokens,
            "ada"));

        Assert.Contains("outside your employee scope", Render.Decoded(html), StringComparison.Ordinal);
    }

    /// <summary>
    /// Every form that changes the directory carries the antiforgery token.
    /// </summary>
    /// <remarks>
    /// This app holds an ambient cookie, so without the token any page on the internet could submit
    /// these forms. <c>Program.cs</c> validates on every POST — a renderer that omits the field
    /// makes its own forms fail closed, which is safe and completely broken.
    /// </remarks>
    [Fact]
    public void Forms_that_change_the_directory_carry_the_antiforgery_token()
    {
        var pages = new[]
        {
            Renderer.RenderAccount(new AccountViewModel(
                Render.Account(), new AntiforgeryTokens("__field", "__token"), null, "ada")),
            Renderer.RenderNewAccount(new NewAccountViewModel(new AntiforgeryTokens("__field", "__token"), null, "ada")),
        };

        foreach (var html in pages)
        {
            Assert.Contains("name=\"__field\"", html, StringComparison.Ordinal);
            Assert.Contains("value=\"__token\"", html, StringComparison.Ordinal);

            // One token per form, not one per page: each of these pages posts to several endpoints.
            var forms = html.Split("<form", StringSplitOptions.None).Length - 1;
            var fields = html.Split("value=\"__token\"", StringSplitOptions.None).Length - 1;

            Assert.True(fields >= forms, $"{fields} token field(s) for {forms} form(s)");
        }
    }

    /// <summary>
    /// The sign-out form carries the token too, on every page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is a shipped defect, and it is the one this contract was written and immediately
    /// found.</b> The shell drew <c>&lt;form method="post" action="/signout"&gt;</c> with a button
    /// and nothing else, while <c>POST /signout</c> validates an antiforgery token like every other
    /// state change here — so pressing Sign out answered <c>400</c>.
    /// </para>
    /// <para>
    /// Confirmed by request rather than by reading: a mirror of this app's antiforgery setup, a GET
    /// that stores the cookie half, then that exact form posted back with no field and no header.
    /// <c>HTTP 400</c>. It went unnoticed because the button had never rendered at all until the
    /// defect above it was fixed, so nobody had pressed it.
    /// </para>
    /// <para>
    /// It is in the contract rather than in a layout test because it is a property of any page:
    /// a replacement layout that draws its own sign-out has exactly the same obligation, and would
    /// fail here the same way.
    /// </para>
    /// </remarks>
    [Fact]
    public void Every_page_s_sign_out_form_carries_the_antiforgery_token()
    {
        foreach (var (page, html) in EveryPage())
        {
            var signOut = html.IndexOf("action=\"/signout\"", StringComparison.Ordinal);

            Assert.True(signOut >= 0, page + " offers a way out of the app");

            var form = html[signOut..(html.IndexOf("</form>", signOut, StringComparison.Ordinal) + 7)];

            Assert.Contains("type=\"hidden\"", form, StringComparison.Ordinal);
            Assert.Contains("value=\"", form, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The account page keeps a way to reach each of the operations the API has.
    /// </summary>
    /// <remarks>
    /// Each is its own verb because none of them is a field somebody could pass to an update by
    /// accident. A renderer that folded them into the patch form would be rebuilding the API's
    /// shape, and the audit entry — written per operation — is what would drift.
    /// </remarks>
    [Fact]
    public void The_account_page_reaches_every_operation()
    {
        var html = Renderer.RenderAccount(new AccountViewModel(
            Render.Account(), new AntiforgeryTokens("__field", "__token"), null, "ada"));

        foreach (var verb in new[] { "patch", "password", "sessions", "anonymise" })
        {
            Assert.Contains($"/users/grace/{verb}\"", html, StringComparison.Ordinal);
        }
    }
}

/// <summary>The shipped renderer, held to the contract every renderer is held to.</summary>
public sealed class DefaultAdminRendererContract : AdminRendererContract
{
    protected override IAdminRenderer Renderer { get; } = Render.With(adminRoles: ["founder"]);
}

/// <summary>
/// A renderer that implements nothing, held to the same contract.
/// </summary>
/// <remarks>
/// <c>class Mine : IAdminRenderer { }</c> compiles, because every member has a default. That is the
/// point of the design — a deployment overrides one page and inherits five — and it is also the
/// footgun, because an override with a typo in its signature lands here without a compile error.
/// Running the contract against the empty implementation is what proves the fallback is a working
/// page rather than an exception waiting for the first deployment to try it.
/// </remarks>
public sealed class EmptyAdminRendererContract : AdminRendererContract
{
    private sealed class Nothing : IAdminRenderer;

    protected override IAdminRenderer Renderer { get; } = new Nothing();
}
