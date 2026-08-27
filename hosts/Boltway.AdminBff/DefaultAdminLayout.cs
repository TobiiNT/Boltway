using System.Collections.Frozen;
using System.Text;

using static Boltway.AdminBff.AdminMarkup;

namespace Boltway.AdminBff;

/// <summary>
/// The shipped page shell: a navigation rail, who is signed in, and a way out.
/// </summary>
/// <remarks>
/// <para>
/// <b>No JavaScript, and no templating engine.</b> §7.1 chose the BFF partly because a
/// server-rendered form keeps <c>auth/</c>'s zero-JavaScript property and needs neither CORS nor a
/// CSP exception - so these pages send <c>default-src 'self'</c> and mean it.
/// </para>
/// <para>
/// <b>Nothing inline.</b> No <c>&lt;style&gt;</c>, no <c>style=</c>, no <c>onclick=</c>. The policy
/// has no <c>style-src</c> or <c>script-src</c> override, so both inherit <c>'self'</c> and the
/// browser refuses inline content - by policy rather than by review. A deployment that wants a
/// different look sets <see cref="AdminBffOptions.StylesheetPaths"/> and serves the file itself.
/// </para>
/// </remarks>
public sealed class DefaultAdminLayout : IAdminLayout
{
    /// <summary>
    /// The stylesheet this app ships in <c>wwwroot</c>.
    /// </summary>
    /// <remarks>
    /// Also <see cref="AdminBffOptions.StylesheetPaths"/>'s default, so a deployment that configures
    /// nothing gets the pages styled rather than bare. That differs from the authorization server,
    /// whose unthemed pages link no stylesheet at all - it is a library and ships no
    /// <c>wwwroot</c>, and this is an application that does.
    /// </remarks>
    public const string ShippedStylesheet = "/css/admin.css";

    private readonly AdminText _text;
    private readonly IReadOnlyList<string> _stylesheets;

    /// <summary>The shell with the shipped stylesheet and the built-in English.</summary>
    public DefaultAdminLayout()
        : this(AdminText.Default, [ShippedStylesheet])
    {
    }

    /// <summary>The shell in a deployment's words and a deployment's stylesheets.</summary>
    /// <param name="text">
    /// Where the navigation labels and the sign-out label come from, and where the document's
    /// language comes from. <see cref="AdminText.Default"/> for the built-in English.
    /// </param>
    /// <param name="stylesheets">
    /// What to link, in order. <b>Validated before it reaches here</b> - see
    /// <see cref="AdminBffOptions.TryValidate"/>. Order is preserved, since for stylesheets order is
    /// meaning.
    /// </param>
    public DefaultAdminLayout(AdminText text, IReadOnlyList<string> stylesheets)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(stylesheets);

        _text = text;
        _stylesheets = stylesheets;
    }

    /// <inheritdoc />
    public string Wrap(AdminPage page)
    {
        ArgumentNullException.ThrowIfNull(page);

        var links = new StringBuilder();

        foreach (var stylesheet in _stylesheets)
        {
            links.Append("<link rel=\"stylesheet\" href=\"").Append(Encode(stylesheet)).Append("\">");
        }

        return $"""
            <!DOCTYPE html><html lang="{Encode(_text.Language)}"{Direction(_text.Language)}><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{Encode(page.Title)}</title>{links}</head>
            <body>{Header(page)}<main>{page.Body}</main></body></html>
            """;
    }

    /// <summary><c> dir="rtl"</c> when the page's language reads right to left, or nothing.</summary>
    /// <remarks>
    /// <para>
    /// The stylesheet was converted to logical properties - <c>padding-inline-start</c> and its
    /// siblings - which do nothing at all until the document says which way it reads. Without this
    /// the admin pages render an Arabic translation left to right with every gutter on the wrong
    /// edge, and the sheet looks like it was never converted.
    /// </para>
    /// <para>
    /// <b>A copy of the list in <c>DefaultInteractionLayout</c> rather than a shared type, on
    /// purpose.</b> This app has no project reference to anything - it is an OAuth client of the
    /// authorization server and talks to it over HTTP, which is what keeps <c>N-17</c> true - so
    /// sharing nine strings would mean taking a dependency on the server to render a page. Same
    /// trade as <c>CloudLoggingFormatter</c>. The two lists can drift; what that costs is one
    /// language mirroring on one of the two surfaces, which is visible the moment anybody looks at
    /// it, and the alternative costs the boundary.
    /// </para>
    /// <para>
    /// Absent rather than <c>dir="ltr"</c> everywhere else: the default is already left to right,
    /// and a language this list does not know renders that way, which is the direction to be wrong
    /// in.
    /// </para>
    /// </remarks>
    private static string Direction(string language)
    {
        var separator = language.IndexOf('-', StringComparison.Ordinal);
        var primary = separator < 0 ? language : language[..separator];

        return RightToLeftLanguages.Contains(primary) ? " dir=\"rtl\"" : string.Empty;
    }

    /// <summary>The primary subtags this shell mirrors for, matched ordinally and case-insensitively.</summary>
    private static readonly FrozenSet<string> RightToLeftLanguages =
        FrozenSet.ToFrozenSet(
            ["ar", "he", "fa", "ur", "ps", "sd", "yi", "ckb", "dv"],
            StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The navigation, the operator, and sign-out.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Sign-out is unconditional, and that is the fix for a defect this shipped with.</b> The
    /// button used to sit inside the <c>OperatorName is { Length: &gt; 0 }</c> branch, which reads as
    /// tidy and is not: this server's ID token carries no name claim of any kind, so the condition
    /// was false on every request and the admin UI had no way out of itself. Measured on a running
    /// stack, not read - <c>form[action="/signout"]</c> matched zero elements on every page. Every
    /// page here is behind <c>RequireAuthorization()</c>, so there is always a session to end.
    /// </para>
    /// <para>
    /// <b>And it carries the antiforgery field, which is the second half of the same defect.</b>
    /// Making the button render revealed that pressing it answered <c>400</c>: <c>POST /signout</c>
    /// validates a token, and this form had never sent one because it had never been reachable.
    /// The first fix made the control visible and the second made it work.
    /// </para>
    /// <para>
    /// <b>The links are in a <c>&lt;nav&gt;</c> and the operator is in a footer, which is what makes
    /// this a rail rather than a line of text.</b> They used to be three anchors separated by a
    /// literal <c>·</c>, and that character is the shape of the shell rather than anything the page
    /// says: a sheet laying the rail out vertically had a stray dot between every pair of rows and
    /// no way to remove it, because a text node between two elements is not selectable. The two
    /// groups are also what a sheet needs to push one to the top and one to the bottom - with one
    /// flat list, "the last two children" was the only way to say it, and adding a fourth
    /// destination would have moved the operator into the navigation.
    /// </para>
    /// </remarks>
    private string Header(AdminPage page)
    {
        var current = Section(page.Kind);

        var header = new StringBuilder("<header><nav>")
            .Append("<a href=\"/\"")
            .Append(Current(current, "/")).Append('>')
            .Append(_text[AdminText.NavAccounts]).Append("</a>")
            .Append("<a href=\"/roles\"")
            .Append(Current(current, "/roles")).Append('>')
            .Append(_text[AdminText.NavRoles]).Append("</a>")
            .Append("<a href=\"/audit\"")
            .Append(Current(current, "/audit")).Append('>')
            .Append(_text[AdminText.NavAudit]).Append("</a>")
            .Append("</nav><div class=\"rail-foot\">");

        if (page.OperatorName is { Length: > 0 } who)
        {
            header.Append("<span class=\"who\">").Append(Encode(who)).Append("</span>");
        }

        return header
            .Append("<form method=\"post\" action=\"/signout\" class=\"inline\">")
            .Append("<input type=\"hidden\" name=\"").Append(Encode(page.Antiforgery.FieldName))
            .Append("\" value=\"").Append(Encode(page.Antiforgery.Token)).Append("\">")
            .Append("<button type=\"submit\">").Append(_text[AdminText.SignOut]).Append("</button></form>")
            .Append("</div></header>")
            .ToString();
    }

    /// <summary>
    /// Which navigation destination a page belongs under, or <see langword="null"/> for none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Derived from the kind rather than passed alongside it, because two facts that must agree are
    /// how a page ends up highlighting the wrong link - the same shape of defect as a Vietnamese
    /// page declaring <c>lang="en"</c>, which is why <see cref="AdminText.Language"/> travels with
    /// the words instead of being its own setting.
    /// </para>
    /// <para>
    /// The create form, one account and a generated password all belong under accounts: they are
    /// reached from there and returning there is what the reader will want next.
    /// <see cref="AdminPageKind.Refused"/> belongs nowhere and marks nothing, which is right for a
    /// page that is not a destination.
    /// </para>
    /// </remarks>
    private static string? Section(AdminPageKind kind) => kind switch
    {
        AdminPageKind.Accounts or AdminPageKind.Account
            or AdminPageKind.NewAccount or AdminPageKind.Password => "/",
        AdminPageKind.Roles => "/roles",
        AdminPageKind.Audit => "/audit",
        _ => null,
    };

    /// <summary>Mark the navigation link the reader is already on.</summary>
    /// <remarks>
    /// <para>
    /// <c>aria-current="page"</c> rather than a class, because it is the same fact stated once:
    /// assistive technology reads it, and CSS selects on it. A class would be the styling half only,
    /// and something would then have to remember to add the aria attribute beside it.
    /// </para>
    /// <para>
    /// It exists because a rail with no current-item state answers "where am I" with nothing - and
    /// unlike everything else in the shell, no stylesheet can supply it: the header was
    /// byte-identical on every page, and CSS cannot read the URL. It is the clearest example of what
    /// this seam is for, and of what configuring a stylesheet could never have reached.
    /// </para>
    /// </remarks>
    private static string Current(string? current, string href) =>
        string.Equals(current, href, StringComparison.Ordinal) ? " aria-current=\"page\"" : string.Empty;
}
