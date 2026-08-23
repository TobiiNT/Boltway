using System.Text.Json;

namespace Boltway.AdminBff;

/// <summary>The account list. <c>E-25</c>.</summary>
/// <param name="Page">The page of accounts, as the admin API returned it.</param>
/// <param name="Antiforgery">This request's tokens. Every page needs them — see <see cref="AntiforgeryTokens"/>.</param>
/// <param name="Notice">
/// What just happened, as one of <see cref="AdminText.NoticeKeys"/> — not a sentence. See
/// <see cref="NoticeValue"/>.
/// </param>
/// <param name="OperatorName">Who is signed in, for the shell. See <see cref="AdminPage.OperatorName"/>.</param>
public sealed record AccountsViewModel(
    JsonElement Page, AntiforgeryTokens Antiforgery, string? Notice, string? OperatorName)
{
    /// <summary>
    /// The <c>{0}</c> of a notice that has one — here, the handle an account used to have.
    /// </summary>
    /// <remarks>
    /// <b>A key and a value rather than the finished sentence, and the split is the point.</b> Both
    /// halves reach this page across a redirect, so both are text somebody could have written into a
    /// link; the key is checked against a closed set and the value is escaped into a slot in a
    /// sentence this app chose. What was here before was the whole sentence, which made this app's
    /// own banner a surface for anything a link wanted it to say. It is also what makes the banner
    /// translatable at all — a sentence composed in an endpoint is the one string on these pages an
    /// <c>ADMIN_TEXT_FILE</c> cannot reach.
    /// </remarks>
    public string? NoticeValue { get; init; }
}

/// <summary>One account, and every operation on it.</summary>
/// <param name="Account">The account, as the admin API returned it.</param>
/// <param name="Antiforgery">This request's tokens, for the five forms this page draws.</param>
/// <param name="Notice">
/// What just happened, as one of <see cref="AdminText.NoticeKeys"/> — not a sentence. See
/// <see cref="NoticeValue"/>.
/// </param>
/// <param name="OperatorName">Who is signed in, for the shell.</param>
public sealed record AccountViewModel(
    JsonElement Account, AntiforgeryTokens Antiforgery, string? Notice, string? OperatorName)
{
    /// <summary>
    /// The <c>{0}</c> of a notice that has one — here, how many grants were revoked.
    /// </summary>
    /// <inheritdoc cref="AccountsViewModel.NoticeValue" path="/remarks"/>
    public string? NoticeValue { get; init; }

    /// <summary>
    /// This account's service account, or a JSON null when it holds none.
    /// </summary>
    /// <remarks>
    /// Optional so that every existing construction site — and the renderer contract's own fixtures
    /// — keep compiling and keep rendering a page without the section. A deployment whose
    /// authorization server predates the endpoint returns nothing here, and the page is simply the
    /// page it was before rather than an error.
    /// </remarks>
    public JsonElement ServiceAccount { get; init; }

    /// <summary>
    /// A secret just minted, shown once, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <b>It exists in this one render and nowhere else.</b> The server stores a digest, so this
    /// string cannot be fetched again by anybody — the page is the only copy, and a reader who
    /// navigates away without taking it has to rotate to get another.
    /// </remarks>
    public string? NewSecret { get; init; }

    /// <summary>
    /// Every scope the authorization server publishes, or <see langword="null"/> when this app
    /// could not find out.
    /// </summary>
    /// <remarks>
    /// <para>
    /// From <c>scopes_supported</c> in the discovery document, which the server documents as "every
    /// scope this server will issue" and enforces on <c>/authorize</c>. That is what makes a list of
    /// checkboxes honest here where the role field is deliberately a free-text box with a
    /// <c>datalist</c>: a role is an opaque string the server never compares to a constant, and a
    /// dropdown there would invent a rule; a scope outside this set is one <c>/authorize</c> would
    /// refuse.
    /// </para>
    /// <para>
    /// <b>Per request rather than on the renderer</b>, which is where <c>ADMIN_ROLES</c> lives. That
    /// is deployment configuration read once at startup; this is the server's own answer, fetched
    /// over the network, and a server that is upgraded to publish a new scope should not need this
    /// app restarted to offer it.
    /// </para>
    /// <para>
    /// <see langword="null"/> is "not known" and never "none": discovery can fail, and the page
    /// falls back to the box an operator types into rather than showing an empty list, which would
    /// read as a server that supports no scopes at all. Empty is treated the same way, because a
    /// document that omits <c>scopes_supported</c> has not said there are none.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string>? ScopesSupported { get; init; }
}

/// <summary>The create form. <c>E-27</c>.</summary>
/// <param name="Antiforgery">This request's tokens.</param>
/// <param name="Error">Why the last attempt was refused, or <see langword="null"/>.</param>
/// <param name="OperatorName">Who is signed in, for the shell.</param>
public sealed record NewAccountViewModel(
    AntiforgeryTokens Antiforgery, string? Error, string? OperatorName);

/// <summary>The audit log. <c>E-32</c>.</summary>
/// <param name="Entries">The entries, as the admin API returned them.</param>
/// <param name="Antiforgery">This request's tokens.</param>
/// <param name="OperatorName">Who is signed in, for the shell.</param>
public sealed record AuditViewModel(
    JsonElement Entries, AntiforgeryTokens Antiforgery, string? OperatorName);

/// <summary>
/// Every role this realm defines, with the forms that change them.
/// </summary>
/// <param name="Roles">The roles, as the admin API returned them.</param>
/// <param name="Antiforgery">This request's tokens.</param>
/// <param name="Notice">
/// What just happened, as one of <see cref="AdminText.NoticeKeys"/> — not a sentence. There is no
/// value beside it as there is on the two account pages, because no notice a role write produces
/// has a <c>{0}</c>: defined, applied and deleted each say only that they happened.
/// </param>
/// <param name="OperatorName">Who is signed in, for the shell.</param>
/// <remarks>
/// One page rather than a list and a detail page each. A realm has a handful of roles and the whole
/// point of looking at them is comparing what they stand for, which a page showing one at a time
/// cannot do.
/// </remarks>
public sealed record RolesViewModel(
    JsonElement Roles, AntiforgeryTokens Antiforgery, string? Notice, string? OperatorName)
{
    /// <summary>
    /// Every account the endpoint could read, for saying who holds each role.
    /// </summary>
    /// <remarks>
    /// Undefined when the accounts could not be fetched, and then the page says nothing about
    /// holders — not "nobody", which is a claim, and a dangerous one next to a delete button.
    /// The grouping happens in the renderer with the same <c>Texts(user, "role")</c> read the
    /// accounts list uses, so the two pages cannot disagree about what an account holds.
    /// </remarks>
    public JsonElement Accounts { get; init; }

    /// <summary>
    /// That <see cref="Accounts"/> stops short of the whole directory.
    /// </summary>
    /// <remarks>
    /// The endpoint walks the account pages with a cap. Under the cap this is false and the
    /// holder lists are exact; over it, every list on the page gets a sentence saying the count
    /// is partial, because "no account holds this role" computed from a truncated walk is how a
    /// held role gets deleted.
    /// </remarks>
    public bool HoldersTruncated { get; init; }
}

/// <summary>
/// A generated password, shown once.
/// </summary>
/// <param name="Handle">Whose password this is.</param>
/// <param name="Password">
/// The password itself — <b>the only page here carrying a live credential</b>.
/// </param>
/// <param name="Antiforgery">This request's tokens.</param>
/// <param name="OperatorName">Who is signed in, for the shell.</param>
/// <remarks>
/// A page of its own rather than a line on the account, and reached by a POST so it is not in
/// browser history as a URL somebody can return to. A renderer replacing this one keeps both
/// properties or the credential outlives the moment it was meant to exist for.
/// </remarks>
public sealed record PasswordViewModel(
    string Handle, string Password, AntiforgeryTokens Antiforgery, string? OperatorName);

/// <summary>What the admin API refused, and why.</summary>
/// <param name="Result">The refusal, with the API's own <c>error</c> and <c>error_description</c>.</param>
/// <param name="Antiforgery">This request's tokens.</param>
/// <param name="OperatorName">Who is signed in, for the shell.</param>
public sealed record RefusalViewModel(
    AdminResult Result, AntiforgeryTokens Antiforgery, string? OperatorName);

/// <summary>
/// Every page this app renders.
/// </summary>
/// <remarks>
/// <para>
/// <b>The highest of the three ways to change this UI, and the last one to reach for.</b>
/// <see cref="AdminBffOptions.StylesheetPaths"/> changes the theme and needs no code;
/// <see cref="IAdminLayout"/> replaces the document around the page. This one replaces the markup —
/// and with it takes on the obligation every page here carries, which is that handles, email
/// addresses, roles and audit details are strings an operator typed and this app never validated.
/// <see cref="AdminMarkup.Encode"/> is public so that obligation comes with a tool.
/// </para>
/// <para>
/// <b>Every member has a default implementation, so a deployment overrides the one page it cares
/// about and inherits five.</b> That is the difference from the authorization server's
/// <c>IInteractionRenderer</c>, where two members are required because they predate the rest; this
/// interface is new and has no such history, so requiring any of them would only be arbitrary.
/// </para>
/// <para>
/// <b>The cost of that, stated plainly:</b> <c>class Mine : IAdminRenderer { }</c> compiles, and so
/// does one whose override has a typo in its signature — it silently becomes a new method and the
/// page falls back to the shipped one. Nothing in the compiler can catch that. What can is
/// <c>AdminRendererContract</c> in <c>Boltway.AdminBff.Tests</c>: inherit it, point it at the
/// renderer, and a page that is not actually being overridden shows up as a failure rather than as a
/// screenshot somebody notices later.
/// </para>
/// <para>
/// <b>Why the defaults render in the shipped shell rather than the deployment's.</b> A default
/// interface member has no dependency injection, so it cannot reach the <see cref="IAdminLayout"/>
/// this deployment registered — the only thing it can honestly produce is the shipped page in the
/// shipped shell. That difference is visible on purpose: a page that does not match the others is
/// the signal to write it. A deployment that replaced only the layout never lands here, because it
/// is still using <see cref="DefaultAdminRenderer"/> and that one wraps with the registered layout.
/// </para>
/// </remarks>
public interface IAdminRenderer
{
    /// <summary>Render the account list.</summary>
    /// <param name="model">The page of accounts, and whatever just happened.</param>
    string RenderAccounts(AccountsViewModel model) => DefaultAdminRenderer.Shipped.RenderAccounts(model);

    /// <summary>Render one account and every operation on it.</summary>
    /// <param name="model">The account, the antiforgery token, and whatever just happened.</param>
    string RenderAccount(AccountViewModel model) => DefaultAdminRenderer.Shipped.RenderAccount(model);

    /// <summary>Render the create form.</summary>
    /// <param name="model">The antiforgery token, and why the last attempt was refused.</param>
    string RenderNewAccount(NewAccountViewModel model) => DefaultAdminRenderer.Shipped.RenderNewAccount(model);

    /// <summary>Render the audit log.</summary>
    /// <param name="model">The entries.</param>
    string RenderAudit(AuditViewModel model) => DefaultAdminRenderer.Shipped.RenderAudit(model);

    /// <summary>Render the roles this realm defines.</summary>
    /// <param name="model">The roles.</param>
    string RenderRoles(RolesViewModel model) => DefaultAdminRenderer.Shipped.RenderRoles(model);

    /// <summary>Render a generated password, once.</summary>
    /// <param name="model">Whose it is, and what it is.</param>
    string RenderPassword(PasswordViewModel model) => DefaultAdminRenderer.Shipped.RenderPassword(model);

    /// <summary>Render what the admin API refused.</summary>
    /// <param name="model">The refusal, in the API's own words.</param>
    string RenderRefusal(RefusalViewModel model) => DefaultAdminRenderer.Shipped.RenderRefusal(model);
}
