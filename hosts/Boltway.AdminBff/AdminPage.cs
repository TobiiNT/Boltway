namespace Boltway.AdminBff;

/// <summary>Which admin page is being wrapped.</summary>
/// <remarks>
/// On the page rather than inferred from its title, because the title is prose a deployment
/// translates and this is a thing a layout branches on. It is also what the navigation is derived
/// from — see <see cref="IAdminLayout"/>.
/// </remarks>
public enum AdminPageKind
{
    /// <summary>The account list, <c>/</c>.</summary>
    Accounts,

    /// <summary>One account and every operation on it, <c>/users/{handle}</c>.</summary>
    Account,

    /// <summary>The create form, <c>/users/new</c>.</summary>
    NewAccount,

    /// <summary>Every role this realm defines, and the forms that change them, <c>/roles</c>.</summary>
    Roles,

    /// <summary>The audit log, <c>/audit</c>.</summary>
    Audit,

    /// <summary>
    /// A generated password, shown once.
    /// </summary>
    /// <remarks>
    /// The one page here that renders a live credential. A layout that adds anything which leaves
    /// the origin — an analytics beacon, a font from a CDN, a form posting elsewhere — must not add
    /// it to this page, and the CSP is what stops it rather than this remark.
    /// </remarks>
    Password,

    /// <summary>What the admin API refused, and why.</summary>
    Refused,
}

/// <summary>
/// The antiforgery field name and token for this request's forms.
/// </summary>
/// <remarks>
/// <para>
/// <b>On every page, because sign-out is on every page.</b> It used to be a parameter on the two
/// pages that draw a form an operator fills in, and the shell's own sign-out form was left without
/// one — so pressing it posted to an endpoint that validates a token the form never carried.
/// Measured against a mirror of this app's antiforgery setup rather than reasoned about: the cookie
/// half is set, the request half is absent, and <c>POST /signout</c> answers <c>400</c>.
/// </para>
/// <para>
/// Two values in one record so that a page cannot carry half of them, and so that adding a form to
/// a page is not also a change to that page's model.
/// </para>
/// </remarks>
/// <param name="FieldName">The hidden input's <c>name</c>.</param>
/// <param name="Token">The hidden input's <c>value</c>.</param>
public sealed record AntiforgeryTokens(string FieldName, string Token);

/// <summary>
/// A rendered admin page, before a deployment's shell goes around it.
/// </summary>
/// <remarks>
/// <see cref="Body"/> is the renderer's, and it is handed over as finished markup rather than as
/// fields precisely so that a layout cannot rebuild it — which is what keeps a layout free of the
/// encoding obligation every value on these pages carries.
/// </remarks>
public sealed record AdminPage
{
    /// <summary>Which page this is.</summary>
    public required AdminPageKind Kind { get; init; }

    /// <summary>
    /// The page's title. <b>Plain text; the layout encodes it.</b>
    /// </summary>
    /// <remarks>
    /// The asymmetry with <see cref="Body"/> is deliberate and was a shipped defect in the other
    /// direction: titles were passed already-encoded, the shell encoded them again, and a Vietnamese
    /// deployment's browser tab read <c>T&amp;#224;i khoản</c>. One of the things that reaches here
    /// is a handle an operator typed, and <c>&lt;/title&gt;</c> ends RCDATA — so the encoding cannot
    /// simply be dropped either. Plain text in, layout encodes, exactly once.
    /// </remarks>
    public required string Title { get; init; }

    /// <summary>
    /// The rendered body. <b>Already encoded — write it out verbatim, do not encode again.</b>
    /// </summary>
    /// <remarks>
    /// The one value here that is markup rather than text, and that exception is what the seam is
    /// for. Encoding it would show an operator the page's HTML as literal text.
    /// </remarks>
    public required string Body { get; init; }

    /// <summary>
    /// Who is signed in, as <b>plain text</b>, or <see langword="null"/> when there is no name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It is a handle when one could be established and the subject when one could not, so a
    /// layout must not read it as either.</b> This server's ID token carries
    /// <c>sub iss aud exp iat auth_time nonce at_hash</c> and nothing else, so the name does not
    /// arrive with the sign-in: <c>OperatorProfile</c> asks <c>/userinfo</c> for it separately and
    /// tolerates every way that can fail. A deployment serving no <c>/userinfo</c>, an account with
    /// no username, or one unlucky sign-in therefore renders a ULID here rather than a handle.
    /// </para>
    /// <para>
    /// <b><see langword="null"/> remains an ordinary answer, not a failure.</b> Nothing about this
    /// field is guaranteed to be present, and a layout that assumed it was is the defect below.
    /// </para>
    /// <para>
    /// A layout must not hang the sign-out control off this being present. That was the shipped
    /// defect: the button sat inside the name branch, the branch was false on every request, and the
    /// admin UI had no way out of itself at all. Whether there is a session to end and whether we can
    /// put a name to it are two questions, and they were one branch apart by accident.
    /// </para>
    /// </remarks>
    public required string? OperatorName { get; init; }

    /// <summary>
    /// The antiforgery tokens for this request.
    /// </summary>
    /// <remarks>
    /// A layout drawing any form of its own must include this as a hidden input, and the shipped
    /// layout does it for sign-out. Every POST this app serves is a state change on the directory
    /// against an ambient cookie, so <c>Program.cs</c> validates all of them — a form without the
    /// field is a button that answers <c>400</c>.
    /// </remarks>
    public required AntiforgeryTokens Antiforgery { get; init; }
}

/// <summary>
/// A deployment's page shell, wrapped around markup the renderer produced.
/// </summary>
/// <remarks>
/// <para>
/// The middle of the three ways to change this UI. <see cref="AdminBffOptions.StylesheetPaths"/>
/// below it changes the theme and needs no code at all; <see cref="IAdminRenderer"/> above it
/// replaces the markup and takes on the encoding obligation with it. This one is where most of the
/// demand actually is: full control of the document — header, navigation, footer, structure, classes
/// — with the page's own content still rendered here.
/// </para>
/// <para>
/// <b>Measured demand, not a guess.</b> Restyling this app for one deployment needed three
/// things a stylesheet could not supply, and two of them were the shell: a current-item state on the
/// navigation, and somewhere for the rail to be a rail. The third was an audit timestamp, which is a
/// renderer concern. So the split is two-to-one in favour of the tier that does not require
/// rewriting a single page.
/// </para>
/// <para>
/// <b>Why this is safer than a renderer, structurally rather than by convention:</b> a layout has
/// exactly one way to lose the page, which is to leave <see cref="AdminPage.Body"/> out. One
/// condition is checkable, so <see cref="DefaultAdminRenderer"/> checks it on every render rather
/// than serving an empty document. A renderer has one way per value, and no check can find them.
/// </para>
/// <para>
/// What a layout must respect is the CSP this app sends — <c>default-src 'self'; frame-ancestors
/// 'none'; form-action 'self'; base-uri 'none'</c>. No inline <c>&lt;script&gt;</c> or
/// <c>&lt;style&gt;</c>, no <c>style=</c> or <c>onclick=</c> attribute, no <c>data:</c> URI, and
/// nothing loaded from another origin. There is no nonce here and deliberately so: these pages have
/// no inline content, and a nonce nobody uses is a token in a header inviting the next person to
/// find a use for it.
/// </para>
/// </remarks>
public interface IAdminLayout
{
    /// <summary>
    /// Return a complete HTML document containing <see cref="AdminPage.Body"/> verbatim.
    /// </summary>
    /// <param name="page">What to wrap.</param>
    /// <returns>The whole document, <c>&lt;!DOCTYPE&gt;</c> onwards.</returns>
    string Wrap(AdminPage page);
}
