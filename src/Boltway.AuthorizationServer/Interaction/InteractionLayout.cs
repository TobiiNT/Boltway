namespace Boltway.AuthorizationServer.Interaction;

/// <summary>Which interactive page is being wrapped.</summary>
/// <remarks>
/// On the page rather than inferred from its title, because the title is prose a deployment may
/// translate and this is a thing a layout branches on.
/// </remarks>
public enum InteractionPageKind
{
    /// <summary>The sign-in page.</summary>
    Login,

    /// <summary>The consent page - the one N-14 governs.</summary>
    Consent,

    /// <summary>The sign-out page: the confirmation, and the answer after it.</summary>
    Logout,

    /// <summary>
    /// The authorization-error page - the one that renders when something has already failed.
    /// </summary>
    /// <remarks>
    /// A layout branching on this should keep it simple. It is reached on a path where something
    /// has already gone wrong, including "the server threw", so anything it needs is a second thing
    /// that can fail while handling the first.
    /// </remarks>
    Error,

    /// <summary>
    /// The self-service front page, <c>/me</c>.
    /// </summary>
    /// <remarks>
    /// The three kinds below are the only ones a user reaches while already signed in, which is the
    /// distinction a layout most often wants: every other page is drawn for somebody the server does
    /// not yet know, so it has no name to greet and no navigation to offer.
    /// </remarks>
    Account,

    /// <summary>The self-service password page, <c>/me/password</c>.</summary>
    ChangePassword,

    /// <summary>The self-service session list, <c>/me/sessions</c>.</summary>
    Sessions,

    /// <summary>
    /// The self-service list of standing approvals, <c>/me/consents</c>.
    /// </summary>
    /// <remarks>
    /// Not <see cref="Consent"/>. That one is drawn mid-authorization for somebody deciding now, and
    /// N-14 governs what it must show; this one is drawn for somebody signed in, reviewing decisions
    /// they already made. A layout that treated them as one page would put a signed-in shell around
    /// the page whose whole job is to be read by a person the server has not finished identifying.
    /// </remarks>
    Consents,

    /// <summary>
    /// Where a password-reset link lands, <c>/reset</c>.
    /// </summary>
    /// <remarks>
    /// Neither signed in nor anonymous in the usual sense: the reader holds a token instead of a
    /// session, which is why this is its own kind rather than being folded in with the three above.
    /// A layout offering "your account" navigation here would be linking somewhere the reader cannot
    /// go.
    /// </remarks>
    ResetPassword,

    /// <summary>Where an email-verification link lands, <c>/verify-email</c>.</summary>
    VerifyEmail,

    /// <summary>Where somebody who cannot sign in asks for a reset link, <c>/forgot</c>.</summary>
    ForgotPassword,
}

/// <summary>
/// A rendered page, before a deployment's shell goes around it.
/// </summary>
/// <remarks>
/// <see cref="Body"/> is the server's, and it is handed over as finished markup rather than as
/// fields precisely so that a layout cannot rebuild it. Everything N-14, A-11 and A-14 require is
/// already in that string, in the required order - so the only thing a layout can do wrong is fail
/// to include it, which is a single condition and therefore one the renderer can check.
/// </remarks>
public sealed record InteractionPage
{
    /// <summary>Which page this is.</summary>
    public required InteractionPageKind Kind { get; init; }

    /// <summary>The page's title. <b>Plain text; the layout encodes.</b></summary>
    public required string Title { get; init; }

    /// <summary>
    /// The server-rendered body. <b>Already encoded - write it out verbatim, do not encode again.</b>
    /// </summary>
    /// <remarks>
    /// The one value on any of these models that is markup rather than text, and the exception is
    /// what the whole seam is for. Encoding it would display the consent page's HTML to the user as
    /// literal text; rebuilding it would be tier three, which is <see cref="IInteractionRenderer"/>
    /// and comes with the obligations this seam exists to avoid handing over.
    /// </remarks>
    public required string Body { get; init; }

    /// <summary>
    /// This response's CSP nonce, or <see langword="null"/> when the deployment configured none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The reason a layout is where inline content becomes possible at all. A shell wanting a theme
    /// switcher, a focus trap or a critical-CSS block writes
    /// <c>&lt;script nonce="@page.Nonce"&gt;</c> and the browser runs it - and writes nothing
    /// inline when this is <see langword="null"/>, because then the policy has no <c>script-src</c>
    /// and <c>default-src 'self'</c> refuses it.
    /// </para>
    /// <para>
    /// It is the response's, not the page's: the same value is already in the
    /// <c>Content-Security-Policy</c> header, taken from the same place. Do not generate one here -
    /// a nonce the header does not name is a nonce the browser has never heard of.
    /// </para>
    /// </remarks>
    public required string? Nonce { get; init; }
}

/// <summary>
/// A deployment's page shell, wrapped around markup the server rendered.
/// </summary>
/// <remarks>
/// <para>
/// The middle of the three ways to change this UI. <see cref="Configuration.InteractionOptions"/>
/// below it changes the theme and can break nothing; <see cref="IInteractionRenderer"/> above it
/// replaces the markup and can break everything. This one moves the boundary to where most
/// deployments actually want it: full control of the document - header, navigation, footer,
/// structure, classes - with the part of the page that says who is asking and where the code is
/// going still rendered by the server.
/// </para>
/// <para>
/// <b>Why this is safer than a renderer, structurally rather than by convention:</b> a layout has
/// exactly one way to lose a security requirement, which is to leave <see cref="InteractionPage.Body"/>
/// out. A renderer has one way per field. One condition is checkable, so
/// <see cref="DefaultInteractionRenderer"/> checks it on every render and throws rather than
/// serving a consent page with no consent on it.
/// </para>
/// <para>
/// What a layout must respect is the CSP the server sends with these pages -
/// <c>default-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none';
/// object-src 'none'</c>. No inline <c>&lt;script&gt;</c> or <c>&lt;style&gt;</c>, no <c>style=</c>
/// or <c>onclick=</c> attribute, no <c>data:</c> URI, and nothing loaded from another origin.
/// <c>InteractionLayoutContract</c> in <c>Boltway.Interaction.Tests</c> asserts all of it.
/// </para>
/// </remarks>
public interface IInteractionLayout
{
    /// <summary>
    /// Return a complete HTML document containing <see cref="InteractionPage.Body"/> verbatim.
    /// </summary>
    /// <param name="page">What to wrap.</param>
    /// <returns>The whole document, <c>&lt;!DOCTYPE&gt;</c> onwards.</returns>
    string Wrap(InteractionPage page);
}
