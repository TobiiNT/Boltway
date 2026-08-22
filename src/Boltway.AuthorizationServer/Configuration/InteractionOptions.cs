using System.Collections.ObjectModel;

namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// How the sign-in and consent pages look, without writing a renderer.
/// </summary>
/// <remarks>
/// <para>
/// <b>The lowest of the three ways to change this UI, and the one to reach for first.</b> The
/// others are <c>IInteractionLayout</c>, which replaces the page around the security-critical block,
/// and <c>IInteractionRenderer</c>, which replaces the markup entirely. Both of those hand a
/// deployment the ability to fail to display something N-14 requires; this one structurally cannot,
/// because nothing here reaches the part of the page that says who is asking and where the code is
/// going. A deployment that only wants its own typography and colours should never have to take on
/// that obligation, and before these options existed it had no choice.
/// </para>
/// <para>
/// <b>Everything here is a path on this origin, and that is not a style preference.</b> The pages
/// ship <c>default-src 'self'</c> with no <c>style-src</c> or <c>script-src</c> override, so a
/// stylesheet on a CDN is refused by the browser. Refusing it here instead means an operator learns
/// at startup, from a message naming the setting, rather than from a page that renders unstyled in
/// production with the explanation only in a browser console.
/// </para>
/// </remarks>
public sealed class InteractionOptions
{
    private IList<string> _stylesheetPaths = new List<string>();

    /// <summary>How long a product name may be before it is refused.</summary>
    /// <remarks>
    /// Operator-supplied rather than attacker-supplied, so this is a layout guard rather than a
    /// security one — but the page it lands on is the one whose entire job is to be read carefully,
    /// and a name long enough to push the client hostname off a phone screen defeats N-14 just as
    /// effectively whether or not anyone meant it to.
    /// </remarks>
    public const int MaxProductNameLength = 64;

    /// <summary>
    /// Stylesheets to link, in order, each an absolute path on this origin.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host serves them itself — <c>app.UseStaticFiles()</c> and a file under <c>wwwroot</c> is
    /// the whole of it. <c>'self'</c> covers a same-origin stylesheet, so this needs no change to
    /// the policy and no nonce.
    /// </para>
    /// <para>
    /// A list rather than one path, because a deployment with a design system has a base sheet and
    /// an override, and concatenating them into one file to satisfy this API is work that buys
    /// nothing. Order is preserved, since for stylesheets order is meaning.
    /// </para>
    /// </remarks>
    public IList<string> StylesheetPaths => _stylesheetPaths;

    /// <summary>
    /// What to call this deployment, appended to the title of each page.
    /// </summary>
    /// <remarks>
    /// The title is where it goes and the heading is not, deliberately. A browser tab reading
    /// "Sign in" tells a user nothing about which of several open tabs is asking, and a user who
    /// cannot tell which server they are signing in to is the condition every consent-page attack
    /// needs. Putting it in an <c>h1</c> instead would compete with the client hostname for the
    /// most prominent text on the page, which is the one thing N-14 fixes the order of.
    /// </remarks>
    public string? ProductName { get; set; }

    /// <summary>
    /// A logo for this deployment, as an absolute path on this origin.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This server's own logo, never the client's.</b> A client's <c>logo_uri</c> is a URL the
    /// client chose, and rendering it would tell whoever hosts it about every consent-page view —
    /// which is why <c>default-src 'self'</c> refuses it and why N-14 says to proxy rather than
    /// hotlink. That proxy does not exist, so no client logo reaches these pages at all.
    /// </para>
    /// <para>
    /// Rendered with <see cref="ProductName"/> as its alt text when there is one, and with empty
    /// alt text when there is not — a decorative image with an invented description is worse for a
    /// screen reader than one that announces nothing.
    /// </para>
    /// </remarks>
    public string? LogoPath { get; set; }

    /// <summary>
    /// Add a per-response nonce to the pages' <c>script-src</c> and <c>style-src</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Off, and the shipped pages do not need it.</b> They contain no inline script and no inline
    /// style, so with this off the policy stays exactly what it has always been —
    /// <c>default-src 'self'</c> governing scripts and styles by fallback, and nothing on the page
    /// asking for more. Turn it on only when a layout genuinely has inline content, because a nonce
    /// nobody uses is a token in a header that invites the next person to find a use for it.
    /// </para>
    /// <para>
    /// <b>What changes when it is on.</b> Two directives appear: <c>script-src 'self' 'nonce-…'</c>
    /// and <c>style-src 'self' 'nonce-…'</c>. <c>'self'</c> is repeated in both on purpose — naming a
    /// directive replaces the <c>default-src</c> fallback for it entirely, so omitting <c>'self'</c>
    /// would silently stop same-origin stylesheets and script files from loading, which is the
    /// stylesheet <see cref="StylesheetPaths"/> just configured.
    /// </para>
    /// <para>
    /// <b>What does not change, ever.</b> <c>frame-ancestors 'none'</c>, <c>base-uri 'none'</c>,
    /// <c>object-src 'none'</c> and <c>form-action</c> are untouched, and no setting anywhere adds
    /// <c>'unsafe-inline'</c> or <c>'unsafe-eval'</c>. A nonce is the alternative to those, not a
    /// step toward them: with a nonce present, a CSP2 browser ignores <c>'unsafe-inline'</c>
    /// altogether.
    /// </para>
    /// <para>
    /// The nonce is 128 bits from the system CSPRNG, fresh for every response, and never reused.
    /// That is only sound because these pages already send <c>Cache-Control: no-store</c> — a nonced
    /// page served twice from a cache is a nonce an attacker has seen, which is the failure that
    /// makes most nonce deployments worthless.
    /// </para>
    /// </remarks>
    public bool UseContentSecurityPolicyNonce { get; set; }

    /// <summary>
    /// Put the configured sign-in providers above the password form rather than below it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Off, because which method leads is a fact about a deployment and not about this server.</b>
    /// A deployment whose people all sign in with Google reads a page that opens with two empty text
    /// fields as friction; one whose people mostly type a password reads a page that opens with
    /// somebody else's logo as a detour. Neither is the general case, so the shipped order is the
    /// one that has always been here and this is the way to change it.
    /// </para>
    /// <para>
    /// <b>Why this is a server setting rather than something CSS could do.</b> A stylesheet can
    /// reorder these with <c>order</c> on a flex container — and doing so would move the buttons
    /// without moving the tab order, so a keyboard reaches them in the order the markup has and the
    /// eye reaches them in the order the page shows. That is WCAG 2.4.3 broken on the one page where
    /// somebody may be typing a password they cannot see. Reordering has to happen in the markup.
    /// </para>
    /// <para>
    /// With this on and both methods available, the renderer draws
    /// <c>InteractionText.LoginOrPassword</c> between them. With only one method configured
    /// there is nothing to order and nothing to separate, so the setting has no effect.
    /// </para>
    /// </remarks>
    public bool ProvidersFirst { get; set; }

    /// <summary>Validate. Collects every problem rather than the first.</summary>
    /// <param name="errors">Every problem found.</param>
    public bool TryValidate(out IReadOnlyList<string> errors)
    {
        List<string> problems = [];

        for (var i = 0; i < StylesheetPaths.Count; i++)
        {
            if (!IsSameOriginPath(StylesheetPaths[i]))
            {
                problems.Add(
                    $"InteractionOptions.StylesheetPaths[{i}] is '{StylesheetPaths[i]}'. It must be an "
                    + "absolute path on this origin, like '/css/authorization.css'. The authorization "
                    + "pages send default-src 'self', so a stylesheet anywhere else is refused by the "
                    + "browser and the page renders unstyled with nothing in any server log.");
            }
        }

        if (LogoPath is not null && !IsSameOriginPath(LogoPath))
        {
            problems.Add(
                $"InteractionOptions.LogoPath is '{LogoPath}'. It must be an absolute path on this "
                + "origin, like '/img/logo.svg' — default-src 'self' refuses an image from anywhere "
                + "else, and the page renders with a broken image.");
        }

        if (ProductName is { Length: > MaxProductNameLength })
        {
            problems.Add(
                $"InteractionOptions.ProductName is {ProductName.Length} characters and the maximum is "
                + $"{MaxProductNameLength}.");
        }

        errors = problems;
        return problems.Count == 0;
    }

    /// <summary>Make the collections read-only, with the rest of the options.</summary>
    internal void Freeze() =>
        _stylesheetPaths = new ReadOnlyCollection<string>([.. _stylesheetPaths]);

    /// <summary>
    /// An absolute path on this origin, and nothing a browser would resolve elsewhere.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>//evil.example/x.css</c> is the case worth naming: it looks like a path, and a browser
    /// reads it as protocol-relative and fetches it from another origin. <c>/\evil.example</c> is the
    /// same attack spelled differently — browsers normalise the backslash to a forward slash, so a
    /// check that only looked for <c>//</c> would pass it through.
    /// </para>
    /// <para>
    /// Printable ASCII only. A path needing anything else needs it percent-encoded, and accepting the
    /// raw bytes would put a space or a control character into an HTML attribute.
    /// </para>
    /// </remarks>
    internal static bool IsSameOriginPath(string? value) =>
        value is { Length: > 0 }
        && value[0] == '/'
        && (value.Length == 1 || (value[1] != '/' && value[1] != '\\'))
        && value.All(character => character is > (char)0x20 and < (char)0x7F
            && character is not ('"' or '\'' or '<' or '>' or '\\'));
}
