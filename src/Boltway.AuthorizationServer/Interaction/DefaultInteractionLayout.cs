using System.Collections.Frozen;
using System.Net;
using System.Text;
using Boltway.AuthorizationServer.Configuration;
using Microsoft.Extensions.Localization;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// The shipped page shell: a head, the configured theme, a brand panel, and the body.
/// </summary>
/// <remarks>
/// <para>
/// This used to be a private method on <see cref="DefaultInteractionRenderer"/>, and separating it
/// is what makes the middle tier exist. A deployment wanting its own header and footer around the
/// server's consent controls now replaces this one type, instead of reimplementing both pages and
/// inheriting every N-14 obligation along with them.
/// </para>
/// <para>
/// <b>Nothing inline.</b> The pages send <c>default-src 'self'</c> with no <c>style-src</c> or
/// <c>script-src</c> override, so both inherit <c>'self'</c> - an inline <c>&lt;style&gt;</c> or
/// <c>style="…"</c> attribute is blocked by the browser rather than by review. A stylesheet on this
/// origin is covered by <c>'self'</c>, which is what <see cref="InteractionOptions.StylesheetPaths"/>
/// produces and why it needs no change to the policy.
/// </para>
/// <para>
/// <b>The shell is two boxes and the stylesheet decides what that means.</b>
/// <c>bw-shell &gt; bw-panel + bw-content</c> is enough structure for a split-panel sign-in - brand
/// on the left, the decision on the right - and for the same markup to stack into a header bar on a
/// phone. It is emitted unconditionally, including when nothing is themed: an unstyled page is then
/// the brand panel's few words followed by the body, in that order, which reads correctly with no
/// stylesheet at all. <b>The panel never carries anything about the client</b>, which is what keeps
/// N-14's ordering a property of <see cref="InteractionPage.Body"/> alone.
/// </para>
/// </remarks>
public sealed class DefaultInteractionLayout : IInteractionLayout
{
    private readonly InteractionOptions _options;
    private readonly IStringLocalizer? _localizer;

    /// <summary>The shell with no theme.</summary>
    public DefaultInteractionLayout()
        : this(new InteractionOptions())
    {
    }

    /// <summary>The shell, themed by a deployment's own configuration.</summary>
    /// <param name="options">
    /// The theme. Its paths have been through <see cref="InteractionOptions.TryValidate"/> when it
    /// came from <c>AddBoltwayAuthorizationServer</c>, which is what makes them safe to write
    /// into an attribute here.
    /// </param>
    public DefaultInteractionLayout(InteractionOptions options)
        : this(options, localizer: null)
    {
    }

    /// <summary>The shell, themed and in a deployment's own words.</summary>
    /// <param name="options">The theme, validated as above.</param>
    /// <param name="localizer">
    /// Where the panel's two sentences come from, or <see langword="null"/> for none. Keys are
    /// <see cref="InteractionText.ShellTagline"/> and <see cref="InteractionText.ShellDomain"/>,
    /// both of which fall back to empty and are then omitted - so a deployment that translates
    /// nothing gets the panel it would have got without a localizer at all.
    /// </param>
    public DefaultInteractionLayout(InteractionOptions options, IStringLocalizer? localizer)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _localizer = localizer;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The product name goes in the <c>title</c> and the logo goes above the body, and neither is
    /// allowed near the sentence naming the client. That ordering is N-14's display requirement, so
    /// the shell is arranged so no theme setting can disturb it.
    /// </remarks>
    public string Wrap(InteractionPage page)
    {
        ArgumentNullException.ThrowIfNull(page);

        // The resolved culture, never the requested one. RequestLocalizationMiddleware has already
        // matched whatever arrived against SupportedUICultures and fallen back if it matched
        // nothing, so this is a value the server chose - putting `ui_locales` here directly would
        // reflect a query parameter into the document.
        //
        // Encoded anyway. A culture name cannot contain a quote, and "cannot" is a property of the
        // current framework rather than of this line.
        var language = WebUtility.HtmlEncode(System.Globalization.CultureInfo.CurrentUICulture.Name);

        if (language.Length == 0)
        {
            // The invariant culture has an empty name, and `lang=""` is worse than no attribute:
            // a screen reader reads it as "unknown" rather than falling back to the document's.
            language = "en";
        }

        var document = new StringBuilder("<!DOCTYPE html><html lang=\"")
            .Append(language)
            .Append('"');

        // Read off the same string `lang` carries, so the two attributes cannot come to disagree
        // about what language this page is in. Absent rather than `dir="ltr"` on everything else:
        // no `dir` already means left-to-right, so writing one would be a second place saying so.
        if (IsRightToLeft(language))
        {
            document.Append(" dir=\"rtl\"");
        }

        document.Append("><head><meta charset=\"utf-8\">")
            .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");

        foreach (var stylesheet in _options.StylesheetPaths)
        {
            document.Append("<link rel=\"stylesheet\" href=\"").Append(Encode(stylesheet)).Append("\">");
        }

        document.Append("<title>").Append(Encode(Titled(page.Title))).Append("</title></head><body>")
            .Append("<div class=\"bw-shell\">");

        Panel(document);

        return document
            .Append("<main class=\"bw-content\">").Append(page.Body).Append("</main>")
            .Append("</div></body></html>")
            .ToString();
    }

    /// <summary>
    /// The brand side of the split: the logo, and at most two sentences under it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The logo is the only thing here that predates the panel, and it is rendered exactly as it
    /// was.</b> The product name reaches this page as that image's <c>alt</c> and by no other route
    /// - writing it as text beside the logo was tried and reverted, because
    /// <c>The_product_name_is_not_in_the_body</c> is N-14 in an assertion: the most prominent text
    /// on the consent page is the client hostname, and a deployment name rendered as text is the
    /// one thing on the page that could out-rank it without anybody choosing that. A deployment
    /// whose mark is a glyph and who wants the word beside it has a stylesheet, which cannot make
    /// the panel say anything the server did not.
    /// </para>
    /// <para>
    /// <b>Both sentences are omitted when empty rather than rendered blank</b>, so this is the
    /// panel's whole configuration surface: a deployment with no logo and no translations gets an
    /// empty panel that a stylesheet can collapse, and one that sets everything gets the three lines
    /// the shipped theme is drawn around. Nothing here is required by anything, and nothing here
    /// comes from the request.
    /// </para>
    /// </remarks>
    private void Panel(StringBuilder document)
    {
        document.Append("<aside class=\"bw-panel\">");

        if (_options.LogoPath is { Length: > 0 } logo)
        {
            // Empty alt when there is no product name. A decorative image announced as "logo" tells
            // a screen-reader user nothing they can act on, and inventing a description for an image
            // this code has never seen would be worse than announcing nothing.
            document.Append("<p class=\"bw-brand\"><img src=\"").Append(Encode(logo))
                .Append("\" alt=\"").Append(Encode(_options.ProductName)).Append("\"></p>");
        }

        if (Text(InteractionText.ShellTagline) is { Length: > 0 } tagline)
        {
            document.Append("<p class=\"bw-tagline\">").Append(Encode(tagline)).Append("</p>");
        }

        // Which server this is, said on the page rather than only in the address bar. It is the
        // deployment's own host and never anything a request carried, which is what keeps it out of
        // N-14's way: nothing a client controls can reach this line.
        if (Text(InteractionText.ShellDomain) is { Length: > 0 } domain)
        {
            document.Append("<p class=\"bw-domain\">").Append(Encode(domain)).Append("</p>");
        }

        document.Append("</aside>");
    }

    /// <summary>The page title, carrying the product name when a deployment configured one.</summary>
    private string Titled(string title) =>
        _options.ProductName is { Length: > 0 } product ? title + " · " + product : title;

    /// <summary>A panel sentence as plain text, empty when nobody supplied one.</summary>
    private string Text(string key) => InteractionText.Plain(_localizer, key);

    private static string Encode(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    /// <summary>Whether a BCP 47 tag names a language whose modern script runs right to left.</summary>
    /// <remarks>
    /// The primary subtag decides it, because direction is a property of the writing system and not
    /// of the country: <c>ar-EG</c> and <c>ar-MA</c> are one script, and a table keyed on whole
    /// culture names would need a row for every region a deployment ever configures.
    /// </remarks>
    private static bool IsRightToLeft(string language)
    {
        var separator = language.IndexOf('-');

        return RightToLeftLanguages.Contains(separator < 0 ? language : language[..separator]);
    }

    /// <summary>The primary subtags this shell mirrors for, matched ordinally and case-insensitively.</summary>
    /// <remarks>
    /// <para>
    /// <b>A list rather than <see cref="System.Globalization.TextInfo.IsRightToLeft"/>, because that
    /// property cannot answer the question in this assembly.</b> It reads ICU data, and the build
    /// sets <c>InvariantGlobalization</c>, under which every culture carries invariant data.
    /// Measured 2026-08-23 on .NET SDK 10.0.111 by constructing each tag below and reading the
    /// property: all nine returned <see langword="false"/>, exactly as <c>en</c> did. So the
    /// framework call is not unavailable here - it is a silent wrong answer for every language
    /// alike, and would have shipped as "no page is ever right-to-left" with nothing failing.
    /// </para>
    /// <para>
    /// <b>Case-insensitive as a guard on the seam, not because the caller needs it.</b> Measured the
    /// same day: .NET normalizes a culture name's language subtag to lower case, so
    /// <c>GetCultureInfo("AR").Name</c> is <c>ar</c> and nothing mixed-case reaches this set through
    /// <c>CurrentUICulture</c> today. That is a property of the framework rather than of this file,
    /// and an ordinal comparer would make it one this file depends on - so there is no test pinning
    /// the insensitivity, because there is no path here that exercises it.
    /// </para>
    /// <para>
    /// A tag this list does not know renders left-to-right, which is the direction to be wrong in.
    /// Missing one leaves that language's page with its panel and accent bars on the far edge;
    /// mirroring one wrongly does the same thing to a language that was reading correctly before.
    /// </para>
    /// </remarks>
    private static readonly FrozenSet<string> RightToLeftLanguages =
        FrozenSet.ToFrozenSet(
            ["ar", "he", "fa", "ur", "ps", "sd", "yi", "ckb", "dv"],
            StringComparer.OrdinalIgnoreCase);
}
