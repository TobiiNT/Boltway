using System.Net;
using System.Text.RegularExpressions;

namespace Boltway.Interaction.Testing;

/// <summary>
/// The small amount of HTML reading the contract needs.
/// </summary>
/// <remarks>
/// <para>
/// Regex rather than a parser, and that is a deliberate trade rather than a shortcut. This assembly
/// ships to customers, so every dependency it takes is one their test project takes too, and an
/// HTML parser is a large one to impose for four questions this narrow. The questions are all
/// "does this shape appear at all", which is exactly the class a regex answers safely.
/// </para>
/// <para>
/// <b>The one assumption:</b> a correctly rendered page has no raw <c>&lt;</c> or <c>&gt;</c> in
/// text or in an attribute value, because everything interpolated has been HTML-encoded. A renderer
/// that violates that breaks <see cref="Text"/> — and fails
/// <c>Interpolated_markup_is_encoded_rather_than_rendered</c> in the same run, which is the finding
/// that matters.
/// </para>
/// </remarks>
public static partial class Markup
{
    [GeneratedRegex("<[^>]*>")]
    private static partial Regex Tag();

    [GeneratedRegex(@"<script\b[^>]*>(?<body>.*?)</script>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex ScriptElement();

    /// <summary>A <c>script</c> or <c>style</c> element, with its opening tag and its content.</summary>
    [GeneratedRegex(
        @"<(?<tag>script|style)\b(?<attributes>[^>]*)>(?<body>.*?)</\k<tag>>",
        RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex InlineBlock();

    [GeneratedRegex(@"\sstyle\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex StyleAttribute();

    /// <summary>Inline event handlers — <c>onclick</c>, <c>onload</c> and the rest of the family.</summary>
    [GeneratedRegex(@"\son[a-z]+\s*=", RegexOptions.IgnoreCase)]
    private static partial Regex EventHandlerAttribute();

    /// <summary>
    /// Anything the page asks the browser to fetch or post to, that is not a same-origin path.
    /// </summary>
    /// <remarks>
    /// Absolute URLs, protocol-relative URLs, <c>data:</c> and <c>javascript:</c>. Under
    /// <c>default-src 'self'</c> with no <c>style-src</c> or <c>script-src</c> override, every one of
    /// them is refused by the browser — so a renderer that emits one has produced a page that is
    /// broken in production and passing in a fixture, which is the failure this whole suite exists
    /// to move earlier.
    /// </remarks>
    [GeneratedRegex(
        @"(?<attribute>src|href|action)\s*=\s*[""'](?<value>(?:https?:|//|data:|javascript:)[^""']*)",
        RegexOptions.IgnoreCase)]
    private static partial Regex OffOriginReference();

    /// <summary>The page's text, as a reader sees it: tags removed, entities resolved once.</summary>
    /// <remarks>
    /// Decoded exactly once, which is what makes this the double-encoding detector. A name encoded
    /// twice arrives here as <c>Caf&amp;#233;</c> rather than <c>Café</c> — the literal mojibake a
    /// review measured on the consent page — and the assertion that the name reads back verbatim is
    /// the one that fails.
    /// </remarks>
    public static string Text(string html) =>
        WebUtility.HtmlDecode(Tag().Replace(html, " "));

    /// <summary>
    /// The markup with entities resolved once and tags left in place, for reading attribute values.
    /// </summary>
    /// <remarks>
    /// <see cref="Text"/> cannot answer questions about attributes, because stripping the tag takes
    /// the attribute with it. A <c>returnUrl</c> carrying a query string is the case that needs
    /// this: it holds <c>&amp;</c>, a correct renderer writes <c>&amp;amp;</c>, and asserting the raw
    /// value appears would be asserting the renderer forgot to encode it.
    /// </remarks>
    public static string Decoded(string html) => WebUtility.HtmlDecode(html);

    /// <summary>A <c>&lt;script&gt;</c> element with a body, which no CSP here will execute.</summary>
    /// <remarks>
    /// A <c>&lt;script src="/js/…"&gt;</c> with an empty body is <i>allowed</i> and deliberately not
    /// reported: <c>'self'</c> covers a same-origin script file, so a renderer wanting behaviour has
    /// a supported way to get it. What is banned is the inline body, which needs
    /// <c>'unsafe-inline'</c> or a nonce.
    /// </remarks>
    public static bool HasInlineScript(string html) =>
        ScriptElement().Matches(html).Any(match => match.Groups["body"].Value.Trim().Length > 0);

    /// <summary>
    /// Inline <c>script</c> and <c>style</c> blocks the given nonce does not cover.
    /// </summary>
    /// <remarks>
    /// <para>
    /// With <paramref name="nonce"/> <see langword="null"/> — which is the deployment default —
    /// every inline block is uncovered, because the policy then has no <c>script-src</c> or
    /// <c>style-src</c> at all and <c>default-src 'self'</c> refuses inline content outright.
    /// </para>
    /// <para>
    /// With a nonce, a block carrying <c>nonce="…"</c> with that exact value runs and one without it
    /// does not. The nonce is compared rather than merely looked for, because a layout that emits a
    /// nonce it generated itself — instead of the one from the model, which is the one in the header
    /// — produces markup that looks correct and is refused by every browser.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> UnnoncedInlineBlocks(string html, string? nonce) =>
    [
        .. InlineBlock().Matches(html)
            .Where(match => match.Groups["body"].Value.Trim().Length > 0)
            .Where(match => nonce is null || !CarriesNonce(match.Groups["attributes"].Value, nonce))
            .Select(match => match.Value),
    ];

    private static bool CarriesNonce(string attributes, string nonce) =>
        attributes.Contains($"nonce=\"{nonce}\"", StringComparison.Ordinal)
        || attributes.Contains($"nonce='{nonce}'", StringComparison.Ordinal);

    /// <summary>
    /// A <c>style</c> attribute, which no nonce can rescue.
    /// </summary>
    /// <remarks>
    /// Separate from the block check because the distinction is real and easy to get wrong: CSP
    /// nonces apply to elements, never to attributes. Turning a nonce on makes an inline
    /// <c>&lt;style&gt;</c> work and leaves <c>style="…"</c> refused exactly as before — it would
    /// take <c>'unsafe-hashes'</c>, which nothing here offers.
    /// </remarks>
    public static bool HasInlineStyleAttribute(string html) => StyleAttribute().IsMatch(html);

    /// <summary>Whether the markup carries an <c>on…=</c> handler, which the policy also refuses.</summary>
    public static bool HasEventHandlerAttribute(string html) =>
        EventHandlerAttribute().IsMatch(html);

    /// <summary>Every <c>src</c> or <c>href</c> pointing somewhere <c>default-src 'self'</c> will not load.</summary>
    public static IReadOnlyList<string> OffOriginReferences(string html) =>
        [.. OffOriginReference().Matches(html).Select(match => match.Groups["value"].Value)];
}
