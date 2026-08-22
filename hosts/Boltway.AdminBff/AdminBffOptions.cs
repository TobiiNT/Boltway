namespace Boltway.AdminBff;

/// <summary>Where the authorization server is, what this app is to it, and how it looks.</summary>
/// <remarks>
/// <para>
/// Five required settings and no defaults for any of them. Every one is a fact about somebody else's
/// deployment, and a default would be this app guessing at a URL it then sends a secret to.
/// </para>
/// <para>
/// <see cref="StylesheetPaths"/> is the exception and is a different kind of thing: it is a fact
/// about this app's own <c>wwwroot</c>, so it has an answer that is right until a deployment says
/// otherwise.
/// </para>
/// </remarks>
public sealed class AdminBffOptions
{
    /// <summary>The authorization server's issuer URL. Discovery hangs off it.</summary>
    public required string Authority { get; init; }

    /// <summary>
    /// Where <c>/admin/*</c> is served.
    /// </summary>
    /// <remarks>
    /// Usually the same origin as <see cref="Authority"/> and settable separately because §1.4 puts
    /// the admin API on its own hostname in a deployment that wants one — the rule is that it is a
    /// separate <i>resource</i>, and a separate host is the ordinary way to make that visible.
    /// </remarks>
    public required string AdminApi { get; init; }

    /// <summary>What this app is registered as. A configured client, not a CIMD one.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// This app's secret.
    /// </summary>
    /// <remarks>
    /// It is what makes this a confidential client, which is the whole reason the BFF shape is
    /// available: a browser app could not hold this, and a token it obtained would live where a
    /// script could reach it.
    /// </remarks>
    public required string ClientSecret { get; init; }

    /// <summary>
    /// The admin API's resource URL, sent as RFC 8707 <c>resource</c>.
    /// </summary>
    /// <remarks>
    /// Binds the access token's <c>aud</c> to the admin API, so a token minted for this app cannot
    /// be replayed against the customer's connector. §1.4 — the admin API is its own resource, and
    /// this parameter is what makes that a property of the token rather than of the documentation.
    /// </remarks>
    public required string Resource { get; init; }

    /// <summary>
    /// Stylesheets to link, in order, each an absolute path on this origin.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The lowest of the three ways to change this UI, and the one to reach for first.</b> The
    /// others are <see cref="IAdminLayout"/>, which replaces the document around the page, and
    /// <see cref="IAdminRenderer"/>, which replaces the markup and takes on the encoding obligation
    /// that comes with it. A deployment that only wants its own typography and colours should never
    /// have to touch either, and before this setting existed it had no choice but to overwrite a file
    /// at a path the shell had hard-coded.
    /// </para>
    /// <para>
    /// The default is the sheet this app ships and serves out of <c>wwwroot</c>, so a deployment that
    /// sets nothing is unchanged. Setting this <i>replaces</i> the list rather than adding to it —
    /// name <c>/css/admin.css</c> alongside your own to keep it.
    /// </para>
    /// <para>
    /// <b>Everything here is a path on this origin, and that is not a style preference.</b> These
    /// pages send <c>default-src 'self'</c> with no <c>style-src</c> override, so a stylesheet on a
    /// CDN is refused by the browser. Refusing it in <see cref="TryValidate"/> instead means an
    /// operator learns at startup, from a message naming the setting, rather than from a page that
    /// renders unstyled in production with the explanation only in a browser console.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> StylesheetPaths { get; init; } = [DefaultAdminLayout.ShippedStylesheet];

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
                    $"ADMIN_STYLESHEETS[{i}] is '{StylesheetPaths[i]}'. It must be an absolute path on "
                    + "this origin, like '/css/admin.css'. The admin pages send default-src 'self', so a "
                    + "stylesheet anywhere else is refused by the browser and the page renders unstyled "
                    + "with nothing in any server log.");
            }
        }

        errors = problems;

        return problems.Count == 0;
    }

    /// <summary>
    /// An absolute path on this origin, and nothing a browser would resolve elsewhere.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same check as the authorization server's <c>InteractionOptions</c>, for the same reason
    /// and against the same two cases. <c>//evil.example/x.css</c> is the one worth naming: it looks
    /// like a path, and a browser reads it as protocol-relative and fetches it from another origin.
    /// <c>/\evil.example</c> is the same attack spelled differently — browsers normalise the
    /// backslash to a forward slash, so a check that only looked for <c>//</c> would pass it through.
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
