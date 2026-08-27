using Boltway.AuthorizationServer.Interaction;

namespace Boltway.Interaction.Testing;

/// <summary>
/// The <see cref="IInteractionLayout"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// Much shorter than <see cref="InteractionRendererContract"/>, and the difference in length is the
/// whole argument for the seam. A layout cannot get N-14 wrong, because it never sees the client's
/// hostname - it receives finished markup with all of that already in it. What is left to check is
/// that it returns a document, puts the markup in it, and does not add anything the page's own CSP
/// will refuse.
/// </para>
/// <para>
/// A deployment writing a layout runs this. A deployment writing a renderer runs the other one,
/// which is nineteen assertions longer, and choosing between them is the choice this tiering
/// exists to make visible.
/// </para>
/// </remarks>
public abstract class InteractionLayoutContract
{
    /// <summary>The layout under test.</summary>
    protected abstract IInteractionLayout NewLayout();

    /// <summary>
    /// The server's markup survives, byte for byte.
    /// </summary>
    /// <remarks>
    /// The one rule. Everything the consent page is required to display is inside that string, so a
    /// layout that drops it, truncates it, or HTML-encodes it has removed the client hostname, the
    /// unverified-name notice, the redirect destination, the scope list and the form, all at once.
    /// <c>DefaultInteractionRenderer</c> checks the same condition at render time - this is the
    /// check a layout author gets to run before deploying rather than after.
    /// </remarks>
    [Theory]
    [InlineData(InteractionPageKind.Consent)]
    [InlineData(InteractionPageKind.Login)]
    public void The_server_rendered_body_appears_verbatim(InteractionPageKind kind)
    {
        var page = Page(kind);

        Assert.Contains(page.Body, NewLayout().Wrap(page), StringComparison.Ordinal);
    }
    /// <summary>A whole HTML document, not a fragment: the endpoint writes the return value as-is.</summary>

    [Theory]
    [InlineData(InteractionPageKind.Consent)]
    [InlineData(InteractionPageKind.Login)]
    public void The_result_is_a_whole_document(InteractionPageKind kind)
    {
        var document = NewLayout().Wrap(Page(kind));

        Assert.Contains("<html", document, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("</html>", document, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<body", document, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The title reaches the document, so a browser tab is distinguishable.</summary>
    [Fact]
    public void The_title_reaches_the_document()
    {
        var document = NewLayout().Wrap(Page(InteractionPageKind.Consent));

        Assert.Contains("Authorize access", Markup.Decoded(document), StringComparison.Ordinal);
    }

    /// <summary>
    /// The shell renders within the policy the server sends with it.
    /// </summary>
    /// <remarks>
    /// A layout is where a stylesheet link, a webfont or a header script would be added, so it is
    /// where <c>default-src 'self'</c> is most likely to be broken - and broken silently, since the
    /// page still renders and only looks wrong. The body in the fixture carries nothing of its own,
    /// so anything this finds came from the shell.
    /// </remarks>
    [Theory]
    [InlineData(InteractionPageKind.Consent, null)]
    [InlineData(InteractionPageKind.Login, null)]
    [InlineData(InteractionPageKind.Consent, "r4nd0m-nonce-value")]
    [InlineData(InteractionPageKind.Login, "r4nd0m-nonce-value")]
    public void The_shell_renders_within_the_policy_the_server_sends(InteractionPageKind kind, string? nonce)
    {
        var document = NewLayout().Wrap(Page(kind) with { Nonce = nonce });

        // The row that matters for a layout with inline content. A shell emitting a theme switcher
        // or a critical-CSS block must nonce it with the value from the page - not one it made up,
        // and not none - and must emit nothing inline at all when the deployment configured no
        // nonce, because the policy then has no script-src for it to satisfy.
        Assert.Empty(Markup.UnnoncedInlineBlocks(document, nonce));

        Assert.False(Markup.HasInlineStyleAttribute(document), "A style attribute cannot carry a nonce.");
        Assert.False(Markup.HasEventHandlerAttribute(document), "An event handler attribute cannot carry a nonce.");

        Assert.Empty(Markup.OffOriginReferences(document));
    }
    /// <summary>A null page is an argument error, not a page rendered from nothing.</summary>

    [Fact]
    public void A_null_page_is_refused()
    {
        Assert.Throws<ArgumentNullException>(() => NewLayout().Wrap(null!));
    }

    /// <summary>
    /// A page whose body is plain and recognisable, so a failure is attributable to the shell.
    /// </summary>
    protected static InteractionPage Page(InteractionPageKind kind) => new()
    {
        Kind = kind,
        Title = kind is InteractionPageKind.Consent ? "Authorize access" : "Sign in",
        Body = "<h1>Authorize access</h1><p>The application at <strong>evil.example</strong> is asking.</p>",
        Nonce = null,
    };
}
