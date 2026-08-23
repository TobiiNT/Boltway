using System.Globalization;

using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Interaction.Testing;

namespace Boltway.Interaction.Tests;

// This repository's own derivations of the layout contract. They travelled with the contract when
// it moved into the shipped package and stopped running there — the Testing project has no test
// runner, deliberately — which is the same defect the move was fixing, one directory along. Two
// suites vanished from the run and the only sign was the total dropping by twenty.

/// <summary>The contract, against the shell that ships.</summary>
public sealed class DefaultInteractionLayoutTests : InteractionLayoutContract
{
    /// <inheritdoc />
    protected override IInteractionLayout NewLayout() => new DefaultInteractionLayout();
}

/// <summary>The contract, against the shell that ships, carrying a full theme.</summary>
/// <remarks>
/// Tier one inside tier two. A stylesheet link and a logo are exactly the shapes that would break
/// the CSP assertion if either were ever allowed to be an absolute URL, and this is where the two
/// tiers meet.
/// </remarks>
public sealed class ThemedDefaultInteractionLayoutTests : InteractionLayoutContract
{
    /// <inheritdoc />
    protected override IInteractionLayout NewLayout()
    {
        var options = new AuthorizationServer.Configuration.InteractionOptions
        {
            ProductName = "Northwind",
            LogoPath = "/img/northwind.svg",
        };

        options.StylesheetPaths.Add("/css/northwind.css");

        return new DefaultInteractionLayout(options);
    }
}

/// <summary>
/// The shell says which way its own text runs.
/// </summary>
/// <remarks>
/// The stylesheet this host ships states its edges in inline terms — <c>border-inline-start</c> on
/// the warning, <c>padding-inline-start</c> on every list, and the two corners the accent bar
/// squares off — and each of those mirrors off the document's direction. With no <c>dir</c> they
/// all resolve left-to-right, so an Arabic page comes back with its accent bars on the edge the
/// text ends at. These are what stop that half and the markup half from being shipped apart.
/// </remarks>
public sealed class ShellDirectionTests
{
    /// <summary>A right-to-left language is marked as one, and the mark agrees with the tag.</summary>
    [Theory]
    [InlineData("ar")]
    [InlineData("he")]
    [InlineData("fa")]
    [InlineData("ur")]
    [InlineData("ps")]
    [InlineData("sd")]
    [InlineData("yi")]
    [InlineData("ckb")]
    [InlineData("dv")]

    // A region names a place, never a script, so it must not change the answer.
    [InlineData("ar-EG")]
    [InlineData("he-IL")]
    public void A_right_to_left_language_is_marked_on_the_document(string tag)
    {
        var document = Wrapped(tag);

        Assert.Contains(" dir=\"rtl\"", document, StringComparison.Ordinal);

        // Both attributes, in one assertion, because the defect worth catching is not a missing
        // `dir` — it is a `dir` that stopped tracking the `lang` beside it.
        Assert.Contains($"lang=\"{tag}\"", document, StringComparison.Ordinal);
    }

    /// <summary>
    /// Everything else carries no direction at all.
    /// </summary>
    /// <remarks>
    /// The control the case above is worth nothing without: an implementation answering
    /// <see langword="true"/> for everything passes every row of it. <c>arn</c> (Mapudungun) and
    /// <c>fat</c> (Fanti) are the two rows that earn their place — both are written left to right,
    /// and both open with the letters of a tag that is on the list, so a match written as
    /// <c>StartsWith</c> instead of on the primary subtag mirrors a page it should not touch.
    /// </remarks>
    [Theory]
    [InlineData("en")]
    [InlineData("vi")]
    [InlineData("hi")]
    [InlineData("arn")]
    [InlineData("fat")]
    public void A_left_to_right_language_is_left_undirected(string tag) =>
        Assert.DoesNotContain("dir=", Wrapped(tag), StringComparison.Ordinal);

    /// <summary>The shipped shell, rendered as a reader in the given culture would receive it.</summary>
    /// <remarks>
    /// Restored in a <c>finally</c>, because <see cref="CultureInfo.CurrentUICulture"/> outlives the
    /// test that set it and the next suite to read it would inherit an Arabic page it never asked
    /// for.
    /// </remarks>
    private static string Wrapped(string tag)
    {
        var previous = CultureInfo.CurrentUICulture;

        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(tag);

            return new DefaultInteractionLayout().Wrap(new InteractionPage
            {
                Kind = InteractionPageKind.Consent,
                Title = "Authorize access",
                Body = "<h1>Authorize access</h1>",
                Nonce = null,
            });
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }
}
