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
