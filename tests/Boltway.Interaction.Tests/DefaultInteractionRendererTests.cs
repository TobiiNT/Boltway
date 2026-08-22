using Boltway.AuthorizationServer.Interaction;

using Boltway.Interaction.Testing;

namespace Boltway.Interaction.Tests;

/// <summary>
/// The contract, against the renderer that ships.
/// </summary>
/// <remarks>
/// The suite exists for renderers this repository did not write, and it is run against the shipped
/// one first for the reason <c>ConsentStoreContract</c> gives about stores: the most likely shape of
/// a customer's first attempt is the one the repository itself had written. A contract the default
/// implementation cannot pass is a contract that is wrong, and finding that out here costs nothing.
/// </remarks>
public sealed class DefaultInteractionRendererTests : InteractionRendererContract
{
    /// <inheritdoc />
    protected override IInteractionRenderer NewRenderer() => new DefaultInteractionRenderer();
}
