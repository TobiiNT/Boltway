using Boltway.OAuth.Primitives.Ids;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>
/// Stands in for the resource registry, which is the only thing that may mint a
/// <see cref="ResourceIdentifier"/>.
/// </summary>
/// <remarks>
/// It exists as a shim because <c>TryRegister</c> is <c>internal</c> — deliberately, since a public
/// factory would make N-01's "there is no other way to obtain one" false. That the test project
/// needs <c>InternalsVisibleTo</c> to construct one is the guarantee working as intended.
/// </remarks>
internal static class TestResourceRegistry
{
    internal static bool TryRegister(string canonical, out ResourceIdentifier? resource, out string? error) =>
        ResourceIdentifier.TryRegister(canonical, out resource, out error);

    /// <summary>Register, or fail the test.</summary>
    internal static ResourceIdentifier Register(string canonical)
    {
        if (!TryRegister(canonical, out var resource, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return resource!;
    }
}
