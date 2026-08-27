using Boltway.ResourceServer.Configuration;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Xunit;

namespace Boltway.Mcp.Tests;

/// <summary>
/// That the call this package used to own still works from here.
/// </summary>
/// <remarks>
/// <para>
/// <c>AddJwksSigningKeys</c> moved to <c>Boltway.ResourceServer</c> in 0.4.0 and left a forwarder
/// marked obsolete. The suite that exercises what it does moved with it; what stays here is the one
/// property this package is still responsible for, which is that a deployment already calling it
/// through <c>Boltway.Mcp</c> keeps getting a wired container rather than a compile error.
/// </para>
/// <para>
/// The obsolete warning is suppressed for exactly the span of the call, because calling it is the
/// test. Suppressing it project-wide would also hide the day something else here starts using a
/// deprecated member.
/// </para>
/// </remarks>
public sealed class JwksSigningKeysForwarderTests
{
    [Fact]
    public void The_moved_call_still_wires_from_this_package()
    {
        var services = new ServiceCollection();

        // The options infrastructure, which AddJwksSigningKeys does not bring on its own - it
        // registers an IConfigureOptions and expects a host to have added the rest. AddLogging is
        // the cheapest thing that does, and it is what the moved suite next door uses.
        services.AddLogging();

#pragma warning disable CS0618 // Calling the obsolete forwarder is the point of this test.
        services.AddJwksSigningKeys("https://auth.example.com");
#pragma warning restore CS0618

        using var provider = services.BuildServiceProvider();

        // The observable end of the wiring: a source installed into the options a resource server
        // reads its verification keys from. Asserting the registration list instead would pass on a
        // forwarder that registered the services and never configured the options.
        Assert.NotNull(provider.GetRequiredService<IOptions<ProtectedResourceOptions>>().Value.SigningKeySource);
    }
}
