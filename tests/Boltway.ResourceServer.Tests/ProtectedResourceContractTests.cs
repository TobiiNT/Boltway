using Boltway.ResourceServer.Testing;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// The shipped contract, run against this repository's own wiring.
/// </summary>
/// <remarks>
/// <para>
/// <c>Boltway.ResourceServer.Testing</c> exists so a deployment can ask a running pipeline the
/// questions a client asks. Deriving it here is what keeps it honest: a contract this repository
/// ships and does not run is a promise, and the first person to find out it had drifted would be
/// somebody else.
/// </para>
/// <para>
/// The pipeline underneath is <see cref="ResourceServerFixture" /> - the same wiring every other
/// test in this assembly uses, which is the wiring the samples and the host README recommend.
/// </para>
/// </remarks>
public sealed class ProtectedResourceContractTests : ProtectedResourceContract, IAsyncLifetime
{
    private ResourceServerFixture _fixture = null!;

    /// <inheritdoc />
    protected override string Resource => Build.Resource;

    /// <inheritdoc />
    protected override string ProtectedPath => "/protected";

    /// <inheritdoc />
    public async Task InitializeAsync() => _fixture = await ResourceServerFixture.StartAsync();

    /// <inheritdoc />
    public async Task DisposeAsync() => await _fixture.DisposeAsync();

    /// <summary>The fixture's own client, handed to the contract.</summary>
    /// <remarks>
    /// The fixture owns it and disposes it. That ownership is the reason the contract takes a
    /// property it never disposes rather than a factory it does - the first draft wrapped this in a
    /// <c>using</c>, and every assertion after the first failed on a disposed client.
    /// </remarks>
    protected override HttpClient Client => _fixture.Client;
}
