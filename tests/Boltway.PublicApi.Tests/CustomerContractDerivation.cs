using Boltway.ResourceServer.Testing;

namespace Boltway.PublicApi.Tests;

/// <summary>
/// A customer's derivation of the shipped resource-server contract.
/// </summary>
/// <remarks>
/// <para>
/// <b>The build is the check, and there is deliberately no assertion.</b> The property held here is
/// that everything <c>ProtectedResourceContract</c> requires of a deriver is reachable from the
/// public API: the three abstract members are implementable, their types are public, and nothing
/// needed to satisfy them is internal. If that stops being true this file stops compiling, which is
/// earlier and louder than a failing test.
/// </para>
/// <para>
/// <b>Abstract, so the runner does not collect it.</b> The contract's own facts would otherwise run
/// here against a client pointed at nothing. Whether those assertions pass is
/// <c>Boltway.ResourceServer.Tests</c>'s question, against a real pipeline; whether a stranger can
/// write this class at all is this one, and only this assembly can ask it - every other test project
/// here is on an <c>InternalsVisibleTo</c> list somewhere.
/// </para>
/// </remarks>
internal abstract class CustomerContractDerivation : ProtectedResourceContract, IDisposable
{
    private readonly HttpClient _client = new() { BaseAddress = new Uri("https://mcp.example.com") };

    /// <inheritdoc />
    protected override HttpClient Client => _client;

    /// <summary>Disposes the client this derivation happens to own.</summary>
    /// <remarks>
    /// Here because the analyzer requires it of a type holding a disposable field, not because the
    /// contract asks for it - the contract never disposes what <see cref="Client" /> returns, which
    /// is the whole point of it being a property. A deriver handing over a client somebody else owns
    /// implements none of this.
    /// </remarks>
    public void Dispose() => _client.Dispose();

    /// <inheritdoc />
    protected override string Resource => "https://mcp.example.com/mcp";

    /// <inheritdoc />
    protected override string ProtectedPath => "/mcp";
}
