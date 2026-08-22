using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.InMemory;

/// <summary>Clients this deployment created, in memory.</summary>
/// <remarks>
/// <para>
/// The twin of <c>EfClientStore</c>, and the pair is held to one contract suite. The two diverging
/// is the failure this repository has already paid for once: the relational store enforced a
/// relationship the in-memory one did not, so a test passed in memory and the behaviour it proved
/// was not the shipped behaviour.
/// </para>
/// <para>
/// <b>Nothing on the CIMD path writes here.</b> A-08: a hundred sequential CIMD connections must
/// leave the client table unchanged.
/// </para>
/// </remarks>
public sealed class InMemoryClientStore : IClientStore
{
    private sealed record Entry(ClientRecord Client, Sha256Hash? SecretHash);

    // Ordinal, because a client id is compared ordinally everywhere else — it is not typed at a
    // login page by somebody who might shift-lock it.
    private readonly Dictionary<string, Entry> _clients = new(StringComparer.Ordinal);

    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task<ClientRecord?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        if (clientId.Value is not { Length: > 0 } value)
        {
            return Task.FromResult<ClientRecord?>(null);
        }

        lock (_gate)
        {
            return Task.FromResult(_clients.TryGetValue(value, out var entry) ? entry.Client : null);
        }
    }

    /// <inheritdoc />
    public Task<ClientRecord?> FindByOwnerAsync(SubjectId owner, CancellationToken cancellationToken)
    {
        if (owner.Value is not { Length: > 0 } value)
        {
            return Task.FromResult<ClientRecord?>(null);
        }

        lock (_gate)
        {
            // Ordered, so a store holding two for one owner answers the same way every time — the
            // relational twin orders by client id and an unordered dictionary scan would not.
            var found = _clients.Values
                .Where(e => e.Client.Owner is { } o && string.Equals(o.Value, value, StringComparison.Ordinal))
                .OrderBy(e => e.Client.ClientId.Value, StringComparer.Ordinal)
                .Select(e => e.Client)
                .FirstOrDefault();

            return Task.FromResult(found);
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(ClientRecord client, Sha256Hash? secretHash, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        var value = client.ClientId.Value
            ?? throw new ArgumentException("The client has no identifier.", nameof(client));

        lock (_gate)
        {
            // A null hash on an update means "unchanged", matching the relational store. Re-storing
            // a client to rename it must not silently destroy the credential it authenticates with.
            var kept = _clients.TryGetValue(value, out var existing) ? existing.SecretHash : null;

            _clients[value] = new Entry(client, secretHash ?? kept);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<Sha256Hash?> FindSecretAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        if (clientId.Value is not { Length: > 0 } value)
        {
            return Task.FromResult<Sha256Hash?>(null);
        }

        lock (_gate)
        {
            // A disabled client still answers with its hash, matching the relational store. See
            // IClientStore.FindSecretAsync for why withholding it would misreport the cause.
            return Task.FromResult(_clients.TryGetValue(value, out var entry) ? entry.SecretHash : null);
        }
    }

    /// <inheritdoc />
    public Task<bool> SetEnabledAsync(
        ClientIdentifier clientId, bool enabled, CancellationToken cancellationToken)
    {
        if (clientId.Value is not { Length: > 0 } value)
        {
            return Task.FromResult(false);
        }

        lock (_gate)
        {
            if (!_clients.TryGetValue(value, out var entry))
            {
                return Task.FromResult(false);
            }

            _clients[value] = entry with { Client = entry.Client with { IsEnabled = enabled } };
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        if (clientId.Value is not { Length: > 0 } value)
        {
            return Task.FromResult(false);
        }

        lock (_gate)
        {
            return Task.FromResult(_clients.Remove(value));
        }
    }
}
