using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Clients this deployment created, in a relational database.</summary>
/// <remarks>
/// <para>
/// <b>Nothing on the CIMD path calls any of this.</b> A-08: a hundred sequential CIMD connections
/// must leave the client table unchanged, and "just cache the resolved document here" is the
/// obvious move that breaks the zero-registration property CIMD exists for. Rows arrive from
/// administration.
/// </para>
/// <para>
/// The secret hash is read from the same row through <c>FindSecretAsync</c> rather than from a
/// second store, so nothing can end up disagreeing about whether a client exists.
/// </para>
/// </remarks>
internal sealed class EfClientStore(
    IDbContextFactory<AuthDbContext> contextFactory, StorageMetrics metrics)
    : IClientStore
{
    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly StorageMetrics _metrics = metrics;

    /// <inheritdoc />
    public async Task<ClientRecord?> FindAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ClientStore.FindAsync");

        if (clientId.Value is not { Length: > 0 } value) return null;

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var row = await context.Clients
            .AsNoTracking()
            .SingleOrDefaultAsync(c => c.ClientId == value, cancellationToken);

        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public async Task<ClientRecord?> FindByOwnerAsync(
        SubjectId owner, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ClientStore.FindByOwnerAsync");

        if (owner.Value is not { Length: > 0 } value) return null;

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // OrderBy so that a deployment which somehow acquired two — the schema permits it even
        // though the product does not offer it — gets the same answer every time rather than
        // whichever the planner happened to return.
        var row = await context.Clients
            .AsNoTracking()
            .Where(c => c.Owner == value)
            .OrderBy(c => c.ClientId)
            .FirstOrDefaultAsync(cancellationToken);

        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public async Task StoreAsync(
        ClientRecord client, Sha256Hash? secretHash, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        using var timing = _metrics.Track("ClientStore.StoreAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var value = client.ClientId.Value
            ?? throw new ArgumentException("The client has no identifier.", nameof(client));

        // AsTracking, because AuthDbContext sets NoTracking globally — mutating an untracked
        // entity and calling SaveChangesAsync is a silent no-op, which the contract suite caught on
        // the real database while the in-memory twin passed. Every mutating read below does this.
        var existing = await context.Clients
            .AsTracking()
            .SingleOrDefaultAsync(c => c.ClientId == value, cancellationToken);

        if (existing is null)
        {
            context.Clients.Add(new ClientRow
            {
                ClientId = value,
                ClientIdKind = (int)client.ClientId.Kind,
                Name = client.ClientName,
                SecretHash = StoredValues.ToBytes(secretHash),
                Owner = client.Owner?.Value,
                Scopes = client.AllowedScopes.ToWireString(),
                RedirectUris = string.Join(' ', client.RedirectUris.Select(r => r.Value)),

                // CreatedAt is set once and never rewritten below, so re-storing a client does not
                // make it look new. "When did this credential start existing" is the question asked
                // after somebody finds one they do not recognise.
                CreatedAt = DateTimeOffset.UtcNow.UtcTicks,
                DisabledAt = client.IsEnabled ? null : DateTimeOffset.UtcNow.UtcTicks,
            });
        }
        else
        {
            existing.Name = client.ClientName;
            existing.Owner = client.Owner?.Value;
            existing.Scopes = client.AllowedScopes.ToWireString();
            existing.RedirectUris = string.Join(' ', client.RedirectUris.Select(r => r.Value));

            // Only when one was supplied. Re-storing a client to change its name must not silently
            // destroy the credential it authenticates with — a null here means "unchanged", and
            // rotating a secret is its own act.
            if (secretHash is not null)
            {
                existing.SecretHash = StoredValues.ToBytes(secretHash);
            }

            existing.DisabledAt = client.IsEnabled
                ? null
                : existing.DisabledAt ?? DateTimeOffset.UtcNow.UtcTicks;
        }

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> SetEnabledAsync(
        ClientIdentifier clientId, bool enabled, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ClientStore.SetEnabledAsync");

        if (clientId.Value is not { Length: > 0 } value) return false;

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var row = await context.Clients
            .AsTracking()
            .SingleOrDefaultAsync(c => c.ClientId == value, cancellationToken);

        if (row is null) return false;

        // Idempotent, and the timestamp is not refreshed by disabling an already-disabled client.
        // "Since when" is the question, and answering it with the time somebody clicked twice is
        // worse than not answering.
        row.DisabledAt = enabled ? null : row.DisabledAt ?? DateTimeOffset.UtcNow.UtcTicks;

        await context.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ClientStore.DeleteAsync");

        if (clientId.Value is not { Length: > 0 } value) return false;

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var row = await context.Clients
            .AsTracking()
            .SingleOrDefaultAsync(c => c.ClientId == value, cancellationToken);

        if (row is null) return false;

        context.Clients.Remove(row);
        await context.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    /// <remarks>
    /// A disabled client's secret is <i>not</i> withheld here. Authentication and authorization are
    /// different questions, and answering "no secret" for a client that has one would report a
    /// disabled client as a misconfigured one — <c>ClientAuthenticator</c> would say it is
    /// registered as public and must not present credentials, which sends the reader somewhere
    /// else entirely. Resolution is what refuses a disabled client, with <c>Disabled</c>.
    /// </remarks>
    public async Task<Sha256Hash?> FindSecretAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ClientStore.FindSecretAsync");

        if (clientId.Value is not { Length: > 0 } value) return null;

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var hash = await context.Clients
            .AsNoTracking()
            .Where(c => c.ClientId == value)
            .Select(c => c.SecretHash)
            .SingleOrDefaultAsync(cancellationToken);

        return StoredValues.ToHashOrNull(hash);
    }

    private static ClientRecord ToRecord(ClientRow row)
    {
        _ = ScopeSet.TryParse(row.Scopes, out var scopes, out _);

        List<RegisteredRedirectUri> redirects = [];

        foreach (var raw in row.RedirectUris.Split(
            ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (RegisteredRedirectUri.TryRegister(raw, out var registered, out _))
            {
                redirects.Add(registered.Value);
            }
        }

        var owner = row.Owner is { Length: > 0 } o ? SubjectId.FromStorage(o) : (SubjectId?)null;

        return new ClientRecord
        {
            ClientId = StoredValues.ToClientIdentifier(row.ClientId, row.ClientIdKind),
            ClientType = row.SecretHash is null ? ClientType.Public : ClientType.Confidential,
            TokenEndpointAuthMethod = row.SecretHash is null
                ? ClientAuthMethod.None
                : ClientAuthMethod.ClientSecretBasic,
            RedirectUris = redirects,

            // Derived from the owner, exactly as for a configured client. A stored list would be a
            // second place for the interactive and service-account sets to overlap, and the record
            // that carried it would be the one nothing validates.
            GrantTypes = owner is null
                ? InteractiveGrants
                : ServiceAccountGrants,
            ResponseTypes = Responses,
            ClientName = row.Name,
            AllowedScopes = scopes,
            IsEnabled = row.DisabledAt is null,
            Owner = owner,
        };
    }

    private static readonly string[] InteractiveGrants = ["authorization_code", "refresh_token"];

    private static readonly string[] ServiceAccountGrants = ["client_credentials"];

    private static readonly string[] Responses = ["code"];
}
