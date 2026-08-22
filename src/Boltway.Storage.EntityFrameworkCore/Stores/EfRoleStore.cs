using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Role definitions, in a relational database.</summary>
/// <remarks>
/// The permissions are one space-separated column. Splitting on whitespace is safe in both
/// directions because <see cref="RoleDefinition"/> refuses a permission carrying any — the round
/// trip cannot turn one permission into two, and cannot lose one either.
/// </remarks>
internal sealed class EfRoleStore(
    IDbContextFactory<AuthDbContext> contextFactory, IRelationalStoreBehavior behavior, StorageMetrics metrics)
    : IRoleStore
{
    private readonly StorageMetrics _metrics = metrics;
    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly IRelationalStoreBehavior _behavior = behavior;

    /// <inheritdoc />
    public async Task<IReadOnlyList<RoleDefinition>> ListAsync(
        RealmId realm, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.ListAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;

        var rows = await context.Roles
            .AsNoTracking()
            .Where(r => r.Realm == realmValue)
            .OrderBy(r => r.Id)
            .ToListAsync(cancellationToken);

        return [.. rows.Select(ToDefinition)];
    }

    /// <inheritdoc />
    public async Task<RoleDefinition?> FindAsync(
        RealmId realm, string id, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.FindAsync");

        if (string.IsNullOrWhiteSpace(id)) return null;

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;

        var row = await context.Roles
            .AsNoTracking()
            .SingleOrDefaultAsync(r => r.Realm == realmValue && r.Id == id, cancellationToken);

        return row is null ? null : ToDefinition(row);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<RoleDefinition>> FindManyAsync(
        RealmId realm, IReadOnlyCollection<string> ids, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.FindManyAsync");

        ArgumentNullException.ThrowIfNull(ids);

        if (ids.Count == 0) return [];

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;
        var wanted = ids.ToList();

        var rows = await context.Roles
            .AsNoTracking()
            .Where(r => r.Realm == realmValue && wanted.Contains(r.Id))
            .OrderBy(r => r.Id)
            .ToListAsync(cancellationToken);

        return [.. rows.Select(ToDefinition)];
    }

    /// <inheritdoc />
    public async Task StoreAsync(RoleDefinition role, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.StoreAsync");

        ArgumentNullException.ThrowIfNull(role);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var realmValue = role.Realm.OrDefault.Value;
        var id = role.Id;

        // Checked here as well as by the primary key, because the contract asks for an
        // InvalidOperationException naming which rule was broken and a provider exception says only
        // that some constraint failed. The catch below turns a raced insert into the same message.
        if (await context.Roles.AnyAsync(r => r.Realm == realmValue && r.Id == id, cancellationToken))
        {
            throw new InvalidOperationException(
                $"Realm `{realmValue}` already defines a role `{id}`. Roles are add-only: replacing one "
                + "would change what every token issued under it turns out to have meant.");
        }

        context.Roles.Add(new RoleRow
        {
            Realm = realmValue,
            Id = id,
            Name = role.Name,
            Permissions = Join(role.Permissions),
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            throw new InvalidOperationException(
                $"Realm `{realmValue}` already defines a role `{id}`.", ex);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> SetNameAsync(
        RealmId realm, string id, string name, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.SetNameAsync");

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("A role's name cannot be blank.", nameof(name));
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;

        // ExecuteUpdate rather than load-modify-save: one statement, no chance of carrying a stale
        // permission set back to the database, and the row count is the answer this method owes.
        var updated = await context.Roles
            .Where(r => r.Realm == realmValue && r.Id == id)
            .ExecuteUpdateAsync(set => set.SetProperty(r => r.Name, name), cancellationToken);

        return updated > 0;
    }

    /// <inheritdoc />
    public async Task<bool> SetPermissionsAsync(
        RealmId realm, string id, IEnumerable<string> permissions, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.SetPermissionsAsync");

        ArgumentNullException.ThrowIfNull(permissions);

        // Through RoleDefinition rather than joined straight, so that the whitespace rule this
        // column depends on is enforced by the one type that states it. A permission with a space
        // in it would otherwise come back as two, from a write that looked like it worked.
        var cleaned = new RoleDefinition(id, id, permissions);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;
        var stored = Join(cleaned.Permissions);

        var updated = await context.Roles
            .Where(r => r.Realm == realmValue && r.Id == id)
            .ExecuteUpdateAsync(set => set.SetProperty(r => r.Permissions, stored), cancellationToken);

        return updated > 0;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The assignments go with it by cascade, declared on <c>user_roles</c>. An account left holding
    /// nothing is the least-privileged outcome, which is the direction to be wrong in.
    /// </remarks>
    public async Task<bool> DeleteAsync(RealmId realm, string id, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RoleStore.DeleteAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var realmValue = realm.OrDefault.Value;

        // Explicit rather than left to the cascade. SQLite enforces a REFERENCES clause only with
        // `PRAGMA foreign_keys` on, which is set per connection — so a cascade is a property of how
        // the connection was opened, and this store would otherwise behave differently on two
        // providers for a reason no reader of this method could see.
        await context.UserRoles
            .Where(r => r.Realm == realmValue && r.RoleId == id)
            .ExecuteDeleteAsync(cancellationToken);

        var deleted = await context.Roles
            .Where(r => r.Realm == realmValue && r.Id == id)
            .ExecuteDeleteAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return deleted > 0;
    }

    private static RoleDefinition ToDefinition(RoleRow row) =>
        new(row.Id, row.Name, Split(row.Permissions)) { Realm = RealmId.FromStorage(row.Realm) };

    private static string Join(IReadOnlySet<string> permissions) =>
        string.Join(' ', permissions.Order(StringComparer.Ordinal));

    private static string[] Split(string permissions) =>
        permissions.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
