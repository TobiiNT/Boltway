using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.Storage.InMemory;

/// <summary>Role definitions in memory.</summary>
/// <remarks>
/// Ships for the same reason the other in-memory stores do: the shared contract suite needs a second
/// implementation, or the contract describes one data access layer rather than a behaviour.
/// </remarks>
public sealed class InMemoryRoleStore : IRoleStore
{
    // Ordinal on the id, because every consumer compares it ordinally. Folding here would make
    // `Founder` and `founder` one role on this side and two on the other.
    private readonly Dictionary<(string Realm, string Id), RoleDefinition> _roles =
        new(RealmScopedIdComparer.Instance);

    private readonly Lock _gate = new();

    /// <summary>
    /// Raised when a role is removed, so the accounts holding it stop holding it.
    /// </summary>
    /// <remarks>
    /// The relational store gets this from <c>ON DELETE CASCADE</c> on <c>user_roles</c>. Here the
    /// assignments live in the user store, which this one must not depend on - the dependency runs
    /// the other way so that assignment can ask whether a role exists. A notification is the shape
    /// that leaves the arrow pointing one way and still makes both implementations answer the same
    /// thing: a test deleted a role and found an account still holding it on one of them.
    /// </remarks>
    internal event Action<RealmId, string>? Deleted;

    /// <summary>Whether a realm defines a role, for the user store's assignment check.</summary>
    internal bool Defines(RealmId realm, string id)
    {
        lock (_gate)
        {
            return _roles.ContainsKey((realm.OrDefault.Value, id));
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<RoleDefinition>> ListAsync(RealmId realm, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var realmValue = realm.OrDefault.Value;

            IReadOnlyList<RoleDefinition> found =
            [
                .. _roles
                    .Where(r => string.Equals(r.Key.Realm, realmValue, StringComparison.Ordinal))
                    .Select(r => r.Value)
                    .OrderBy(r => r.Id, StringComparer.Ordinal),
            ];

            return Task.FromResult(found);
        }
    }

    /// <inheritdoc />
    public Task<RoleDefinition?> FindAsync(RealmId realm, string id, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(
                string.IsNullOrWhiteSpace(id) ? null : _roles.GetValueOrDefault((realm.OrDefault.Value, id)));
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<RoleDefinition>> FindManyAsync(
        RealmId realm, IReadOnlyCollection<string> ids, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ids);

        lock (_gate)
        {
            var realmValue = realm.OrDefault.Value;

            IReadOnlyList<RoleDefinition> found =
            [
                .. ids
                    .Select(id => _roles.GetValueOrDefault((realmValue, id)))
                    .OfType<RoleDefinition>()
                    .OrderBy(r => r.Id, StringComparer.Ordinal),
            ];

            return Task.FromResult(found);
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(RoleDefinition role, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(role);

        lock (_gate)
        {
            var key = (role.Realm.OrDefault.Value, role.Id);

            if (!_roles.TryAdd(key, role with { Realm = role.Realm.OrDefault }))
            {
                throw new InvalidOperationException(
                    $"Realm `{key.Item1}` already defines a role `{role.Id}`. Roles are add-only: replacing "
                    + "one would change what every token issued under it turns out to have meant.");
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> SetNameAsync(RealmId realm, string id, string name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("A role's name cannot be blank.", nameof(name));
        }

        lock (_gate)
        {
            var key = (realm.OrDefault.Value, id);

            if (!_roles.TryGetValue(key, out var role)) return Task.FromResult(false);

            _roles[key] = new RoleDefinition(role.Id, name, role.Permissions) { Realm = role.Realm };

            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task<bool> SetPermissionsAsync(
        RealmId realm, string id, IEnumerable<string> permissions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(permissions);

        // Constructed before the lock so the whitespace rule refuses the write rather than half of it.
        var replacement = new RoleDefinition(id, id, permissions);

        lock (_gate)
        {
            var key = (realm.OrDefault.Value, id);

            if (!_roles.TryGetValue(key, out var role)) return Task.FromResult(false);

            _roles[key] = new RoleDefinition(role.Id, role.Name, replacement.Permissions) { Realm = role.Realm };

            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// The assignments are held by the user store, which reads <see cref="Defines"/> - so a role
    /// removed here stops resolving everywhere, and an account holding only it holds nothing. That
    /// is the cascade the relational store declares, arriving by the other route.
    /// </remarks>
    public Task<bool> DeleteAsync(RealmId realm, string id, CancellationToken cancellationToken)
    {
        bool removed;

        lock (_gate)
        {
            removed = _roles.Remove((realm.OrDefault.Value, id));
        }

        // Outside the lock: the handler takes the user store's lock, and taking two in a fixed
        // order here and the reverse order there is how a deadlock arrives at three in the morning.
        if (removed) Deleted?.Invoke(realm.OrDefault, id);

        return Task.FromResult(removed);
    }

    /// <summary>Ordinal on both halves - a role id is not folded anywhere else either.</summary>
    private sealed class RealmScopedIdComparer : IEqualityComparer<(string Realm, string Id)>
    {
        internal static RealmScopedIdComparer Instance { get; } = new();

        public bool Equals((string Realm, string Id) x, (string Realm, string Id) y) =>
            string.Equals(x.Realm, y.Realm, StringComparison.Ordinal)
            && string.Equals(x.Id, y.Id, StringComparison.Ordinal);

        public int GetHashCode((string Realm, string Id) obj) =>
            HashCode.Combine(
                StringComparer.Ordinal.GetHashCode(obj.Realm),
                StringComparer.Ordinal.GetHashCode(obj.Id));
    }
}
