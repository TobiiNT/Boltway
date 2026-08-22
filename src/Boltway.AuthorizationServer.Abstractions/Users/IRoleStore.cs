using System.Collections.Frozen;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Abstractions.Users;

/// <summary>
/// A role: an identifier a token carries, a name a person reads, and the permissions it stands for.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every string in here is opaque to this library.</b> It stores them, emits them as claims, and
/// never compares one to a constant. <c>founder</c>, <c>tier-2</c>, <c>read_ledgers</c> are all the
/// same to it. Knowing what a role or a permission <i>means</i> is the resource server's job, and a
/// library that shipped a vocabulary would be shipping one customer's org chart to every other
/// customer. That rule is older than this type — it is why <c>UserAccount</c> carried a bare string
/// for a year — and moving roles into a table does not relax it. The table holds names; it does not
/// know what they are for.
/// </para>
/// <para>
/// <b>The id and the name are separate because they change on different schedules.</b> The id is
/// written into every token issued while it was assigned, and a deployment's own configuration is
/// likely to name it too. Changing it is therefore not a rename, it is an invalidation of everything
/// already issued. The name is read by people and by nothing else, so it can be reworded or
/// translated freely — which is the only reason a role can be renamed at all.
/// </para>
/// </remarks>
public sealed record RoleDefinition
{
    /// <summary>The longest an id may be, matching the column that used to hold a bare role.</summary>
    /// <remarks>
    /// Generous for a word, and small enough that the column can never become somewhere to keep a
    /// policy document.
    /// </remarks>
    public const int MaxIdLength = 64;

    /// <summary>The longest a display name may be.</summary>
    public const int MaxNameLength = 128;

    /// <summary>Define a role.</summary>
    /// <param name="id">
    /// What a token carries and what a resource server matches on, exactly. Non-blank, at most
    /// <see cref="MaxIdLength"/> characters, and carrying no whitespace — it is compared ordinally
    /// against a claim value, and a leading space is a difference nobody can see.
    /// </param>
    /// <param name="name">
    /// What to call it in a sentence. Non-blank and at most <see cref="MaxNameLength"/> characters,
    /// and free to carry spaces — nothing matches on a name, which is the reason it is its own field.
    /// </param>
    /// <param name="permissions">
    /// What the role stands for, in the resource server's vocabulary. Stored space-separated, the
    /// same as a grant's scopes, so a permission carrying whitespace is refused here rather than
    /// silently becoming two on the way back out.
    /// </param>
    /// <exception cref="ArgumentException">Any of the rules above is broken.</exception>
    public RoleDefinition(string id, string name, IEnumerable<string> permissions)
    {
        ArgumentNullException.ThrowIfNull(permissions);

        Id = Token(id, nameof(id), MaxIdLength);
        Name = Readable(name, nameof(name), MaxNameLength);

        var held = new HashSet<string>(StringComparer.Ordinal);

        foreach (var permission in permissions)
        {
            held.Add(Token(permission, nameof(permissions), MaxIdLength));
        }

        Permissions = held.ToFrozenSet(StringComparer.Ordinal);
    }

    /// <summary>What a token carries. Immutable once anything has been issued under it.</summary>
    public string Id { get; }

    /// <summary>What a person reads. Free to be reworded.</summary>
    public string Name { get; }

    /// <summary>What the role stands for, uninterpreted.</summary>
    public IReadOnlySet<string> Permissions { get; }

    /// <summary>Which directory this role belongs to.</summary>
    /// <remarks>
    /// Roles are keyed by something a person chose, so they are realm-scoped for the same reason
    /// usernames are: two directories must be able to hold an <c>editor</c> that means different
    /// things.
    /// </remarks>
    public RealmId Realm { get; init; } = RealmId.Default;

    /// <summary>
    /// An id or a permission: something matched on, so it carries no whitespace.
    /// </summary>
    /// <remarks>
    /// The rule is not about tidiness. An id is compared ordinally against a claim value, where a
    /// leading space is a difference nobody can see; a permission is stored space-separated, where
    /// an inner space is a value that comes back as two.
    /// </remarks>
    private static string Token(string value, string parameter, int maxLength)
    {
        var present = Readable(value, parameter, maxLength);

        if (present.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException(
                $"`{value}` carries whitespace. Ids and permissions are compared ordinally against a "
                + "claim value and stored space-separated, so a space in one is either a difference "
                + "nobody can see or a value that comes back as two.",
                parameter);
        }

        return present;
    }

    /// <summary>
    /// A display name: present, and short enough for its column.
    /// </summary>
    /// <remarks>
    /// <b>Whitespace is allowed here and refused for the other two, which is the whole point of the
    /// split.</b> A name is stored in its own column and nothing matches on it, so `Nhà phân tích`
    /// is exactly what it is for. Applying the token rule to all three fields — which this type did
    /// until a test wrote a two-word name — made the editable half unable to hold the kind of value
    /// it exists to hold.
    /// </remarks>
    private static string Readable(string value, string parameter, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("A role's identifiers cannot be blank.", parameter);
        }

        if (value.Length > maxLength)
        {
            throw new ArgumentException(
                $"`{value}` is longer than the {maxLength} characters this column holds.", parameter);
        }

        return value;
    }
}

/// <summary>Stores role definitions.</summary>
/// <remarks>
/// <para>
/// Separate from <see cref="IUserStore"/> because it answers a different question. This one says
/// what a role <i>is</i>; which accounts hold it is a property of the account, and lives on
/// <see cref="UserAccount.Roles"/> with <see cref="IUserStore.SetRolesAsync"/> to change it.
/// </para>
/// <para>
/// <b>Nothing here enforces that an assigned role exists.</b> A directory that has been rolled back
/// to an older image, or restored from a backup taken before a role was defined, holds assignments
/// naming a definition it cannot find — and refusing to issue a token in that case would turn a
/// tidy-up into an outage on a path that has nothing to do with it. The claims mapper drops what it
/// cannot resolve and the account still signs in, holding less. That is the same decision
/// <c>UserAccountClaims</c> already makes for an account deleted mid-grant.
/// </para>
/// </remarks>
public interface IRoleStore
{
    /// <summary>Every role in a realm, ordered by id.</summary>
    /// <param name="realm">The directory.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<IReadOnlyList<RoleDefinition>> ListAsync(RealmId realm, CancellationToken cancellationToken);

    /// <summary>One role, or <see langword="null"/> when the realm does not define it.</summary>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id, matched ordinally and exactly.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<RoleDefinition?> FindAsync(RealmId realm, string id, CancellationToken cancellationToken);

    /// <summary>
    /// Resolve several ids at once, dropping the ones the realm does not define.
    /// </summary>
    /// <remarks>
    /// One round trip rather than one per role, because the caller with several ids is the claims
    /// mapper and it runs on every token issued. Missing ids are dropped rather than reported for
    /// the reason on this interface: an assignment naming a definition that is not there must cost
    /// the account that permission, not its sign-in.
    /// </remarks>
    /// <param name="realm">The directory.</param>
    /// <param name="ids">The role ids.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<IReadOnlyList<RoleDefinition>> FindManyAsync(
        RealmId realm, IReadOnlyCollection<string> ids, CancellationToken cancellationToken);

    /// <summary>
    /// Add a role. Refuses an id the realm already defines.
    /// </summary>
    /// <remarks>
    /// Add-only, the same shape as <see cref="IUserStore.StoreAsync"/>. An upsert here would let a
    /// caller who meant to create one silently replace the permissions of a role somebody is
    /// already holding — and every token issued under it would keep saying what it used to mean.
    /// </remarks>
    /// <param name="role">The role.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="InvalidOperationException">The realm already defines that id.</exception>
    Task StoreAsync(RoleDefinition role, CancellationToken cancellationToken);

    /// <summary>Reword a role. <see langword="false"/> when the realm does not define it.</summary>
    /// <remarks>
    /// The operation the id/name split exists for, and the only one of these three that is safe on a
    /// live directory: nothing matches on a name, so no token and no configuration goes stale.
    /// </remarks>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id.</param>
    /// <param name="name">The new name.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    Task<bool> SetNameAsync(RealmId realm, string id, string name, CancellationToken cancellationToken);

    /// <summary>
    /// Replace what a role stands for. <see langword="false"/> when the realm does not define it.
    /// </summary>
    /// <remarks>
    /// Replaces rather than merges, so that taking a permission away is expressible. Tokens already
    /// issued carry the old set until they expire — the same caveat every role change has had, and
    /// the reason <c>revoke-sessions</c> exists.
    /// </remarks>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id.</param>
    /// <param name="permissions">The new permissions, replacing all of them.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    Task<bool> SetPermissionsAsync(
        RealmId realm, string id, IEnumerable<string> permissions, CancellationToken cancellationToken);

    /// <summary>
    /// Remove a role, and every assignment of it. <see langword="false"/> when it was not there.
    /// </summary>
    /// <remarks>
    /// The assignments go with it, because the alternative is rows naming a definition nobody can
    /// read — which is indistinguishable from the rolled-back-image case this interface tolerates,
    /// and would make that case impossible to tell from a bug. Accounts holding only this role are
    /// left holding none, which is the least-privileged answer rather than an error.
    /// </remarks>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    Task<bool> DeleteAsync(RealmId realm, string id, CancellationToken cancellationToken);
}
