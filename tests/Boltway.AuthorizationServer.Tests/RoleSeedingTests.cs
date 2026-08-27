using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Roles a deployment declares, and what a new account holds when nobody names one.
/// </summary>
/// <remarks>
/// The two halves of "a fresh directory comes up ready": <c>SeedRolesAsync</c> is what the host's
/// <c>migrate</c> verb runs, and <see cref="AccountDefaults"/> is what fills the role argument
/// nobody passed. They are tested together because they fail together - a default naming a role
/// nothing seeded is the misconfiguration both halves exist to keep impossible.
/// </remarks>
public sealed class RoleSeedingTests
{
    private static UserAdministration Service(
        IUserStore users, IRoleStore roles, AccountDefaults? defaults = null) =>
        new(users, new Argon2idPasswordHasher(), new UlidSubjectIdFactory(TimeProvider.System),
            roles: roles, accountDefaults: defaults);

    [Fact]
    public async Task Seeding_defines_absent_roles()
    {
        var roles = new InMemoryRoleStore();
        var service = Service(new InMemoryUserStore(roles), roles);

        var outcomes = await service.SeedRolesAsync(
            Actor.Cli, RealmId.Default,
            [
                new RoleSeed("founder", "Chief", ["docs_read", "docs_write"]),
                new RoleSeed("member"),
            ],
            CancellationToken.None);

        Assert.Equal([("founder", true), ("member", true)], outcomes.Select(o => (o.Id, o.Created)));

        var founder = await roles.FindAsync(RealmId.Default, "founder", CancellationToken.None);
        Assert.Equal("Chief", founder!.Name);
        Assert.Equal(["docs_read", "docs_write"], founder.Permissions.Order(StringComparer.Ordinal));

        // No name and no permissions is a role that stands for nothing yet, named after itself -
        // the same defaults CreateRoleAsync applies, because it is CreateRoleAsync that ran.
        var member = await roles.FindAsync(RealmId.Default, "member", CancellationToken.None);
        Assert.Equal("member", member!.Name);
        Assert.Empty(member.Permissions);
    }

    /// <summary>
    /// The guarantee the whole design leans on: a deploy re-running its seeds cannot revert what an
    /// operator changed on the admin surface in between.
    /// </summary>
    [Fact]
    public async Task Seeding_leaves_an_existing_definition_untouched()
    {
        var roles = new InMemoryRoleStore();
        var service = Service(new InMemoryUserStore(roles), roles);

        await roles.StoreAsync(
            new RoleDefinition("founder", "Nhà sáng lập", ["docs_read"]), CancellationToken.None);

        var outcomes = await service.SeedRolesAsync(
            Actor.Cli, RealmId.Default,
            [new RoleSeed("founder", "Chief", ["docs_read", "docs_write"])],
            CancellationToken.None);

        var outcome = Assert.Single(outcomes);
        Assert.False(outcome.Created);

        var kept = await roles.FindAsync(RealmId.Default, "founder", CancellationToken.None);
        Assert.Equal("Nhà sáng lập", kept!.Name);
        Assert.Equal(["docs_read"], kept.Permissions.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Seeding_twice_changes_nothing_the_second_time()
    {
        var roles = new InMemoryRoleStore();
        var service = Service(new InMemoryUserStore(roles), roles);
        IReadOnlyList<RoleSeed> seeds = [new RoleSeed("founder", null, ["docs_read"]), new RoleSeed("member")];

        var first = await service.SeedRolesAsync(Actor.Cli, RealmId.Default, seeds, CancellationToken.None);
        var second = await service.SeedRolesAsync(Actor.Cli, RealmId.Default, seeds, CancellationToken.None);

        Assert.All(first, o => Assert.True(o.Created));
        Assert.All(second, o => Assert.False(o.Created));
    }

    /// <summary>
    /// One malformed seed fails the pass before anything lands, so a deploy log shows either what
    /// was done or one message naming what to fix - never both.
    /// </summary>
    [Fact]
    public async Task A_malformed_seed_applies_nothing()
    {
        var roles = new InMemoryRoleStore();
        var service = Service(new InMemoryUserStore(roles), roles);

        await Assert.ThrowsAsync<ArgumentException>(() => service.SeedRolesAsync(
            Actor.Cli, RealmId.Default,
            [
                new RoleSeed("member"),
                new RoleSeed("bad id"),
            ],
            CancellationToken.None));

        Assert.Empty(await roles.ListAsync(RealmId.Default, CancellationToken.None));
    }

    /// <summary>
    /// A malformed seed is refused even when the role it names already exists. Validation that
    /// depends on absence lets a typo sit unnoticed exactly as long as the role is defined.
    /// </summary>
    [Fact]
    public async Task A_malformed_seed_is_refused_even_for_a_defined_role()
    {
        var roles = new InMemoryRoleStore();
        var service = Service(new InMemoryUserStore(roles), roles);

        await roles.StoreAsync(new RoleDefinition("member", "member", []), CancellationToken.None);

        await Assert.ThrowsAsync<ArgumentException>(() => service.SeedRolesAsync(
            Actor.Cli, RealmId.Default,
            [new RoleSeed("member", null, ["two words"])],
            CancellationToken.None));
    }

    /// <summary>
    /// Two migrates racing: the loser's refusal from the store means the role exists, which is all
    /// a seed asks for - the same outcome as having found it, not a failure.
    /// </summary>
    [Fact]
    public async Task Losing_the_race_to_define_a_role_reads_as_already_defined()
    {
        var roles = new RacingRoleStore();
        var service = Service(new InMemoryUserStore(), roles);

        var outcomes = await service.SeedRolesAsync(
            Actor.Cli, RealmId.Default, [new RoleSeed("member")], CancellationToken.None);

        var outcome = Assert.Single(outcomes);
        Assert.False(outcome.Created);
    }

    [Fact]
    public async Task Creating_with_no_role_assigns_the_defaults()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var audit = new InMemoryAdminAuditStore();
        var service = new UserAdministration(
            users, new Argon2idPasswordHasher(), new UlidSubjectIdFactory(TimeProvider.System),
            audit, roles: roles,
            accountDefaults: new AccountDefaults(["member", "monitor"]));

        foreach (var id in new[] { "member", "monitor" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);
        Assert.Equal(["member", "monitor"], stored!.Roles);

        // Reported as what was actually assigned, space separated like the claim, so `new-user`
        // prints the truth and its "no role set" warning stays quiet.
        Assert.Equal("member monitor", created.Role);

        // The trail says the operator did not choose this - the deployment did.
        var entry = Assert.Single(await audit.ReadAsync(new AuditQuery(), CancellationToken.None));
        Assert.Equal("role=member monitor (defaulted)", entry.Detail);
    }

    [Fact]
    public async Task Creating_with_an_explicit_role_ignores_the_defaults()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var service = Service(users, roles, new AccountDefaults(["member"]));

        foreach (var id in new[] { "member", "founder" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, "founder", CancellationToken.None);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        // Exactly the named role - the defaults are not unioned in. An assignment the operator did
        // not make and cannot see in their own request is how an account holds more than anyone
        // decided it should.
        Assert.Equal(["founder"], stored!.Roles);
        Assert.Equal("founder", created.Role);
    }

    /// <summary>
    /// An empty string is what a form whose role field was left blank submits, and it means the
    /// same thing null does: nobody named a role.
    /// </summary>
    [Fact]
    public async Task Creating_with_a_blank_role_still_takes_the_defaults()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var service = Service(users, roles, new AccountDefaults(["member"]));

        await roles.StoreAsync(new RoleDefinition("member", "member", []), CancellationToken.None);

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, string.Empty, CancellationToken.None);

        Assert.Equal("member", created.Role);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);
        Assert.Equal(["member"], stored!.Roles);
    }

    [Fact]
    public async Task Creating_with_no_role_and_no_defaults_still_assigns_nothing()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var service = Service(users, roles);

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        Assert.Null(created.Role);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);
        Assert.Empty(stored!.Roles);
    }

    /// <summary>
    /// A default naming a role the realm does not define fails the creation with the store's own
    /// message naming it. The half-state left behind - an account with no roles - is the one
    /// CreateAsync already documents, and the migrate verb exists to make this unreachable.
    /// </summary>
    [Fact]
    public async Task A_default_naming_an_undefined_role_fails_the_creation()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var service = Service(users, roles, new AccountDefaults(["ghost"]));

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None));

        Assert.Contains("ghost", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_default_set_is_refused()
    {
        // "No defaults" is said by not constructing one at all, so an empty set can only be a
        // configuration mistake - the ADMIN_ROLES lesson, refused at the type.
        Assert.Throws<ArgumentException>(() => new AccountDefaults([]));
        Assert.Throws<ArgumentException>(() => new AccountDefaults([" "]));
        Assert.Throws<ArgumentException>(() => new AccountDefaults(["two words"]));
    }

    [Fact]
    public void Duplicate_defaults_collapse_to_one()
    {
        Assert.Equal(["member"], new AccountDefaults(["member", "member"]).Roles);
    }

    /// <summary>
    /// FindAsync answers null and StoreAsync then refuses - the window between a seed's read and
    /// its write, held open on purpose.
    /// </summary>
    private sealed class RacingRoleStore : IRoleStore
    {
        public Task<IReadOnlyList<RoleDefinition>> ListAsync(
            RealmId realm, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<RoleDefinition>>([]);

        public Task<RoleDefinition?> FindAsync(
            RealmId realm, string id, CancellationToken cancellationToken) =>
            Task.FromResult<RoleDefinition?>(null);

        public Task<IReadOnlyList<RoleDefinition>> FindManyAsync(
            RealmId realm, IReadOnlyCollection<string> ids, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<RoleDefinition>>([]);

        public Task StoreAsync(RoleDefinition role, CancellationToken cancellationToken) =>
            throw new InvalidOperationException($"Role `{role.Id}` is already defined.");

        public Task<bool> SetNameAsync(
            RealmId realm, string id, string name, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> SetPermissionsAsync(
            RealmId realm, string id, IEnumerable<string> permissions,
            CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> DeleteAsync(RealmId realm, string id, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }
}
