using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Administration;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The one implementation of each administrative operation.
/// </summary>
/// <remarks>
/// These rules used to live inline in the host's <c>Program.cs</c>, which meant they were reachable
/// only by running a command. Nothing tested them, and the first HTTP admin surface would have been
/// a second copy of each - with the copies drifting first where nobody looks, which is the audit
/// write and the "no password parameter" rule.
/// </remarks>
public sealed class UserAdministrationTests
{
    private static UserAdministration NewService(IUserStore users) =>
        new(users, new Argon2idPasswordHasher(), new UlidSubjectIdFactory(TimeProvider.System));

    private static (UserAdministration Service, InMemoryAdminAuditStore Audit) Audited(IUserStore users)
    {
        var audit = new InMemoryAdminAuditStore();

        return (
            new UserAdministration(
                users, new Argon2idPasswordHasher(), new UlidSubjectIdFactory(TimeProvider.System), audit),
            audit);
    }

    [Fact]
    public async Task Creating_an_account_returns_a_password_that_signs_in()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var hasher = new Argon2idPasswordHasher();
        var service = new UserAdministration(users, hasher, new UlidSubjectIdFactory(TimeProvider.System));

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", "ada@example.com", "founder", CancellationToken.None);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        // Verified against the hash rather than compared to a field. The password is the one thing
        // this method returns that is never stored, so "it came back" and "it works" are different
        // claims and only the second one matters.
        Assert.True(hasher.Verify(created.Password, stored!.PasswordHash!));
        Assert.Equal(created.Subject, stored.Subject);
        Assert.Equal(["founder"], stored.Roles);
        Assert.Equal("ada@example.com", stored.Email);

        // Never true at creation. It is the upstream's or the person's assertion, and nothing here
        // has either.
        Assert.False(stored.EmailVerified);
    }

    /// <summary>
    /// A new account lands in the realm it was asked for, not the default.
    /// </summary>
    [Fact]
    public async Task Creating_an_account_puts_it_in_the_named_realm()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(
            Actor.Cli, RealmId.FromStorage("acme"), "ada", null, null, CancellationToken.None);

        Assert.NotNull(await users.FindByUsernameAsync(RealmId.FromStorage("acme"), "ada", CancellationToken.None));
        Assert.Null(await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None));
    }

    [Fact]
    public async Task Resetting_a_password_replaces_it_and_leaves_the_role_alone()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var hasher = new Argon2idPasswordHasher();
        var service = new UserAdministration(users, hasher, new UlidSubjectIdFactory(TimeProvider.System));

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, "founder", CancellationToken.None);

        var reset = await service.ResetPasswordAsync(Actor.Cli, RealmId.Default, "ada", CancellationToken.None);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.Equal(AdministrationStatus.Ok, reset.Status);
        Assert.True(hasher.Verify(reset.Password!, stored!.PasswordHash!));

        // The old one stops working. A reset that added a password rather than replacing one would
        // pass every assertion above and leave the previous credential live.
        Assert.False(hasher.Verify(created.Password, stored.PasswordHash!));

        // The role is untouched, which is the whole reason SetPasswordHashAsync is a targeted
        // setter rather than a general update: rewriting the account to change one field is how a
        // password change silently reverts an authorization decision.
        Assert.Equal(["founder"], stored.Roles);
    }

    [Fact]
    public async Task A_password_reset_for_a_handle_nobody_has_says_so()
    {
        var service = NewService(new InMemoryUserStore());

        var reset = await service.ResetPasswordAsync(Actor.Cli, RealmId.Default, "nobody", CancellationToken.None);

        Assert.Equal(AdministrationStatus.NoSuchAccount, reset.Status);
        Assert.Null(reset.Password);
    }

    /// <summary>
    /// A handle in another realm is not this realm's account.
    /// </summary>
    /// <remarks>
    /// The realm reaching the store is what this proves. A service that resolved handles without it
    /// would reset the password of whoever the index happened to return, in whichever directory.
    /// </remarks>
    [Fact]
    public async Task An_operation_does_not_reach_across_realms()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(
            Actor.Cli, RealmId.FromStorage("acme"), "ada", null, null, CancellationToken.None);

        var reset = await service.ResetPasswordAsync(
            Actor.Cli, RealmId.FromStorage("globex"), "ada", CancellationToken.None);

        Assert.Equal(AdministrationStatus.NoSuchAccount, reset.Status);
    }

    [Fact]
    public async Task Setting_and_clearing_a_role_both_work()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var promoted = await service.SetRoleAsync(
            Actor.Cli, RealmId.Default, "ada", "founder", CancellationToken.None);

        Assert.Equal(AdministrationStatus.Ok, promoted.Status);
        Assert.Equal("founder", promoted.Role);
        Assert.Equal(
            ["founder"],
            (await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None))!.Roles);

        var cleared = await service.SetRoleAsync(Actor.Cli, RealmId.Default, "ada", null, CancellationToken.None);

        Assert.Equal(AdministrationStatus.Ok, cleared.Status);
        Assert.Null(cleared.Role);
        Assert.Empty((await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None))!.Roles);
    }

    [Fact]
    public async Task A_role_change_for_a_handle_nobody_has_says_so()
    {
        var service = NewService(new InMemoryUserStore());

        var change = await service.SetRoleAsync(
            Actor.Cli, RealmId.Default, "nobody", "founder", CancellationToken.None);

        Assert.Equal(AdministrationStatus.NoSuchAccount, change.Status);
    }

    private static readonly DateTimeOffset Now = new(2026, 8, 10, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Disabling_stops_a_sign_in_and_enabling_restores_it()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var disabled = await service.SetEnabledAsync(
            Actor.Cli, RealmId.Default, "ada", enabled: false, Now, CancellationToken.None);

        Assert.Equal(AdministrationStatus.Ok, disabled.Status);
        Assert.Equal(Now, disabled.DisabledAt);

        // IsActive is what both sign-in paths read. Asserting the column would be asserting the
        // store; asserting this is asserting the rule.
        Assert.False((await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None))!.IsActive);

        var enabled = await service.SetEnabledAsync(
            Actor.Cli, RealmId.Default, "ada", enabled: true, Now, CancellationToken.None);

        Assert.Null(enabled.DisabledAt);
        Assert.True((await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None))!.IsActive);
    }

    /// <summary>
    /// Disabling twice keeps the first time.
    /// </summary>
    /// <remarks>
    /// "Since when" is the question a disabled account is asked, and moving the answer to the moment
    /// somebody ran the command a second time loses the only fact worth having - usually while
    /// somebody is reconstructing an incident.
    /// </remarks>
    [Fact]
    public async Task Disabling_an_already_disabled_account_keeps_the_original_time()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        await service.SetEnabledAsync(Actor.Cli, RealmId.Default, "ada", false, Now, CancellationToken.None);

        var again = await service.SetEnabledAsync(
            Actor.Cli, RealmId.Default, "ada", false, Now.AddHours(3), CancellationToken.None);

        Assert.Equal(Now, again.DisabledAt);
    }

    [Fact]
    public async Task Setting_an_email_can_make_email_verified_true()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var result = await service.SetEmailAsync(
            Actor.Cli, RealmId.Default, "ada", "ada@example.com", verified: true, CancellationToken.None);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.Equal(AdministrationStatus.Ok, result.Status);
        Assert.True(stored!.EmailVerified);
        Assert.Equal("ada@example.com", stored.Email);
    }

    /// <summary>
    /// A cleared address is never verified, whatever the caller asked for.
    /// </summary>
    /// <remarks>
    /// A verified null is not a state: it would put <c>email_verified: true</c> in a token with no
    /// <c>email</c> claim beside it, which is a proof about nothing. The caller passing
    /// <c>verified: true</c> here is the mistake being made impossible rather than documented.
    /// </remarks>
    [Fact]
    public async Task Clearing_an_address_clears_the_flag_even_when_asked_not_to()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", "ada@example.com", null, CancellationToken.None);
        await service.SetEmailAsync(Actor.Cli, RealmId.Default, "ada", "ada@example.com", true, CancellationToken.None);

        var cleared = await service.SetEmailAsync(
            Actor.Cli, RealmId.Default, "ada", null, verified: true, CancellationToken.None);

        var stored = await users.FindByUsernameAsync(RealmId.Default, "ada", CancellationToken.None);

        Assert.False(cleared.Verified);
        Assert.Null(stored!.Email);
        Assert.False(stored.EmailVerified);
    }

    [Fact]
    public async Task State_changes_for_a_handle_nobody_has_say_so()
    {
        var service = NewService(new InMemoryUserStore());

        Assert.Equal(
            AdministrationStatus.NoSuchAccount,
            (await service.SetEnabledAsync(Actor.Cli, RealmId.Default, "nobody", false, Now, CancellationToken.None)).Status);

        Assert.Equal(
            AdministrationStatus.NoSuchAccount,
            (await service.SetEmailAsync(Actor.Cli, RealmId.Default, "nobody", "x@example.com", false, CancellationToken.None)).Status);
    }

    /// <summary>
    /// Two accounts never get the same password.
    /// </summary>
    /// <remarks>
    /// Cheap, and it is the assertion that would fail if the generator were ever replaced with
    /// something seeded, time-derived, or a constant left in during debugging. <c>N-16</c> is about
    /// exactly that class of substitution.
    /// </remarks>
    [Fact]
    public async Task Generated_passwords_differ()
    {
        var service = NewService(new InMemoryUserStore());

        var first = await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);
        var second = await service.CreateAsync(Actor.Cli, RealmId.Default, "grace", null, null, CancellationToken.None);

        Assert.NotEqual(first.Password, second.Password);
        Assert.NotEqual(first.Subject, second.Subject);
    }

    [Fact]
    public async Task Every_operation_writes_an_audit_entry()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var (service, audit) = Audited(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);
        await service.SetRoleAsync(Actor.Cli, RealmId.Default, "ada", "founder", CancellationToken.None);
        await service.ResetPasswordAsync(Actor.Cli, RealmId.Default, "ada", CancellationToken.None);
        await service.SetEnabledAsync(Actor.Cli, RealmId.Default, "ada", false, Now, CancellationToken.None);
        await service.SetEmailAsync(Actor.Cli, RealmId.Default, "ada", "ada@example.com", false, CancellationToken.None);

        var entries = await audit.ReadAsync(new AuditQuery(), CancellationToken.None);

        // Every operation, not most of them. An audit trail with a gap is worse than none, because
        // its silence about one action reads exactly like its silence about an action nobody took.
        Assert.Equal(
            ["user.email", "user.enablement", "user.password.reset", "user.role", "user.create"],
            entries.Select(e => e.Action));

        Assert.All(entries, e => Assert.Equal(AdminAuditOutcome.Succeeded, e.Outcome));
        Assert.All(entries, e => Assert.Equal("cli", e.ActorKind));

        // Honestly null. Inventing a subject for a shell would make the trail read as if the person
        // being changed made the change.
        Assert.All(entries, e => Assert.Null(e.ActorSubject));
    }

    /// <summary>
    /// An action against a handle nobody has is recorded as an attempt.
    /// </summary>
    /// <remarks>
    /// Somebody guessing handles against the administrative surface produces exactly this, and a log
    /// holding only successes cannot tell it from nobody trying at all.
    /// </remarks>
    [Fact]
    public async Task A_refused_operation_is_recorded_with_no_target()
    {
        var (service, audit) = Audited(new InMemoryUserStore());

        await service.ResetPasswordAsync(Actor.Cli, RealmId.Default, "nobody", CancellationToken.None);

        var entry = Assert.Single(await audit.ReadAsync(new AuditQuery(), CancellationToken.None));

        Assert.Equal(AdminAuditOutcome.Refused, entry.Outcome);
        Assert.Null(entry.TargetSubject);
        Assert.Equal("nobody", entry.TargetHandle);
    }

    /// <summary>
    /// No entry carries a credential.
    /// </summary>
    /// <remarks>
    /// The log is the one table nobody prunes, so anything that reaches it is there permanently. A
    /// password in an audit entry survives the password change that was supposed to end it.
    /// </remarks>
    [Fact]
    public async Task No_entry_carries_the_password_it_generated()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var (service, audit) = Audited(users);

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var reset = await service.ResetPasswordAsync(Actor.Cli, RealmId.Default, "ada", CancellationToken.None);

        var entries = await audit.ReadAsync(new AuditQuery(), CancellationToken.None);

        foreach (var entry in entries)
        {
            var text = string.Join('|', entry.Action, entry.Detail, entry.TargetHandle, entry.CorrelationId);

            Assert.DoesNotContain(created.Password, text, StringComparison.Ordinal);
            Assert.DoesNotContain(reset.Password!, text, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A deployment with no audit store still works.
    /// </summary>
    /// <remarks>
    /// Refusing to reset a password because the log is unavailable locks somebody out in order to
    /// protect the record of locking them out. The entry is skipped; the operation is not.
    /// </remarks>
    [Fact]
    public async Task Operations_work_without_an_audit_store()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        Assert.Equal(
            AdministrationStatus.Ok,
            (await service.ResetPasswordAsync(Actor.Cli, RealmId.Default, "ada", CancellationToken.None)).Status);
    }

    /// <summary>
    /// There is no way to hand this service a password.
    /// </summary>
    /// <remarks>
    /// An architecture assertion rather than a behavioural one, and it is here because the rule is
    /// about what cannot be added rather than about what happens. A <c>password</c> parameter on any
    /// of these methods is how a chosen password reaches shell history, terminal scrollback and
    /// whatever ran the command - so the absence is the control, and a test is what notices it
    /// <summary>
    /// Without a grant store, the two session operations say which line is missing.
    /// </summary>
    /// <remarks>
    /// The same shape as the missing <c>ISubjectIdFactory</c>: optional on the constructor so a
    /// deployment that never ends a session need not register one, demanded here so the one that
    /// does is told what to add rather than reading a container activation failure naming a type
    /// they have never heard of. Every other operation keeps working.
    /// </remarks>
    [Theory]
    [InlineData("revoke-sessions")]
    [InlineData("anonymise")]
    public async Task The_session_operations_say_what_is_missing_without_a_grant_store(string operation)
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => operation == "anonymise"
                ? service.AnonymiseAsync(
                    Actor.Cli, RealmId.Default, "ada", DateTimeOffset.UnixEpoch, CancellationToken.None)
                : service.RevokeSessionsAsync(
                    Actor.Cli, RealmId.Default, "ada", DateTimeOffset.UnixEpoch, CancellationToken.None));

        Assert.Contains("IGrantStore", failure.Message, StringComparison.Ordinal);

        // The control: everything else still works without one, which is why it is optional.
        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        Assert.NotNull(created.Password);
    }

    /// <summary>
    /// Anonymising revokes the sessions first and the account second.
    /// </summary>
    /// <remarks>
    /// These are two writes and nothing here can make them one. The order is the recovery story:
    /// anonymising first and dying in between leaves a tombstoned account whose refresh tokens still
    /// mint - a session belonging to somebody the directory says is gone. This way round it leaves an
    /// ordinary account whose owner has been signed out, which an operator can see and rerun.
    /// </remarks>
    [Fact]
    public async Task Anonymising_revokes_the_sessions_before_it_touches_the_account()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var grants = new RecordingOrder(users);
        var service = new UserAdministration(
            users,
            new Argon2idPasswordHasher(),
            new UlidSubjectIdFactory(TimeProvider.System),
            grants: grants);

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var result = await service.AnonymiseAsync(
            Actor.Cli, RealmId.Default, "ada", DateTimeOffset.UnixEpoch, CancellationToken.None);

        // Read out of the directory at the moment the revoke ran: still the person's own name, and
        // still carrying their credential. Had the order been the other way this would be the
        // tombstone, which is the state whose refresh tokens must never still mint.
        Assert.Equal("ada", grants.UsernameWhenRevoked);
        Assert.True(grants.HadPasswordWhenRevoked);

        // And the control, so a fake that stopped being called could not pass this: the account
        // really was rewritten afterwards.
        Assert.Equal(UserAdministration.TombstonePrefix + created.Subject.Value, result.Handle);
    }

    /// <summary>An <see cref="Abstractions.Stores.IGrantStore"/> that reads the directory as it revokes.</summary>
    /// <remarks>
    /// A recorder rather than a call-order list, because the property under test is not "two calls
    /// happened in this order" but "the account was still itself when the sessions ended". Reading
    /// the username at that moment asserts the thing the ordering exists for.
    /// </remarks>
    private sealed class RecordingOrder(InMemoryUserStore users) : Abstractions.Stores.IGrantStore
    {
        internal string? UsernameWhenRevoked { get; private set; }

        internal bool HadPasswordWhenRevoked { get; private set; }

        public Task StoreAsync(Abstractions.Grants.GrantRecord grant, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<Abstractions.Grants.GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken) =>
            Task.FromResult<Abstractions.Grants.GrantRecord?>(null);

        public Task<bool> RevokeAsync(string grantId, DateTimeOffset now, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public async Task<int> RevokeAllForSubjectAsync(
            SubjectId subject, DateTimeOffset now, CancellationToken cancellationToken)
        {
            // Read from the directory, not remembered from a parameter. What is being asserted is
            // the state of the account at the instant the sessions ended, and only the store knows
            // that.
            var account = await users.FindBySubjectAsync(subject, cancellationToken);

            UsernameWhenRevoked = account?.Username;
            HadPasswordWhenRevoked = account?.PasswordHash is not null;

            return 0;
        }

        public Task<IReadOnlyList<Abstractions.Grants.GrantRecord>> ListForSubjectAsync(
            SubjectId subject, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Abstractions.Grants.GrantRecord>>([]);

        public Task<IReadOnlyList<string>> ListApprovedUserAgentsAsync(
            SubjectId subject, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>([]);

        public Task<bool> IsRevokedAsync(string grantId, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }

    /// <summary>
    /// Anonymising an account records the handle it destroyed.
    /// </summary>
    /// <remarks>
    /// The audit entry is the only place the handle survives - the account no longer carries it.
    /// That is the boundary of what the operation promises: the directory stops naming the person,
    /// and the record of who was administered stays readable, because otherwise nobody can answer
    /// whether it was done properly.
    /// </remarks>
    [Fact]
    public async Task Anonymising_records_the_handle_it_destroyed()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var audit = new InMemoryAdminAuditStore();
        var service = new UserAdministration(
            users,
            new Argon2idPasswordHasher(),
            new UlidSubjectIdFactory(TimeProvider.System),
            audit,
            grants: new InMemoryGrantStore());

        await service.CreateAsync(Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var result = await service.AnonymiseAsync(
            Actor.Cli, RealmId.Default, "ada", DateTimeOffset.UnixEpoch, CancellationToken.None);

        Assert.Equal(AdministrationStatus.Ok, result.Status);
        Assert.Equal(UserAdministration.TombstonePrefix + result.Subject.Value, result.Handle);

        var entries = await audit.ReadAsync(new AuditQuery(RealmId.Default), CancellationToken.None);
        var entry = entries.Single(e => e.Action == "user.anonymise");

        Assert.Equal("ada", entry.TargetHandle);
        Assert.Equal(result.Subject, entry.TargetSubject);
        Assert.Equal(AdminAuditOutcome.Succeeded, entry.Outcome);
    }

    /// <summary>
    /// Exactly one method accepts a password, and it is the one the account holder calls.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This used to assert that <b>no</b> method did, guarding a real rule: a password parameter on
    /// an operator's method is an invitation to pass what somebody typed into a terminal, where it
    /// lands in shell history, in scrollback, and in whatever ran the command.
    /// </para>
    /// <para>
    /// <c>E-34</c> made the blanket form false rather than the rule wrong. <c>S-49</c> requires the
    /// current password as proof, and a password somebody has to remember cannot be generated for
    /// them, so <see cref="UserAdministration.ChangePasswordAsync"/> takes two. What is still true -
    /// and what this now pins - is that <b>the operator path takes none</b>: no CLI verb can grow a
    /// password field, because the method behind every CLI verb has no parameter to bind it to.
    /// </para>
    /// <para>
    /// Named individually rather than by a pattern, so adding a second password-taking method is a
    /// failing test and a decision rather than a diff nobody reads.
    /// </para>
    /// </remarks>
    [Fact]
    public void Only_the_self_service_change_accepts_a_password()
    {
        var parameters = typeof(UserAdministration)
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .SelectMany(method => method.GetParameters().Select(parameter => (method, parameter)))
            .ToList();

        // The control. A reflection query that stopped matching would report zero offenders and read
        // as a pass, which is the one way an assertion like this fails silently.
        Assert.Contains(parameters, pair => pair.parameter.Name == "handle");

        var offenders = parameters
            .Where(pair => pair.parameter.Name?.Contains("password", StringComparison.OrdinalIgnoreCase) is true)
            .Where(pair => pair.method.Name != nameof(UserAdministration.ChangePasswordAsync))
            .Select(pair => $"{pair.method.Name}({pair.parameter.Name})")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Only ChangePasswordAsync accepts a password; every other operation generates one. "
            + "Found: " + string.Join(", ", offenders));

        // And the exception is real rather than a hole left open for nothing: the method named in
        // the filter above exists and takes the two S-49 needs.
        var change = typeof(UserAdministration).GetMethod(nameof(UserAdministration.ChangePasswordAsync))!;

        Assert.Equal(
            ["currentPassword", "newPassword"],
            change.GetParameters()
                .Where(p => p.Name?.Contains("assword", StringComparison.Ordinal) is true)
                .Select(p => p.Name));

        // It is keyed on the subject, not a handle. §1.6: a handler with no target parameter has no
        // code path that reaches another account, and a `handle` here would be that parameter.
        Assert.DoesNotContain(change.GetParameters(), p => p.Name == "handle");
    }

    /// <summary>
    /// Asking to revoke sessions without a grant store fails before the password changes.
    /// </summary>
    /// <remarks>
    /// The ordering is the whole assertion. Discovering the missing store after the write would
    /// leave the account half-done - new password, old sessions - behind a 500 that says nothing
    /// about which half landed, which is the confidence rule broken where it costs most.
    /// </remarks>
    [Fact]
    public async Task Revoking_without_a_grant_store_changes_nothing()
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles is one where nobody can be given
        // one - the rule, stated as a fixture.
        foreach (var id in new[] { "founder", "employee" })
        {
            await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
        }
        var service = NewService(users);

        var created = await service.CreateAsync(
            Actor.Cli, RealmId.Default, "ada", null, null, CancellationToken.None);

        var before = await users.FindBySubjectAsync(created.Subject, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ChangePasswordAsync(
            new Actor(ActorKind.Client, created.Subject),
            created.Subject,
            created.Password,
            "something else entirely",
            revokeSessions: true,
            CancellationToken.None));

        var after = await users.FindBySubjectAsync(created.Subject, CancellationToken.None);

        Assert.Equal(before!.PasswordHash, after!.PasswordHash);
    }
}
