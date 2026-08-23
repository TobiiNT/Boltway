using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Users and the external-login table, in a relational database.</summary>
internal sealed class EfUserStore(
    IDbContextFactory<AuthDbContext> contextFactory, IRelationalStoreBehavior behavior, StorageMetrics metrics) : IUserStore
{
    private readonly StorageMetrics _metrics = metrics;

    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly IRelationalStoreBehavior _behavior = behavior;

    /// <inheritdoc />
    public async Task<UserAccount?> FindBySubjectAsync(SubjectId subject, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.FindBySubjectAsync");

        if (string.IsNullOrEmpty(subject.Value))
        {
            return null;
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var row = await context.Users
            .Include(u => u.Roles)
            .SingleOrDefaultAsync(u => u.Subject == subjectValue, cancellationToken);

        return row is null ? null : ToAccount(row);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The lookup is on the normalized column, so the case-folding happens in C# and the SQL
    /// comparison is ordinal. Doing it the other way — <c>WHERE lower(username) = lower(@name)</c>,
    /// or a case-insensitive collation — makes the answer depend on the database's collation, and
    /// then two implementations of this interface disagree on the same input.
    /// </remarks>
    public async Task<UserAccount?> FindByUsernameAsync(
        RealmId realm, string username, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.FindByUsernameAsync");

        // Answers null for an empty name rather than throwing: this is reached straight from a form
        // field, so "the user submitted nothing" has to be an unsuccessful login and not a 500
        // anyone can provoke by posting an empty form.
        if (string.IsNullOrEmpty(username))
        {
            return null;
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var normalized = StoredValues.NormalizeUsername(username);
        var realmValue = realm.OrDefault.Value;
        var row = await context.Users
            .Include(u => u.Roles)
            .SingleOrDefaultAsync(
                u => u.Realm == realmValue && u.NormalizedUsername == normalized, cancellationToken);

        return row is null ? null : ToAccount(row);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// Two rows are fetched where one is wanted, so "more than one account has this address" is
    /// distinguishable from "one does" — <c>SingleOrDefaultAsync</c> would throw on the ambiguous
    /// case, turning a data condition into a 500 on the sign-in page, and <c>FirstOrDefault</c>
    /// would silently pick one and make which account a password reaches depend on the store's
    /// ordering. Neither is an answer; the contract says refuse.
    /// </para>
    /// <para>
    /// Normalised the same way a username is, and stored normalised alongside the address as typed.
    /// Folding in the query instead — <c>u.Email.ToUpper() == …</c> — is the version that cannot use
    /// the index, on the one query where a scan is an anonymous caller's lever.
    /// </para>
    /// </remarks>
    public async Task<UserAccount?> FindByVerifiedEmailAsync(
        RealmId realm, string email, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.FindByVerifiedEmailAsync");

        // Empty is null rather than a match: this arrives straight from a form field, and every row
        // with no address would otherwise be a candidate.
        if (string.IsNullOrEmpty(email))
        {
            return null;
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var normalized = StoredValues.NormalizeEmail(email);
        var realmValue = realm.OrDefault.Value;

        var rows = await context.Users
            .Include(u => u.Roles)
            .Where(u => u.Realm == realmValue && u.NormalizedEmail == normalized && u.EmailVerified)
            .Take(2)
            .ToListAsync(cancellationToken);

        return rows.Count == 1 ? ToAccount(rows[0]) : null;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Ordinal on both halves. An upstream issuer and subject are opaque values chosen by someone
    /// else; case-folding them would merge two identities the upstream considers distinct.
    /// </remarks>
    public async Task<UserAccount?> FindByExternalLoginAsync(
        RealmId realm, string upstreamIssuer, string upstreamSubject, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.FindByExternalLoginAsync");

        if (string.IsNullOrEmpty(upstreamIssuer) || string.IsNullOrEmpty(upstreamSubject))
        {
            return null;
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;
        // `Include` on the projected side of a join is not translated, so the roles are loaded by
        // the subject the join produced. Two round trips where the others take one, and the
        // alternative — dropping to a manual join over user_roles — would be a second place that
        // has to agree with `ToAccount` about what an account's roles are.
        var row = await (from link in context.ExternalLogins
                         where link.Realm == realmValue
                            && link.UpstreamIssuer == upstreamIssuer
                            && link.UpstreamSubject == upstreamSubject
                         join user in context.Users on link.Subject equals user.Subject
                         select user).SingleOrDefaultAsync(cancellationToken);

        if (row is not null)
        {
            var linkedSubject = row.Subject;

            row.Roles = await context.UserRoles
                .Where(r => r.Subject == linkedSubject)
                .ToListAsync(cancellationToken);
        }

        return row is null ? null : ToAccount(row);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Straight off <c>ix_external_logins_subject</c>, which has existed since the table did — the
    /// index was declared for the join this method finally makes directly.
    /// </remarks>
    public async Task<IReadOnlyList<ExternalLogin>> ListExternalLoginsAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.ListExternalLoginsAsync");

        if (string.IsNullOrEmpty(subject.Value))
        {
            return [];
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;

        var rows = await context.ExternalLogins
            .Where(link => link.Subject == subjectValue)
            .ToListAsync(cancellationToken);

        return [.. rows.Select(row => new ExternalLogin(row.UpstreamIssuer, row.UpstreamSubject, subject)
        {
            Realm = RealmId.FromStorage(row.Realm),
        })];
    }

    /// <inheritdoc />
    /// <remarks>
    /// Add-only. An upsert would let a re-registration replace an existing account's password hash,
    /// which is account takeover by whoever can reach the registration path.
    /// </remarks>
    public async Task StoreAsync(UserAccount user, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.StoreAsync");

        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrEmpty(user.Subject.Value))
        {
            throw new ArgumentException("An account needs a subject identifier.", nameof(user));
        }

        if (string.IsNullOrWhiteSpace(user.Username))
        {
            throw new ArgumentException("An account needs a username.", nameof(user));
        }

        // Creation does not assign. Refused rather than ignored: silently dropping what a caller
        // passed is the shape this whole branch exists to remove, and an account that came back
        // holding nothing after being created with a role would be diagnosed anywhere but here.
        if (user.Roles.Count > 0)
        {
            throw new ArgumentException(
                "An account is created holding no roles. Assign them with SetRolesAsync, which is the "
                + "only path that can refuse an id the realm does not define — two ways in would be two "
                + "places that rule has to be remembered the same way.",
                nameof(user));
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var subjectValue = user.Subject.Value;
        var normalized = StoredValues.NormalizeUsername(user.Username);

        // Checked here as well as by the unique index, because the contract asks for
        // InvalidOperationException with a message naming which rule was broken, and a provider
        // exception says only that some constraint failed. The index is still declared: it is what
        // holds if this check is ever raced, and the catch below turns that into the same exception.
        if (await context.Users.AnyAsync(u => u.Subject == subjectValue, cancellationToken))
        {
            throw new InvalidOperationException(
                "An account with this subject already exists. Accounts are add-only: overwriting "
                + "one would replace its credentials.");
        }

        var realmValue = user.Realm.OrDefault.Value;

        if (await context.Users.AnyAsync(
            u => u.Realm == realmValue && u.NormalizedUsername == normalized, cancellationToken))
        {
            throw new InvalidOperationException("An account with this username already exists, ignoring case.");
        }

        context.Users.Add(new UserRow
        {
            Subject = subjectValue,
            Realm = realmValue,
            Username = user.Username,
            NormalizedUsername = normalized,
            Email = user.Email,
            NormalizedEmail = StoredValues.NormalizeEmail(user.Email),
            EmailVerified = user.EmailVerified,
            PasswordHash = user.PasswordHash,
            DisabledAt = StoredValues.ToTicks(user.DisabledAt),
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            throw new InvalidOperationException(
                "An account with this subject or username already exists.", ex);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// One upstream identity maps to at most one local account, and re-linking it is refused. If it
    /// could be moved, whoever controls the upstream subject — or anyone who can replay a link
    /// request — repoints it at an account of their choosing, and the next federated sign-in lands
    /// inside someone else's data.
    /// </para>
    /// <para>
    /// The reverse direction is left open: one local account may carry links from several upstream
    /// issuers, which is what makes "sign in with Google, then also with Facebook" work rather than
    /// producing two accounts for one person.
    /// </para>
    /// </remarks>
    public async Task LinkExternalLoginAsync(ExternalLogin link, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.LinkExternalLoginAsync");

        ArgumentNullException.ThrowIfNull(link);

        if (string.IsNullOrEmpty(link.UpstreamIssuer) || string.IsNullOrEmpty(link.UpstreamSubject))
        {
            throw new ArgumentException("An external login needs an upstream issuer and subject.", nameof(link));
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var subjectValue = link.Subject.Value ?? string.Empty;
        var realmValue = link.Realm.OrDefault.Value;
        var issuer = link.UpstreamIssuer;
        var upstreamSubject = link.UpstreamSubject;

        if (!await context.Users.AnyAsync(u => u.Subject == subjectValue, cancellationToken))
        {
            // The foreign key, checked here so the message names the problem. A dangling link
            // resolves to nothing at sign-in time and the failure surfaces as "your account is not
            // connected" long after the mistake.
            throw new InvalidOperationException(
                "No local account has this subject, so there is nothing to link the upstream identity to.");
        }

        var existing = await context.ExternalLogins
            .SingleOrDefaultAsync(
                e => e.Realm == realmValue
                  && e.UpstreamIssuer == issuer
                  && e.UpstreamSubject == upstreamSubject,
                cancellationToken);

        if (existing is not null)
        {
            if (string.Equals(existing.Subject, subjectValue, StringComparison.Ordinal))
            {
                // Idempotent. Signing in twice through the same upstream identity must not be an
                // error; only pointing it somewhere new is.
                return;
            }

            throw new InvalidOperationException(
                "This upstream identity is already linked to a different local account.");
        }

        context.ExternalLogins.Add(new ExternalLoginRow
        {
            Realm = realmValue,
            UpstreamIssuer = issuer,
            UpstreamSubject = upstreamSubject,
            Subject = subjectValue,
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            throw new InvalidOperationException(
                "This upstream identity is already linked to a local account.", ex);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// Three statements inside one transaction, where setting a single role was one. The account is
    /// read for its realm — a role id is only meaningful inside one — the old assignments go, and
    /// the new ones land. Atomic, because the state between the delete and the insert is an account
    /// holding nothing, and a caller reading it there would see a demotion that was never asked for.
    /// </para>
    /// <para>
    /// It still never touches a credential: it is not given one, and it writes only the join table.
    /// That is the property <c>StoreAsync</c> being add-only depends on.
    /// </para>
    /// </remarks>
    public async Task<bool> SetRolesAsync(
        SubjectId subject, IReadOnlyList<string> roles, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.SetRolesAsync");

        ArgumentNullException.ThrowIfNull(roles);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var subjectValue = subject.Value;

        var account = await context.Users
            .Select(u => new { u.Subject, u.Realm })
            .SingleOrDefaultAsync(u => u.Subject == subjectValue, cancellationToken);

        if (account is null) return false;

        var wanted = roles.Distinct(StringComparer.Ordinal).ToList();

        // Checked here as well as by the foreign key, because the contract asks for an exception
        // naming the id that was wrong, and a provider exception says only that some constraint
        // failed. The key is still declared: it is what holds if this check is raced.
        if (wanted.Count > 0)
        {
            var defined = await context.Roles
                .Where(r => r.Realm == account.Realm && wanted.Contains(r.Id))
                .Select(r => r.Id)
                .ToListAsync(cancellationToken);

            if (defined.Count != wanted.Count)
            {
                var missing = wanted.Except(defined, StringComparer.Ordinal);

                throw new InvalidOperationException(
                    $"Realm `{account.Realm}` defines no role `{string.Join("`, `", missing)}`. A role has to "
                    + "exist before an account can hold it, so that a mistyped id is a refusal here rather "
                    + "than an account quietly holding nothing.");
            }
        }

        await context.UserRoles
            .Where(r => r.Subject == subjectValue)
            .ExecuteDeleteAsync(cancellationToken);

        foreach (var role in wanted)
        {
            context.UserRoles.Add(new UserRoleRow
            {
                Subject = subjectValue,
                Realm = account.Realm,
                RoleId = role,
            });
        }

        await context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return true;
    }

    public async Task<bool> SetPasswordHashAsync(
        SubjectId subject, string passwordHash, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.SetPasswordHashAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;

        // Same shape as SetRoleAsync, and the comment there applies in the mirror image: one
        // statement, so this cannot carry a stale *role* back to the database while changing a
        // credential. Load-modify-save would read the account, hash, and write everything back —
        // and a role changed between the read and the write would be silently undone by a password
        // reset, which is the kind of authorization regression nobody thinks to look for.
        var updated = await context.Users
            .Where(u => u.Subject == subjectValue)
            .ExecuteUpdateAsync(set => set.SetProperty(u => u.PasswordHash, passwordHash), cancellationToken);

        return updated > 0;
    }

    /// <inheritdoc />
    public async Task<bool> StampSessionsAsync(
        SubjectId subject, DateTimeOffset at, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.StampSessionsAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var ticks = at.UtcTicks;

        // One statement, for the reason SetPasswordHashAsync gives: this runs on the password
        // routes, beside a write to the hash, and a load-modify-save here could carry a stale role
        // back to the database while somebody is in the middle of responding to a compromise.
        var updated = await context.Users
            .Where(u => u.Subject == subjectValue)
            .ExecuteUpdateAsync(set => set.SetProperty(u => u.SessionsValidFrom, ticks), cancellationToken);

        return updated > 0;
    }

    /// <inheritdoc />
    public async Task<bool> SetEnabledAsync(
        SubjectId subject, DateTimeOffset? disabledAt, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.SetEnabledAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var ticks = StoredValues.ToTicks(disabledAt);

        // One statement, like the two setters above it, and for the same reason: a load-modify-save
        // would write back every column it happened to have read, so disabling an account would
        // undo a password change made in between.
        var updated = await context.Users
            .Where(u => u.Subject == subjectValue)
            .ExecuteUpdateAsync(set => set.SetProperty(u => u.DisabledAt, ticks), cancellationToken);

        return updated > 0;
    }

    /// <inheritdoc />
    public async Task<bool> SetEmailAsync(
        SubjectId subject, string? email, bool verified, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.SetEmailAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;

        // Both columns in one statement. Two statements would leave a window in which the address is
        // the new one and the verification flag still describes the old one — brief, and in exactly
        // the direction that matters, since the wrong half to be visible is "verified".
        var updated = await context.Users
            .Where(u => u.Subject == subjectValue)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(u => u.Email, email)
                    .SetProperty(u => u.NormalizedEmail, StoredValues.NormalizeEmail(email))
                    .SetProperty(u => u.EmailVerified, verified),
                cancellationToken);

        return updated > 0;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<UserAccount>> ListAsync(
        RealmId realm, SubjectId? after, int limit, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.ListAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var realmValue = realm.OrDefault.Value;
        var rows = context.Users.AsNoTracking().Include(u => u.Roles).Where(u => u.Realm == realmValue);

        if (after?.Value is { } cursor)
        {
            // `CompareTo`, because `string.Compare(a, b, StringComparison.Ordinal)` does not
            // translate — measured, EF Core refuses the query rather than falling back, which is the
            // right refusal: a client-side evaluation here would page by loading the table.
            //
            // The comparison and the ORDER BY below both run in the column's collation, so they
            // agree with each other whatever that collation is, and that agreement is what makes the
            // cursor sound. It is *not* guaranteed to be ordinal: pinning that would mean an
            // explicit collation on the column, which is a migration and a decision about every
            // deployed database. Subjects are ULIDs — digits and uppercase Crockford base32 — so
            // every collation this is likely to meet orders them the same way, and the contract
            // asserts the property that actually matters: no row skipped and none repeated.
            rows = rows.Where(u => u.Subject.CompareTo(cursor) > 0);
        }

        var page = await rows
            .OrderBy(u => u.Subject)
            .Take(Math.Clamp(limit, 1, 500))
            .ToListAsync(cancellationToken);

        return [.. page.Select(ToAccount)];
    }

    /// <inheritdoc />
    public async Task<bool> AnonymiseAsync(
        SubjectId subject, string tombstoneUsername, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserStore.AnonymiseAsync");

        ArgumentException.ThrowIfNullOrEmpty(tombstoneUsername);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // A transaction, unlike every other setter on this store, because this one spans two tables.
        // The account and its external links have to change together: a tombstoned account with a
        // live Google link is an account the next federated sign-in walks straight back into, under
        // a name that says nobody is there.
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var subjectValue = subject.Value;
        var normalized = StoredValues.NormalizeUsername(tombstoneUsername);
        var disabledAt = StoredValues.ToTicks(now);

        var updated = await context.Users
            .Where(u => u.Subject == subjectValue)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(u => u.Username, tombstoneUsername)
                    .SetProperty(u => u.NormalizedUsername, normalized)
                    .SetProperty(u => u.Email, (string?)null)
                    .SetProperty(u => u.NormalizedEmail, (string?)null)
                    .SetProperty(u => u.EmailVerified, false)
                    .SetProperty(u => u.PasswordHash, (string?)null)
                    // Not `?? now`, unlike SetEnabledAsync — an account already disabled keeps its
                    // original time there because "since when" is the question a disabled account is
                    // asked. Here the answer wanted is when it stopped being a person's account, and
                    // that is now whatever else was true a minute ago.
                    .SetProperty(u => u.DisabledAt, disabledAt),
                cancellationToken);

        if (updated == 0)
        {
            return false;
        }

        // Deleted rather than repointed at the tombstone. A link is a claim that an upstream
        // identity belongs to this account, and it is exactly the claim being withdrawn — keeping it
        // would leave the person's Google subject in the database, which is one of the identifiers
        // this operation exists to remove.
        await context.ExternalLogins
            .Where(e => e.Subject == subjectValue)
            .ExecuteDeleteAsync(cancellationToken);

        // And what it held. A tombstone still carrying an administrative role is a row that says
        // something about the person, and the next token minted for that subject would still carry
        // the permissions.
        await context.UserRoles
            .Where(r => r.Subject == subjectValue)
            .ExecuteDeleteAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return true;
    }

    private static UserAccount ToAccount(UserRow row) => new(
        SubjectId.FromStorage(row.Subject),
        row.Username,
        row.Email,
        row.EmailVerified,
        row.PasswordHash,
        StoredValues.FromTicks(row.DisabledAt))
    {
        Realm = RealmId.FromStorage(row.Realm),
        SessionsValidFrom = StoredValues.FromTicks(row.SessionsValidFrom),

        // Ordered, because the set is unordered and a caller rendering it — an admin page, a log
        // line, an assertion — otherwise gets whatever order the join came back in, which differs
        // between providers and between two runs on one of them.
        Roles = [.. row.Roles.Select(r => r.RoleId).Order(StringComparer.Ordinal)],
    };
}
