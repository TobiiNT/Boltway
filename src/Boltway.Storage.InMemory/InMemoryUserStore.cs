using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.Storage.InMemory;

/// <summary>
/// Users in memory, with the external-login table D-10 requires from day one.
/// </summary>
/// <remarks>
/// <para>
/// Ships in the box for the same reason the grant stores do: a customer implementing
/// <see cref="IUserStore"/> against their own directory needs something to compare against, and the
/// shared contract suite needs a second implementation to prove the contract describes behaviour
/// rather than one data access layer.
/// </para>
/// <para>
/// Two indexes over one set of accounts, and both are enforced rather than advisory. The username
/// index is <see cref="StringComparer.OrdinalIgnoreCase"/>, which does two jobs at once: it makes
/// the lookup case-insensitive, as the interface requires, and it makes registering <c>Alice</c>
/// after <c>alice</c> fail - because if both rows existed, which one a login reached would depend on
/// the store's collation, and two implementations of this interface would answer differently on
/// identical input.
/// </para>
/// </remarks>
public sealed class InMemoryUserStore : IUserStore
{
    /// <summary>An account store whose realm defines no roles yet.</summary>
    /// <remarks>
    /// The role store is a constructor dependency rather than something this one owns, because
    /// assignment has to be refused for an id nothing defines and there is no way to answer that
    /// without the definitions. A test that builds this directly gets an empty one, so assigning
    /// any role fails until it is defined - which is the contract, not an inconvenience.
    /// </remarks>
    public InMemoryUserStore() : this(new InMemoryRoleStore()) { }

    /// <summary>Share a role store, so assignment can ask whether a role exists.</summary>
    /// <param name="roles">Where the definitions live.</param>
    public InMemoryUserStore(InMemoryRoleStore roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        _roles = roles;

        // The cascade `user_roles` declares, arriving by the only route available here: the
        // dependency runs from this store to that one so assignment can check, so removal has to
        // come back the other way as a notification. Without it a role deleted here leaves accounts
        // holding an id nothing defines - which the relational store makes impossible and this one
        // did until a test deleted a role and read the account back.
        _roles.Deleted += Forget;
    }

    private readonly InMemoryRoleStore _roles;

    private readonly Dictionary<string, UserAccount> _bySubject = new(StringComparer.Ordinal);
    // Keyed on (realm, username) and (realm, issuer, upstream subject). The realm is part of the
    // key rather than a filter applied after the lookup, which is the same decision the relational
    // store makes with a composite unique index - so the two cannot disagree about whether two
    // realms may hold the same username.
    private readonly Dictionary<(string Realm, string Username), UserAccount> _byUsername =
        new(RealmScopedNameComparer.Instance);

    private readonly Dictionary<(string Realm, string Issuer, string Subject), SubjectId> _external = [];
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task<UserAccount?> FindBySubjectAsync(SubjectId subject, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(subject.Value is null ? null : _bySubject.GetValueOrDefault(subject.Value));
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Answers <see langword="null"/> for a null or empty name rather than throwing. This is reached
    /// straight from a form field, so "the user submitted nothing" has to be an unsuccessful login
    /// and not a 500 that anyone can provoke by posting an empty form.
    /// </remarks>
    public Task<UserAccount?> FindByUsernameAsync(
        RealmId realm, string username, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(
                string.IsNullOrEmpty(username)
                    ? null
                    : _byUsername.GetValueOrDefault((realm.OrDefault.Value, username)));
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// A scan rather than an index, and the relational store does the opposite for a reason that
    /// does not apply here: there, this lookup is reached from the sign-in form and a scan is
    /// unbounded work an anonymous caller can ask for. This store holds a test's dozen accounts in
    /// a dictionary. An index maintained on every write to make a scan of twelve entries faster is
    /// a second place for the two stores to disagree, bought with nothing.
    /// </para>
    /// <para>
    /// Two matches answer null, exactly as the relational store does, and the contract suite runs
    /// that case against both - otherwise this store would be the one that never reproduces it.
    /// </para>
    /// </remarks>
    public Task<UserAccount?> FindByVerifiedEmailAsync(
        RealmId realm, string email, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(email))
        {
            return Task.FromResult<UserAccount?>(null);
        }

        lock (_gate)
        {
            var realmValue = realm.OrDefault.Value;
            UserAccount? found = null;

            foreach (var ((entryRealm, _), account) in _byUsername)
            {
                if (!string.Equals(entryRealm, realmValue, StringComparison.Ordinal)
                    || !account.EmailVerified
                    || !string.Equals(account.Email, email, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (found is not null)
                {
                    // A second match: ambiguous, so neither. Returning the first would make which
                    // account a password reaches depend on dictionary order.
                    return Task.FromResult<UserAccount?>(null);
                }

                found = account;
            }

            return Task.FromResult(found);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// A scan of the link table, which the relational store indexes. Same trade as the address
    /// lookup: this store holds a test's handful of rows, and an index maintained on every write to
    /// speed up a scan of them buys nothing and adds a second place to disagree.
    /// </remarks>
    public Task<IReadOnlyList<ExternalLogin>> ListExternalLoginsAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            IReadOnlyList<ExternalLogin> links =
            [
                .. _external
                    .Where(entry => string.Equals(entry.Value.Value, subject.Value, StringComparison.Ordinal))
                    .Select(entry => new ExternalLogin(entry.Key.Issuer, entry.Key.Subject, subject)
                    {
                        Realm = RealmId.FromStorage(entry.Key.Realm),
                    }),
            ];

            return Task.FromResult(links);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Ordinal on both halves. An upstream issuer and subject are opaque values chosen by someone
    /// else; case-folding them would merge two identities the upstream considers distinct, which is
    /// the account-takeover shape D-10's mapping table exists to keep impossible.
    /// </remarks>
    public Task<UserAccount?> FindByExternalLoginAsync(
        RealmId realm, string upstreamIssuer, string upstreamSubject, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (string.IsNullOrEmpty(upstreamIssuer) || string.IsNullOrEmpty(upstreamSubject))
            {
                return Task.FromResult<UserAccount?>(null);
            }

            return Task.FromResult(
                _external.TryGetValue((realm.OrDefault.Value, upstreamIssuer, upstreamSubject), out var subject)
                    ? _bySubject.GetValueOrDefault(subject.Value)
                    : null);
        }
    }

    /// <summary>Drop a role every account held, because it no longer exists.</summary>
    private void Forget(RealmId realm, string id)
    {
        lock (_gate)
        {
            foreach (var (subject, account) in _bySubject.ToList())
            {
                if (!account.Realm.OrDefault.Equals(realm.OrDefault)
                    || !account.Roles.Contains(id, StringComparer.Ordinal))
                {
                    continue;
                }

                var updated = account with
                {
                    Roles = [.. account.Roles.Where(r => !string.Equals(r, id, StringComparison.Ordinal))],
                };

                // Both dictionaries, for the reason SetRolesAsync gives: they hold the record rather
                // than a reference to one shared object, so updating one leaves the other answering
                // from before the change.
                _bySubject[subject] = updated;
                _byUsername[(updated.Realm.OrDefault.Value, updated.Username)] = updated;
            }
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Add-only, like every other store here. An upsert would let a re-registration silently replace
    /// an existing account's password hash - which is account takeover by whoever can reach the
    /// registration path - and a relational store's unique constraints would throw, so tolerating it
    /// would make two implementations disagree on identical input.
    /// </remarks>
    public Task StoreAsync(UserAccount user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrEmpty(user.Subject.Value))
        {
            throw new ArgumentException("An account needs a subject identifier.", nameof(user));
        }

        if (string.IsNullOrWhiteSpace(user.Username))
        {
            throw new ArgumentException("An account needs a username.", nameof(user));
        }

        // The same refusal the relational store makes, and for the same reason - see
        // UserAccount.Roles. Creation does not assign.
        if (user.Roles.Count > 0)
        {
            throw new ArgumentException(
                "An account is created holding no roles. Assign them with SetRolesAsync, which is the "
                + "only path that can refuse an id the realm does not define — two ways in would be two "
                + "places that rule has to be remembered the same way.",
                nameof(user));
        }

        lock (_gate)
        {
            if (_bySubject.ContainsKey(user.Subject.Value))
            {
                throw new InvalidOperationException(
                    "An account with this subject already exists. Accounts are add-only: overwriting "
                    + "one would replace its credentials.");
            }

            if (_byUsername.ContainsKey((user.Realm.OrDefault.Value, user.Username)))
            {
                // Case-insensitively. Two accounts differing only by case is the defect the
                // interface names, and it has to fail here rather than at the login that finds the
                // wrong one.
                throw new InvalidOperationException(
                    "An account with this username already exists, ignoring case.");
            }

            _bySubject.Add(user.Subject.Value, user);
            _byUsername.Add((user.Realm.OrDefault.Value, user.Username), user);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// One upstream identity maps to at most one local account, and re-linking it is refused. If it
    /// could be moved, whoever controls the upstream subject - or anyone who can replay a link
    /// request - repoints it at an account of their choosing, and the next federated sign-in lands
    /// inside someone else's data.
    /// </para>
    /// <para>
    /// The reverse direction is left open: one local account may carry links from several upstream
    /// issuers, which is what makes "sign in with Google, then also with Facebook" work rather than
    /// producing two accounts for one person. That asymmetry is the whole shape of the table.
    /// </para>
    /// </remarks>
    public Task LinkExternalLoginAsync(ExternalLogin link, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(link);

        if (string.IsNullOrEmpty(link.UpstreamIssuer) || string.IsNullOrEmpty(link.UpstreamSubject))
        {
            throw new ArgumentException("An external login needs an upstream issuer and subject.", nameof(link));
        }

        lock (_gate)
        {
            if (!_bySubject.ContainsKey(link.Subject.Value ?? string.Empty))
            {
                // The foreign key, enforced. A link to an account that does not exist is a row that
                // resolves to nothing at sign-in time, and the failure would surface as "your Google
                // account is not connected" long after the mistake.
                throw new InvalidOperationException(
                    "No local account has this subject, so there is nothing to link the upstream identity to.");
            }

            var key = (link.Realm.OrDefault.Value, link.UpstreamIssuer, link.UpstreamSubject);

            if (_external.TryGetValue(key, out var existing))
            {
                if (existing == link.Subject)
                {
                    // Idempotent. Signing in twice through the same upstream identity must not be an
                    // error; only pointing it somewhere new is.
                    return Task.CompletedTask;
                }

                throw new InvalidOperationException(
                    "This upstream identity is already linked to a different local account.");
            }

            _external.Add(key, link.Subject);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> SetRolesAsync(
        SubjectId subject, IReadOnlyList<string> roles, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(roles);

        lock (_gate)
        {
            if (subject.Value is not { } value || !_bySubject.TryGetValue(value, out var account))
            {
                return Task.FromResult(false);
            }

            var wanted = roles.Distinct(StringComparer.Ordinal).ToList();

            // The relational store leaves this to a foreign key and checks first for the message.
            // Here the check is the only thing there is, so it is the same refusal reached by the
            // only available route.
            var missing = wanted.Where(role => !_roles.Defines(account.Realm, role)).ToList();

            if (missing.Count > 0)
            {
                throw new InvalidOperationException(
                    $"Realm `{account.Realm.OrDefault.Value}` defines no role "
                    + $"`{string.Join("`, `", missing)}`. A role has to exist before an account can hold "
                    + "it, so that a mistyped id is a refusal here rather than an account quietly "
                    + "holding nothing.");
            }

            var updated = account with { Roles = [.. wanted.Order(StringComparer.Ordinal)] };

            // Both dictionaries, because they hold the record rather than a reference to one shared
            // mutable object. Updating only `_bySubject` would leave a sign-in - which arrives by
            // username - reading the role from before the change, and that divergence would show up
            // as "the promotion worked, then it did not".
            _bySubject[value] = updated;
            _byUsername[(account.Realm.OrDefault.Value, account.Username)] = updated;
        }

        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task<bool> SetPasswordHashAsync(
        SubjectId subject, string passwordHash, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (subject.Value is not { } value || !_bySubject.TryGetValue(value, out var account))
            {
                return Task.FromResult(false);
            }

            var updated = account with { PasswordHash = passwordHash };

            // Both dictionaries, for the reason above - and here the divergence would be worse than
            // a stale role. Sign-in arrives by username, so updating only `_bySubject` would leave
            // the old password working and the new one refused, which reads as "the reset did not
            // happen" while the store believes it did.
            _bySubject[value] = updated;
            _byUsername[(account.Realm.OrDefault.Value, account.Username)] = updated;
        }

        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task<bool> StampSessionsAsync(
        SubjectId subject, DateTimeOffset at, CancellationToken cancellationToken) =>
        Task.FromResult(Update(subject, account => account with { SessionsValidFrom = at }));

    /// <inheritdoc />
    public Task<bool> SetEnabledAsync(
        SubjectId subject, DateTimeOffset? disabledAt, CancellationToken cancellationToken) =>
        Task.FromResult(Update(subject, account => account with { DisabledAt = disabledAt }));

    /// <inheritdoc />
    public Task<bool> SetEmailAsync(
        SubjectId subject, string? email, bool verified, CancellationToken cancellationToken) =>
        Task.FromResult(Update(subject, account => account with { Email = email, EmailVerified = verified }));

    /// <inheritdoc />
    public Task<IReadOnlyList<UserAccount>> ListAsync(
        RealmId realm, SubjectId? after, int limit, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var realmValue = realm.OrDefault.Value;
            var cursor = after?.Value;

            IReadOnlyList<UserAccount> page =
            [
                .. _bySubject.Values
                    .Where(account => string.Equals(
                        account.Realm.OrDefault.Value, realmValue, StringComparison.Ordinal))
                    .Where(account => cursor is null
                        || string.CompareOrdinal(account.Subject.Value, cursor) > 0)
                    .OrderBy(account => account.Subject.Value, StringComparer.Ordinal)
                    .Take(Math.Clamp(limit, 1, 500)),
            ];

            return Task.FromResult(page);
        }
    }

    /// <inheritdoc />
    public Task<bool> AnonymiseAsync(
        SubjectId subject, string tombstoneUsername, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(tombstoneUsername);

        lock (_gate)
        {
            if (subject.Value is not { } value || !_bySubject.TryGetValue(value, out var account))
            {
                return Task.FromResult(false);
            }

            var updated = account with
            {
                Username = tombstoneUsername,
                Email = null,
                EmailVerified = false,
                PasswordHash = null,

                // And what it held. A tombstone still carrying an administrative role says
                // something about the person, and the next token minted for that subject would
                // still carry it.
                Roles = [],
                DisabledAt = now,
            };

            var realm = account.Realm.OrDefault.Value;

            // Not `Update`, and that is the whole difference: every other setter leaves the username
            // alone, so re-indexing under `account.Username` is right for them and would leave the
            // old name resolving to the tombstone here. Remove, then add.
            _byUsername.Remove((realm, account.Username));
            _byUsername[(realm, tombstoneUsername)] = updated;
            _bySubject[value] = updated;

            // The links go, not repoint. A link is the claim that an upstream identity belongs to
            // this account, and it is the claim being withdrawn - keeping it would leave the
            // person's Google subject in the store, which is one of the identifiers this removes.
            foreach (var key in _external.Where(pair => pair.Value == subject).Select(pair => pair.Key).ToList())
            {
                _external.Remove(key);
            }

            return Task.FromResult(true);
        }
    }

    /// <summary>
    /// Replace an account in both indexes, or report that there was none.
    /// </summary>
    /// <remarks>
    /// Extracted once there were four setters doing it. The two dictionaries hold records rather
    /// than references to one mutable object, so updating one and not the other leaves the two
    /// lookups answering differently - and since sign-in arrives by username, the half that goes
    /// stale is the half that decides whether somebody gets in.
    /// </remarks>
    private bool Update(SubjectId subject, Func<UserAccount, UserAccount> change)
    {
        lock (_gate)
        {
            if (subject.Value is not { } value || !_bySubject.TryGetValue(value, out var account))
            {
                return false;
            }

            var updated = change(account);

            _bySubject[value] = updated;
            _byUsername[(account.Realm.OrDefault.Value, account.Username)] = updated;

            return true;
        }
    }
}

/// <summary>
/// Realm ordinally, username ignoring case - the composite the relational store indexes on.
/// </summary>
/// <remarks>
/// A comparer rather than a tuple of pre-folded strings, because folding at the call site is
/// something one of the four call sites eventually forgets. Realms are already constrained to
/// lowercase at creation, so ordinal there is exact; usernames are typed by people, so the
/// username half must ignore case for the same reason the interface says so.
/// </remarks>
internal sealed class RealmScopedNameComparer : IEqualityComparer<(string Realm, string Username)>
{
    internal static RealmScopedNameComparer Instance { get; } = new();

    public bool Equals((string Realm, string Username) x, (string Realm, string Username) y) =>
        string.Equals(x.Realm, y.Realm, StringComparison.Ordinal)
        && string.Equals(x.Username, y.Username, StringComparison.OrdinalIgnoreCase);

    public int GetHashCode((string Realm, string Username) obj) =>
        HashCode.Combine(
            StringComparer.Ordinal.GetHashCode(obj.Realm),
            StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Username));
}
