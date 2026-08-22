using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Grants and the revocation denylist, in a relational database.</summary>
internal sealed class EfGrantStore(
    IDbContextFactory<AuthDbContext> contextFactory, IRelationalStoreBehavior behavior, StorageMetrics metrics) : IGrantStore
{
    private readonly StorageMetrics _metrics = metrics;

    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly IRelationalStoreBehavior _behavior = behavior;

    /// <inheritdoc />
    public async Task StoreAsync(GrantRecord grant, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.StoreAsync");

        ArgumentNullException.ThrowIfNull(grant);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        context.Grants.Add(new GrantRow
        {
            GrantId = grant.GrantId,
            Subject = grant.Subject.Value,
            ClientId = grant.ClientId.Value,
            ClientIdKind = (int)grant.ClientId.Kind,
            Scope = grant.Scope.ToWireString(),
            Resources = StoredValues.EncodeResources(grant.Resources),
            CreatedAt = StoredValues.ToTicks(grant.CreatedAt),
            AuthTime = StoredValues.ToTicks(grant.AuthTime),
            RevokedAt = StoredValues.ToTicks(grant.RevokedAt),
            UserAgent = grant.UserAgent,
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            throw new InvalidOperationException($"Grant '{grant.GrantId}' already exists.", ex);
        }
    }

    /// <inheritdoc />
    public async Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.FindAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var row = await context.Grants.SingleOrDefaultAsync(g => g.GrantId == grantId, cancellationToken);

        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public async Task<bool> RevokeAsync(string grantId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.RevokeAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // A local, not the call inline: a method call inside the setter would have to be translated
        // to SQL, and the value wanted here is a parameter computed once on this side.
        var revokedAt = StoredValues.ToTicks(now);

        // One conditional UPDATE, and its rows-affected is the answer. A read followed by a write
        // would let two concurrent revocations both report they did it, and a caller reacting to
        // reuse detection logs "grant revoked" per call.
        var updated = await context.Grants
            .Where(g => g.GrantId == grantId && g.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(g => g.RevokedAt, revokedAt), cancellationToken);

        return updated == 1;
    }

    /// <inheritdoc />
    public async Task<int> RevokeAllForSubjectAsync(
        SubjectId subject, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.RevokeAllForSubjectAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var revokedAt = StoredValues.ToTicks(now);

        // One conditional UPDATE over the subject's grants, and its rows-affected is the answer.
        // `RevokedAt == null` is what makes the count "how many this call transitioned" rather than
        // "how many exist" — and it is also what makes calling this twice harmless.
        //
        // There is no index on Subject today. The table is grants, one row per (user, client,
        // authorization), so a sequential scan here is a scan of a table with as many rows as the
        // deployment has authorizations — and this runs when an operator is signing somebody out,
        // not on a request path. An index is the right thing when that stops being true; adding one
        // now would be a migration on every deployed database for a query nobody runs in a loop.
        return await context.Grants
            .Where(g => g.Subject == subjectValue && g.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(g => g.RevokedAt, revokedAt), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> IsRevokedAsync(string grantId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.IsRevokedAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // Revoked, not merely absent. An unknown grant is not revoked — conflating the two would
        // make the denylist answer yes for every id anyone asks about.
        return await context.Grants.AnyAsync(g => g.GrantId == grantId && g.RevokedAt != null, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<GrantRecord>> ListForSubjectAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.ListForSubjectAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;

        // The same `Subject` predicate `RevokeAllForSubjectAsync` runs, and the same absence of an
        // index behind it. Both read one account's grants, both are reached by a person looking at
        // their own account rather than by a request path, and the table has one row per
        // authorization. The note there is the note here.
        var rows = await context.Grants
            .Where(g => g.Subject == subjectValue && g.RevokedAt == null)
            .OrderByDescending(g => g.CreatedAt)
            .ToListAsync(cancellationToken);

        return [.. rows.Select(ToRecord)];
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ListApprovedUserAgentsAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("GrantStore.ListApprovedUserAgentsAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;

        // No `RevokedAt` predicate, unlike every other read of this table: the question is what this
        // person has ever approved from, and revoking a grant does not un-use the machine.
        //
        // Distinct in the database. The projection runs before it, so the server compares one column
        // rather than shipping a row per authorization to compare here.
        var agents = await context.Grants
            .Where(g => g.Subject == subjectValue && g.UserAgent != null && g.UserAgent != "")
            .Select(g => g.UserAgent!)
            .Distinct()
            .ToListAsync(cancellationToken);

        return agents;
    }

    private static GrantRecord ToRecord(GrantRow row) => new(
        row.GrantId,
        SubjectId.FromStorage(row.Subject),
        StoredValues.ToClientIdentifier(row.ClientId, row.ClientIdKind),
        ScopeSet.FromStorage(row.Scope),
        StoredValues.DecodeResources(row.Resources),
        StoredValues.FromTicks(row.CreatedAt),
        StoredValues.FromTicks(row.AuthTime),
        StoredValues.FromTicks(row.RevokedAt),
        row.UserAgent);
}
