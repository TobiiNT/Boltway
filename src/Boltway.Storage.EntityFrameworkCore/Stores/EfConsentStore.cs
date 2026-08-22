using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Consent, in a relational database.</summary>
/// <remarks>
/// <b>Widening is the whole contract.</b> C-24: a client that comes back asking for one more scope
/// must end up with the union. Replacing silently revokes authority the user granted earlier and
/// never withdrew, and the symptom is a tool that worked yesterday returning 403 today.
/// </remarks>
internal sealed class EfConsentStore(
    IDbContextFactory<AuthDbContext> contextFactory, IRelationalStoreBehavior behavior, StorageMetrics metrics) : IConsentStore
{
    private readonly StorageMetrics _metrics = metrics;

    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly IRelationalStoreBehavior _behavior = behavior;

    /// <inheritdoc />
    public async Task<ConsentRecord?> FindAsync(
        SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ConsentStore.FindAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var clientValue = clientId.Value;
        var row = await context.Consents
            .SingleOrDefaultAsync(c => c.Subject == subjectValue && c.ClientId == clientValue, cancellationToken);

        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public async Task<ConsentRecord> GrantAsync(
        SubjectId subject,
        ClientIdentifier clientId,
        ScopeSet scope,
        IReadOnlyList<string> resources,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ConsentStore.GrantAsync");

        ArgumentNullException.ThrowIfNull(resources);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // Read-merge-write, so it needs the write transaction: two authorizations for the same user
        // and client can be in flight at once — a browser tab and a native app, or a user who
        // double-submits — and a lost update here silently drops a scope the user approved.
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var subjectValue = subject.Value;
        var clientValue = clientId.Value;

        var existing = await context.Consents
            .AsTracking()
            .SingleOrDefaultAsync(c => c.Subject == subjectValue && c.ClientId == clientValue, cancellationToken);

        ConsentRow row;

        if (existing is null)
        {
            row = new ConsentRow
            {
                Subject = subjectValue,
                ClientId = clientValue,
                ClientIdKind = (int)clientId.Kind,
                Scope = scope.ToWireString(),
                Resources = StoredValues.EncodeResources(resources),
                GrantedAt = StoredValues.ToTicks(now),
            };

            context.Consents.Add(row);
        }
        else
        {
            existing.ClientIdKind = (int)clientId.Kind;
            existing.Scope = Union(ScopeSet.FromStorage(existing.Scope), scope).ToWireString();
            existing.Resources = StoredValues.EncodeResources(
                [.. StoredValues.DecodeResources(existing.Resources).Union(resources, StringComparer.Ordinal)]);
            existing.GrantedAt = StoredValues.ToTicks(now);
            row = existing;
        }

        await context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return ToRecord(row);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ConsentRecord>> ListAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ConsentStore.ListAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;

        // Ordered in the database rather than after materialising, so the ordering is the same one
        // a paged version would use if this ever needs one.
        var rows = await context.Consents
            .Where(c => c.Subject == subjectValue)
            .OrderByDescending(c => c.GrantedAt)
            .ToListAsync(cancellationToken);

        return [.. rows.Select(ToRecord)];
    }

    /// <inheritdoc />
    public async Task<bool> RevokeAsync(
        SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ConsentStore.RevokeAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var clientValue = clientId.Value;

        return await context.Consents
            .Where(c => c.Subject == subjectValue && c.ClientId == clientValue)
            .ExecuteDeleteAsync(cancellationToken) > 0;
    }

    /// <summary>Every scope from either set, once.</summary>
    /// <remarks>
    /// Through <see cref="ScopeSet.FromStorage"/>, which is the one entry point that re-applies the
    /// name rules to a value coming back from a store. Ordinal throughout: scope names are
    /// case-sensitive, so <c>Read</c> and <c>read</c> are two scopes and merging them would grant one
    /// the user never approved.
    /// </remarks>
    private static ScopeSet Union(ScopeSet existing, ScopeSet added) =>
        ScopeSet.FromStorage(string.Join(' ', existing.Values.Union(added.Values, StringComparer.Ordinal)));

    private static ConsentRecord ToRecord(ConsentRow row) => new(
        SubjectId.FromStorage(row.Subject),
        StoredValues.ToClientIdentifier(row.ClientId, row.ClientIdKind),
        ScopeSet.FromStorage(row.Scope),
        StoredValues.DecodeResources(row.Resources),
        StoredValues.FromTicks(row.GrantedAt));
}
