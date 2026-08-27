using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// The administrative audit log, in a relational database.
/// </summary>
/// <remarks>
/// <para>
/// <b>Insert and select. There is no update and no delete, and their absence is the design.</b> A
/// log an administrator can edit proves nothing about administrators, so the type offers no way to
/// do it - not as a guard that could be relaxed, but as a method that was never written.
/// </para>
/// <para>
/// Times are stored as ticks, like every other timestamp here, so ordering is exact on both
/// providers and does not depend on either one's datetime precision.
/// </para>
/// </remarks>
/// <param name="contextFactory">Where a context comes from.</param>
/// <param name="metrics">Where the timings go.</param>
public sealed class EfAdminAuditStore(
    IDbContextFactory<AuthDbContext> contextFactory, StorageMetrics metrics) : IAdminAuditStore
{
    /// <inheritdoc />
    public async Task RecordAsync(AdminAuditEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        using var timing = metrics.Track("AdminAuditStore.RecordAsync");

        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);

        context.AdminAudit.Add(new AdminAuditRow
        {
            At = entry.At.UtcTicks,
            ActorKind = entry.ActorKind,
            ActorSubject = entry.ActorSubject?.Value,
            ActorClient = entry.ActorClient,
            Action = entry.Action,
            TargetRealm = entry.TargetRealm.OrDefault.Value,
            TargetSubject = entry.TargetSubject?.Value,
            TargetHandle = entry.TargetHandle,
            Outcome = entry.Outcome is AdminAuditOutcome.Succeeded ? "succeeded" : "refused",
            Detail = entry.Detail,
            CorrelationId = entry.CorrelationId,
        });

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AdminAuditEntry>> ReadAsync(
        AuditQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        using var timing = metrics.Track("AdminAuditStore.ReadAsync");

        await using var context = await contextFactory.CreateDbContextAsync(cancellationToken);

        var rows = context.AdminAudit.AsNoTracking();

        if (query.Realm is { } realm)
        {
            var value = realm.OrDefault.Value;
            rows = rows.Where(r => r.TargetRealm == value);
        }

        if (query.TargetSubject is { } subject)
        {
            var value = subject.Value;
            rows = rows.Where(r => r.TargetSubject == value);
        }

        if (query.Since is { } since)
        {
            var ticks = since.UtcTicks;
            rows = rows.Where(r => r.At >= ticks);
        }

        // Descending id breaks a tie on the timestamp, so two entries written in the same tick come
        // back in the order they were written rather than in whatever order the index walks.
        var page = await rows
            .OrderByDescending(r => r.At)
            .ThenByDescending(r => r.Id)
            .Take(query.Limit)
            .ToListAsync(cancellationToken);

        return [.. page.Select(ToEntry)];
    }

    private static AdminAuditEntry ToEntry(AdminAuditRow row) => new(
        new DateTimeOffset(row.At, TimeSpan.Zero),
        row.ActorKind,
        row.ActorSubject is null ? null : SubjectId.FromStorage(row.ActorSubject),
        row.ActorClient,
        row.Action,
        RealmId.FromStorage(row.TargetRealm),
        row.TargetSubject is null ? null : SubjectId.FromStorage(row.TargetSubject),
        row.TargetHandle,
        string.Equals(row.Outcome, "succeeded", StringComparison.Ordinal)
            ? AdminAuditOutcome.Succeeded
            : AdminAuditOutcome.Refused,
        row.CorrelationId)
    {
        Detail = row.Detail,
    };
}
