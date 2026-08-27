using Boltway.AuthorizationServer.Abstractions.Administration;

namespace Boltway.Storage.InMemory;

/// <summary>
/// The audit log in memory, append-only like every other implementation of it.
/// </summary>
/// <remarks>
/// Ships for the reason the other in-memory stores do: the shared contract suite needs a second
/// implementation, or the contract describes one data access layer rather than a behaviour. It is
/// not a deployment option - an audit trail that a restart empties is not one.
/// </remarks>
public sealed class InMemoryAdminAuditStore : IAdminAuditStore
{
    private readonly List<AdminAuditEntry> _entries = [];
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task RecordAsync(AdminAuditEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        lock (_gate)
        {
            _entries.Add(entry);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<AdminAuditEntry>> ReadAsync(
        AuditQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        lock (_gate)
        {
            IEnumerable<AdminAuditEntry> matching = _entries;

            if (query.Realm is { } realm)
            {
                matching = matching.Where(e => e.TargetRealm == realm);
            }

            if (query.TargetSubject is { } subject)
            {
                matching = matching.Where(e => e.TargetSubject == subject);
            }

            if (query.Since is { } since)
            {
                matching = matching.Where(e => e.At >= since);
            }

            // Most recent first, and the index breaks ties. Two entries written in the same tick are
            // ordered by arrival rather than arbitrarily, which is what makes a page of results
            // stable enough to read twice.
            IReadOnlyList<AdminAuditEntry> page =
            [
                .. matching
                    .Select((entry, index) => (entry, index))
                    .OrderByDescending(pair => pair.entry.At)
                    .ThenByDescending(pair => pair.index)
                    .Select(pair => pair.entry)
                    .Take(query.Limit),
            ];

            return Task.FromResult(page);
        }
    }
}
