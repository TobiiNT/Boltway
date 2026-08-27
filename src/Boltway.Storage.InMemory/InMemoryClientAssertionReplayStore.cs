using System.Collections.Concurrent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.Storage.InMemory;

/// <summary>
/// Used client-assertion identifiers, in this process and nowhere else. RFC 7523 §3.
/// </summary>
/// <remarks>
/// <para>
/// <b>Per process, and for this store that is not merely a persistence limit - it is a hole in the
/// property.</b> Every other in-memory store here loses state on restart and shares none of it
/// between replicas, which costs a re-authorization or a re-asked consent. This one costs the thing
/// it exists to prevent: with <i>n</i> replicas behind a load balancer, one assertion can be
/// presented once to each, because each holds its own set and none has seen the others'. A replay
/// guard that admits <i>n</i> uses is a replay guard for <i>n</i> = 1.
/// </para>
/// <para>
/// So this is a development implementation, and <c>AddBoltwayPostgreSqlStores</c> is what a
/// deployment calls. It is written down here rather than only in the README because the failure is
/// silent: nothing logs, nothing errors, and the second acceptance looks exactly like the first.
/// </para>
/// <para>
/// <see cref="ConcurrentDictionary{TKey,TValue}.TryAdd"/> is the whole atomicity argument. It is one
/// operation and it reports whether it was the one that inserted, which is what
/// <see cref="IClientAssertionReplayStore.TryClaimAsync"/> asks for - a read followed by an insert
/// would race precisely when two requests carry the same assertion, which is the case being
/// defended against.
/// </para>
/// </remarks>
public sealed class InMemoryClientAssertionReplayStore : IClientAssertionReplayStore
{
    /// <summary>
    /// The claimed identifiers, keyed by client and <c>jti</c>, valued by the assertion's expiry.
    /// </summary>
    /// <remarks>
    /// <c>StringComparer.Ordinal</c> on both halves of the key. A <c>jti</c> is an opaque string the
    /// client chose and two that differ only in case are two different identifiers - folding them
    /// would refuse an assertion nobody replayed.
    /// </remarks>
    private readonly ConcurrentDictionary<(string ClientId, string JwtId), DateTimeOffset> _claimed =
        new(TupleComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> TryClaimAsync(
        ClientIdentifier clientId,
        string jwtId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        return Task.FromResult(_claimed.TryAdd((clientId.Value, jwtId), expiresAt));
    }

    /// <inheritdoc />
    public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var removed = 0;

        foreach (var entry in _claimed)
        {
            // Compared against the stored expiry rather than against a sweep timestamp, and removed
            // by the key-and-value overload so a row re-claimed between the read and the remove is
            // not deleted out from under the request that claimed it.
            if (entry.Value <= now && _claimed.TryRemove(entry))
            {
                removed++;
            }
        }

        return Task.FromResult(removed);
    }

    /// <summary>How many identifiers are held. For tests and for a health line.</summary>
    public int Count => _claimed.Count;

    private sealed class TupleComparer : IEqualityComparer<(string ClientId, string JwtId)>
    {
        internal static readonly TupleComparer Ordinal = new();

        public bool Equals((string ClientId, string JwtId) x, (string ClientId, string JwtId) y) =>
            string.Equals(x.ClientId, y.ClientId, StringComparison.Ordinal)
            && string.Equals(x.JwtId, y.JwtId, StringComparison.Ordinal);

        public int GetHashCode((string ClientId, string JwtId) obj) =>
            HashCode.Combine(
                StringComparer.Ordinal.GetHashCode(obj.ClientId),
                StringComparer.Ordinal.GetHashCode(obj.JwtId));
    }
}
