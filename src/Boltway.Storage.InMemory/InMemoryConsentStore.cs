using System.Collections.Concurrent;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.Storage.InMemory;

/// <summary>
/// Consent records in memory.
/// </summary>
/// <remarks>
/// <para>
/// Ships because <see cref="IConsentStore"/> is required, had no implementation anywhere in
/// <c>src/</c>, and the only one in the repository was a test double that got the contract's central
/// rule backwards. That double did <c>_records[key] = record</c> - replace, not widen - which is
/// precisely what <see cref="IConsentStore.GrantAsync"/>'s remarks warn against, so the most likely
/// shape of a customer's first draft was the one the repository itself had written down.
/// </para>
/// <para>
/// <b>Widening is the whole contract.</b> C-24: a client that comes back asking for one more scope
/// must end up with the union. Replacing silently revokes authority the user granted earlier and
/// never withdrew.
/// </para>
/// <para>
/// In memory, so consent does not survive a restart and every user is asked again after a deploy.
/// That is a real cost and it is why this is opt-in rather than a default - see
/// <c>AddBoltwayInMemoryStores</c>, which registers it alongside the other in-memory stores so
/// a deployment says "in memory" once, deliberately, rather than inheriting it.
/// </para>
/// </remarks>
public sealed class InMemoryConsentStore : IConsentStore
{
    private readonly ConcurrentDictionary<(string Subject, string ClientId), ConsentRecord> _records = new();

    /// <inheritdoc />
    public Task<ConsentRecord?> FindAsync(
        SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult(_records.GetValueOrDefault((subject.Value, clientId.Value)));

    /// <inheritdoc />
    public Task<ConsentRecord> GrantAsync(
        SubjectId subject,
        ClientIdentifier clientId,
        ScopeSet scope,
        IReadOnlyList<string> resources,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resources);

        // AddOrUpdate rather than read-then-write: two authorizations for the same user and client
        // can be in flight at once - a browser tab and a native app, or a user who double-submits -
        // and a lost update here silently drops a scope the user approved.
        var record = _records.AddOrUpdate(
            (subject.Value, clientId.Value),
            _ => new ConsentRecord(subject, clientId, scope, [.. resources], now),
            (_, existing) => new ConsentRecord(
                subject,
                clientId,
                Union(existing.Scope, scope),
                [.. existing.Resources.Union(resources, StringComparer.Ordinal)],
                now));

        return Task.FromResult(record);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ConsentRecord>> ListAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        // Keyed on (subject, client), so this is a scan of every subject's records rather than a
        // lookup. Correct, and the reason it is acceptable rather than merely tolerable: the store
        // exists for tests and single-process development, where the dictionary holds the accounts
        // one machine signed in. A second index keyed on subject alone would be a second copy of the
        // membership, kept in step by hand, for a store whose whole point is that it is the simple
        // one to read.
        IReadOnlyList<ConsentRecord> records =
        [
            .. _records.Values
                .Where(r => r.Subject == subject)
                .OrderByDescending(r => r.GrantedAt),
        ];

        return Task.FromResult(records);
    }

    /// <inheritdoc />
    public Task<bool> RevokeAsync(
        SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult(_records.TryRemove((subject.Value, clientId.Value), out _));

    /// <summary>Every scope from either set, once.</summary>
    /// <remarks>
    /// Through <see cref="ScopeSet.FromStorage"/> rather than by constructing a set directly,
    /// because that is the one entry point that re-applies the name rules to a value coming back
    /// from a store - and a widened record is exactly a value that came back from a store.
    /// Ordinal throughout: scope names are case-sensitive (OAuth 2.1 §1.4.1), so <c>Read</c> and
    /// <c>read</c> are two scopes and merging them would grant one the user never approved.
    /// </remarks>
    private static ScopeSet Union(ScopeSet existing, ScopeSet added) =>
        ScopeSet.FromStorage(string.Join(' ', existing.Values.Union(added.Values, StringComparer.Ordinal)));
}
