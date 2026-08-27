using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.Storage.Testing;

/// <summary>
/// <see cref="IAdminAuditStore"/>, run against every implementation.
/// </summary>
/// <remarks>
/// The behaviour worth pinning is not "it stores things" but the order it reads back in and the
/// fields it keeps. An audit log is read once, during an incident, by somebody who cannot re-run the
/// query against a different implementation to see whether it agrees.
/// </remarks>
public abstract class AdminAuditStoreContract
{
    /// <summary>The store under test.</summary>
    protected abstract IAdminAuditStore NewAuditStore();

    private static readonly DateTimeOffset Start = new(2026, 8, 10, 9, 0, 0, TimeSpan.Zero);

    private static AdminAuditEntry Entry(
        DateTimeOffset at,
        string action = "user.role",
        string realm = "default",
        string? target = "01J8XKQ7M3N4P5R6S7T8V9W0XY",
        AdminAuditOutcome outcome = AdminAuditOutcome.Succeeded) =>
        new(
            at,
            "cli",
            ActorSubject: null,
            ActorClient: null,
            action,
            RealmId.FromStorage(realm),
            target is null ? null : SubjectId.FromStorage(target),
            "ada",
            outcome,
            CorrelationId: "cid-1")
        {
            Detail = "role=founder",
        };

    /// <summary>
    /// One recorded entry reads back with its time, actor, action, realm, handle, outcome,
    /// correlation id and detail.
    /// </summary>
    [Fact]
    public async Task Every_field_survives_a_round_trip()
    {
        var store = NewAuditStore();

        await store.RecordAsync(Entry(Start), CancellationToken.None);

        var read = Assert.Single(await store.ReadAsync(new AuditQuery(), CancellationToken.None));

        Assert.Equal(Start, read.At);
        Assert.Equal("cli", read.ActorKind);
        Assert.Null(read.ActorSubject);
        Assert.Equal("user.role", read.Action);
        Assert.Equal(RealmId.Default, read.TargetRealm);
        Assert.Equal("ada", read.TargetHandle);
        Assert.Equal(AdminAuditOutcome.Succeeded, read.Outcome);
        Assert.Equal("cid-1", read.CorrelationId);
        Assert.Equal("role=founder", read.Detail);
    }

    /// <summary>
    /// Most recent first, with insertion order breaking a tie.
    /// </summary>
    /// <remarks>
    /// Two actions in the same tick are a real sequence - a script does several in a row - and an
    /// order that depended on which index the provider walked would make the same page read
    /// differently on two deployments of the same product.
    /// </remarks>
    [Fact]
    public async Task Entries_come_back_newest_first_and_ties_keep_their_order()
    {
        var store = NewAuditStore();

        await store.RecordAsync(Entry(Start, action: "first"), CancellationToken.None);
        await store.RecordAsync(Entry(Start, action: "second"), CancellationToken.None);
        await store.RecordAsync(Entry(Start.AddMinutes(1), action: "later"), CancellationToken.None);

        var read = await store.ReadAsync(new AuditQuery(), CancellationToken.None);

        Assert.Equal(["later", "second", "first"], read.Select(e => e.Action));
    }

    /// <summary>
    /// Each of the three filters - realm, target subject and <c>Since</c> - narrows on its own.
    /// </summary>
    /// <remarks>
    /// One log in which a different entry answers each filter, so a store that ignores one of the
    /// three hands back rows the caller did not ask for rather than failing where somebody sees it.
    /// </remarks>
    [Fact]
    public async Task A_query_can_narrow_by_realm_subject_and_time()
    {
        var store = NewAuditStore();
        var other = "01J8XKQ7M3N4P5R6S7T8V9W0ZZ";

        await store.RecordAsync(Entry(Start, action: "acme", realm: "acme"), CancellationToken.None);
        await store.RecordAsync(Entry(Start, action: "mine"), CancellationToken.None);
        await store.RecordAsync(Entry(Start, action: "theirs", target: other), CancellationToken.None);
        await store.RecordAsync(Entry(Start.AddHours(2), action: "recent"), CancellationToken.None);

        var byRealm = await store.ReadAsync(
            new AuditQuery(Realm: RealmId.FromStorage("acme")), CancellationToken.None);

        var bySubject = await store.ReadAsync(
            new AuditQuery(TargetSubject: SubjectId.FromStorage(other)), CancellationToken.None);

        var since = await store.ReadAsync(
            new AuditQuery(Since: Start.AddHours(1)), CancellationToken.None);

        Assert.Equal(["acme"], byRealm.Select(e => e.Action));
        Assert.Equal(["theirs"], bySubject.Select(e => e.Action));
        Assert.Equal(["recent"], since.Select(e => e.Action));
    }

    /// <summary>
    /// The limit caps the read, and the entries it keeps are the newest ones.
    /// </summary>
    /// <remarks>
    /// The cap applies after the ordering rather than before it. A store that truncated first would
    /// honour the count and answer an incident with the two oldest lines it holds.
    /// </remarks>
    [Fact]
    public async Task The_limit_is_honoured()
    {
        var store = NewAuditStore();

        for (var i = 0; i < 5; i++)
        {
            await store.RecordAsync(Entry(Start.AddMinutes(i), action: "a" + i), CancellationToken.None);
        }

        var read = await store.ReadAsync(new AuditQuery(Limit: 2), CancellationToken.None);

        Assert.Equal(["a4", "a3"], read.Select(e => e.Action));
    }

    /// <summary>
    /// An action against a handle nobody has is stored, with no target subject.
    /// </summary>
    /// <remarks>
    /// The half of an audit trail that shows somebody trying. A log holding only successes cannot
    /// tell "nobody tried" from "everybody was stopped", and the second is the one worth waking up
    /// for.
    /// </remarks>
    [Fact]
    public async Task A_refused_action_against_no_account_is_recorded()
    {
        var store = NewAuditStore();

        await store.RecordAsync(
            Entry(Start, target: null, outcome: AdminAuditOutcome.Refused), CancellationToken.None);

        var read = Assert.Single(await store.ReadAsync(new AuditQuery(), CancellationToken.None));

        Assert.Null(read.TargetSubject);
        Assert.Equal("ada", read.TargetHandle);
        Assert.Equal(AdminAuditOutcome.Refused, read.Outcome);
    }

    /// <summary>
    /// The interface offers no way to change or remove an entry.
    /// </summary>
    /// <remarks>
    /// Append-only is the whole property, and the way to keep it is that the methods do not exist -
    /// not a guard somebody can relax, and not a convention a reviewer has to notice. A log an
    /// administrator can edit proves nothing about administrators.
    /// </remarks>
    [Fact]
    public void The_log_offers_no_way_to_change_the_past()
    {
        var names = typeof(IAdminAuditStore).GetMethods().Select(m => m.Name).ToList();

        Assert.Contains("RecordAsync", names);

        Assert.DoesNotContain(
            names,
            name => name.Contains("Update", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Delete", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Remove", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Purge", StringComparison.OrdinalIgnoreCase));
    }
}
