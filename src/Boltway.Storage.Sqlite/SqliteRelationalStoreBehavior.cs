using System.Data;
using Boltway.Storage.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Boltway.Storage.Sqlite;

/// <summary>
/// How SQLite makes a redemption atomic, and what a duplicate key looks like on it.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>BEGIN IMMEDIATE</c>, not <c>BEGIN</c>.</b> SQLite's default is a deferred transaction: it
/// takes no lock until the first statement, and a shared read lock at that point. A transaction that
/// reads and then writes therefore has to <i>upgrade</i> to the reserved lock, and two transactions
/// that both hold a read lock cannot: each is waiting for the other to let go, and waiting longer
/// cannot help. <c>BEGIN IMMEDIATE</c> takes the reserved lock up front, so the contention happens
/// where waiting resolves it and no transaction ever upgrades.
/// </para>
/// <para>
/// Measured, by changing this one argument to <c>deferred: true</c> and running the store contract:
/// <c>Two_concurrent_redemptions_produce_one_successor_and_both_callers_get_it</c> stopped finishing
/// — its four workers were still blocked when the suite's 30-second join expired — and the other 30
/// tests passed. That the code-store cases survived is not luck: a code redemption's first statement
/// inside the transaction is the conditional <c>UPDATE</c>, so a deferred transaction takes the
/// reserved lock straight away and never upgrades. Only the refresh path reads first, which is
/// exactly the path the whole four-case contract exists for.
/// </para>
/// <para>
/// <b>That is also the answer to "what about serialization failures on <c>/token</c>".</b>
/// <c>RefreshRedemption</c> has four cases and none of them is "retry me", and <c>DESIGN.md</c> §1.2
/// keeps <c>EnableRetryOnFailure</c> off on that endpoint because a retry inside a ten-second budget
/// turns a fast failure into a timeout. An optimistic isolation level would raise exactly the error
/// that has nowhere to go. Pessimistic locking has no such error: a writer that arrives second waits
/// and then proceeds, bounded by the connection's timeout and by the caller's
/// <see cref="CancellationToken"/>. The cost is that SQLite admits one writer at a time — which it
/// does anyway — so this buys correctness at no throughput that was available.
/// </para>
/// </remarks>
public sealed class SqliteRelationalStoreBehavior : IRelationalStoreBehavior
{
    /// <inheritdoc />
    public async Task<IDbContextTransaction> BeginWriteAsync(DbContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Through EF rather than on the raw connection, so EF's open-count stays right and the
        // provider's own connection setup (which is where PRAGMA foreign_keys is applied) runs.
        await context.Database.OpenConnectionAsync(cancellationToken);

        SqliteTransaction? raw = null;

        try
        {
            var connection = (SqliteConnection)context.Database.GetDbConnection();

            // deferred: false is what emits BEGIN IMMEDIATE. There is no EF-level API for it —
            // Database.BeginTransactionAsync always emits a deferred BEGIN — so the transaction is
            // started on the connection and handed to EF.
            try
            {
                raw = connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);
            }
            catch (SqliteException started) when (started.SqliteErrorCode == 1)
            {
                // The undiagnosed one — see the remarks above. Wrapped rather than left bare so that
                // whoever meets it in CI gets the pointer instead of a five-word SQLite string, and
                // so the state at the moment of failure is in the record rather than reconstructed.
                //
                // Deliberately does NOT try to recover. An earlier version of this probe issued a
                // ROLLBACK to prove the handle held somebody else's transaction; it would have
                // proved it, and it would have rolled back their in-flight write to do so. A
                // diagnostic that damages the thing it is diagnosing is not one.
                throw new InvalidOperationException(
                    $"BEGIN IMMEDIATE found this connection already in a transaction (state={connection.State}, "
                    + "thread=" + Environment.CurrentManagedThreadId + "). This is the intermittent defect documented on "
                    + nameof(SqliteRelationalStoreBehavior) + ": one connection in a concurrent batch, "
                    + "cause not established. Postgres is unaffected.",
                    started);
            }

            var adopted = await context.Database.UseTransactionAsync(raw, cancellationToken)
                ?? throw new InvalidOperationException("EF Core declined to adopt the SQLite transaction.");

            return new AdoptedSqliteTransaction(adopted, raw);
        }
        catch
        {
            if (raw is not null)
            {
                await raw.DisposeAsync();
            }

            // Only on this path. Nothing adopted the connection, so the open above is unmatched and
            // this is the call that matches it. On the success path the close is EF's — see
            // AdoptedSqliteTransaction, where closing a second time is the defect.
            await context.Database.CloseConnectionAsync();
            throw;
        }
    }

    /// <inheritdoc />
    public bool IsUniqueViolation(DbUpdateException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        // The provider's code, not the wrapper's type. Answering true for every DbUpdateException
        // would turn a disk-full or a closed connection into "this row already exists", and the
        // caller's response to that answer is to tell the client its request was a duplicate.
        return exception.InnerException is SqliteException sqlite
            && sqlite.SqliteErrorCode == SqliteConstraint
            && sqlite.SqliteExtendedErrorCode is SqliteConstraintPrimaryKey or SqliteConstraintUnique;
    }

    /// <summary>SQLITE_CONSTRAINT.</summary>
    private const int SqliteConstraint = 19;

    /// <summary>SQLITE_CONSTRAINT_PRIMARYKEY.</summary>
    private const int SqliteConstraintPrimaryKey = 1555;

    /// <summary>SQLITE_CONSTRAINT_UNIQUE.</summary>
    private const int SqliteConstraintUnique = 2067;

    /// <summary>
    /// The EF transaction wrapper, plus the two things EF does not own.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>UseTransaction</c> adopts a transaction it did not create. <c>Commit</c> and
    /// <c>Rollback</c> on EF's wrapper still end it, but <b>disposing</b> that wrapper does not,
    /// because it does not own it — so on any path that returns without committing, something here
    /// has to, and an unfinished SQLite transaction holds the write lock with no exception attached
    /// to say so.
    /// </para>
    /// <para>
    /// <b>Two things about disposal here were found by running the contract, not by reading.</b>
    /// </para>
    /// <para>
    /// First, <b>the connection is closed once, by EF, and not again here.</b> An earlier draft
    /// opened the connection through <c>Database.OpenConnectionAsync</c> and closed it through
    /// <c>Database.CloseConnectionAsync</c> on dispose, which reads like a matched pair and is not
    /// one: EF closes the connection itself when it clears the transaction, so the explicit close was
    /// a second one, and the same pooled connection reached two callers at once.
    /// </para>
    /// <para>
    /// Measured. With the explicit close,
    /// <c>Redeeming_many_times_in_parallel_still_succeeds_exactly_once</c> failed in <b>three of the
    /// eight runs</b> it was exercised in — twice with
    /// <c>SQLite Error 1: 'cannot start a transaction within a transaction'</c>, which is what
    /// <c>BEGIN IMMEDIATE</c> says on a connection that is already in one, and once with
    /// <c>SQLite Error 1: 'no more rows available'</c>, which is what a reader says when someone else
    /// is using its connection. Without it, 12 consecutive runs of the three concurrency tests
    /// passed. Nothing about the store logic changed between those two numbers: the store was already
    /// correct, on a connection it did not exclusively hold.
    /// </para>
    /// <para>
    /// <b>Twelve runs was not enough, and the paragraph above should be read as a fix that removed
    /// one route rather than the route.</b> Re-measured later: with the whole <c>auth/</c> solution
    /// running in parallel, <c>Redeeming_many_times_in_parallel_still_succeeds_exactly_once</c>
    /// failed in <b>three of four</b> Release runs, and once in three Debug runs of that test alone
    /// — with the same <c>SQLite Error 1: 'cannot start a transaction within a transaction'</c>.
    /// Run alone in Release it passed three times out of three, taking about 20 seconds each; the
    /// failing runs end in about 4. So it is load-sensitive, it is frequent rather than rare, and
    /// it is still here.
    /// </para>
    /// <para>
    /// <b>Where it is not — and the two entries here were both recorded as ruled out on probes that
    /// measured nothing.</b> Neither is ruled out. They are kept, corrected, rather than deleted,
    /// because a hypothesis wrongly marked dead is worse than one never tried: the next person
    /// skips it.
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// <b>A pooled handle returned with a live transaction on it. NOT ruled out — the opposite is
    /// now measured.</b> The original probe opened a connection, took a transaction through
    /// <c>BeginTransaction</c>, closed without ending it, reopened, and saw a clean handle. That
    /// cannot separate "the pool cleaned it" from "<c>Close()</c> rolled it back", because
    /// <c>SqliteConnection.Close</c> disposes the managed transaction and disposing it emits
    /// <c>ROLLBACK</c> — so the handle was clean before it ever reached the pool. The error being
    /// chased means the <i>native</i> handle is in a transaction while the managed connection
    /// believes it is not, and only a <c>BEGIN IMMEDIATE</c> issued as raw SQL produces that.
    /// Re-probed with both arms: managed <c>BEGIN</c> then close then reopen is <b>clean</b>
    /// (the original result, reproduced as the control); raw <c>BEGIN IMMEDIATE</c> then close then
    /// reopen is <b>poisoned</b>, and the next <c>BEGIN IMMEDIATE</c> fails with this defect's
    /// message character for character. <b>The pool does not clean the handle.</b> So a connection
    /// that goes back inside a transaction is a live route to this error, and finding what puts one
    /// there is the open question rather than a dead end.
    /// </description></item>
    /// <item><description>
    /// <b>A double close putting one handle in the pool twice. NOT ruled out.</b> Recorded as ruled
    /// out on a probe that closed one <c>SqliteConnection</c> twice and then watched two fresh
    /// connections contend normally — but <c>Close()</c> is idempotent on the managed object, so
    /// that probe never put a handle in the pool twice and tested nothing.
    /// </description></item>
    /// </list>
    /// <para>
    /// <b>What is ruled out: any single-threaded exit path from this method.</b> A probe reproducing
    /// this method's exact shape — <c>OpenConnectionAsync</c>, raw <c>BeginTransaction</c> with
    /// <c>deferred: false</c>, <c>UseTransactionAsync</c>, and the wrapper's dispose order — was run
    /// through five endings: commit, an early return with no commit, a <c>SaveChanges</c> that
    /// throws, an explicit rollback, and a cancelled token. After each, the context was disposed and
    /// a fresh connection drawn from the pool: <b>clean five times out of five</b>, and the
    /// connection was <c>Open</c> at dispose in every one, so <c>SqliteTransaction.Dispose</c>'s
    /// <c>State == Open</c> guard — which skips the <c>ROLLBACK</c> in silence when it does not hold
    /// — never fired. Whatever poisons a handle needs more than one thread to do it, which is
    /// consistent with the test only ever failing under concurrency.
    /// </para>
    /// <para>
    /// <b>And this method hands the poisoned handle straight back.</b> When <c>BEGIN IMMEDIATE</c>
    /// fails with error 1, <c>raw</c> is null, so the catch below only closes the connection — which
    /// returns a handle that is still inside a transaction to the pool for the next caller. That is
    /// left as it is, deliberately: evicting it means <c>ClearPool</c>, which discards every idle
    /// handle other callers were about to use, and there is no measurement yet that says the cascade
    /// happens. One worker of sixteen throwing is evidence that it mostly does not.
    /// </para>
    /// <para>
    /// <b>One worker of sixteen throws, not all of them.</b> The contract harness used to report the
    /// first failure and drop the rest, so this was not visible; it now reports the count. That
    /// number is the strongest evidence available: fifteen callers take the write lock in turn and
    /// proceed, and one meets a connection that is already inside a transaction. It is a single
    /// poisoned connection, not a lock everybody lost — which is consistent with a shared handle and
    /// inconsistent with contention.
    /// </para>
    /// <para>
    /// Also not it: each store operation takes its own <c>DbContext</c> from
    /// <c>IDbContextFactory</c>, so no context is shared across threads.
    /// </para>
    /// <para>
    /// And no reliable trigger was found. Saturating all four cores while running this suite alone
    /// produced three passes out of three, so it is not simply load — the failing observations came
    /// from the whole solution running, and once from this test alone in Debug. Any A/B on run
    /// counts needs far more runs than were taken here: an earlier comparison that looked like
    /// evidence (<c>Pooling=False</c>, four clean runs) was worthless, because the control passed
    /// four times too.
    /// </para>
    /// <para>
    /// So: real, reproducible about a third of the time, and <b>undiagnosed</b>. It matters for a
    /// deployment on <c>SQLITE_PATH</c>, which is offered for a single instance — and a single
    /// instance still serves concurrent requests.
    /// </para>
    /// <para>
    /// It does not affect a Postgres deployment, which is what the shipped workflow deploys.
    /// </para>
    /// <para>
    /// Second, <b>the SQLite transaction ends before EF's wrapper.</b> Disposing the wrapper first
    /// would mean ending the adopted transaction on a connection EF had already closed. This one is
    /// reasoning rather than a measurement: no test was seen to fail because of it, and the order is
    /// this way round because it is the order that does not depend on being lucky.
    /// </para>
    /// </remarks>
    private sealed class AdoptedSqliteTransaction(IDbContextTransaction inner, SqliteTransaction raw)
        : IDbContextTransaction
    {
        public Guid TransactionId => inner.TransactionId;

        public void Commit() => inner.Commit();

        public Task CommitAsync(CancellationToken cancellationToken = default) =>
            inner.CommitAsync(cancellationToken);

        public void Rollback() => inner.Rollback();

        public Task RollbackAsync(CancellationToken cancellationToken = default) =>
            inner.RollbackAsync(cancellationToken);

        public void Dispose()
        {
            // Rolls back if Commit was not called, and is a no-op if it was. That is what makes an
            // early return from a store method — NotFound, ReuseDetected, a second RevokeFamily —
            // leave nothing behind.
            raw.Dispose();
            inner.Dispose();
        }

        public async ValueTask DisposeAsync()
        {
            await raw.DisposeAsync();
            await inner.DisposeAsync();
        }
    }
}
