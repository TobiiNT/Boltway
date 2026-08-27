using System.Data;
using System.Runtime.CompilerServices;
using Boltway.Storage.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;

namespace Boltway.Storage.PostgreSql;

/// <summary>
/// How PostgreSQL makes a redemption atomic, and what a duplicate key looks like on it.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>LOCK TABLE … IN SHARE ROW EXCLUSIVE MODE</c>, not <c>SERIALIZABLE</c>.</b> PostgreSQL's
/// optimistic levels do satisfy the atomicity
/// <see cref="IRelationalStoreBehavior.BeginWriteAsync"/> asks for, and they satisfy it by raising
/// <c>40001</c> at the loser - an answer <c>RefreshRedemption</c> has no case for, on the endpoint
/// <c>DESIGN.md</c> §1.2 keeps <c>EnableRetryOnFailure</c> off for. A pessimistic lock has no such
/// error: the writer that arrives second waits and then proceeds.
/// </para>
/// <para>
/// <b>Measured, not assumed.</b> The <c>SERIALIZABLE</c> version was written first and run against a
/// live PostgreSQL 16.13. All four concurrency tests in <c>GrantStoreContract</c> failed, each
/// within the first attempts of the 25–200 it makes, in four distinct shapes of the same error:
/// <c>40001: could not serialize access due to concurrent update</c> from the code redemption's
/// conditional <c>UPDATE</c>, the same from the refresh redemption's read, <c>40001: could not
/// serialize access due to concurrent delete</c> where the sweeper races a redemption, and one
/// wrapped in a <c>DbUpdateException</c> from the rotation's <c>SaveChanges</c>. Put on a rate by a
/// harness running the same work 300 times per scenario, first under <c>SERIALIZABLE</c> and then
/// under this implementation with nothing else changed:
/// </para>
/// <list type="table">
/// <item><description>four-way code redemption - <b>294/300</b> rounds raised <c>40001</c>, then <b>0/300</b>;</description></item>
/// <item><description>four-way refresh rotation - <b>300/300</b>, then <b>0/300</b>;</description></item>
/// <item><description>sweep against redemption - <b>168/300</b>, then <b>0/300</b>;</description></item>
/// <item><description>consent widening against withdrawal - <b>251/300</b>, then <b>0/300</b>.</description></item>
/// </list>
/// <para>
/// Total wall-clock time went <i>down</i>, not up: 43.2 s to 36.6 s over the four scenarios on one
/// run and 43.9 s to 35.8 s on a repeat, because a serialization failure is work thrown away and a
/// lock is work queued. The two runs disagreed about which individual scenarios got faster, so the
/// direction of the total is the claim and the per-scenario numbers are not.
/// </para>
/// <para>
/// <b>Why <c>SHARE ROW EXCLUSIVE</c> and not one of the other seven modes.</b> The mode has to do
/// three things, and it is the weakest one that does all three. Measured against this server by
/// holding each mode in one session and probing from another:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Conflict with itself</b>, or two write transactions both proceed and the second write of each
/// races. <c>SHARE</c> fails this: two holders of <c>SHARE</c> can both proceed to a write, which
/// needs <c>ROW EXCLUSIVE</c>, which conflicts with the <i>other</i> holder's <c>SHARE</c> - so
/// neither can finish. That is a deadlock, and it is the same shape as SQLite's deferred
/// <c>BEGIN</c> upgrading to reserved.
/// </item>
/// <item>
/// <b>Conflict with <c>ROW EXCLUSIVE</c></b>, which is what a plain <c>INSERT</c>, <c>UPDATE</c> or
/// <c>DELETE</c> takes. Not every writer of these tables goes through this method:
/// <c>DeleteExpiredAsync</c>, <c>IConsentStore.RevokeAsync</c> and <c>IGrantStore.RevokeAsync</c>
/// are bare statements that never open a write transaction, and <c>StoreAsync</c> is a bare insert.
/// <c>SHARE UPDATE EXCLUSIVE</c> is the mode that fails exactly this test and no other - it
/// conflicts with itself, so it looks right, and it lets a plain <c>DELETE</c> straight through.
/// <b>The shared contract suite passes under it</b>, all 62 tests, which is why the choice rests on
/// a measurement made outside that suite: <c>EfConsentStore.GrantAsync</c> reads a consent row and
/// then updates it, and <c>RevokeAsync</c> deletes it without a transaction, so the delete can land
/// between the two. Run 300 times against this server with two threads doing exactly that,
/// <c>SHARE UPDATE EXCLUSIVE</c> raised <c>DbUpdateConcurrencyException</c> - "expected to affect 1
/// row, actually affected 0" - in 129 rounds. <c>SHARE ROW EXCLUSIVE</c> raised it in none.
/// </item>
/// <item>
/// <b>Not</b> conflict with <c>ACCESS SHARE</c>, which is what an ordinary <c>SELECT</c> takes.
/// <c>FindAsync</c>, <c>IsRevokedAsync</c> and the whole read side must not queue behind a rotation.
/// <c>EXCLUSIVE</c> and <c>ACCESS EXCLUSIVE</c> also satisfy the first two and are strictly stronger
/// - <c>EXCLUSIVE</c> additionally blocks <c>SELECT … FOR UPDATE</c>, <c>ACCESS EXCLUSIVE</c> blocks
/// every reader - and buy nothing this needs.
/// </item>
/// </list>
/// <para>
/// <b>The table list, and why it is every table.</b> One <c>LOCK TABLE</c> statement naming every
/// table in the model, ordered ordinally by name. PostgreSQL takes the locks in the order written,
/// so every write transaction requests the same locks in the same total order and no cycle can form;
/// a transaction that arrives second queues on the first table and waits there. <b>It is every table
/// because this method cannot know which tables its caller will touch</b> - the seam is a
/// <see cref="DbContext"/> and a token, and the six call sites between them touch five different
/// combinations. Locking a guessed subset is how a read-decide-write sequence ends up unprotected on
/// exactly the path nobody thought about, so the breadth here is a consequence of the seam's shape
/// rather than of PostgreSQL.
/// </para>
/// <para>
/// <b>Both halves of that were checked by breaking them.</b> Replacing the ordinal sort with a
/// shuffle, and bypassing the cache so the order differs per call, turned the concurrency tests into
/// <c>40P01: deadlock detected</c> - so the fixed order is doing work rather than being tidy.
/// Removing a single table from the list, <c>consents</c>, put the consent-widening defect above
/// back at 74 rounds in 150. The tables come from the model rather than from a list typed here for
/// the same reason: a table added to <c>AuthDbContext</c> and forgotten in such a list is that
/// second control, in production, with nothing to notice it.
/// </para>
/// <para>
/// <b>Two things it costs, stated here rather than discovered in a deployment.</b> First, writes
/// serialise across aggregates that have nothing to do with each other: a consent grant and a
/// refresh rotation cannot commit at the same time even though they share no row. Second - and this
/// one is a <c>GRANT</c> a deployment has to get right - <b>the database role needs <c>UPDATE</c>,
/// <c>DELETE</c>, <c>TRUNCATE</c> or <c>MAINTAIN</c> on every table in the model</b>, because those
/// are the privileges PostgreSQL accepts for any mode above <c>ROW EXCLUSIVE</c>. Measured: a role
/// holding <c>SELECT, INSERT</c> on <c>external_logins</c> - which is every statement this server
/// ever issues against that table - answers <c>permission denied for table external_logins</c> to
/// the lock, and <c>GRANT UPDATE</c> fixes it. Neither cost is a reason to guess a narrower list;
/// both are reasons a future change to the seam would pay for itself.
/// </para>
/// <para>
/// <b>Read Committed, deliberately, and not merely by omission.</b> With the tables locked there is
/// nothing left for an isolation level to protect, so the one to pick is the one that does not raise
/// the error this design exists to avoid - and the two optimistic levels raise it by design on
/// exactly the read-modify-write these transactions are made of. Naming it rather than taking the
/// default also means a server with <c>default_transaction_isolation</c> set to something else does
/// not quietly get a different contract. It is safe for the same reason the level does not matter:
/// the lock is taken before the first read, and at Read Committed each statement takes its snapshot
/// when it starts, so nothing this transaction reads can be older than the moment it got the lock.
/// Measured, because the opposite would be a silent wrong answer rather than an error: a transaction
/// that queues on the lock and then reads sees the value the transaction it waited for committed -
/// at Read Committed, and, as it happens, at Repeatable Read and Serializable too.
/// </para>
/// </remarks>
public sealed class PostgreSqlRelationalStoreBehavior : IRelationalStoreBehavior
{
    /// <summary>
    /// The lock statement for a model, built once.
    /// </summary>
    /// <remarks>
    /// Keyed on the model rather than cached in a field, because one process may serve several
    /// contexts. A weak table rather than a dictionary so that a model belonging to a disposed
    /// provider - which is the normal shape of a test run, one per database - does not keep it alive.
    /// </remarks>
    private static readonly ConditionalWeakTable<IModel, string> LockStatements = new();

    /// <inheritdoc />
    public async Task<IDbContextTransaction> BeginWriteAsync(DbContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // EF opens the connection here and closes it when the transaction it returns is disposed, so
        // unlike the SQLite implementation there is no unmatched open to undo: this transaction is
        // one EF created rather than one it adopted.
        var transaction = await context.Database
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);

        try
        {
            await context.Database.ExecuteSqlRawAsync(LockStatementFor(context.Model), cancellationToken);

            return transaction;
        }
        catch
        {
            // The lock was not taken, so the caller must not get a transaction that looks like it
            // holds one. Disposing rolls back and releases whatever partial set of locks the
            // statement had acquired before it failed.
            await transaction.DisposeAsync();
            throw;
        }
    }

    /// <inheritdoc />
    public bool IsUniqueViolation(DbUpdateException exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        // The server's SQLSTATE, not the wrapper's type. Answering true for every DbUpdateException
        // would turn a dropped connection or a disk-full into "this row already exists", and the
        // caller's response to that answer is to tell the client its request was a duplicate.
        //
        // 23505 exactly, not the 23xxx class: 23503 is a foreign-key violation and 23514 a check
        // constraint, and neither means the row is already there. Measured against this server: a
        // duplicate primary key reports 23505, a dangling external_logins row reports 23503.
        return exception.InnerException is PostgresException postgres
            && string.Equals(postgres.SqlState, PostgresErrorCodes.UniqueViolation, StringComparison.Ordinal);
    }

    /// <summary>One <c>LOCK TABLE</c> naming every table in <paramref name="model"/>.</summary>
    private static string LockStatementFor(IModel model) =>
        LockStatements.GetValue(model, BuildLockStatement);

    private static string BuildLockStatement(IModel model)
    {
        var tables = model.GetEntityTypes()
            .Select(entity => (Schema: entity.GetSchema(), Table: entity.GetTableName()))
            .Where(name => name.Table is not null)
            .Select(name => name.Schema is null
                ? Quote(name.Table!)
                : Quote(name.Schema) + "." + Quote(name.Table!))

            // Ordinal, and sorted: the order is what makes the lock acquisition total across every
            // caller, and a culture-sensitive sort would not be the same order on every machine.
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        if (tables.Count == 0)
        {
            throw new InvalidOperationException(
                "The model declares no tables, so there is nothing to lock and a write transaction "
                + "opened here would guarantee nothing. This is a wiring mistake, not a data state.");
        }

        return "LOCK TABLE " + string.Join(", ", tables) + " IN SHARE ROW EXCLUSIVE MODE;";
    }

    /// <summary>
    /// A quoted identifier.
    /// </summary>
    /// <remarks>
    /// These names come from the model rather than from a request, so this is not an injection
    /// boundary. It is here because an unquoted identifier is folded to lower case by PostgreSQL,
    /// which would silently miss a table somebody mapped with a capital letter - and a lock statement
    /// that names six of seven tables is the failure this whole class is written to avoid.
    /// </remarks>
    private static string Quote(string identifier) =>
        "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
}
