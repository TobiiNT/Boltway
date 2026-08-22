using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Boltway.Storage.EntityFrameworkCore;

/// <summary>
/// The two things a relational provider does differently, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no default implementation, deliberately.</b> A default would have to guess, and the
/// plausible guess — <c>BeginTransactionAsync()</c> with the provider's default isolation, plus "any
/// <see cref="DbUpdateException"/> is a unique violation" — is wrong in a way that compiles, passes
/// a single-threaded test, and forks a refresh-token family under load. Requiring the provider
/// package to supply one makes "nobody wired the provider up" a startup failure rather than a race.
/// </para>
/// </remarks>
public interface IRelationalStoreBehavior
{
    /// <summary>
    /// Open the transaction a read-decide-write sequence runs inside.
    /// </summary>
    /// <param name="context">The context. Its connection is opened if it was not already.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// The transaction. Disposing it without committing must roll back, and must also release
    /// anything the implementation opened in order to create it.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>The requirement: between this call and the commit, no other writer may change the rows
    /// this one reads.</b> <c>IRefreshTokenStore.RedeemAsync</c> is why. It reads the presented row,
    /// checks family revocation and expiry, reads a <i>second</i> row — the successor — checks that
    /// row's own consumption and expiry, and only then inserts and updates. No conditional
    /// <c>UPDATE … WHERE hash = @h AND consumed_at IS NULL</c> expresses that, so the atomicity has
    /// to come from here.
    /// </para>
    /// <para>
    /// <b>An implementation that satisfies this by taking an optimistic isolation level owes the
    /// caller an answer it cannot give.</b> <c>RefreshRedemption</c> has four cases and none of them
    /// is "retry me", and <c>DESIGN.md</c> §1.2 configures <c>EnableRetryOnFailure</c> off on
    /// <c>/token</c> because a retry inside a ten-second budget converts a fast failure into a
    /// timeout. So a serialization failure raised here has nowhere to go but a 500, on the endpoint
    /// with the tightest budget. <b>Take the lock instead of gambling on one:</b> SQLite's
    /// implementation opens <c>BEGIN IMMEDIATE</c>, which excludes every other writer for the whole
    /// transaction and turns contention into bounded waiting rather than a retryable error.
    /// PostgreSQL's is the same idea — <c>LOCK TABLE … IN SHARE ROW EXCLUSIVE MODE</c> naming every
    /// table in the model, one statement at the top of the transaction so the acquisition order is
    /// total and no cycle can form.
    /// </para>
    /// <para>
    /// <b>Both are measured, and the optimistic alternative is measured too.</b>
    /// <c>PostgreSqlRelationalStoreBehavior</c> was written twice: first as
    /// <c>BeginTransactionAsync(IsolationLevel.Serializable)</c> and nothing else, which is the
    /// plausible guess this interface exists to head off. Against a live PostgreSQL 16.13 that
    /// version failed all four concurrency tests in <c>GrantStoreContract</c> with <c>40001</c>, at
    /// rates from 168 to 300 rounds out of 300 depending on the scenario; the locking version raised
    /// none in the same harness. The numbers, the rejected lock modes and what each control broke
    /// are recorded on that class.
    /// </para>
    /// </remarks>
    Task<IDbContextTransaction> BeginWriteAsync(DbContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Whether this exception is a primary-key or unique-index violation.
    /// </summary>
    /// <param name="exception">The exception <c>SaveChanges</c> threw.</param>
    /// <returns>Whether it was a uniqueness violation.</returns>
    /// <remarks>
    /// The store contract makes every insert add-only and specifies
    /// <see cref="InvalidOperationException"/> for a duplicate, so each provider has to recognise its
    /// own code — 19 on SQLite, with extended codes 1555 and 2067; 23505 on PostgreSQL. Answering
    /// <see langword="true"/> for any <see cref="DbUpdateException"/> would report a connection
    /// failure as a duplicate key, which is a wrong answer a caller acts on.
    /// </remarks>
    bool IsUniqueViolation(DbUpdateException exception);
}
