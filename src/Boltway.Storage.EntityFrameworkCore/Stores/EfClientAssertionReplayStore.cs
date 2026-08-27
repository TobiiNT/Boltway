using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Used client-assertion identifiers, in a relational database. RFC 7523 §3.</summary>
/// <remarks>
/// <b>The unique violation is the answer, not a failure to recover from.</b> This inserts and lets
/// the primary key decide: a caught <see cref="DbUpdateException"/> means the row was already there,
/// which is a replay. Written as a read followed by an insert it would be correct in every test and
/// wrong under exactly the concurrency a replay attempt produces - two requests carrying one
/// assertion, both finding it absent, both proceeding. The other stores here reach for the same
/// shape wherever atomicity <i>is</i> the requirement; see <c>IAuthorizationCodeStore.RedeemAsync</c>.
/// </remarks>
internal sealed class EfClientAssertionReplayStore(
    IDbContextFactory<AuthDbContext> contextFactory, StorageMetrics metrics) : IClientAssertionReplayStore
{
    private readonly StorageMetrics _metrics = metrics;
    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;

    /// <inheritdoc />
    public async Task<bool> TryClaimAsync(
        ClientIdentifier clientId,
        string jwtId,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        using var timing = _metrics.Track("ClientAssertionReplayStore.TryClaimAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        context.ClientAssertions.Add(new ClientAssertionRow
        {
            ClientId = clientId.Value,
            JwtId = jwtId,
            ExpiresAt = StoredValues.ToTicks(expiresAt),
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);

            return true;
        }
        catch (DbUpdateException)
        {
            // A duplicate key, which is the whole point: this assertion has been presented before.
            //
            // Deliberately not narrowed to a provider-specific SQLSTATE. The two providers behind
            // this store report a unique violation differently, and the only other DbUpdateException
            // reachable from a single add of a row with no foreign keys and no concurrency token is
            // a constraint this schema does not have. Narrowing would mean a provider whose code we
            // did not enumerate reports a replay as a 500 - failing closed on the request, and open
            // on the property, because the client simply retries.
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("ClientAssertionReplayStore.DeleteExpiredAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        return await context.ClientAssertions
            .Where(row => row.ExpiresAt <= StoredValues.ToTicks(now))
            .ExecuteDeleteAsync(cancellationToken);
    }
}
