using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Reset and verification links, in a relational database. S-47.</summary>
internal sealed class EfUserTokenStore(
    IDbContextFactory<AuthDbContext> contextFactory, StorageMetrics metrics) : IUserTokenStore
{
    private readonly StorageMetrics _metrics = metrics;
    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;

    /// <inheritdoc />
    public async Task StoreAsync(UserTokenRecord token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        using var timing = _metrics.Track("UserTokenStore.StoreAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        context.UserTokens.Add(new UserTokenRow
        {
            TokenHash = token.TokenHash.Value.ToArray(),
            Subject = token.Subject.Value,
            Purpose = (int)token.Purpose,
            ExpiresAt = StoredValues.ToTicks(token.ExpiresAt),
            Detail = token.Detail,
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException duplicate)
        {
            // The primary key. Cannot happen with 256 bits of CSPRNG output, and the in-memory store
            // throws here too - two implementations disagreeing on identical input is the thing
            // these contracts exist to prevent.
            throw new InvalidOperationException(
                "A user token with this hash already exists. Tokens are add-only: overwriting one "
                + "would move somebody else's expiry.",
                duplicate);
        }
    }

    /// <inheritdoc />
    public async Task<UserTokenRecord?> RedeemAsync(
        Sha256Hash tokenHash,
        UserTokenPurpose purpose,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserTokenStore.RedeemAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var hash = tokenHash.Value.ToArray();
        var wanted = (int)purpose;

        // Read then conditional-delete, and the DELETE's rows-affected is the authority. The read
        // cannot be trusted on its own: two presentations of one link would both find the row and
        // both act. Only the caller whose delete removed something is holding a live token, which
        // is what makes a reset link single-use under a race rather than only under politeness.
        //
        // The read is scoped to the purpose as well, so a verification link presented at the reset
        // endpoint is not found and - because the delete never runs - is not consumed either.
        var row = await context.UserTokens
            .SingleOrDefaultAsync(t => t.TokenHash == hash && t.Purpose == wanted, cancellationToken);

        if (row is null)
        {
            return null;
        }

        var removed = await context.UserTokens
            .Where(t => t.TokenHash == hash && t.Purpose == wanted)
            .ExecuteDeleteAsync(cancellationToken);

        if (removed == 0)
        {
            return null;
        }

        // Deleted, then reported absent. An expired token has nothing left to answer, so taking it
        // away on the way past is the sweeper's job done early.
        var expiresAt = StoredValues.FromTicks(row.ExpiresAt);

        return expiresAt <= now
            ? null
            : new UserTokenRecord(
                tokenHash, SubjectId.FromStorage(row.Subject), (UserTokenPurpose)row.Purpose, expiresAt, row.Detail);
    }

    /// <inheritdoc />
    public async Task<int> DeleteForSubjectAsync(
        SubjectId subject, UserTokenPurpose purpose, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserTokenStore.DeleteForSubjectAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var subjectValue = subject.Value;
        var wanted = (int)purpose;

        return await context.UserTokens
            .Where(t => t.Subject == subjectValue && t.Purpose == wanted)
            .ExecuteDeleteAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("UserTokenStore.DeleteExpiredAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var cutoff = StoredValues.ToTicks(now);

        return await context.UserTokens
            .Where(t => t.ExpiresAt <= cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
