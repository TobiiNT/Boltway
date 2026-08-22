using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>Authorization codes, in a relational database.</summary>
internal sealed class EfAuthorizationCodeStore(
    IDbContextFactory<AuthDbContext> contextFactory, IRelationalStoreBehavior behavior, StorageMetrics metrics) : IAuthorizationCodeStore
{
    private readonly StorageMetrics _metrics = metrics;

    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly IRelationalStoreBehavior _behavior = behavior;

    /// <inheritdoc />
    public async Task StoreAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("AuthorizationCodeStore.StoreAsync");

        ArgumentNullException.ThrowIfNull(record);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        context.AuthorizationCodes.Add(new AuthorizationCodeRow
        {
            CodeHash = StoredValues.ToBytes(record.CodeHash),
            GrantId = record.GrantId,
            ClientId = record.ClientId.Value,
            ClientIdKind = (int)record.ClientId.Kind,
            RedirectUriUsed = record.RedirectUriUsed,
            CodeChallenge = record.CodeChallenge,
            ChallengeMethod = (int)record.ChallengeMethod,
            PkceWasRequested = record.PkceWasRequested,
            Scope = record.Scope.ToWireString(),
            Resources = StoredValues.EncodeResources(record.Resources),
            Nonce = record.Nonce,
            AuthTime = StoredValues.ToTicks(record.AuthTime),
            IssuedAt = StoredValues.ToTicks(record.IssuedAt),
            ExpiresAt = StoredValues.ToTicks(record.ExpiresAt),
            RedeemedAt = StoredValues.ToTicks(record.RedeemedAt),
        });

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            // Add-only. An upsert would clear RedeemedAt and make a spent code redeemable again,
            // resetting N-07's replay protection.
            throw new InvalidOperationException(
                "An authorization code with this hash already exists. Codes are add-only: "
                + "overwriting one would clear its redemption and reset replay protection.",
                ex);
        }
    }

    /// <inheritdoc />
    public async Task<AuthorizationCodeRecord?> FindAsync(Sha256Hash codeHash, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("AuthorizationCodeStore.FindAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var hash = StoredValues.ToBytes(codeHash);
        var row = await context.AuthorizationCodes
            .SingleOrDefaultAsync(c => c.CodeHash == hash, cancellationToken);

        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public async Task<CodeRedemption> RedeemAsync(
        Sha256Hash codeHash, DateTimeOffset now, TimeSpan graceWindow, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("AuthorizationCodeStore.RedeemAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // Inside the provider's write transaction, for one reason that a conditional UPDATE alone
        // does not cover: when the UPDATE affects no rows this call has to read the row back to tell
        // a retry from a replay, and between the two statements the sweeper could remove it. Then a
        // second presentation inside its grace window would answer ReplayedOutsideGrace, which is
        // the answer a caller revokes the grant on.
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var hash = StoredValues.ToBytes(codeHash);

        // The answer comes from rows-affected, not from a preceding read. Two simultaneous
        // redemptions of one code must produce exactly one Redeemed whatever the interleaving, and
        // "read then decide then write" cannot promise that on its own.
        //
        // Expiry is deliberately NOT in this predicate. Folding it in would send an expired code
        // down the revoke path, which is the denial of service N-07 exists to prevent.
        var redeemedAt = StoredValues.ToTicks(now);
        var redeemed = await context.AuthorizationCodes
            .Where(c => c.CodeHash == hash && c.RedeemedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.RedeemedAt, redeemedAt), cancellationToken);

        if (redeemed == 1)
        {
            await transaction.CommitAsync(cancellationToken);
            return new CodeRedemption.Redeemed();
        }

        var existing = await context.AuthorizationCodes
            .Where(c => c.CodeHash == hash)
            .Select(c => c.RedeemedAt)
            .SingleOrDefaultAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        if (existing is not { } redeemedTicks)
        {
            // No row, or a row with no redemption to date. The second reading would need a code to
            // have been inserted between the UPDATE and this read, which the write transaction is
            // there to prevent; either way this presentation is not a retry of a redemption the
            // store can account for, and ReplayedOutsideGrace is the answer for an unknown hash.
            return new CodeRedemption.ReplayedOutsideGrace();
        }

        // Clamped below as well as above. `now` is the caller's and this server runs as several
        // instances, so a fast clock stamping a redemption in the future would otherwise stretch the
        // window arbitrarily.
        var elapsed = now - StoredValues.FromTicks(redeemedTicks);
        var within = elapsed >= -GraceWindows.MaxClockSkew && elapsed <= graceWindow;

        return within ? new CodeRedemption.ReplayedWithinGrace() : new CodeRedemption.ReplayedOutsideGrace();
    }

    /// <inheritdoc />
    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("AuthorizationCodeStore.DeleteExpiredAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var expiry = StoredValues.ToTicks(now);

        // A redeemed row outlives its expiry by RedeemedRetention, because the retry window it was
        // written for outlives it too: a code lives about a minute and is redeemed whenever consent
        // finishes, so the window routinely starts in the last seconds of the code's life. Deleting
        // on expiry alone undoes the redemption one call later — the retry then presents a hash the
        // store has no memory of, and an unknown hash is ReplayedOutsideGrace, the answer a caller
        // revokes on. The constant is read from GraceWindows rather than retyped here.
        var retentionCutoff = StoredValues.ToTicks(now - GraceWindows.RedeemedRetention);

        // One statement, so there is no window between choosing rows and deleting them, and the
        // count returned is the count the database removed.
        return await context.AuthorizationCodes
            .Where(c => c.ExpiresAt <= expiry && (c.RedeemedAt == null || c.RedeemedAt <= retentionCutoff))
            .ExecuteDeleteAsync(cancellationToken);
    }

    private static AuthorizationCodeRecord ToRecord(AuthorizationCodeRow row) => new(
        StoredValues.ToHash(row.CodeHash),
        row.GrantId,
        StoredValues.ToClientIdentifier(row.ClientId, row.ClientIdKind),
        row.RedirectUriUsed,
        row.CodeChallenge,
        (CodeChallengeMethod)row.ChallengeMethod,
        row.PkceWasRequested,
        ScopeSet.FromStorage(row.Scope),
        StoredValues.DecodeResources(row.Resources),
        row.Nonce,
        StoredValues.FromTicks(row.AuthTime),
        StoredValues.FromTicks(row.IssuedAt),
        StoredValues.FromTicks(row.ExpiresAt),
        StoredValues.FromTicks(row.RedeemedAt));
}
