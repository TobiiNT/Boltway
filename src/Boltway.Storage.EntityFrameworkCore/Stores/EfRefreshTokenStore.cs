using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.EntityFrameworkCore.Entities;
using Microsoft.EntityFrameworkCore;

namespace Boltway.Storage.EntityFrameworkCore.Stores;

/// <summary>
/// Refresh tokens, in a relational database, including the rotation decision.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="RedeemAsync"/> is not a conditional UPDATE, and writing it as one is the defect
/// this class exists to avoid.</b> The obvious shape -
/// <c>UPDATE refresh_tokens SET consumed_at = @now WHERE token_hash = @h AND consumed_at IS NULL</c>
/// - answers "did I win", which is enough for an authorization code and not enough here. When it
/// affects no rows, the store still has to decide between a benign retry and a stolen token, and
/// that decision reads a <i>second</i> row: the successor, whose own <c>consumed_at</c> and
/// <c>expires_at</c> are what stop an attacker walking the chain to the live head. Two dependent
/// reads and two writes have to be one atomic region, which is what
/// <see cref="IRelationalStoreBehavior.BeginWriteAsync"/> supplies.
/// </para>
/// </remarks>
internal sealed class EfRefreshTokenStore(
    IDbContextFactory<AuthDbContext> contextFactory, IRelationalStoreBehavior behavior, StorageMetrics metrics) : IRefreshTokenStore
{
    private readonly StorageMetrics _metrics = metrics;

    private readonly IDbContextFactory<AuthDbContext> _contextFactory = contextFactory;
    private readonly IRelationalStoreBehavior _behavior = behavior;

    /// <inheritdoc />
    public async Task<RefreshTokenRecord?> FindAsync(Sha256Hash tokenHash, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RefreshTokenStore.FindAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        var hash = StoredValues.ToBytes(tokenHash);
        var row = await context.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash, cancellationToken);

        return row is null ? null : ToRecord(row);
    }

    /// <inheritdoc />
    public async Task StoreAsync(RefreshTokenRecord record, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RefreshTokenStore.StoreAsync");

        ArgumentNullException.ThrowIfNull(record);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        context.RefreshTokens.Add(ToRow(record));

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            // Add-only. Re-storing a consumed token would erase its ConsumedAt and let the parent
            // rotate a second time: two live successors with one predecessor, which is the family
            // fork this design exists to prevent.
            throw new InvalidOperationException(
                "A refresh token with this hash already exists. Tokens are add-only: "
                + "overwriting one would clear its consumption and allow the family to fork.",
                ex);
        }
    }

    /// <inheritdoc />
    public async Task<RefreshRedemption> RedeemAsync(
        Sha256Hash presented,
        RefreshTokenSeed successor,
        DateTimeOffset now,
        TimeSpan graceWindow,
        CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RefreshTokenStore.RedeemAsync");

        ArgumentNullException.ThrowIfNull(successor);

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        var presentedHash = StoredValues.ToBytes(presented);

        // Tracked, unlike every other read in these stores: the rotation updates this row, and the
        // update has to be part of the same SaveChanges as the successor's insert so that neither
        // can land without the other.
        var row = await context.RefreshTokens
            .AsTracking()
            .SingleOrDefaultAsync(t => t.TokenHash == presentedHash, cancellationToken);

        if (row is null)
        {
            return new RefreshRedemption.NotFound();
        }

        var nowTicks = StoredValues.ToTicks(now);

        // Family revocation is one row in its own table rather than a flag on each token. Rows are
        // never deleted on revocation: replaying a consumed token from a revoked family must still
        // reach ReuseDetected rather than NotFound, or a thief learns nothing was noticed.
        var familyRevoked = await context.RefreshTokenFamilies
            .AnyAsync(f => f.FamilyId == row.FamilyId, cancellationToken);

        if (familyRevoked || row.ExpiresAt <= nowTicks)
        {
            // Expiry is normal and must not revoke a family, so it is NotFound rather than reuse.
            return new RefreshRedemption.NotFound();
        }

        if (row.ConsumedAt is { } consumedTicks)
        {
            return await AlreadyConsumedAsync(context, row, consumedTicks, now, graceWindow, cancellationToken);
        }

        var issued = new RefreshTokenRow
        {
            TokenHash = StoredValues.ToBytes(successor.TokenHash),
            GrantId = row.GrantId,
            FamilyId = row.FamilyId,
            Generation = row.Generation + 1,
            PredecessorHash = row.TokenHash,
            SuccessorHash = null,
            IssuedAt = nowTicks,
            ExpiresAt = StoredValues.ToTicks(successor.ExpiresAt),
            ConsumedAt = null,
        };

        context.RefreshTokens.Add(issued);
        row.ConsumedAt = nowTicks;
        row.SuccessorHash = issued.TokenHash;

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            // The caller handed us a hash already in use. Clobbering it would move another family's
            // token into this chain, so the insert is allowed to fail and the transaction rolls back
            // - the presented token is left unconsumed, exactly as it was.
            throw new InvalidOperationException(
                "The successor hash is already in use. A refresh token hash must be unique.", ex);
        }

        await transaction.CommitAsync(cancellationToken);

        return new RefreshRedemption.Rotated(ToRecord(issued));
    }

    /// <summary>Decide what an already-consumed token means: a retry, or a theft.</summary>
    /// <remarks>
    /// The grace branch requires the successor to be <b>unconsumed and unexpired</b>. Checking only
    /// that it exists lets an attacker walk the chain: each hop returns the next token, whose
    /// consumption is more recent, so every hop stays inside the window and the walk reaches the live
    /// head with no reuse ever raised. A consumed successor means the chain moved on, so this
    /// presentation is a genuine replay.
    /// </remarks>
    private static async Task<RefreshRedemption> AlreadyConsumedAsync(
        AuthDbContext context,
        RefreshTokenRow row,
        long consumedTicks,
        DateTimeOffset now,
        TimeSpan graceWindow,
        CancellationToken cancellationToken)
    {
        var age = now - StoredValues.FromTicks(consumedTicks);

        // Bounded on BOTH sides. `now` is the caller's and this server runs as several instances, so
        // a fast clock stamping a consumption in the future would otherwise turn a 45-second window
        // into an arbitrarily long one. MaxClockSkew is read from the contract assembly rather than
        // retyped, which is why it is public there.
        var withinWindow = age >= -GraceWindows.MaxClockSkew && age <= graceWindow;

        if (withinWindow && row.SuccessorHash is { } successorHash)
        {
            var nowTicks = StoredValues.ToTicks(now);

            // The dependent read. It is inside the same transaction as the read above, which is the
            // part a conditional UPDATE cannot express.
            var alreadyIssued = await context.RefreshTokens
                .SingleOrDefaultAsync(
                    t => t.TokenHash == successorHash && t.ConsumedAt == null && t.ExpiresAt > nowTicks,
                    cancellationToken);

            if (alreadyIssued is not null)
            {
                // Hand back the successor that exists. Minting another would fork the family, and
                // after a fork there is no single chain against which a replay is anomalous.
                return new RefreshRedemption.ReplayedWithinGrace(ToRecord(alreadyIssued));
            }
        }

        return new RefreshRedemption.ReuseDetected(row.GrantId, row.FamilyId);
    }

    /// <inheritdoc />
    public async Task<int> RevokeFamilyAsync(string familyId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RefreshTokenStore.RevokeFamilyAsync");

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await _behavior.BeginWriteAsync(context, cancellationToken);

        // Insert-if-absent, then count - in one write transaction, so two concurrent revocations
        // cannot both report they did it and a redemption in flight cannot rotate a family this call
        // has just killed.
        if (await context.RefreshTokenFamilies.AnyAsync(f => f.FamilyId == familyId, cancellationToken))
        {
            return 0;
        }

        context.RefreshTokenFamilies.Add(new RefreshTokenFamilyRow
        {
            FamilyId = familyId,
            RevokedAt = StoredValues.ToTicks(now),
        });

        // Rows this call actually transitioned: the tokens that were still live. Counting every row
        // in the family, consumed and expired ones included, gives a number no caller can act on.
        // Nothing is written to the token rows - see RefreshTokenFamilyRow for why that shape was
        // chosen over stamping a revoked_at on each one.
        var live = await context.RefreshTokens
            .CountAsync(t => t.FamilyId == familyId && t.ConsumedAt == null, cancellationToken);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (_behavior.IsUniqueViolation(ex))
        {
            // Another caller inserted the family row between the check above and this insert, so
            // that call is the one that revoked it and this one transitioned nothing. Under SQLite
            // the write transaction excludes that interleaving and this branch is unreachable; it is
            // here because the interface promises "a second revoke returns zero" to every provider,
            // and a provider that allows concurrent writers would otherwise throw out of the reuse
            // detection path.
            return 0;
        }

        await transaction.CommitAsync(cancellationToken);

        return live;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, DateTimeOffset>> LastIssuedForGrantsAsync(
        IReadOnlyCollection<string> grantIds, CancellationToken cancellationToken)
    {
        using var timing = _metrics.Track("RefreshTokenStore.LastIssuedForGrantsAsync");

        ArgumentNullException.ThrowIfNull(grantIds);

        // Short-circuited rather than sent as `IN ()`, which is a syntax error on some providers and
        // a full scan on others. A caller with no grants is the ordinary state of a new account.
        if (grantIds.Count == 0)
        {
            return new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        }

        await using var context = await _contextFactory.CreateDbContextAsync(cancellationToken);

        // Grouped in the database rather than by loading the rows and folding them here. A family
        // that has rotated for a month is a thousand rows, and all this needs from them is one
        // number per grant - the difference does not show with three sessions and is the whole cost
        // of the page with a year of them.
        //
        // No filter on ConsumedAt or on the family being live: every token but the newest in a live
        // family is consumed, so excluding them reports the wrong moment for every session that has
        // rotated. The question is when the grant last minted, not what is still usable.
        var rows = await context.RefreshTokens
            .Where(t => grantIds.Contains(t.GrantId))
            .GroupBy(t => t.GrantId)
            .Select(g => new { GrantId = g.Key, IssuedAt = g.Max(t => t.IssuedAt) })
            .ToListAsync(cancellationToken);

        // Grants with no tokens are simply absent, which is what lets a caller tell "never
        // refreshed" from "refreshed at tick zero".
        return rows.ToDictionary(r => r.GrantId, r => StoredValues.FromTicks(r.IssuedAt), StringComparer.Ordinal);
    }

    private static RefreshTokenRow ToRow(RefreshTokenRecord record) => new()
    {
        TokenHash = StoredValues.ToBytes(record.TokenHash),
        GrantId = record.GrantId,
        FamilyId = record.FamilyId,
        Generation = record.Generation,
        PredecessorHash = StoredValues.ToBytes(record.PredecessorHash),
        SuccessorHash = StoredValues.ToBytes(record.SuccessorHash),
        IssuedAt = StoredValues.ToTicks(record.IssuedAt),
        ExpiresAt = StoredValues.ToTicks(record.ExpiresAt),
        ConsumedAt = StoredValues.ToTicks(record.ConsumedAt),
    };

    private static RefreshTokenRecord ToRecord(RefreshTokenRow row) => new(
        StoredValues.ToHash(row.TokenHash),
        row.GrantId,
        row.FamilyId,
        row.Generation,
        StoredValues.ToHashOrNull(row.PredecessorHash),
        StoredValues.ToHashOrNull(row.SuccessorHash),
        StoredValues.FromTicks(row.IssuedAt),
        StoredValues.FromTicks(row.ExpiresAt),
        StoredValues.FromTicks(row.ConsumedAt));
}
