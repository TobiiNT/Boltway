using System.Collections.Concurrent;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.InMemory;

/// <summary>
/// Authorization codes in memory.
/// </summary>
/// <remarks>
/// Ships in the box rather than living in a test project, because a customer implementing their own
/// store needs something to compare against and the shared contract suite needs a third
/// implementation to prove the contract is about behaviour rather than about EF Core.
/// </remarks>
public sealed class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly Dictionary<Sha256Hash, AuthorizationCodeRecord> _codes = [];
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task StoreAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        lock (_gate)
        {
            // Add-only. An upsert would let a re-store of an already-redeemed code clear its
            // RedeemedAt and make it redeemable again, resetting N-07's replay protection — and a
            // relational store's primary key would throw here, so tolerating it would make two
            // implementations disagree on identical input.
            if (!_codes.TryAdd(record.CodeHash, record))
            {
                throw new InvalidOperationException(
                    "An authorization code with this hash already exists. Codes are add-only: " +
                    "overwriting one would clear its redemption and reset replay protection.");
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<AuthorizationCodeRecord?> FindAsync(Sha256Hash codeHash, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_codes.TryGetValue(codeHash, out var record) ? record : null);
        }
    }

    /// <inheritdoc />
    public Task<CodeRedemption> RedeemAsync(
        Sha256Hash codeHash, DateTimeOffset now, TimeSpan graceWindow, CancellationToken cancellationToken)
    {
        // The relational store does this as `UPDATE ... WHERE code_hash = @h AND redeemed_at IS
        // NULL` and reads the affected count. Here the lock plays the same role: the read of
        // RedeemedAt and the write must not interleave, or two concurrent redemptions both see null
        // and both redeem.
        //
        // Expiry is deliberately NOT checked — see the interface remarks. Folding it in would send
        // an expired code down the revoke path, which is the denial of service N-07 exists to
        // prevent.
        lock (_gate)
        {
            if (!_codes.TryGetValue(codeHash, out var record))
            {
                return Task.FromResult<CodeRedemption>(new CodeRedemption.ReplayedOutsideGrace());
            }

            if (record.RedeemedAt is { } redeemedAt)
            {
                // Clamped below, like the refresh window. `now` is the caller's and this server runs
                // as several instances, so a fast clock stamping a redemption in the future would
                // otherwise stretch the window arbitrarily.
                var elapsed = now - redeemedAt;
                var within = elapsed >= -GraceWindows.MaxClockSkew && elapsed <= graceWindow;

                return Task.FromResult<CodeRedemption>(
                    within ? new CodeRedemption.ReplayedWithinGrace() : new CodeRedemption.ReplayedOutsideGrace());
            }

            // Replaced, not removed. N-07 needs the row to survive redemption so a replay can be
            // validated in full before anything is revoked.
            _codes[codeHash] = record with { RedeemedAt = now };
            return Task.FromResult<CodeRedemption>(new CodeRedemption.Redeemed());
        }
    }

    /// <inheritdoc />
    public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        // Under the same lock as redemption. Without it, a sweep interleaved with a redemption
        // reported a row deleted that the redemption then wrote back — measured at 166 in 5000 —
        // so the row survived and the returned count was a lie.
        lock (_gate)
        {
            var expired = new List<Sha256Hash>();

            foreach (var (hash, record) in _codes)
            {
                // A redeemed row outlives its expiry, because the retry window it was written for
                // outlives it too. Removing it here reports a deletion that undoes a redemption
                // this store already answered Redeemed to, and leaves the retry facing the answer
                // reserved for a code nobody ever issued. Measured without this guard, in the
                // sweep/redeem race over three runs of 200: 189, 197 and 183 attempts ended with
                // a successful redemption and no row.
                if (record.RedeemedAt is { } redeemedAt && now - redeemedAt < GraceWindows.RedeemedRetention)
                {
                    continue;
                }

                if (record.ExpiresAt <= now)
                {
                    expired.Add(hash);
                }
            }

            foreach (var hash in expired)
            {
                _codes.Remove(hash);
            }

            return Task.FromResult(expired.Count);
        }
    }
}

/// <summary>Refresh tokens in memory, including the rotation decision.</summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly Dictionary<Sha256Hash, RefreshTokenRecord> _tokens = [];
    private readonly Dictionary<string, DateTimeOffset> _revokedFamilies = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task<RefreshTokenRecord?> FindAsync(Sha256Hash tokenHash, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            return Task.FromResult(_tokens.GetValueOrDefault(tokenHash));
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(RefreshTokenRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        lock (_gate)
        {
            // Add-only, for the same reason codes are. Re-storing a consumed token erased its
            // ConsumedAt and let the parent rotate a second time: two live successors with the same
            // predecessor, which is the family fork this whole design exists to prevent.
            if (!_tokens.TryAdd(record.TokenHash, record))
            {
                throw new InvalidOperationException(
                    "A refresh token with this hash already exists. Tokens are add-only: " +
                    "overwriting one would clear its consumption and allow the family to fork.");
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<RefreshRedemption> RedeemAsync(
        Sha256Hash presented,
        RefreshTokenSeed successor,
        DateTimeOffset now,
        TimeSpan graceWindow,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(successor);

        // One critical section covering the whole decision, mirroring the transaction the
        // relational store opens. Splitting it — read, decide, write — is precisely the race that
        // forks a family: two callers both see an unconsumed token and both mint a successor.
        lock (_gate)
        {
            if (!_tokens.TryGetValue(presented, out var record))
            {
                return Task.FromResult<RefreshRedemption>(new RefreshRedemption.NotFound());
            }

            if (_revokedFamilies.ContainsKey(record.FamilyId) || record.ExpiresAt <= now)
            {
                return Task.FromResult<RefreshRedemption>(new RefreshRedemption.NotFound());
            }

            if (record.ConsumedAt is { } consumedAt)
            {
                return Task.FromResult(AlreadyConsumed(record, consumedAt, now, graceWindow));
            }

            if (_tokens.ContainsKey(successor.TokenHash))
            {
                // The caller handed us a hash that is already in use. Clobbering it would move
                // another family's token into this chain; a relational store's primary key would
                // throw, so throwing keeps the two implementations agreeing.
                throw new InvalidOperationException(
                    "The successor hash is already in use. A refresh token hash must be unique.");
            }

            var issued = new RefreshTokenRecord(
                successor.TokenHash,
                record.GrantId,
                record.FamilyId,
                record.Generation + 1,
                PredecessorHash: record.TokenHash,
                SuccessorHash: null,
                IssuedAt: now,
                ExpiresAt: successor.ExpiresAt);

            _tokens[successor.TokenHash] = issued;
            _tokens[presented] = record with { ConsumedAt = now, SuccessorHash = successor.TokenHash };

            return Task.FromResult<RefreshRedemption>(new RefreshRedemption.Rotated(issued));
        }
    }

    /// <summary>
    /// Decide what a already-consumed token means: a retry, or a theft.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The grace branch requires the successor to be <b>unconsumed and unexpired</b>, and that is
    /// not a detail. Checking only that the successor exists let an attacker walk the whole chain:
    /// with a stolen <c>rt0</c> replayed after a legitimate burst, each hop returned the next token
    /// in the chain, every hop's <c>consumedAt</c> was later than the last so every hop stayed
    /// inside the window, and the walk ended at the live head with no <c>ReuseDetected</c> ever
    /// raised. Measured over 200 rounds of a client refreshing every 30 s with an attacker polling
    /// 20 s behind: zero detections, and both parties holding the same token.
    /// </para>
    /// <para>
    /// A consumed successor means the chain moved on, so this presentation is a genuine replay.
    /// </para>
    /// </remarks>
    private RefreshRedemption AlreadyConsumed(
        RefreshTokenRecord record, DateTimeOffset consumedAt, DateTimeOffset now, TimeSpan graceWindow)
    {
        var age = now - consumedAt;

        // Bounded on BOTH sides. `now` is supplied by the caller and this server runs several
        // instances, so a fast clock on one of them stamped a ConsumedAt in the future and turned a
        // 45-second window into a 60-minute one — measured. A negative age of any magnitude used to
        // pass, which made clock skew an unbounded skeleton key.
        var withinWindow = age >= -GraceWindows.MaxClockSkew && age <= graceWindow;

        if (withinWindow
            && record.SuccessorHash is { } successorHash
            && _tokens.TryGetValue(successorHash, out var alreadyIssued)
            && alreadyIssued.ConsumedAt is null
            && alreadyIssued.ExpiresAt > now)
        {
            // Hand back the successor that exists. Minting another would fork the family, and after
            // a fork there is no single chain against which a replay is anomalous — reuse detection
            // stops working from that point on.
            return new RefreshRedemption.ReplayedWithinGrace(alreadyIssued);
        }

        return new RefreshRedemption.ReuseDetected(record.GrantId, record.FamilyId);
    }

    /// <inheritdoc />
    public Task<int> RevokeFamilyAsync(string familyId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        // Under the same lock as rotation. Without it a redemption in flight returned Rotated for a
        // family being revoked — measured at 36 in 3000 — so the caller minted an access token and
        // a successor for a family it had just killed on reuse detection.
        lock (_gate)
        {
            // Rows are never deleted. RFC 9700 §4.14.2 wants the relationship retained, and it is
            // what keeps reuse detection working after revocation: replaying a consumed parent
            // must still say ReuseDetected rather than NotFound, or a thief learns nothing has
            // been noticed.
            if (!_revokedFamilies.TryAdd(familyId, now))
            {
                return Task.FromResult(0);
            }

            var revoked = 0;
            foreach (var (_, record) in _tokens)
            {
                if (string.Equals(record.FamilyId, familyId, StringComparison.Ordinal)
                    && record.ConsumedAt is null)
                {
                    revoked++;
                }
            }

            // Rows this call actually transitioned, so a second revoke returns 0 and a caller can
            // log honestly. Counting every row in the family made the number meaningless.
            return Task.FromResult(revoked);
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyDictionary<string, DateTimeOffset>> LastIssuedForGrantsAsync(
        IReadOnlyCollection<string> grantIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grantIds);

        var wanted = new HashSet<string>(grantIds, StringComparer.Ordinal);
        var latest = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);

        if (wanted.Count == 0)
        {
            return Task.FromResult<IReadOnlyDictionary<string, DateTimeOffset>>(latest);
        }

        // Under the lock, like every other read here: `_tokens` is a plain Dictionary and rotation
        // adds to it, so enumerating it outside the gate throws on a perfectly ordinary refresh.
        lock (_gate)
        {
            foreach (var (_, record) in _tokens)
            {
                // Consumed and revoked rows count. Every token but the newest in a live family is
                // consumed by definition, so skipping them would report the wrong moment for every
                // session that has ever rotated — which is every session older than half an hour.
                if (wanted.Contains(record.GrantId)
                    && (!latest.TryGetValue(record.GrantId, out var seen) || record.IssuedAt > seen))
                {
                    latest[record.GrantId] = record.IssuedAt;
                }
            }
        }

        return Task.FromResult<IReadOnlyDictionary<string, DateTimeOffset>>(latest);
    }
}

/// <summary>Grants and the revocation denylist, in memory.</summary>
public sealed class InMemoryGrantStore : IGrantStore
{
    private readonly ConcurrentDictionary<string, GrantRecord> _grants = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task StoreAsync(GrantRecord grant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);

        if (!_grants.TryAdd(grant.GrantId, grant))
        {
            throw new InvalidOperationException($"Grant '{grant.GrantId}' already exists.");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken) =>
        Task.FromResult(_grants.TryGetValue(grantId, out var grant) ? grant : null);

    /// <inheritdoc />
    public Task<bool> RevokeAsync(string grantId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        // Returns whether this call did it, so revoking an unknown grant is observable rather than
        // a silent success. A caller reacting to reuse detection needs to know the revocation
        // landed.
        while (_grants.TryGetValue(grantId, out var grant))
        {
            if (grant.RevokedAt is not null)
            {
                return Task.FromResult(false);
            }

            if (_grants.TryUpdate(grantId, grant with { RevokedAt = now }, grant))
            {
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc />
    public Task<int> RevokeAllForSubjectAsync(
        SubjectId subject, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var revoked = 0;

        // A snapshot of the keys, then a compare-and-swap per grant. Enumerating the dictionary
        // while updating it is safe for `ConcurrentDictionary` — unlike `List<T>` — but the same
        // CAS the single-grant revoke uses is what makes the count "how many this call transitioned"
        // rather than "how many looked unrevoked when we read them".
        //
        // The relational implementation does this as one statement and has no window at all. This
        // one has a small one, and it is an in-memory store for tests and single-process
        // development, where there is no second writer to lose to.
        foreach (var grantId in _grants.Keys)
        {
            while (_grants.TryGetValue(grantId, out var grant))
            {
                if (grant.RevokedAt is not null || grant.Subject != subject)
                {
                    break;
                }

                if (_grants.TryUpdate(grantId, grant with { RevokedAt = now }, grant))
                {
                    revoked++;
                    break;
                }
            }
        }

        return Task.FromResult(revoked);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<GrantRecord>> ListForSubjectAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        // `ConcurrentDictionary.Values` is a snapshot, so this cannot throw part-way through the way
        // enumerating a `List<T>` under a concurrent write would. A grant revoked while the snapshot
        // is being filtered may still appear, which is what a listing means: it is the state at a
        // moment, and the alternative — locking the store for a read — buys a freshness no caller
        // can use, since the answer is stale by the time it reaches the wire regardless.
        IReadOnlyList<GrantRecord> grants =
        [
            .. _grants.Values
                .Where(g => g.Subject == subject && g.RevokedAt is null)
                .OrderByDescending(g => g.CreatedAt),
        ];

        return Task.FromResult(grants);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> ListApprovedUserAgentsAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        // No `RevokedAt` filter, unlike the listing above. Revoking a grant does not un-use the
        // machine it was approved from, and the caller is asking what this person has ever used.
        IReadOnlyList<string> agents =
        [
            .. _grants.Values
                .Where(g => g.Subject == subject && !string.IsNullOrEmpty(g.UserAgent))
                .Select(g => g.UserAgent!)
                .Distinct(StringComparer.Ordinal),
        ];

        return Task.FromResult(agents);
    }

    /// <inheritdoc />
    public Task<bool> IsRevokedAsync(string grantId, CancellationToken cancellationToken) =>
        Task.FromResult(_grants.TryGetValue(grantId, out var grant) && grant.RevokedAt is not null);
}
