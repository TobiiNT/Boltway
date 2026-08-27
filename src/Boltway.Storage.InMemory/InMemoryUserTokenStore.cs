using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.InMemory;

/// <summary>
/// Reset and verification tokens in memory.
/// </summary>
/// <remarks>
/// In memory, so every outstanding link stops working on a restart. That is a smaller cost than it
/// is for the other stores - a reset link lives fifteen minutes and asking again is one click - but
/// it is still a cost, and it is why this is opt-in with the rest of them.
/// </remarks>
public sealed class InMemoryUserTokenStore : IUserTokenStore
{
    private readonly Dictionary<Sha256Hash, UserTokenRecord> _tokens = [];
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task StoreAsync(UserTokenRecord token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        lock (_gate)
        {
            if (!_tokens.TryAdd(token.TokenHash, token))
            {
                throw new InvalidOperationException(
                    "A user token with this hash already exists. Tokens are add-only: overwriting "
                    + "one would move somebody else's expiry.");
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<UserTokenRecord?> RedeemAsync(
        Sha256Hash tokenHash,
        UserTokenPurpose purpose,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            // Under the lock, and the read and the remove are one critical section. The relational
            // store does it as a conditional DELETE whose rows-affected is the answer; splitting it
            // here would let two presentations of one link both return a record, which is a person
            // double-clicking their own mail on a good day and a stolen link being raced on a bad
            // one.
            if (!_tokens.TryGetValue(tokenHash, out var token))
            {
                return Task.FromResult<UserTokenRecord?>(null);
            }

            // Wrong purpose is not found, and it is not removed either: a verification link
            // presented at the reset endpoint is somebody probing, and consuming it would let them
            // destroy a token they could not use.
            if (token.Purpose != purpose)
            {
                return Task.FromResult<UserTokenRecord?>(null);
            }

            _tokens.Remove(tokenHash);

            // Removed and then reported absent. An expired token has nothing left to answer, so
            // taking it away on the way past is the same housekeeping DeleteExpiredAsync does.
            return Task.FromResult(token.ExpiresAt <= now ? null : token);
        }
    }

    /// <inheritdoc />
    public Task<int> DeleteForSubjectAsync(
        SubjectId subject, UserTokenPurpose purpose, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var doomed = _tokens
                .Where(e => e.Value.Subject == subject && e.Value.Purpose == purpose)
                .Select(e => e.Key)
                .ToList();

            foreach (var hash in doomed)
            {
                _tokens.Remove(hash);
            }

            return Task.FromResult(doomed.Count);
        }
    }

    /// <inheritdoc />
    public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            var doomed = _tokens.Where(e => e.Value.ExpiresAt <= now).Select(e => e.Key).ToList();

            foreach (var hash in doomed)
            {
                _tokens.Remove(hash);
            }

            return Task.FromResult(doomed.Count);
        }
    }
}
