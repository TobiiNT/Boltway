using System.Collections.Concurrent;
using System.Text;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Net;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>Knobs for <see cref="ClientKeySource"/>.</summary>
public sealed class ClientKeySourceOptions
{
    /// <summary>The shortest a fetched key set may be cached.</summary>
    /// <remarks>
    /// The same floor <c>CimdClientResolverOptions.MinimumCacheLifetime</c> uses and for the same
    /// reason: this fetch is on the token endpoint's latency budget, and a client that asks not to
    /// be cached is asking to spend it on every authentication.
    /// </remarks>
    public static TimeSpan MinimumCacheLifetime { get; } = TimeSpan.FromSeconds(300);

    /// <summary>The longest a fetched key set may be cached.</summary>
    /// <remarks>
    /// A ceiling bounds how long this server can be verifying against a key the client has already
    /// retired. Shorter than the CIMD document's day, because a key is the thing an attacker wants
    /// and a document is not.
    /// </remarks>
    public static TimeSpan MaximumCacheLifetime { get; } = TimeSpan.FromSeconds(3_600);

    /// <summary>
    /// Cap on bytes read from a key set.
    /// </summary>
    /// <remarks>
    /// Larger than the CIMD document's 5 KB because a JWKS holds keys rather than URLs, and small
    /// enough that a hostile origin cannot make this endpoint read a stream. A set of eight RSA-2048
    /// public keys is under 3 KB.
    /// </remarks>
    public int MaxDocumentBytes { get; set; } = 32 * 1024;

    /// <summary>
    /// The shortest gap between two fetches for one client, whatever asks for one.
    /// </summary>
    /// <remarks>
    /// <b>What bounds the unknown-<c>kid</c> trigger.</b> That trigger is reachable by anyone who
    /// can reach the token endpoint — a syntactically valid assertion naming a random <c>kid</c>
    /// costs nothing to make — so without a floor it is an outbound request per inbound request,
    /// aimed at somebody else's origin. The same shape
    /// <c>OidcProviderOptions.JwksMinimumRefreshInterval</c> bounds upstream.
    /// </remarks>
    public TimeSpan MinimumRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How long past its expiry a cached key set may still be used when a refresh fails.</summary>
    /// <remarks>
    /// The trade, stated: for up to this long an origin that is unreachable does not stop its
    /// client's users authenticating, and equally a client that has retired a key keeps being
    /// verified against it. Bounded by the transient-outcome test below, so a document that was
    /// fetched and found unusable is <b>not</b> covered — only one that could not be fetched.
    /// </remarks>
    public TimeSpan StaleTolerance { get; set; } = TimeSpan.FromHours(1);

    /// <summary>How many clients' key sets may be held at once.</summary>
    public int MaxCachedClients { get; set; } = 1024;
}

/// <summary>What a key lookup produced.</summary>
/// <param name="Keys">The verification keys, or empty when none could be had.</param>
/// <param name="Detail">Why there are none. Null on success.</param>
public readonly record struct ClientKeys(IReadOnlyList<SecurityKey> Keys, string? Detail);

/// <summary>
/// Fetches and caches a client's own signing keys, for <c>private_key_jwt</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not <c>JwksKeySource</c>, and the difference is who chose the URL.</b> That type reads the
/// authorization server's keys from an operator-configured issuer and goes through
/// <c>UpstreamEndpointClient</c>. This one dereferences a <c>jwks_uri</c> that arrived inside a
/// document fetched from a host an attacker picked, so it goes through <c>ISafeHttpFetcher</c> —
/// the CIMD-grade fetcher, with the tighter budgets and the per-host governor.
/// <c>FetchPurpose.JwksUri</c> has existed unused for exactly this caller.
/// </para>
/// <para>
/// <b>The unknown-<c>kid</c> refresh is required, not an optimisation.</b> A client rotates its
/// signing key and publishes the new set; this cache holds the old one until it expires, and every
/// assertion in between fails on a key that is perfectly good. That is the same defect
/// <c>JwksKeySource</c> exists to remove on the resource-server side. Unlike there, this path is
/// asynchronous and off the hot path, so the refresh can be awaited rather than started and
/// abandoned.
/// </para>
/// <para>
/// <b>Everything here is per process</b> — the cache, the refresh floor. A fleet of <i>n</i>
/// replicas holds <i>n</i> caches and admits <i>n</i> times the refresh rate against a client's
/// origin.
/// </para>
/// </remarks>
public sealed class ClientKeySource(ISafeHttpFetcher fetcher, TimeProvider time, ClientKeySourceOptions? options = null)
{
    private readonly ISafeHttpFetcher _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ClientKeySourceOptions _options = options ?? new ClientKeySourceOptions();

    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.Ordinal);

    /// <summary>
    /// The keys to verify this client's assertion with.
    /// </summary>
    /// <param name="client">The client, which must carry a <c>jwks_uri</c>.</param>
    /// <param name="refreshBecauseKeyUnknown">
    /// Whether this call follows a validation failure naming a <c>kid</c> the cached set does not
    /// hold. Honoured only once <see cref="ClientKeySourceOptions.MinimumRefreshInterval"/> has
    /// elapsed since the last fetch for this client.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<ClientKeys> GetAsync(
        ClientRecord client, bool refreshBecauseKeyUnknown, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        if (!AbsoluteHttpsUrl.TryCreate(client.JwksUri, out var jwksUri))
        {
            // CimdDocument refuses a private_key_jwt client with no jwks_uri, so reaching here means
            // a client registered by some other route. Reported rather than thrown: it is a
            // configuration error about one client, not about this server.
            return new ClientKeys([], "This client is registered for 'private_key_jwt' with no usable 'jwks_uri'.");
        }

        var key = jwksUri.Value;
        var now = _time.GetUtcNow();

        if (_cache.TryGetValue(key, out var cached))
        {
            var stale = now >= cached.ExpiresAt;
            var wanted = refreshBecauseKeyUnknown && now - cached.FetchedAt >= _options.MinimumRefreshInterval;

            if (!stale && !wanted)
            {
                return new ClientKeys(cached.Keys, null);
            }
        }

        var outcome = await _fetcher.FetchAsync(
            new SafeFetchRequest(jwksUri, FetchPurpose.JwksUri, _options.MaxDocumentBytes),
            cancellationToken);

        if (outcome is not FetchOutcome.Ok ok)
        {
            return Fallback(cached, now, outcome);
        }

        IReadOnlyList<SecurityKey> keys;

        try
        {
            // GetSigningKeys(), not Keys: it drops anything whose `use` is not signature and
            // anything it cannot turn into a verification key, so a set carrying an encryption key
            // does not put one in the signature allow-list.
            keys = [.. new JsonWebKeySet(Encoding.UTF8.GetString(ok.Body)).GetSigningKeys()];
        }
        catch (ArgumentException ex)
        {
            // Fetched and unusable, which is the client's problem rather than a transient one — so
            // no stale fallback. See Fallback for why the two are separated.
            return new ClientKeys([], $"The client's key set could not be parsed: {ex.GetType().Name}.");
        }

        if (keys.Count == 0)
        {
            return new ClientKeys([], "The client's key set carries no signing keys.");
        }

        Cache(key, keys, ok.MaxAge, now);

        return new ClientKeys(keys, null);
    }

    /// <summary>What to answer when the fetch did not produce a usable document.</summary>
    /// <remarks>
    /// <b>Stale keys are served only for a failure to <i>reach</i> the origin.</b> A 404, a 500 and a
    /// timeout are all "we could not ask", and refusing every authentication for the length of
    /// somebody else's outage is a worse answer than verifying against keys they published an hour
    /// ago. A document that arrived and parsed to nothing is not that case: the origin answered, and
    /// what it said was that these keys are gone.
    /// </remarks>
    private ClientKeys Fallback(Entry? cached, DateTimeOffset now, FetchOutcome outcome)
    {
        var detail = Describe(outcome);

        if (cached is { } entry
            && _options.StaleTolerance > TimeSpan.Zero
            && now < entry.ExpiresAt + _options.StaleTolerance)
        {
            return new ClientKeys(entry.Keys, null);
        }

        return new ClientKeys([], $"The client's key set could not be fetched: {detail}.");
    }

    private void Cache(string key, IReadOnlyList<SecurityKey> keys, TimeSpan? maxAge, DateTimeOffset now)
    {
        var lifetime = Clamp(maxAge ?? ClientKeySourceOptions.MinimumCacheLifetime);

        _cache[key] = new Entry(keys, now + lifetime, now);

        if (_cache.Count <= _options.MaxCachedClients)
        {
            return;
        }

        // The key is attacker-chosen — every distinct jwks_uri that resolves is an entry — so the
        // map is bounded. Oldest fetch first, which is the cheapest defensible order and is not
        // load-bearing: the cap is about memory, and a wrongly evicted entry costs one refetch.
        foreach (var stale in _cache.OrderBy(e => e.Value.FetchedAt).Take(_cache.Count - _options.MaxCachedClients))
        {
            _ = _cache.TryRemove(stale.Key, out _);
        }
    }

    private static TimeSpan Clamp(TimeSpan lifetime) =>
        lifetime < ClientKeySourceOptions.MinimumCacheLifetime ? ClientKeySourceOptions.MinimumCacheLifetime
        : lifetime > ClientKeySourceOptions.MaximumCacheLifetime ? ClientKeySourceOptions.MaximumCacheLifetime
        : lifetime;

    /// <summary>A short, non-secret description of a failed fetch.</summary>
    private static string Describe(FetchOutcome outcome) => outcome switch
    {
        FetchOutcome.Blocked blocked => $"blocked ({blocked.Reason})",
        FetchOutcome.Redirected redirected => $"redirected ({redirected.Status}), not followed",
        FetchOutcome.NotOk notOk => $"status {notOk.Status}",
        FetchOutcome.TooLarge tooLarge => $"body over {tooLarge.BytesRead} bytes",
        FetchOutcome.Timeout => "timed out",
        FetchOutcome.TransportFailed => "transport failure",
        FetchOutcome.RateLimited limited => $"outbound budget spent, retry after {limited.RetryAfter}",
        _ => "unknown outcome",
    };

    private sealed record Entry(IReadOnlyList<SecurityKey> Keys, DateTimeOffset ExpiresAt, DateTimeOffset FetchedAt);
}
