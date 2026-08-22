using System.Collections.Concurrent;
using System.Globalization;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Net;
using Boltway.OAuth.Net.RateLimiting;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>Knobs for <see cref="CimdClientResolver"/>.</summary>
public sealed class CimdClientResolverOptions
{
    /// <summary>
    /// The shortest a fetched document may be cached. S-30's floor.
    /// </summary>
    /// <remarks>
    /// A floor, not a default with a smaller override: it applies even when the origin sent
    /// <c>max-age=0</c>. §5.2 permits an authorization server to "define its own upper and/or lower
    /// bounds on an acceptable cache lifetime", and this is that lower bound. It exists because the
    /// fetch happens inside <c>/authorize</c>, on the user's latency budget, and a client that asks
    /// not to be cached is asking to spend it on every authorization.
    /// </remarks>
    public static TimeSpan MinimumCacheLifetime { get; } = TimeSpan.FromSeconds(300);

    /// <summary>The longest a fetched document may be cached. S-30's ceiling.</summary>
    /// <remarks>
    /// §8.4: documents are served from URLs under client control and change. A ceiling bounds how
    /// long this server can be acting on a redirect URI or a key the client has already replaced.
    /// </remarks>
    public static TimeSpan MaximumCacheLifetime { get; } = TimeSpan.FromSeconds(86_400);

    /// <summary>Cap on bytes read from a metadata document. §8.7 recommends 5 KB.</summary>
    public int MaxDocumentBytes { get; set; } = 5 * 1024;

    /// <summary>Total fetch budget, or <see langword="null"/> for the fetcher's own.</summary>
    public TimeSpan? FetchTimeout { get; set; }

    /// <summary>Whether an https redirect URI must be same-origin with the <c>client_id</c>. U-17.</summary>
    public bool RequireSameOriginRedirectUris { get; set; } = true;

    /// <summary><c>client_id</c> values exempt from the same-origin rule. U-17's escape hatch.</summary>
    public ISet<string> SameOriginExemptClientIds { get; } = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// How many resolved clients may be held in the cache at once.
    /// </summary>
    /// <remarks>
    /// A bound, because the cache key is attacker-chosen: every distinct URL-shaped
    /// <c>client_id</c> that resolves is an entry, and nothing stops a caller sending a new one each
    /// time. At the cap the least recently <i>used</i> entries are dropped — see
    /// <see cref="CimdClientResolver"/> for why used rather than oldest, and for what the previous
    /// policy of refusing new entries cost.
    /// </remarks>
    public int MaxCachedClients { get; set; } = 1024;

    /// <summary>
    /// How long past its expiry a cached document may still be served when the refresh fails.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One hour. The trade is stated rather than implied: for up to this long after a document has
    /// expired, an origin that is unreachable or answering 5xx does not take its client's users
    /// offline — and, equally, a client that has taken its document down and expects to stop being
    /// trusted keeps being trusted for this long. An hour is short against the 24-hour ceiling on a
    /// fresh entry and long against every transient outage worth surviving.
    /// </para>
    /// <para>
    /// The window is measured from the entry's own expiry and is not extended by serving it, so a
    /// permanently dead origin produces at most one hour of stale service and then hard failures.
    /// Set to <see cref="TimeSpan.Zero"/> to switch stale-serve off entirely.
    /// </para>
    /// </remarks>
    public TimeSpan StaleTolerance { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How many fetches one <c>client_id</c> may cause in <see cref="FetchWindow"/>. X-31.
    /// </summary>
    /// <remarks>
    /// Ten a minute. A resolved document is cached for at least 300 s, so a legitimate client costs
    /// at most one fetch per five minutes per instance and this is fifty times its ceiling. What it
    /// bounds is the case that is <i>not</i> cached: §5.2 forbids caching an error, so a
    /// <c>client_id</c> whose document is missing or malformed produces one outbound fetch per
    /// authorization request forever, which is what made <c>/authorize</c> an amplifier.
    /// </remarks>
    public int MaxFetchesPerClientIdPerWindow { get; set; } = 10;

    /// <summary>The window <see cref="MaxFetchesPerClientIdPerWindow"/> counts in.</summary>
    public TimeSpan FetchWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How long a <c>client_id</c> over its fetch budget is refused.</summary>
    public TimeSpan FetchBackoff { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How many consecutive failed fetches stop this server trying a <c>client_id</c> for a while.
    /// </summary>
    /// <remarks>
    /// Three, then a 60 s cooldown that doubles per failed probe up to ten minutes. Nothing a user
    /// can do is lost by this: the authorization was going to fail anyway — the document is not
    /// fetchable — and the only difference is that it now fails in microseconds with a
    /// <c>Retry-After</c> instead of after a DNS lookup, a TLS handshake and a request. A single
    /// successful fetch clears the whole entry.
    /// </remarks>
    public int ConsecutiveFailuresBeforeBreakerOpens { get; set; } = 3;

    /// <summary>How long the breaker holds a failing <c>client_id</c> the first time.</summary>
    public TimeSpan BreakerCooldown { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>The longest the breaker holds one. It doubles per failed probe up to this.</summary>
    public TimeSpan MaxBreakerCooldown { get; set; } = TimeSpan.FromMinutes(10);
}

/// <summary>
/// Resolves a URL-shaped <c>client_id</c> by fetching the document it names. S-16.
/// </summary>
/// <remarks>
/// <para>
/// The default client-acquisition path, and the reason this server needs no administrator in the
/// loop for a connection (A-03, A-20). A client this server has never seen sends
/// <c>client_id=https://claude.ai/oauth/mcp-oauth-client-metadata</c>, the document at that URL is
/// fetched and validated, and the authorization proceeds. There is no import step and no credential
/// exchanged out of band.
/// </para>
/// <para>
/// <b>Nothing here writes to <see cref="IClientStore"/>, and the constructor is where that is
/// visible.</b> A-08: a hundred sequential CIMD connections must leave the client table unchanged.
/// The obvious optimisation — persist the resolved record so the next authorization skips the fetch
/// — turns every client that ever tried to connect into a row somebody has to garbage-collect, which
/// is the failure mode CIMD exists to avoid. The cache below is in memory, bounded, and expires.
/// </para>
/// <para>
/// Registered last in the resolver chain. It is the only resolver that makes an outbound request, so
/// a client that some cheaper resolver already knows never costs one.
/// </para>
/// <para>
/// <b>Everything this class keeps is per process.</b> The cache, the single-flight table, the fetch
/// budget and the breaker are all fields of one instance. A deployment of <i>n</i> replicas has
/// <i>n</i> caches that miss independently, <i>n</i> budgets, and <i>n</i> breakers — so the
/// outbound volume a client can cause across the fleet is <i>n</i> times what the options here say,
/// and a breaker open on one replica says nothing about the others. That is a statement of what
/// these limits are, not a caveat on them: they bound one instance, which is where the sockets and
/// the CPU are.
/// </para>
/// </remarks>
public sealed class CimdClientResolver : IClientResolver
{
    private readonly ISafeHttpFetcher _fetcher;

    // Optional and last, so every existing construction still compiles. Nothing here changes
    // behaviour when it is null; an instrument with no listener is a branch on a cached flag.
    private readonly Diagnostics.AuthorizationServerMetrics? _metrics;
    private readonly TimeProvider _time;
    private readonly CimdClientResolverOptions _options;
    private readonly KeyedRateLimiter _fetchBudget;
    private readonly NegativeResultBreaker _breaker;

    /// <summary>
    /// The §5.2 cache. Keyed on the raw <c>client_id</c>, ordinal.
    /// </summary>
    /// <remarks>
    /// Ordinal, because the key is the client's identity and §3 compares identities as strings. A
    /// case-insensitive comparer here would merge two distinct clients into one cache entry, and the
    /// second one would be served the first one's redirect URIs.
    /// </remarks>
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);

    /// <summary>
    /// The fetches currently running, so concurrent callers for one <c>client_id</c> share one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without this, a burst of sign-ins for a client whose entry has just expired is one outbound
    /// request each — measured at 64 fetches for 64 concurrent first resolutions. Since the entry
    /// expires at a fixed instant for everybody, that burst is exactly the shape a popular client
    /// produces, not a contrived one.
    /// </para>
    /// <para>
    /// <see cref="Lazy{T}"/> rather than <c>GetOrAdd</c> with a task-returning factory:
    /// <see cref="ConcurrentDictionary{TKey, TValue}.GetOrAdd(TKey, Func{TKey, TValue})"/> does not
    /// hold a lock across the factory, so several threads can run it and only one result is kept —
    /// which starts the fetches this is here to collapse and then throws all but one away.
    /// <see cref="LazyThreadSafetyMode.ExecutionAndPublication"/> is the mode that runs it once.
    /// </para>
    /// </remarks>
    private readonly ConcurrentDictionary<string, Lazy<Task<ClientResolution>>> _inFlight =
        new(StringComparer.Ordinal);

    private readonly object _evictionGate = new();

    /// <summary>Create a resolver.</summary>
    public CimdClientResolver(
        ISafeHttpFetcher fetcher,
        TimeProvider time,
        CimdClientResolverOptions? options = null,
        Diagnostics.AuthorizationServerMetrics? metrics = null)
    {
        _metrics = metrics;
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options ?? new CimdClientResolverOptions();

        _fetchBudget = new KeyedRateLimiter(_time, new KeyedRateLimiterOptions
        {
            Window = _options.FetchWindow,
            PermitsPerWindow = _options.MaxFetchesPerClientIdPerWindow,
            InitialBackoff = _options.FetchBackoff,
            MaxBackoff = _options.FetchBackoff,
            MaxTrackedKeys = _options.MaxCachedClients,
        });

        _breaker = new NegativeResultBreaker(_time, new NegativeResultBreakerOptions
        {
            ConsecutiveFailuresBeforeOpen = _options.ConsecutiveFailuresBeforeBreakerOpens,
            Cooldown = _options.BreakerCooldown,
            MaxCooldown = _options.MaxBreakerCooldown,
            MaxTrackedKeys = _options.MaxCachedClients,
        });
    }

    /// <summary>
    /// One recording site's worth of arithmetic, so the two callers cannot disagree about units.
    /// </summary>
    /// <remarks>
    /// Milliseconds, matching the instrument's declared unit. <c>Stopwatch.GetElapsedTime</c> rather
    /// than a <c>Stopwatch</c> instance: this is on the authorize path and the struct-free form
    /// allocates nothing when nobody is listening.
    /// </remarks>
    private void Record(long startedAt, string outcome) =>
        _metrics?.CimdFetchDuration.Record(
            System.Diagnostics.Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds,
            new KeyValuePair<string, object?>("outcome", outcome));

    /// <summary>How many documents are currently cached. For tests.</summary>
    internal int CachedCount => _cache.Count;

    /// <summary>
    /// Whether this identifier is URL-shaped. Cheap, and it makes no network call.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the prefix test, not the whole of §3. The rest of §3 is applied in
    /// <see cref="ResolveAsync"/> on purpose: a resolver that answers <see langword="false"/> is
    /// skipped silently, and the request then ends at the chain's fall-through message — "no client
    /// is registered with that identifier" — for a <c>client_id</c> whose real problem is that it
    /// has no path component. A-07 asks for the description that names the failed check, and only
    /// the resolver that recognised the identifier can produce one.
    /// </para>
    /// <para>
    /// It is not a claim about kind. §7.1 warns that an <c>https://</c> prefix is not a reliable
    /// signal that a client is a CIMD client — an administrator may issue URL-shaped identifiers for
    /// other reasons. What keeps those apart from these is chain order: a pre-registered resolver
    /// runs first and answers for its own clients before this one is asked.
    /// </para>
    /// </remarks>
    public bool CanResolve(ClientIdentifier clientId) => clientId.LooksLikeCimdUrl;

    /// <inheritdoc />
    public async ValueTask<ClientResolution> ResolveAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        if (!CimdClientIdUrl.TryParse(clientId.Value, out var url, out var shapeFailure))
        {
            return ClientResolution.Failed(ClientResolutionError.MetadataUnusable, shapeFailure);
        }

        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var now = _time.GetUtcNow();

        if (TryReadFresh(url.Value, now, out var cached))
        {
            // Recorded with a duration too, not just counted. A cache hit is not free — it is a
            // dictionary read on the authorize path — and the point of the histogram is that "how
            // long does resolving a client_id take" has one answer covering both routes, with
            // `outcome` telling you which population you are looking at.
            Record(started, "hit");
            return ClientResolution.Resolved(cached);
        }

        var flight = _inFlight.GetOrAdd(
            url.Value,
            key => new Lazy<Task<ClientResolution>>(() => RefreshAsync(key, url), LazyThreadSafetyMode.ExecutionAndPublication));

        // The shared work runs on no caller's cancellation token — see RefreshAsync — and each
        // caller waits on its own. Awaiting the shared task directly would let the first browser to
        // navigate away cancel the fetch for every other caller queued behind it.
        return await flight.Value.WaitAsync(cancellationToken);
    }

    /// <summary>
    /// The one fetch, shared by every caller for this <c>client_id</c>.
    /// </summary>
    /// <remarks>
    /// Takes no <see cref="CancellationToken"/>, deliberately. It is awaited by callers who each
    /// have their own, and a cancellation that propagated in here would abort work the other callers
    /// are still waiting on. What bounds it instead is the fetcher's own budget —
    /// <see cref="SafeHttpFetcherOptions.TotalTimeout"/>, or
    /// <see cref="CimdClientResolverOptions.FetchTimeout"/> when the caller sets one — which is a
    /// bound on the fetch itself rather than on one caller's patience.
    /// </remarks>
    private async Task<ClientResolution> RefreshAsync(string key, CimdClientIdUrl url)
    {
        // One timer for the shared work, and the tag set at whichever return actually fires. The
        // duration measured is the fetch every waiting caller is behind, not one caller's wait —
        // which is the number that answers "is the origin slow".
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var outcome = "error";

        try
        {
            var now = _time.GetUtcNow();

            // Another flight for this key may have completed between the caller's cache read and
            // its arrival here.
            if (TryReadFresh(key, now, out var refreshed))
            {
                outcome = "hit";
                return ClientResolution.Resolved(refreshed);
            }

            if (TryAnswerWithoutFetching(key, now, out var withoutFetching))
            {
                return withoutFetching;
            }

            var fetched = await _fetcher.FetchAsync(
                new SafeFetchRequest(
                    url.Url,
                    FetchPurpose.ClientIdMetadataDocument,
                    _options.MaxDocumentBytes,
                    _options.FetchTimeout),
                CancellationToken.None);

            if (fetched is not FetchOutcome.Ok ok)
            {
                // The fetcher's own per-host budget is not the client's fault and is not a failure
                // of the document, so it does not count against the breaker: doing so would let a
                // noisy neighbour on a shared host open the breaker for an innocent client_id.
                if (fetched is FetchOutcome.RateLimited limited)
                {
                    outcome = "stale";
                    return StaleOr(
                        key,
                        now,
                        ClientResolution.RateLimited(DescribeFetchFailure(fetched, _options.MaxDocumentBytes), limited.RetryAfter));
                }

                _breaker.RecordFailure(key);
                outcome = "stale";

                return StaleOr(
                    key,
                    now,
                    ClientResolution.Failed(
                        ClientResolutionError.MetadataUnusable,
                        DescribeFetchFailure(fetched, _options.MaxDocumentBytes)),
                    IsWorthServingStaleFor(fetched));
            }

            if (!CimdDocument.TryRead(ok.Body, ok.ContentType, url, _options, out var client, out var documentFailure))
            {
                _breaker.RecordFailure(key);

                // No stale-serve here, and that is the line: the origin answered 200 with a document,
                // so what it published is what it currently says about itself. Honouring the previous
                // document's redirect URIs against the client's own current statement is a different
                // act from surviving an outage, and it is one this server has no standing to perform.
                return ClientResolution.Failed(ClientResolutionError.MetadataUnusable, documentFailure);
            }

            _breaker.RecordSuccess(key);

            // Reached only on success. §5.2: "The authorization server MUST NOT cache error responses.
            // The authorization server also MUST NOT cache documents which are invalid or malformed."
            // Both of those are early returns above, so there is no branch here that could cache one.
            Cache(key, client, ok.MaxAge, now);

            outcome = "fetched";
            return ClientResolution.Resolved(client);
        }
        finally
        {
            Record(started, outcome);

            // Inside the shared work rather than in each caller, so the entry is gone before the
            // task is observable as completed. A caller arriving after this line starts a fresh
            // fetch; one arriving before it joins this one. Neither reads a finished result out of
            // the table, which is what would make this a cache of the outcome — including, for a
            // failure, the error §5.2 forbids caching.
            _ = _inFlight.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Whether this instance will decline to make the outbound request at all right now. X-31.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two independent budgets. The breaker answers "this identifier has failed repeatedly and it is
    /// too soon to try again"; the rate limiter answers "this identifier is asking too often,
    /// whatever the answers were". A caller who rotates through fresh failing identifiers defeats
    /// both, and is caught by the fetcher's per-host budget instead.
    /// </para>
    /// <para>
    /// The answer is a whole <see cref="ClientResolution"/> and not a refusal, because a stale
    /// entry — if there is one inside its window — is a better answer than a 429 and the decision
    /// belongs in one place.
    /// </para>
    /// </remarks>
    private bool TryAnswerWithoutFetching(string key, DateTimeOffset now, out ClientResolution answer)
    {
        var breaker = _breaker.TryBegin(key);

        if (!breaker.MayProceed)
        {
            answer = StaleOr(key, now, ClientResolution.RateLimited(
                "The client metadata document at this identifier has failed repeatedly, so this "
                + "server is not fetching it again yet.",
                breaker.RetryAfter));

            return true;
        }

        var budget = _fetchBudget.Acquire(key);

        if (!budget.Allowed)
        {
            answer = StaleOr(key, now, ClientResolution.RateLimited(
                "This client identifier has used up this server's fetch budget for it.",
                budget.RetryAfter));

            return true;
        }

        answer = null!;
        return false;
    }

    /// <summary>
    /// Serve the last good document if there is one and it is still inside the stale window.
    /// </summary>
    /// <remarks>
    /// Not a cached error and not a cached failure: the thing served is a document this server
    /// fetched, validated and cached while it was fresh. §5.2's prohibition is on remembering the
    /// error, and the error is exactly what is discarded here.
    /// </remarks>
    private ClientResolution StaleOr(string key, DateTimeOffset now, ClientResolution fallback, bool permitted = true)
    {
        if (!permitted || _options.StaleTolerance <= TimeSpan.Zero)
        {
            return fallback;
        }

        if (!_cache.TryGetValue(key, out var entry) || now >= entry.StaleUntil)
        {
            return fallback;
        }

        entry.Touch(now);

        return ClientResolution.Resolved(entry.Client);
    }

    /// <summary>
    /// Which fetch failures a previously-valid document should outlive.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rule is: the origin could not be reached, or could not answer. A timeout, a refused
    /// connection, a DNS failure and a 5xx are all the network or the origin being unavailable, and
    /// surviving them is the whole point of a stale window.
    /// </para>
    /// <para>
    /// Everything else is excluded because the origin <i>did</i> answer, and what it answered is a
    /// statement. A 4xx says the document is not there. A redirect says it moved. An oversized body
    /// says it is not a document this server will read. And a special-use address means the name now
    /// resolves somewhere private — which is a rebinding signal, and serving a stale document over
    /// the top of it would hide exactly the event worth seeing.
    /// </para>
    /// </remarks>
    private static bool IsWorthServingStaleFor(FetchOutcome outcome) => outcome switch
    {
        FetchOutcome.Timeout => true,
        FetchOutcome.TransportFailed => true,
        FetchOutcome.Blocked { Reason: BlockReason.DnsFailed } => true,
        FetchOutcome.NotOk notOk => notOk.Status is >= 500 or 429,
        _ => false,
    };

    /// <summary>
    /// Turn a fetch outcome into a sentence that names what happened. X-03, A-07, A-12.
    /// </summary>
    /// <remarks>
    /// Every case is distinct, and that is the requirement rather than a nicety. X-03 enumerates the
    /// CIMD failure conditions separately because they send whoever is debugging in different
    /// directions: a redirect means the URL is a shortener or a vanity domain, a special-use address
    /// means DNS is answering with something private, and a 404 means the file is not published. One
    /// shared "could not fetch client metadata" collapses all three into a day of guessing.
    /// </remarks>
    private static string DescribeFetchFailure(FetchOutcome outcome, int maxBytes) => outcome switch
    {
        // §5: "The authorization server MUST NOT automatically follow HTTP redirects when fetching
        // the Client ID Metadata Document." A redirect is therefore something to report, not
        // something to chase — and §3 notes this is why URL shorteners cannot be client identifiers.
        FetchOutcome.Redirected redirected =>
            $"The client metadata document answered HTTP {Number(redirected.Status)}; redirects are not followed (CIMD section 5).",

        // §5: "The Client ID Metadata Document MUST be served with a 200 OK HTTP status code. The
        // authorization server MUST treat all other HTTP status codes as an error response."
        FetchOutcome.NotOk notOk =>
            $"The client metadata document answered HTTP {Number(notOk.Status)}; only 200 is accepted (CIMD section 5).",

        FetchOutcome.TooLarge =>
            $"The client metadata document is larger than the {Number(maxBytes)}-byte read limit (CIMD section 8.7).",

        FetchOutcome.Timeout =>
            "Fetching the client metadata document timed out.",

        FetchOutcome.TransportFailed =>
            "The client metadata document could not be fetched: the connection or TLS handshake failed.",

        // X-31, and phrased as what happened rather than as a fault in the request: the identifier
        // may be fine and the document may be valid. The Detail names the budget, and the caller
        // turns this into a 429 with a Retry-After rather than an invalid_client.
        FetchOutcome.RateLimited limited =>
            $"The client metadata document was not fetched: {Echo(limited.Detail)}.",

        // The fetcher's own Detail carries the host and the address it resolved to, which is the
        // whole content of the diagnosis. It is truncated because it embeds a caller-supplied host,
        // and a host may be 253 characters: without the bound the sentence explaining the failure
        // would be the part ErrorText's 240-character cap threw away.
        FetchOutcome.Blocked { Reason: BlockReason.SpecialUseAddress } blocked =>
            $"Refused before connecting: {Echo(blocked.Detail)} (CIMD section 8.6).",

        FetchOutcome.Blocked { Reason: BlockReason.DnsFailed } blocked =>
            $"The client metadata document host did not resolve: {Echo(blocked.Detail)}",

        FetchOutcome.Blocked blocked =>
            $"The client metadata document URL was refused before connecting: {Echo(blocked.Detail)}",

        // FetchOutcome is a closed hierarchy with a private constructor, so this is unreachable
        // unless a case is added. It says so rather than pretending to a diagnosis.
        _ => "The client metadata document could not be fetched.",
    };

    /// <summary>Format an integer without asking the ambient culture what a digit is.</summary>
    private static string Number(int value) => value.ToString(CultureInfo.InvariantCulture);

    /// <summary>Bound a value that came from outside, so it cannot crowd out the explanation.</summary>
    private const int MaxEcho = 140;

    private static string Echo(string value) => value.Length <= MaxEcho ? value : value[..MaxEcho];

    /// <summary>Read a cache entry that is still inside its own lifetime.</summary>
    private bool TryReadFresh(string key, DateTimeOffset now, out ClientRecord client)
    {
        if (_cache.TryGetValue(key, out var entry) && now < entry.ExpiresAt)
        {
            entry.Touch(now);
            client = entry.Client;
            return true;
        }

        client = null!;
        return false;
    }

    /// <summary>Store a resolved client under the clamped lifetime. §5.2, S-30.</summary>
    private void Cache(string key, ClientRecord client, TimeSpan? maxAge, DateTimeOffset now)
    {
        // §5.2: "SHOULD respect HTTP cache headers ... but MAY define its own upper and/or lower
        // bounds". No Cache-Control at all means the floor rather than "do not cache": re-fetching
        // on every authorization would put an outbound request on the critical path of every sign-in.
        var lifetime = Clamp(maxAge ?? CimdClientResolverOptions.MinimumCacheLifetime);
        var expiresAt = now + lifetime;

        _cache[key] = new CacheEntry(client, expiresAt, expiresAt + _options.StaleTolerance, now);

        // After the insert, never instead of it. The previous policy refused admission at the cap,
        // and a measurement showed what that bought: 1024 anonymous requests carrying documents with
        // max-age=86400 filled the cache with live entries, and every client that connected
        // afterwards was then re-fetched on every single authorization — for a day, at the
        // attacker's choice, at no further cost to them. Evicting means an attacker can instead cost
        // some other client one fetch, which the budgets above bound and which recovers by itself.
        EnforceBound(now);
    }

    /// <summary>S-30's clamp: 300 s floor, 86 400 s ceiling.</summary>
    internal static TimeSpan Clamp(TimeSpan maxAge) =>
        maxAge < CimdClientResolverOptions.MinimumCacheLifetime ? CimdClientResolverOptions.MinimumCacheLifetime
        : maxAge > CimdClientResolverOptions.MaximumCacheLifetime ? CimdClientResolverOptions.MaximumCacheLifetime
        : maxAge;

    /// <summary>
    /// Keep the cache under its cap, dropping the least recently used entries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Least recently used, not soonest to expire.</b> The obvious policy is wrong here in a way
    /// that hands the cache to the attacker: expiry is taken from the origin's own
    /// <c>Cache-Control</c>, so a filler document declaring <c>max-age=86400</c> is clamped to the
    /// 24-hour ceiling and a real vendor document declaring <c>max-age=300</c> is clamped to the
    /// five-minute floor. Evicting by expiry evicts the vendors first and keeps the fillers, which
    /// is the previous behaviour with extra steps.
    /// </para>
    /// <para>
    /// Recency of <i>use</i> has the opposite bias: a filler is written once and never read again,
    /// while a client that is actually authorizing is read on every request. What it does not do is
    /// make any entry safe — a flood large enough, sustained long enough, still evicts anything. It
    /// costs the evicted client one fetch, not a day of them.
    /// </para>
    /// </remarks>
    private void EnforceBound(DateTimeOffset now)
    {
        if (_cache.Count <= _options.MaxCachedClients)
        {
            return;
        }

        lock (_evictionGate)
        {
            if (_cache.Count <= _options.MaxCachedClients)
            {
                return;
            }

            foreach (var (key, entry) in _cache)
            {
                if (now >= entry.StaleUntil)
                {
                    _ = _cache.TryRemove(new KeyValuePair<string, CacheEntry>(key, entry));
                }
            }

            if (_cache.Count <= _options.MaxCachedClients)
            {
                return;
            }

            var batch = Math.Max(1, _options.MaxCachedClients / 16);
            var surplus = _cache.Count - _options.MaxCachedClients + batch;

            foreach (var pair in _cache.OrderBy(e => e.Value.LastUsedTicks).Take(surplus))
            {
                _ = _cache.TryRemove(pair);
            }
        }
    }

    /// <summary>A cached document, when it goes stale, and when it stops being usable at all.</summary>
    /// <remarks>
    /// Absolute instants rather than a duration plus a fetch time, so reading the entry needs one
    /// comparison and no arithmetic — and so there is no second place that could apply the clamp
    /// differently. <see cref="StaleUntil"/> is fixed when the entry is written and is never pushed
    /// out by serving it, which is what bounds how long a dead origin can be papered over.
    /// </remarks>
    private sealed class CacheEntry(
        ClientRecord client, DateTimeOffset expiresAt, DateTimeOffset staleUntil, DateTimeOffset usedAt)
    {
        private long _lastUsedTicks = usedAt.UtcTicks;

        public ClientRecord Client { get; } = client;

        public DateTimeOffset ExpiresAt { get; } = expiresAt;

        public DateTimeOffset StaleUntil { get; } = staleUntil;

        /// <summary>When this entry was last read. The eviction order, and nothing else.</summary>
        public long LastUsedTicks => Volatile.Read(ref _lastUsedTicks);

        /// <summary>
        /// Mark the entry as used now.
        /// </summary>
        /// <remarks>
        /// Deliberately not <see cref="Interlocked"/>: two readers racing produce one of two
        /// timestamps microseconds apart, and either is a correct answer to "recently". Paying for a
        /// compare-and-swap on every cache hit to pick between them would be paying on the hot path
        /// for nothing.
        /// </remarks>
        public void Touch(DateTimeOffset now) => Volatile.Write(ref _lastUsedTicks, now.UtcTicks);
    }
}
