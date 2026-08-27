using System.Collections.Concurrent;

namespace Boltway.OAuth.Net.RateLimiting;

/// <summary>Whether one attempt may proceed, and how long to wait if not.</summary>
/// <param name="Allowed">Whether the attempt may proceed.</param>
/// <param name="RetryAfter">
/// How long until the key is admissible again. <see cref="TimeSpan.Zero"/> when
/// <paramref name="Allowed"/>, and always positive when it is not - X-31 requires a
/// <c>Retry-After</c>, and a zero there tells a client to retry immediately.
/// </param>
public readonly record struct RateDecision(bool Allowed, TimeSpan RetryAfter)
{
    /// <summary>The attempt may proceed.</summary>
    public static RateDecision Allow { get; } = new(true, TimeSpan.Zero);

    /// <summary>The attempt is refused for this long.</summary>
    public static RateDecision Refuse(TimeSpan retryAfter) =>
        new(false, retryAfter > TimeSpan.Zero ? retryAfter : TimeSpan.FromSeconds(1));
}

/// <summary>Knobs for <see cref="KeyedRateLimiter"/>.</summary>
public sealed class KeyedRateLimiterOptions
{
    /// <summary>The counting window.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How many attempts one key may make inside one <see cref="Window"/>.</summary>
    public int PermitsPerWindow { get; set; } = 10;

    /// <summary>How long a key is refused the first time it exceeds <see cref="PermitsPerWindow"/>.</summary>
    public TimeSpan InitialBackoff { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The longest a key is ever refused. The backoff doubles per consecutive breach up to this.
    /// </summary>
    /// <remarks>
    /// Set equal to <see cref="InitialBackoff"/> for a flat limiter with no escalation, which is
    /// what a machine-to-machine budget wants: escalation is for a caller that keeps pushing after
    /// being told to stop, and it is what makes a slow guessing attack expensive.
    /// </remarks>
    public TimeSpan MaxBackoff { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How long a key must be untouched before its history - counters <b>and</b> escalation - is
    /// forgotten.
    /// </summary>
    /// <remarks>
    /// Without this, one bad afternoon leaves an address on the longest backoff forever, because
    /// nothing ever lowers it again.
    /// </remarks>
    public TimeSpan HistoryLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How many keys may be tracked at once.
    /// </summary>
    /// <remarks>
    /// A bound, because the key is attacker-chosen in every use here - a <c>client_id</c> URL, a
    /// remote host, a submitted username, a source address. Without it the limiter is itself the
    /// memory-exhaustion primitive it was added to prevent. See <see cref="KeyedRateLimiter"/> for
    /// which entry is dropped at the cap and what that costs.
    /// </remarks>
    public int MaxTrackedKeys { get; set; } = 16_384;
}

/// <summary>
/// A fixed-window attempt counter per key, with an escalating backoff. <b>In memory, per instance.</b>
/// </summary>
/// <remarks>
/// <para>
/// <b>The bound is per process, and that is a limitation rather than a detail.</b> A deployment
/// running <i>n</i> instances behind a load balancer enforces <i>n</i> times whatever is configured
/// here, because each instance counts only the requests it happened to receive, and a caller
/// spreading requests across the fleet is counted separately by each. Nothing in this type observes
/// the other instances, and no comment anywhere should describe its limits as fleet-wide. A
/// fleet-wide bound needs a shared store; this is the floor under it, not a substitute.
/// </para>
/// <para>
/// It is still worth having on its own: a single instance is where the CPU, the memory and the
/// outbound sockets actually are, so a per-instance bound is what stops one instance being starved
/// by one caller - which is the failure that was measured.
/// </para>
/// <para>
/// Fixed window rather than sliding or token bucket, on purpose. A fixed window admits up to twice
/// <see cref="KeyedRateLimiterOptions.PermitsPerWindow"/> across a window boundary, and that is
/// acceptable here because every limit is set with an order of magnitude of headroom over legitimate
/// traffic. What it buys is that one entry is four fields and one comparison, so the limiter cannot
/// itself become the expensive part of a request under load.
/// </para>
/// </remarks>
public sealed class KeyedRateLimiter
{
    private readonly TimeProvider _time;
    private readonly KeyedRateLimiterOptions _options;
    private readonly ConcurrentDictionary<string, Entry> _entries;
    private readonly object _evictionGate = new();

    /// <summary>Create a limiter.</summary>
    /// <param name="time">The clock. Injected so every window here is testable without sleeping.</param>
    /// <param name="options">The limits, or the defaults.</param>
    public KeyedRateLimiter(TimeProvider time, KeyedRateLimiterOptions? options = null)
    {
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options ?? new KeyedRateLimiterOptions();
        _entries = new ConcurrentDictionary<string, Entry>(StringComparer.Ordinal);
    }

    /// <summary>How many keys are being tracked. For tests and for a doctor probe.</summary>
    public int TrackedKeys => _entries.Count;

    /// <summary>
    /// Count one attempt against a key and say whether it may proceed.
    /// </summary>
    /// <param name="key">
    /// The bucket. Compared ordinally, so the caller owns normalisation - two spellings that should
    /// share a budget must arrive here as one string.
    /// </param>
    /// <remarks>
    /// The attempt is counted whether or not it is allowed, which is what makes this work against a
    /// simultaneous burst. A limiter that counted only completed failures would admit all of a
    /// hundred requests that arrived together, because none of them has failed yet when the last one
    /// is admitted.
    /// </remarks>
    public RateDecision Acquire(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var now = _time.GetUtcNow();
        var entry = _entries.GetOrAdd(key, _ => new Entry(now));

        EnforceBound(now);

        lock (entry)
        {
            // A key nobody has touched for HistoryLifetime starts again from nothing, escalation
            // included. Read before the block check, so a key blocked for longer than its own
            // history lifetime cannot be held past it.
            if (now - entry.LastSeen >= _options.HistoryLifetime)
            {
                entry.Reset(now);
            }

            entry.LastSeen = now;

            if (now < entry.BlockedUntil)
            {
                return RateDecision.Refuse(entry.BlockedUntil - now);
            }

            if (now - entry.WindowStart >= _options.Window)
            {
                entry.WindowStart = now;
                entry.Used = 0;
            }

            entry.Used++;

            if (entry.Used <= _options.PermitsPerWindow)
            {
                return RateDecision.Allow;
            }

            entry.Breaches++;

            var backoff = Backoff(entry.Breaches);

            entry.BlockedUntil = now + backoff;
            entry.WindowStart = now;
            entry.Used = 0;

            return RateDecision.Refuse(backoff);
        }
    }

    /// <summary>
    /// Forget a key's history entirely.
    /// </summary>
    /// <remarks>
    /// For the caller that has proof the attempts were legitimate - a correct password against the
    /// account being counted. Whether that proof exists is the caller's judgement and not this
    /// type's: calling it on a key an attacker can also reach hands them a reset button.
    /// </remarks>
    public void Reset(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        _ = _entries.TryRemove(key, out _);
    }

    /// <summary>Double per consecutive breach, capped, and without overflowing on the shift.</summary>
    private TimeSpan Backoff(int breaches)
    {
        var doublings = Math.Min(breaches - 1, 30);
        var scaled = _options.InitialBackoff.Ticks * (1L << doublings);

        return scaled >= _options.MaxBackoff.Ticks || scaled < 0
            ? _options.MaxBackoff
            : TimeSpan.FromTicks(scaled);
    }

    /// <summary>
    /// Keep the tracked set under the cap, dropping the entries that matter least.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>By how much an entry is still enforcing, not by how old it is.</b> Least-recently-used is
    /// the wrong policy here and was measured to be: under a flood of fresh keys, every entry's
    /// last-seen time is newer than the blocked entry's, so LRU drops precisely the key that was
    /// being held. The order is dead entries, then entries that hold nothing but escalation history,
    /// then entries counting inside a live window, and blocked entries last.
    /// </para>
    /// <para>
    /// <b>Dropping a live entry releases whatever block it carried.</b> That is the cost of a bound,
    /// and it is real: a caller who can create enough distinct keys, and keep creating them, will
    /// eventually push a blocked entry out even under this ordering, because blocked entries are
    /// only evicted last rather than never. What makes it a poor attack rather than a bypass is that
    /// the flood is itself counted under whatever key the caller shares - a source address, a remote
    /// host - and that the flood's own entries are always chosen first. The honest statement is that
    /// the cap trades a hard memory bound for a soft enforcement one.
    /// </para>
    /// </remarks>
    private void EnforceBound(DateTimeOffset now)
    {
        if (_entries.Count <= _options.MaxTrackedKeys)
        {
            return;
        }

        // One evictor at a time. Under a key flood every call arrives here, and letting all of them
        // scan concurrently turns the defence into the load.
        lock (_evictionGate)
        {
            if (_entries.Count <= _options.MaxTrackedKeys)
            {
                return;
            }

            foreach (var (key, entry) in _entries)
            {
                if (now >= ExpiryOf(entry))
                {
                    _ = _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));
                }
            }

            if (_entries.Count <= _options.MaxTrackedKeys)
            {
                return;
            }

            // A batch rather than exactly one, so a sustained flood pays for the scan once every
            // few hundred inserts instead of on every one.
            var batch = Math.Max(1, _options.MaxTrackedKeys / 16);
            var surplus = _entries.Count - _options.MaxTrackedKeys + batch;

            foreach (var pair in _entries
                .Select(e => (Pair: e, Order: EvictionOrderOf(e.Value, now)))
                .OrderBy(e => e.Order.Rank)
                .ThenBy(e => e.Order.Until)
                .Take(surplus))
            {
                _ = _entries.TryRemove(pair.Pair);
            }
        }
    }

    /// <summary>When an entry stops being able to refuse anything, so it is safe to forget.</summary>
    private DateTimeOffset ExpiryOf(Entry entry)
    {
        lock (entry)
        {
            var window = entry.WindowStart + _options.Window;
            var history = entry.LastSeen + _options.HistoryLifetime;
            var latest = entry.BlockedUntil > window ? entry.BlockedUntil : window;

            return latest > history ? latest : history;
        }
    }

    /// <summary>How much an entry is still doing, lowest first. See <see cref="EnforceBound"/>.</summary>
    private (int Rank, DateTimeOffset Until) EvictionOrderOf(Entry entry, DateTimeOffset now)
    {
        lock (entry)
        {
            if (now < entry.BlockedUntil)
            {
                return (3, entry.BlockedUntil);
            }

            if (entry.Used > 0 && now < entry.WindowStart + _options.Window)
            {
                return (2, entry.WindowStart + _options.Window);
            }

            return (1, entry.LastSeen + _options.HistoryLifetime);
        }
    }

    /// <summary>One key's counters. Mutable, and every read and write holds its own monitor.</summary>
    private sealed class Entry(DateTimeOffset now)
    {
        public DateTimeOffset WindowStart { get; set; } = now;

        public DateTimeOffset LastSeen { get; set; } = now;

        public DateTimeOffset BlockedUntil { get; set; } = DateTimeOffset.MinValue;

        public int Used { get; set; }

        /// <summary>Consecutive breaches, which is what the backoff escalates on.</summary>
        public int Breaches { get; set; }

        public void Reset(DateTimeOffset now)
        {
            WindowStart = now;
            LastSeen = now;
            BlockedUntil = DateTimeOffset.MinValue;
            Used = 0;
            Breaches = 0;
        }
    }
}
