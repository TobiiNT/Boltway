using System.Collections.Concurrent;

namespace Boltway.OAuth.Net.RateLimiting;

/// <summary>Whether an attempt against a key may be made, and how long to wait if not.</summary>
/// <param name="MayProceed">Whether the caller should go ahead.</param>
/// <param name="RetryAfter">How long until the breaker will let one through, when it will not now.</param>
public readonly record struct BreakerDecision(bool MayProceed, TimeSpan RetryAfter)
{
    /// <summary>Go ahead.</summary>
    public static BreakerDecision Proceed { get; } = new(true, TimeSpan.Zero);

    /// <summary>Do not go ahead; try again after this long.</summary>
    public static BreakerDecision Open(TimeSpan retryAfter) =>
        new(false, retryAfter > TimeSpan.Zero ? retryAfter : TimeSpan.FromSeconds(1));
}

/// <summary>Knobs for <see cref="NegativeResultBreaker"/>.</summary>
public sealed class NegativeResultBreakerOptions
{
    /// <summary>How many consecutive failures open the breaker for a key.</summary>
    public int ConsecutiveFailuresBeforeOpen { get; set; } = 3;

    /// <summary>How long the breaker stays open the first time.</summary>
    public TimeSpan Cooldown { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>The longest the breaker stays open. It doubles per failed probe up to this.</summary>
    public TimeSpan MaxCooldown { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How many keys may be tracked. Attacker-chosen, so bounded.</summary>
    public int MaxTrackedKeys { get; set; } = 4_096;
}

/// <summary>
/// Stops repeating an operation that keeps failing for one key. <b>In memory, per instance.</b>
/// </summary>
/// <remarks>
/// <para>
/// <b>Refusing to act is not the same as remembering an answer, and the difference is the whole
/// reason this type exists rather than a negative cache.</b> CIMD §5.2 says an authorization server
/// "MUST NOT cache error responses" and "MUST NOT cache documents which are invalid or malformed".
/// Nothing here holds a response, a status, a body or a reason: an entry is a count and two
/// timestamps. When the breaker is open the caller does not receive a remembered failure — it
/// receives a different answer, computed now, that says the operation was not attempted and when to
/// ask again. The moment the cooldown elapses the next caller performs a real fetch and its real
/// result is used, and a single success clears the entry outright. That is the distinction §5.2
/// draws: a cached error would still be served after the origin recovered; this cannot be.
/// </para>
/// <para>
/// <b>Per instance.</b> Each process has its own breaker, so a fleet of <i>n</i> instances will make
/// up to <i>n</i> probes per cooldown rather than one, and a caller whose requests land on different
/// instances opens each one separately. That is a real limit on what this bounds and it is not
/// described anywhere as fleet-wide.
/// </para>
/// <para>
/// Half-open by construction: when the cooldown elapses, exactly one caller is let through and the
/// cooldown is immediately re-armed, so a burst arriving at the moment the breaker reopens produces
/// one attempt rather than all of them. A failed probe doubles the cooldown up to
/// <see cref="NegativeResultBreakerOptions.MaxCooldown"/>.
/// </para>
/// </remarks>
public sealed class NegativeResultBreaker
{
    private readonly TimeProvider _time;
    private readonly NegativeResultBreakerOptions _options;
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly object _evictionGate = new();

    /// <summary>Create a breaker.</summary>
    /// <param name="time">The clock. Injected so the cooldown is testable without sleeping.</param>
    /// <param name="options">The thresholds, or the defaults.</param>
    public NegativeResultBreaker(TimeProvider time, NegativeResultBreakerOptions? options = null)
    {
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _options = options ?? new NegativeResultBreakerOptions();
    }

    /// <summary>How many keys are being tracked. For tests.</summary>
    public int TrackedKeys => _entries.Count;

    /// <summary>Whether an attempt for this key should be made now.</summary>
    /// <param name="key">The bucket, compared ordinally.</param>
    public BreakerDecision TryBegin(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (!_entries.TryGetValue(key, out var entry))
        {
            return BreakerDecision.Proceed;
        }

        var now = _time.GetUtcNow();

        lock (entry)
        {
            if (now < entry.OpenUntil)
            {
                return BreakerDecision.Open(entry.OpenUntil - now);
            }

            if (entry.OpenUntil > DateTimeOffset.MinValue)
            {
                // The half-open probe. Re-arm before returning, so the caller behind this one is
                // still refused and one attempt is made rather than the whole queued burst.
                entry.OpenUntil = now + entry.Cooldown;
            }

            return BreakerDecision.Proceed;
        }
    }

    /// <summary>Record that the operation succeeded, which forgets the key entirely.</summary>
    public void RecordSuccess(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        _ = _entries.TryRemove(key, out _);
    }

    /// <summary>Record that the operation failed. The Nth consecutive failure opens the breaker.</summary>
    public void RecordFailure(string key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var now = _time.GetUtcNow();
        var entry = _entries.GetOrAdd(key, _ => new Entry(now, _options.Cooldown));

        EnforceBound(now);

        lock (entry)
        {
            entry.LastSeen = now;
            entry.Failures++;

            if (entry.Failures < _options.ConsecutiveFailuresBeforeOpen)
            {
                return;
            }

            if (entry.OpenUntil > DateTimeOffset.MinValue)
            {
                // A probe that failed. Back further off, capped.
                var doubled = entry.Cooldown.Ticks * 2;

                entry.Cooldown = doubled >= _options.MaxCooldown.Ticks || doubled < 0
                    ? _options.MaxCooldown
                    : TimeSpan.FromTicks(doubled);
            }

            entry.OpenUntil = now + entry.Cooldown;
        }
    }

    private void EnforceBound(DateTimeOffset now)
    {
        if (_entries.Count <= _options.MaxTrackedKeys)
        {
            return;
        }

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

            // Open entries last, closed ones first, oldest of each first — not simply by expiry, and
            // not by recency. A flood of fresh keys is all newer than the key that is actually open,
            // so either of those orderings drops precisely the entry that is doing the work.
            //
            // Dropping a live entry closes the breaker for that key, which costs one more attempt at
            // whatever was failing. The alternative — refusing to track a new key once full — leaves
            // the breaker permanently blind to every key after the first MaxTrackedKeys, which is
            // the failure mode the CIMD cache had.
            var batch = Math.Max(1, _options.MaxTrackedKeys / 16);
            var surplus = _entries.Count - _options.MaxTrackedKeys + batch;

            foreach (var entry in _entries
                .Select(e => (Pair: e, Order: EvictionOrderOf(e.Value, now)))
                .OrderBy(e => e.Order.Rank)
                .ThenBy(e => e.Order.Until)
                .Take(surplus))
            {
                _ = _entries.TryRemove(entry.Pair);
            }
        }
    }

    private DateTimeOffset ExpiryOf(Entry entry)
    {
        lock (entry)
        {
            // A closed entry is only a failure count, and a count nobody has added to for a full
            // maximum cooldown is not going to open anything.
            var idle = entry.LastSeen + _options.MaxCooldown;

            return entry.OpenUntil > idle ? entry.OpenUntil : idle;
        }
    }

    /// <summary>How much an entry is still doing, lowest first. See <see cref="EnforceBound"/>.</summary>
    private (int Rank, DateTimeOffset Until) EvictionOrderOf(Entry entry, DateTimeOffset now)
    {
        lock (entry)
        {
            return now < entry.OpenUntil
                ? (2, entry.OpenUntil)
                : (1, entry.LastSeen + _options.MaxCooldown);
        }
    }

    private sealed class Entry(DateTimeOffset now, TimeSpan cooldown)
    {
        public int Failures { get; set; }

        public DateTimeOffset LastSeen { get; set; } = now;

        /// <summary><see cref="DateTimeOffset.MinValue"/> while the breaker has never opened.</summary>
        public DateTimeOffset OpenUntil { get; set; } = DateTimeOffset.MinValue;

        public TimeSpan Cooldown { get; set; } = cooldown;
    }
}
