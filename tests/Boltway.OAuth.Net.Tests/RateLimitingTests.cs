using System.Globalization;
using System.Net;
using Boltway.OAuth.Net.RateLimiting;

namespace Boltway.OAuth.Net.Tests;

/// <summary>A clock a test moves. Every window below is driven by it, and none by sleeping.</summary>
internal sealed class MovableClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>
/// X-31's two primitives: the keyed budget and the negative-result breaker.
/// </summary>
/// <remarks>
/// <para>
/// Every guard here has been broken on purpose and watched to fail. The controls are recorded in the
/// commit message; the ones a reader can re-run are written as their own facts below - a limiter
/// that refuses everything passes every negative test, so each refusal is paired with the case that
/// must still be admitted.
/// </para>
/// <para>
/// Nothing here asserts anything about a fleet. These are per-process bounds, and a test with one
/// limiter in one process could not tell the difference - which is exactly why the claim is made in
/// prose on the types and not implied by a green test.
/// </para>
/// </remarks>
public sealed class KeyedRateLimiterTests
{
    private static DateTimeOffset Start => new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    private static KeyedRateLimiterOptions Options(int permits = 3) => new()
    {
        Window = TimeSpan.FromMinutes(1),
        PermitsPerWindow = permits,
        InitialBackoff = TimeSpan.FromSeconds(30),
        MaxBackoff = TimeSpan.FromMinutes(4),
        HistoryLifetime = TimeSpan.FromHours(1),
        MaxTrackedKeys = 64,
    };

    [Fact]
    public void The_permits_are_spent_before_anything_is_refused()
    {
        var limiter = new KeyedRateLimiter(new MovableClock(Start), Options());

        for (var i = 0; i < 3; i++)
        {
            Assert.True(limiter.Acquire("k").Allowed, $"attempt {i.ToString(CultureInfo.InvariantCulture)} should be allowed");
        }

        var refused = limiter.Acquire("k");

        Assert.False(refused.Allowed);
        Assert.True(refused.RetryAfter > TimeSpan.Zero, "a refusal with no Retry-After tells a client to retry immediately");
    }

    /// <summary>The control for the test above: another key has its own budget.</summary>
    [Fact]
    public void One_key_running_out_does_not_refuse_another()
    {
        var limiter = new KeyedRateLimiter(new MovableClock(Start), Options());

        for (var i = 0; i < 10; i++)
        {
            _ = limiter.Acquire("noisy");
        }

        Assert.True(limiter.Acquire("quiet").Allowed);
    }

    [Fact]
    public void A_block_ends_exactly_when_it_said_it_would()
    {
        var clock = new MovableClock(Start);
        var limiter = new KeyedRateLimiter(clock, Options());

        for (var i = 0; i < 4; i++)
        {
            _ = limiter.Acquire("k");
        }

        var refused = limiter.Acquire("k");
        Assert.False(refused.Allowed);

        // One tick short of the stated wait, still refused. Without this the assertion below is
        // satisfied by a limiter that forgot the block entirely.
        clock.Advance(refused.RetryAfter - TimeSpan.FromTicks(1));
        Assert.False(limiter.Acquire("k").Allowed);

        clock.Advance(TimeSpan.FromTicks(1));
        Assert.True(limiter.Acquire("k").Allowed);
    }

    [Fact]
    public void The_window_rolls_and_the_budget_refills()
    {
        var clock = new MovableClock(Start);
        var limiter = new KeyedRateLimiter(clock, Options());

        for (var i = 0; i < 3; i++)
        {
            Assert.True(limiter.Acquire("k").Allowed);
        }

        clock.Advance(TimeSpan.FromMinutes(1));

        Assert.True(limiter.Acquire("k").Allowed);
    }

    [Fact]
    public void The_backoff_doubles_per_breach_and_stops_at_the_ceiling()
    {
        var clock = new MovableClock(Start);
        var limiter = new KeyedRateLimiter(clock, Options());

        var waits = new List<TimeSpan>();

        for (var breach = 0; breach < 5; breach++)
        {
            for (var i = 0; i < 3; i++)
            {
                _ = limiter.Acquire("k");
            }

            var refused = limiter.Acquire("k");
            Assert.False(refused.Allowed);

            waits.Add(refused.RetryAfter);
            clock.Advance(refused.RetryAfter);
        }

        Assert.Equal(
            [
                TimeSpan.FromSeconds(30),
                TimeSpan.FromMinutes(1),
                TimeSpan.FromMinutes(2),
                TimeSpan.FromMinutes(4),
                TimeSpan.FromMinutes(4),
            ],
            waits);
    }

    [Fact]
    public void Reset_forgets_a_key_outright()
    {
        var limiter = new KeyedRateLimiter(new MovableClock(Start), Options());

        for (var i = 0; i < 4; i++)
        {
            _ = limiter.Acquire("k");
        }

        Assert.False(limiter.Acquire("k").Allowed);

        limiter.Reset("k");

        Assert.True(limiter.Acquire("k").Allowed);
    }

    /// <summary>
    /// A key nobody has touched for the history lifetime starts again, escalation included.
    /// </summary>
    /// <remarks>
    /// Without this, one bad afternoon leaves an address on the maximum backoff permanently: nothing
    /// else lowers it, so the second offence a week later is punished as the fifth.
    /// </remarks>
    [Fact]
    public void History_is_forgotten_after_the_idle_period()
    {
        var clock = new MovableClock(Start);
        var limiter = new KeyedRateLimiter(clock, Options());

        for (var i = 0; i < 4; i++)
        {
            _ = limiter.Acquire("k");
        }

        Assert.False(limiter.Acquire("k").Allowed);

        clock.Advance(TimeSpan.FromHours(1));

        for (var i = 0; i < 3; i++)
        {
            Assert.True(limiter.Acquire("k").Allowed);
        }

        // The first backoff again, not the second - the escalation went with the history.
        Assert.Equal(TimeSpan.FromSeconds(30), limiter.Acquire("k").RetryAfter);
    }

    [Fact]
    public void The_tracked_set_is_bounded()
    {
        var limiter = new KeyedRateLimiter(new MovableClock(Start), Options());

        for (var i = 0; i < 5_000; i++)
        {
            _ = limiter.Acquire("k" + i.ToString(CultureInfo.InvariantCulture));
        }

        Assert.True(
            limiter.TrackedKeys <= 64 + 64 / 16,
            $"the limiter is holding {limiter.TrackedKeys.ToString(CultureInfo.InvariantCulture)} keys against a cap of 64");
    }

    /// <summary>
    /// A blocked key outlives a flood of fresh ones, because eviction drops what expires soonest.
    /// </summary>
    /// <remarks>
    /// The property the bound would otherwise cost. It is not absolute and the type says so: a
    /// flood large enough and sustained long enough evicts anything. What this pins is that a
    /// single pass over the cap does not, because a fresh unblocked entry expires before a blocked
    /// one and is therefore chosen first.
    /// </remarks>
    [Fact]
    public void A_blocked_key_survives_a_flood_of_fresh_ones()
    {
        var clock = new MovableClock(Start);
        var limiter = new KeyedRateLimiter(clock, Options());

        for (var i = 0; i < 4; i++)
        {
            _ = limiter.Acquire("victim");
        }

        Assert.False(limiter.Acquire("victim").Allowed);

        for (var i = 0; i < 200; i++)
        {
            _ = limiter.Acquire("flood" + i.ToString(CultureInfo.InvariantCulture));
        }

        Assert.False(limiter.Acquire("victim").Allowed);
    }

    [Fact]
    public void Keys_are_compared_ordinally()
    {
        var limiter = new KeyedRateLimiter(new MovableClock(Start), Options(permits: 1));

        Assert.True(limiter.Acquire("Key").Allowed);
        Assert.True(limiter.Acquire("key").Allowed);
    }
}

/// <summary>The breaker, and the §5.2 distinction it rests on.</summary>
public sealed class NegativeResultBreakerTests
{
    private static DateTimeOffset Start => new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    private static NegativeResultBreakerOptions Options() => new()
    {
        ConsecutiveFailuresBeforeOpen = 3,
        Cooldown = TimeSpan.FromSeconds(60),
        MaxCooldown = TimeSpan.FromMinutes(4),
        MaxTrackedKeys = 64,
    };

    [Fact]
    public void Failures_below_the_threshold_do_not_open_it()
    {
        var breaker = new NegativeResultBreaker(new MovableClock(Start), Options());

        breaker.RecordFailure("k");
        breaker.RecordFailure("k");

        Assert.True(breaker.TryBegin("k").MayProceed);
    }

    [Fact]
    public void The_nth_consecutive_failure_opens_it()
    {
        var breaker = new NegativeResultBreaker(new MovableClock(Start), Options());

        for (var i = 0; i < 3; i++)
        {
            breaker.RecordFailure("k");
        }

        var decision = breaker.TryBegin("k");

        Assert.False(decision.MayProceed);
        Assert.Equal(TimeSpan.FromSeconds(60), decision.RetryAfter);
    }

    /// <summary>
    /// A success clears the key outright, which is what makes this not a cache of the error.
    /// </summary>
    /// <remarks>
    /// CIMD §5.2 forbids caching an error response. A cached error would still be served after the
    /// origin recovered; this cannot be, because the first successful attempt removes the entry and
    /// the count with it.
    /// </remarks>
    [Fact]
    public void A_success_forgets_everything()
    {
        var breaker = new NegativeResultBreaker(new MovableClock(Start), Options());

        breaker.RecordFailure("k");
        breaker.RecordFailure("k");
        breaker.RecordSuccess("k");

        // Nothing at all is left, not merely a closed breaker: the count that would have opened it
        // on the next failure is gone with the entry.
        Assert.Equal(0, breaker.TrackedKeys);

        breaker.RecordFailure("k");
        breaker.RecordFailure("k");

        Assert.True(breaker.TryBegin("k").MayProceed);
    }

    /// <summary>
    /// A key blocked by the breaker outlives a flood of fresh ones.
    /// </summary>
    /// <remarks>
    /// The control for the bound. Written after eviction-by-expiry was measured doing the opposite:
    /// with a cooldown shorter than the idle lifetime, every fresh entry outranked the open one and
    /// the flood cleared the breaker it was supposed to be caught by.
    /// </remarks>
    [Fact]
    public void An_open_breaker_survives_a_flood_of_fresh_keys()
    {
        var breaker = new NegativeResultBreaker(new MovableClock(Start), Options());

        for (var i = 0; i < 3; i++)
        {
            breaker.RecordFailure("victim");
        }

        Assert.False(breaker.TryBegin("victim").MayProceed);

        for (var i = 0; i < 200; i++)
        {
            breaker.RecordFailure("flood" + i.ToString(CultureInfo.InvariantCulture));
        }

        Assert.False(breaker.TryBegin("victim").MayProceed);
    }

    [Fact]
    public void The_cooldown_lets_exactly_one_probe_through()
    {
        var clock = new MovableClock(Start);
        var breaker = new NegativeResultBreaker(clock, Options());

        for (var i = 0; i < 3; i++)
        {
            breaker.RecordFailure("k");
        }

        clock.Advance(TimeSpan.FromSeconds(60));

        Assert.True(breaker.TryBegin("k").MayProceed);

        // The caller behind the probe. Without the re-arm inside TryBegin, every request queued at
        // the moment the breaker reopens becomes an attempt, which is the burst it exists to stop.
        Assert.False(breaker.TryBegin("k").MayProceed);
    }

    [Fact]
    public void A_failed_probe_backs_further_off_and_stops_at_the_ceiling()
    {
        var clock = new MovableClock(Start);
        var breaker = new NegativeResultBreaker(clock, Options());

        for (var i = 0; i < 3; i++)
        {
            breaker.RecordFailure("k");
        }

        var waits = new List<TimeSpan> { breaker.TryBegin("k").RetryAfter };

        for (var probe = 0; probe < 4; probe++)
        {
            clock.Advance(waits[^1]);
            Assert.True(breaker.TryBegin("k").MayProceed);

            breaker.RecordFailure("k");
            waits.Add(breaker.TryBegin("k").RetryAfter);
        }

        Assert.Equal(
            [
                TimeSpan.FromSeconds(60),
                TimeSpan.FromSeconds(120),
                TimeSpan.FromSeconds(240),
                TimeSpan.FromMinutes(4),
                TimeSpan.FromMinutes(4),
            ],
            waits);
    }

    /// <summary>
    /// A probe that succeeds reopens the key immediately, with no residue.
    /// </summary>
    /// <remarks>
    /// The other half of the §5.2 argument: what the breaker holds is a decision not to act, not an
    /// answer. One real attempt with a real result replaces it entirely.
    /// </remarks>
    [Fact]
    public void A_successful_probe_reopens_the_key_at_once()
    {
        var clock = new MovableClock(Start);
        var breaker = new NegativeResultBreaker(clock, Options());

        for (var i = 0; i < 3; i++)
        {
            breaker.RecordFailure("k");
        }

        clock.Advance(TimeSpan.FromSeconds(60));

        Assert.True(breaker.TryBegin("k").MayProceed);
        breaker.RecordSuccess("k");

        Assert.True(breaker.TryBegin("k").MayProceed);
        Assert.True(breaker.TryBegin("k").MayProceed);
    }

    [Fact]
    public void The_tracked_set_is_bounded()
    {
        var breaker = new NegativeResultBreaker(new MovableClock(Start), Options());

        for (var i = 0; i < 2_000; i++)
        {
            breaker.RecordFailure("k" + i.ToString(CultureInfo.InvariantCulture));
        }

        Assert.True(
            breaker.TrackedKeys <= 64 + 64 / 16,
            $"the breaker is holding {breaker.TrackedKeys.ToString(CultureInfo.InvariantCulture)} keys against a cap of 64");
    }
}

/// <summary>
/// The fetcher's own per-remote-host outbound budget. X-31.
/// </summary>
/// <remarks>
/// It lives in the fetcher rather than in a caller for the same reason the RFC 6890 check does:
/// every outbound request in this solution goes through this one class, so a bound here is a bound
/// on all of them, including whatever fetches a <c>jwks_uri</c> or a <c>logo_uri</c> later.
/// </remarks>
public sealed class OutboundHostBudgetTests
{
    private static DateTimeOffset Start => new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Counts arrivals at the network layer. The budget runs before it, so this count is the
    /// number of fetches that got past the budget.
    /// </summary>
    private sealed class CountingResolver : IAddressResolver
    {
        public int Calls { get; private set; }

        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            Calls++;

            // Loopback, so the special-use check refuses before a socket is opened. What is being
            // counted is arrival here.
            return Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
        }
    }

    private static SafeHttpFetcherOptions Options() => new()
    {
        MaxFetchesPerHostPerWindow = 5,
        HostRateLimitWindow = TimeSpan.FromMinutes(1),
        HostRateLimitBackoff = TimeSpan.FromMinutes(1),
    };

    private static async Task<FetchOutcome> FetchAsync(SafeHttpFetcher fetcher, string url)
    {
        Assert.True(AbsoluteHttpsUrl.TryCreate(url, out var parsed), url);

        return await fetcher.FetchAsync(
            new SafeFetchRequest(parsed, FetchPurpose.ClientIdMetadataDocument), CancellationToken.None);
    }

    [Fact]
    public async Task A_host_over_its_budget_is_refused_before_the_network_is_touched()
    {
        var resolver = new CountingResolver();
        using var fetcher = new SafeHttpFetcher(Options(), resolver, new MovableClock(Start));

        var outcomes = new List<FetchOutcome>();

        for (var i = 0; i < 20; i++)
        {
            outcomes.Add(await FetchAsync(fetcher, "https://victim.example/c" + i.ToString(CultureInfo.InvariantCulture)));
        }

        Assert.Equal(5, resolver.Calls);
        Assert.Equal(5, outcomes.Count(o => o is FetchOutcome.Blocked));

        var limited = outcomes.OfType<FetchOutcome.RateLimited>().ToList();

        Assert.Equal(15, limited.Count);
        Assert.All(limited, l => Assert.True(l.RetryAfter > TimeSpan.Zero));
        Assert.All(limited, l => Assert.Contains("victim.example", l.Detail, StringComparison.Ordinal));
    }

    /// <summary>
    /// The budget is per host, so a port scan spends one host's worth rather than one per port.
    /// </summary>
    /// <remarks>
    /// This is the measured shape of the abuse: one anonymous authorization request per port, each
    /// producing one connection with the port preserved. Keyed on host:port each port would have its
    /// own budget and the bound would be nothing.
    /// </remarks>
    [Fact]
    public async Task Every_port_on_one_host_shares_one_budget()
    {
        var resolver = new CountingResolver();
        using var fetcher = new SafeHttpFetcher(Options(), resolver, new MovableClock(Start));

        for (var port = 9000; port < 9100; port++)
        {
            _ = await FetchAsync(fetcher, $"https://victim.example:{port.ToString(CultureInfo.InvariantCulture)}/c");
        }

        Assert.Equal(5, resolver.Calls);
    }

    /// <summary>The control: the bound is per host, not a global one that would stop the server.</summary>
    [Fact]
    public async Task A_different_host_has_its_own_budget()
    {
        var resolver = new CountingResolver();
        using var fetcher = new SafeHttpFetcher(Options(), resolver, new MovableClock(Start));

        for (var i = 0; i < 20; i++)
        {
            _ = await FetchAsync(fetcher, "https://victim.example/c");
        }

        Assert.IsType<FetchOutcome.Blocked>(await FetchAsync(fetcher, "https://elsewhere.example/c"));
    }

    [Fact]
    public async Task The_budget_refills_on_the_injected_clock()
    {
        var clock = new MovableClock(Start);
        var resolver = new CountingResolver();
        using var fetcher = new SafeHttpFetcher(Options(), resolver, clock);

        for (var i = 0; i < 20; i++)
        {
            _ = await FetchAsync(fetcher, "https://victim.example/c");
        }

        Assert.Equal(5, resolver.Calls);

        clock.Advance(TimeSpan.FromMinutes(1));

        Assert.IsType<FetchOutcome.Blocked>(await FetchAsync(fetcher, "https://victim.example/c"));
        Assert.Equal(6, resolver.Calls);
    }

    /// <summary>
    /// The control for every test above: an ordinary volume of fetches is not touched.
    /// </summary>
    /// <remarks>
    /// A limiter that refused everything would satisfy all four assertions above. The shipped
    /// default is sixty a minute per host, and the two live vendors publish two documents each on
    /// two hosts - so this is the traffic a real deployment produces, driven against the real
    /// default rather than the tightened one the other tests use.
    /// </remarks>
    [Fact]
    public async Task The_shipped_default_does_not_touch_vendor_shaped_traffic()
    {
        var resolver = new CountingResolver();
        using var fetcher = new SafeHttpFetcher(new SafeHttpFetcherOptions(), resolver, new MovableClock(Start));

        foreach (var host in new[] { "claude.ai", "chatgpt.com" })
        {
            for (var i = 0; i < 20; i++)
            {
                Assert.IsType<FetchOutcome.Blocked>(
                    await FetchAsync(fetcher, $"https://{host}/oauth/client{i.ToString(CultureInfo.InvariantCulture)}"));
            }
        }

        Assert.Equal(40, resolver.Calls);
    }
}
