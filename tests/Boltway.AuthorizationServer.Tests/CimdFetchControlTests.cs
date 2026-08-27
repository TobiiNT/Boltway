using System.Globalization;
using System.Net;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Clients;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A fetcher that can be made slow and can be counted. For single-flight and for concurrency.
/// </summary>
/// <remarks>
/// Separate from <c>StubFetcher</c> because that one is synchronous and records into a plain
/// <see cref="List{T}"/>, which is not safe to drive from sixty-four threads - a test that raced it
/// would fail for the harness's reasons rather than the server's.
/// </remarks>
internal sealed class ConcurrentStubFetcher : ISafeHttpFetcher
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, FetchOutcome> _responses =
        new(StringComparer.Ordinal);

    private int _calls;
    private int _inFlight;
    private int _peakInFlight;

    /// <summary>How many outbound fetches were made. The measurement most of these tests turn on.</summary>
    public int Calls => Volatile.Read(ref _calls);

    /// <summary>The most fetches that were ever in flight at once.</summary>
    public int PeakInFlight => Volatile.Read(ref _peakInFlight);

    /// <summary>How long each fetch takes, so a burst really does overlap.</summary>
    public TimeSpan Delay { get; set; }

    /// <summary>Set when a fetch observed its own cancellation token already cancelled.</summary>
    public bool SawCancellation { get; private set; }

    private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private TaskCompletionSource? _release;

    /// <summary>
    /// Hold every fetch inside <see cref="FetchAsync"/> until <see cref="Release"/> is called.
    /// </summary>
    /// <remarks>
    /// For the tests that need a fetch to still be in flight while they assert something about the
    /// callers waiting on it. <see cref="Delay"/> cannot do that job: a delay is a bet that the test
    /// finishes its setup before the clock runs out, and on a loaded runner it loses - the fetch
    /// completes, the caller returns normally, and the assertion that a cancellation was observed
    /// fails with no defect present. A gate has no clock in it.
    /// </remarks>
    public ConcurrentStubFetcher Gated()
    {
        _release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        return this;
    }

    /// <summary>Completes once a fetch has entered and been counted.</summary>
    public Task Started => _started.Task;

    /// <summary>Let the gated fetches finish.</summary>
    public void Release() => _release?.TrySetResult();

    public ConcurrentStubFetcher Respond(string url, FetchOutcome outcome)
    {
        _responses[url] = outcome;
        return this;
    }

    public ConcurrentStubFetcher Serve(string url, string json, TimeSpan? maxAge = null)
    {
        _ = MediaType.TryParse("application/json", out var type);
        return Respond(url, new FetchOutcome.Ok(System.Text.Encoding.UTF8.GetBytes(json), type, null, maxAge));
    }

    public async Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (cancellationToken.IsCancellationRequested)
        {
            SawCancellation = true;
        }

        _ = Interlocked.Increment(ref _calls);
        var now = Interlocked.Increment(ref _inFlight);

        int seen;
        while (now > (seen = Volatile.Read(ref _peakInFlight)))
        {
            _ = Interlocked.CompareExchange(ref _peakInFlight, now, seen);
        }

        _ = _started.TrySetResult();

        try
        {
            if (_release is { } gate)
            {
                await gate.Task;
            }

            if (Delay > TimeSpan.Zero)
            {
                await Task.Delay(Delay, CancellationToken.None);
            }

            return _responses.TryGetValue(request.Url.Value, out var outcome) ? outcome : new FetchOutcome.NotOk(404);
        }
        finally
        {
            _ = Interlocked.Decrement(ref _inFlight);
        }
    }
}

/// <summary>
/// X-31 on the CIMD path: the fetch budget, the breaker, single-flight, stale-serve and eviction.
/// </summary>
/// <remarks>
/// <para>
/// The measurements these replace, taken on the code before this file existed: fifty sequential
/// anonymous <c>GET /authorize</c> with one failing <c>client_id</c> produced fifty outbound
/// fetches; sixty-four concurrent first resolutions of one <c>client_id</c> produced sixty-four; a
/// cache filled with 1024 documents declaring <c>max-age=86400</c> then refused to admit any new
/// entry, so every client that connected afterwards was re-fetched on every authorization.
/// </para>
/// <para>
/// Every limit here is per process. Nothing in this file could tell the difference between a
/// per-instance bound and a fleet-wide one, and no test in it claims to.
/// </para>
/// </remarks>
public sealed class CimdFetchControlTests
{
    private const string ClaudeId = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    private const string ClaudeCallback = "https://claude.ai/api/mcp/auth_callback";

    private static DateTimeOffset Start => new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    private static string Document(string clientId = ClaudeId, string callback = ClaudeCallback) =>
        $$"""{"client_id":"{{clientId}}","redirect_uris":["{{callback}}"]}""";

    private static ClientIdentifier Id(string clientId) =>
        ClientIdentifier.TryParseFromRequest(clientId, out var parsed)
            ? parsed
            : throw new InvalidOperationException($"'{clientId}' is not a usable client_id.");

    private static CimdClientResolverOptions Options() => new()
    {
        ConsecutiveFailuresBeforeBreakerOpens = 3,
        BreakerCooldown = TimeSpan.FromSeconds(60),
        MaxBreakerCooldown = TimeSpan.FromMinutes(10),
        MaxFetchesPerClientIdPerWindow = 10,
        FetchWindow = TimeSpan.FromMinutes(1),
        FetchBackoff = TimeSpan.FromMinutes(1),
        StaleTolerance = TimeSpan.FromHours(1),
    };

    // ─────────────────────────────────────────────────────────────────────────
    // The breaker
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A <c>client_id</c> whose document keeps failing stops producing outbound fetches.
    /// </summary>
    /// <remarks>
    /// The measurement this exists for: fifty resolutions used to be fifty fetches, because §5.2
    /// forbids caching the error - which is precisely what makes each request a fresh probe.
    /// </remarks>
    [Fact]
    public async Task Fifty_resolutions_of_a_failing_client_id_make_three_fetches()
    {
        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(503));
        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), Options());

        var outcomes = new List<ClientResolution>();

        for (var i = 0; i < 50; i++)
        {
            outcomes.Add(await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None));
        }

        Assert.Equal(3, fetcher.Calls);

        Assert.Equal(3, outcomes.Count(o => o.Error is ClientResolutionError.MetadataUnusable));
        Assert.Equal(47, outcomes.Count(o => o.Error is ClientResolutionError.RateLimited));

        var throttled = outcomes.Last();
        Assert.NotNull(throttled.RetryAfter);
        Assert.True(throttled.RetryAfter > TimeSpan.Zero);
    }

    /// <summary>
    /// The breaker refuses to fetch; it does not remember the answer. CIMD §5.2.
    /// </summary>
    /// <remarks>
    /// The distinction the specification draws, made checkable. A cached error would still be served
    /// after the origin recovered. Here the cooldown elapses, one real fetch happens, the origin now
    /// answers 200 - and the client resolves. Nothing of the 503 survived.
    /// </remarks>
    [Fact]
    public async Task The_breaker_refuses_to_fetch_rather_than_remembering_the_error()
    {
        var clock = new MovableClock(Start);
        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(503));
        var resolver = new CimdClientResolver(fetcher, clock, Options());

        for (var i = 0; i < 10; i++)
        {
            _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        }

        Assert.Equal(3, fetcher.Calls);

        // The origin is fixed while the breaker is open. Nothing tells the server so.
        _ = fetcher.Serve(ClaudeId, Document());

        Assert.Equal(
            ClientResolutionError.RateLimited,
            (await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Error);
        Assert.Equal(3, fetcher.Calls);

        clock.Advance(TimeSpan.FromSeconds(60));

        var recovered = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.NotNull(recovered.Client);
        Assert.Equal(4, fetcher.Calls);
    }

    /// <summary>
    /// The control: two failures do not open it, so an intermittent origin is not cut off.
    /// </summary>
    [Fact]
    public async Task Two_failures_do_not_open_the_breaker()
    {
        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(503));
        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), Options());

        for (var i = 0; i < 2; i++)
        {
            _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        }

        _ = fetcher.Serve(ClaudeId, Document());

        Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);
        Assert.Equal(3, fetcher.Calls);
    }

    /// <summary>A success anywhere in the run clears the count, so failures must be consecutive.</summary>
    [Fact]
    public async Task A_success_between_failures_clears_the_count()
    {
        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(503));
        var clock = new MovableClock(Start);

        // Stale-serve off, so this measures the breaker's count and nothing else. With it on the
        // later failures are answered from the entry the success cached, which is correct behaviour
        // and makes the count invisible - measured, this test read "resolved" for that reason.
        var options = Options();
        options.StaleTolerance = TimeSpan.Zero;

        var resolver = new CimdClientResolver(fetcher, clock, options);

        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        _ = fetcher.Serve(ClaudeId, Document());
        Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);

        // Past the entry's own lifetime, so the next resolutions really fetch.
        clock.Advance(TimeSpan.FromSeconds(301));
        _ = fetcher.Respond(ClaudeId, new FetchOutcome.NotOk(503));

        // Two more failures. Were the count not cleared, the second of these would be the third and
        // would open the breaker.
        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.Equal(
            ClientResolutionError.MetadataUnusable,
            (await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Error);
    }

    /// <summary>
    /// A per-<c>client_id</c> fetch budget, independent of whether the fetches are failing.
    /// </summary>
    /// <remarks>
    /// The breaker catches a failing identifier. This catches one that resolves and is being asked
    /// for far faster than any cache lifetime allows - which needs the origin to keep answering with
    /// something uncacheable, and is the case the breaker's consecutive-failure count would miss.
    /// </remarks>
    [Fact]
    public async Task A_client_id_has_a_fetch_budget_of_its_own()
    {
        var options = Options();
        options.ConsecutiveFailuresBeforeBreakerOpens = int.MaxValue;

        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(404));
        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), options);

        for (var i = 0; i < 30; i++)
        {
            _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        }

        Assert.Equal(10, fetcher.Calls);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Single-flight
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sixty-four concurrent first resolutions share one fetch, and all sixty-four get the client.
    /// </summary>
    /// <remarks>
    /// A cache entry expires at one instant for everybody, so a burst of sign-ins for a popular
    /// client is exactly this shape rather than a contrived one. Measured before: sixty-four
    /// fetches.
    /// </remarks>
    [Fact]
    public async Task Concurrent_resolutions_of_one_client_id_share_one_fetch()
    {
        var fetcher = new ConcurrentStubFetcher { Delay = TimeSpan.FromMilliseconds(50) };
        _ = fetcher.Serve(ClaudeId, Document());

        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), Options());

        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ =>
            Task.Run(async () => await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None))));

        Assert.Equal(1, fetcher.Calls);
        Assert.Equal(1, fetcher.PeakInFlight);
        Assert.All(results, r => Assert.NotNull(r.Client));
    }

    /// <summary>
    /// The control: two different <c>client_id</c> values are not collapsed into one another.
    /// </summary>
    /// <remarks>
    /// A single-flight table keyed on something too coarse - the host, say - would serve one
    /// client's document to another, which is the CIMD self-reference check defeated from inside.
    /// </remarks>
    [Fact]
    public async Task Concurrent_resolutions_of_different_client_ids_are_not_shared()
    {
        const string Sibling = "https://claude.ai/oauth/other";

        var fetcher = new ConcurrentStubFetcher { Delay = TimeSpan.FromMilliseconds(50) };
        _ = fetcher.Serve(ClaudeId, Document());
        _ = fetcher.Serve(Sibling, Document(Sibling, "https://claude.ai/other-cb"));

        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), Options());

        var results = await Task.WhenAll(
            Task.Run(async () => await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)),
            Task.Run(async () => await resolver.ResolveAsync(Id(Sibling), CancellationToken.None)));

        Assert.Equal(2, fetcher.Calls);
        Assert.Equal(ClaudeId, results[0].Client!.ClientId.Value);
        Assert.Equal(Sibling, results[1].Client!.ClientId.Value);
    }

    /// <summary>
    /// Single-flight ends with the fetch; it is not a cache of the result. §5.2.
    /// </summary>
    /// <remarks>
    /// The risk in coalescing is that the in-flight table quietly becomes a place where a failure
    /// lives after it has been decided. Two sequential failing resolutions must therefore be two
    /// fetches, below the breaker's threshold - and they are, because the entry is removed before
    /// the shared task can be observed as completed.
    /// </remarks>
    [Fact]
    public async Task Sequential_failing_resolutions_each_fetch()
    {
        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(404));
        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), Options());

        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.Equal(2, fetcher.Calls);
    }

    /// <summary>
    /// One caller giving up does not cancel the fetch the others are waiting on.
    /// </summary>
    /// <remarks>
    /// The classic single-flight defect. Whoever happens to start the shared work would otherwise
    /// own its cancellation token, so the first browser to navigate away aborts the authorization of
    /// everyone queued behind it - a failure that only appears under concurrency and reads as a
    /// flaky server.
    /// <para>
    /// <b>Gated rather than timed, because the timed version failed on CI with no defect present.</b>
    /// It gave the leaver a 150 ms fetch and 30 ms to start it, then cancelled. On a runner whose
    /// thread pool is saturated by the rest of the suite, the continuation after a 30 ms delay can
    /// be scheduled well past 150 ms - so the fetch had already completed, the leaver returned a
    /// resolution, and the run failed on <c>Assert.ThrowsAny() Failure: No exception was thrown</c>.
    /// Both sleeps are gone: the fetch cannot finish until this test releases it, and the stayer
    /// signals that its thread is running rather than being assumed to have started.
    /// </para>
    /// <para>
    /// <c>Calls == 1</c> is the assertion that says they shared one fetch, and it is new. Without it
    /// a stayer that started its own second fetch - which is what the defect being guarded against
    /// produces, since it removes the in-flight entry - would still see a document and still see no
    /// cancellation, and the test would pass.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task One_caller_cancelling_does_not_abort_the_shared_fetch()
    {
        var fetcher = new ConcurrentStubFetcher().Gated();
        _ = fetcher.Serve(ClaudeId, Document());

        var resolver = new CimdClientResolver(fetcher, new MovableClock(Start), Options());

        using var giveUp = new CancellationTokenSource();

        var leaver = Task.Run(async () => await resolver.ResolveAsync(Id(ClaudeId), giveUp.Token));

        // The leaver owns the in-flight fetch from here, and that fetch cannot complete until this
        // test says so. Nothing about the timing of what follows can end it early.
        await fetcher.Started;

        var stayerRunning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var stayer = Task.Run(async () =>
        {
            stayerRunning.SetResult();
            return await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        });

        await stayerRunning.Task;

        await giveUp.CancelAsync();

        // Deterministic: ResolveAsync awaits the shared task through WaitAsync(cancellationToken),
        // so the caller's token cancels the caller's wait and the fetch is still gated.
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await leaver);

        fetcher.Release();

        var resolution = await stayer;

        Assert.NotNull(resolution.Client);
        Assert.Equal(1, fetcher.Calls);
        Assert.False(fetcher.SawCancellation, "the shared fetch was handed a caller's cancellation token");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stale-serve
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>An expired entry survives an origin that has stopped answering.</summary>
    [Fact]
    public async Task An_expired_document_is_served_when_the_refresh_fails()
    {
        var clock = new MovableClock(Start);
        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var resolver = new CimdClientResolver(fetcher, clock, Options());

        Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);

        clock.Advance(TimeSpan.FromSeconds(301));
        _ = fetcher.Respond(ClaudeId, new FetchOutcome.NotOk(503));

        var stale = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.NotNull(stale.Client);
        Assert.Equal(ClaudeCallback, stale.Client!.RedirectUris.Single().Value);
    }

    /// <summary>
    /// The stale window is bounded, and serving from it does not push the bound out.
    /// </summary>
    /// <remarks>
    /// Without the second half, a permanently dead origin would be papered over forever: each stale
    /// serve would renew the entry and the tolerance would never elapse. The window is fixed when
    /// the entry is written.
    /// </remarks>
    [Fact]
    public async Task The_stale_window_is_bounded_and_is_not_extended_by_using_it()
    {
        var clock = new MovableClock(Start);
        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var resolver = new CimdClientResolver(fetcher, clock, Options());

        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);
        _ = fetcher.Respond(ClaudeId, new FetchOutcome.NotOk(503));

        // Eleven serves spread over the hour, each one an opportunity to renew the window.
        for (var i = 0; i < 11; i++)
        {
            clock.Advance(TimeSpan.FromMinutes(5));
            Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);
        }

        clock.Advance(TimeSpan.FromMinutes(10));

        var refused = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.Null(refused.Client);
    }

    /// <summary>
    /// Stale-serve covers an origin that could not answer, and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The line is whether the origin made a statement. A 404 says the document is not published; a
    /// redirect says it moved; a document that fails validation is what the client publishes now.
    /// Serving the previous document over any of those is this server overruling the client about
    /// its own registration.
    /// </para>
    /// <para>
    /// A link-local answer is here for a different reason: the origin did not make a statement, but
    /// nothing benign resolves a public name into <c>169.254.0.0/16</c>, so it is the one address
    /// answer worth keeping a client broken over rather than papering over with a cache entry.
    /// </para>
    /// <para>
    /// <strong>This row used to be every special-use address, and that was wrong.</strong> It said
    /// one "means the name resolves somewhere private, which is a rebinding signal" - an inference
    /// from a single lookup, where a filtered resolver, split-horizon DNS and an attack are the same
    /// observation. The row was also spelled with <c>169.254.169.254</c> under
    /// <c>SpecialUseAddress</c>, so it only ever exercised the case that survives. What it cost was
    /// the rest: a client whose name a resolver had begun filtering lost its cached document, while
    /// the same block delivered as <c>NXDOMAIN</c> kept serving one theory below.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("404")]
    [InlineData("redirect")]
    [InlineData("too-large")]
    [InlineData("link-local")]
    [InlineData("malformed")]
    public async Task Stale_serve_does_not_cover_an_origin_that_answered(string kind)
    {
        var clock = new MovableClock(Start);
        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var resolver = new CimdClientResolver(fetcher, clock, Options());
        Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);

        clock.Advance(TimeSpan.FromSeconds(301));

        _ = fetcher.Respond(ClaudeId, kind switch
        {
            "404" => new FetchOutcome.NotOk(404),
            "redirect" => new FetchOutcome.Redirected(302, "https://elsewhere.example/c"),
            "too-large" => new FetchOutcome.TooLarge(5 * 1024),
            "link-local" => new FetchOutcome.Blocked(
                BlockReason.LinkLocalAddress,
                "'client.example' resolves to 169.254.169.254, which is link-local (RFC 3927)."),
            _ => Malformed(),
        });

        var resolution = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.Null(resolution.Client);
        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);

        static FetchOutcome Malformed()
        {
            _ = MediaType.TryParse("application/json", out var type);
            return new FetchOutcome.Ok(System.Text.Encoding.UTF8.GetBytes("{"), type, null, TimeSpan.FromHours(12));
        }
    }

    /// <summary>The controls for the theory above: the failures stale-serve does cover.</summary>
    /// <remarks>
    /// <c>special-use</c> is here rather than in the theory above because serving the cache connects
    /// to nothing - the address check has already refused - so refusing the cache as well refuses no
    /// further connection, and the only thing it achieved was signing out every client of a name
    /// somebody's resolver had begun filtering. <c>dns</c> is the same block spelled
    /// <c>NXDOMAIN</c>, and it was already on this side.
    /// </remarks>
    [Theory]
    [InlineData("503")]
    [InlineData("429")]
    [InlineData("timeout")]
    [InlineData("transport")]
    [InlineData("dns")]
    [InlineData("special-use")]
    public async Task Stale_serve_covers_an_origin_that_could_not_answer(string kind)
    {
        var clock = new MovableClock(Start);
        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var resolver = new CimdClientResolver(fetcher, clock, Options());
        Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);

        clock.Advance(TimeSpan.FromSeconds(301));

        _ = fetcher.Respond(ClaudeId, kind switch
        {
            "503" => new FetchOutcome.NotOk(503),
            "429" => new FetchOutcome.NotOk(429),
            "timeout" => new FetchOutcome.Timeout(TimeSpan.FromSeconds(5)),
            "dns" => new FetchOutcome.Blocked(BlockReason.DnsFailed, "'claude.ai' did not resolve."),
            "special-use" => new FetchOutcome.Blocked(
                BlockReason.SpecialUseAddress,
                "'client.example' resolves to 0.0.0.0, which is a special-use address (RFC 6890)."),
            _ => new FetchOutcome.TransportFailed("connection reset"),
        });

        Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);
    }

    /// <summary>A throttled refresh serves stale too: a budget is not a reason to sign a user out.</summary>
    [Fact]
    public async Task A_stale_entry_beats_a_rate_limit()
    {
        var clock = new MovableClock(Start);
        var options = Options();
        options.ConsecutiveFailuresBeforeBreakerOpens = 1;

        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var resolver = new CimdClientResolver(fetcher, clock, options);
        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        clock.Advance(TimeSpan.FromSeconds(301));
        _ = fetcher.Respond(ClaudeId, new FetchOutcome.NotOk(503));

        // One failure opens the breaker with this configuration; the entry is still inside its
        // stale window, so what comes back is the document rather than a 429.
        _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        var next = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

        Assert.NotNull(next.Client);
        Assert.Equal(2, fetcher.Calls);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The cache bound
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A full cache evicts rather than refusing to admit.
    /// </summary>
    /// <remarks>
    /// The measurement: with admission refused at the cap, a client connecting after 1024 attacker
    /// documents with <c>max-age=86400</c> was re-fetched on every authorization - ten resolutions,
    /// ten fetches - for as long as the fillers lived. Now it is fetched once.
    /// </remarks>
    [Fact]
    public async Task A_client_arriving_after_a_cache_fill_is_still_cached()
    {
        var clock = new MovableClock(Start);
        var options = Options();
        options.MaxCachedClients = 64;

        var fetcher = new ConcurrentStubFetcher();
        var resolver = new CimdClientResolver(fetcher, clock, options);

        for (var i = 0; i < 256; i++)
        {
            var filler = $"https://filler{i.ToString(CultureInfo.InvariantCulture)}.example/c";
            _ = fetcher.Serve(filler, Document(filler, $"https://filler{i.ToString(CultureInfo.InvariantCulture)}.example/cb"), TimeSpan.FromSeconds(86_400));
            _ = await resolver.ResolveAsync(Id(filler), CancellationToken.None);

            clock.Advance(TimeSpan.FromMilliseconds(100));
        }

        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var before = fetcher.Calls;

        for (var i = 0; i < 10; i++)
        {
            Assert.NotNull((await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None)).Client);
        }

        Assert.Equal(1, fetcher.Calls - before);
        Assert.True(resolver.CachedCount <= 64 + 64 / 16, $"the cache holds {resolver.CachedCount.ToString(CultureInfo.InvariantCulture)} entries");
    }

    /// <summary>
    /// A client that is in use survives a fill; eviction is by recency of use, not by expiry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Evicting by expiry would be exactly backwards, and the fillers here prove it: they declare
    /// <c>max-age=86400</c> and clamp to the 24-hour ceiling, while the vendor documents declare
    /// <c>max-age=300</c> and clamp to the five-minute floor. Ordering by expiry evicts the vendors
    /// first and keeps the fillers.
    /// </para>
    /// <para>
    /// <b>What this does not claim.</b> An entry that is <i>not</i> being used during a fill is
    /// evicted - that is the cost of the change and it is measured: a client resolved once before a
    /// 1024-document fill and not used during it is re-fetched afterwards, where the old
    /// refuse-admission policy would have kept it. One fetch, against a day of them for everyone
    /// else.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_client_in_use_survives_a_cache_fill()
    {
        var clock = new MovableClock(Start);
        var options = Options();
        options.MaxCachedClients = 64;

        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(ClaudeId, Document(), TimeSpan.FromSeconds(300));

        var resolver = new CimdClientResolver(fetcher, clock, options);

        for (var i = 0; i < 256; i++)
        {
            var filler = $"https://filler{i.ToString(CultureInfo.InvariantCulture)}.example/c";
            _ = fetcher.Serve(filler, Document(filler, $"https://filler{i.ToString(CultureInfo.InvariantCulture)}.example/cb"), TimeSpan.FromSeconds(86_400));
            _ = await resolver.ResolveAsync(Id(filler), CancellationToken.None);

            // The vendor is authorizing throughout, which is what "in use" means.
            _ = await resolver.ResolveAsync(Id(ClaudeId), CancellationToken.None);

            clock.Advance(TimeSpan.FromMilliseconds(100));
        }

        Assert.Equal(257, fetcher.Calls);
    }
}
