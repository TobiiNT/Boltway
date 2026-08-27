using System.Net;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The readiness probe: that it reaches the store, that it is bounded, and that it says nothing
/// about the failure it saw.
/// </summary>
/// <remarks>
/// This lives in the library and therefore in a test project, which is the entire reason the type
/// is not three lines in the host. The host is referenced by nothing that compiles in CI except the
/// Docker build, and a Docker build cannot tell a working probe from one that always answers yes -
/// the lesson <c>ProxyHeadersTests</c> is named after.
/// </remarks>
public sealed class StoreReadinessTests
{
    /// <summary>An <see cref="IUserStore"/> that counts lookups and can be made to fail or hang.</summary>
    private sealed class ProbeableStore : IUserStore
    {
        private int _lookups;

        public int Lookups => Volatile.Read(ref _lookups);

        public List<SubjectId> Asked { get; } = [];

        public Exception? Throw { get; set; }

        public TimeSpan Delay { get; set; }

        public async Task<UserAccount?> FindBySubjectAsync(
            SubjectId subject, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _lookups);
            lock (Asked)
            {
                Asked.Add(subject);
            }

            if (Delay > TimeSpan.Zero)
            {
                // Real delay, real token: this is the path the timeout has to cut short, so faking
                // it with an immediate throw would test the catch block and not the deadline.
                await Task.Delay(Delay, cancellationToken).ConfigureAwait(false);
            }

            return Throw is null ? null : throw Throw;
        }

        public Task<UserAccount?> FindByUsernameAsync(RealmId realm, string username, CancellationToken cancellationToken) =>
            Task.FromResult<UserAccount?>(null);

        public Task<UserAccount?> FindByVerifiedEmailAsync(
            RealmId realm, string email, CancellationToken cancellationToken) =>
            Task.FromResult<UserAccount?>(null);

        public Task<IReadOnlyList<ExternalLogin>> ListExternalLoginsAsync(
            SubjectId subject, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ExternalLogin>>([]);

        public Task<UserAccount?> FindByExternalLoginAsync(
            RealmId realm, string upstreamIssuer, string upstreamSubject, CancellationToken cancellationToken) =>
            Task.FromResult<UserAccount?>(null);

        public Task StoreAsync(UserAccount user, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task LinkExternalLoginAsync(ExternalLogin link, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<bool> SetRolesAsync(SubjectId subject, IReadOnlyList<string> roles, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> SetPasswordHashAsync(
            SubjectId subject, string passwordHash, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> StampSessionsAsync(
            SubjectId subject, DateTimeOffset at, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> SetEnabledAsync(
            SubjectId subject, DateTimeOffset? disabledAt, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> SetEmailAsync(
            SubjectId subject, string? email, bool verified, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<IReadOnlyList<UserAccount>> ListAsync(
            RealmId realm, SubjectId? after, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<UserAccount>>([]);

        public Task<bool> AnonymiseAsync(
            SubjectId subject, string tombstoneUsername, DateTimeOffset now, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }

    private static StoreReadiness Build(
        ProbeableStore store,
        MovableClock clock,
        TimeSpan? freshFor = null,
        TimeSpan? timeout = null) =>
        new(store, clock, NullLogger<StoreReadiness>.Instance, freshFor, timeout);

    private static MovableClock Clock() => new(new DateTimeOffset(2026, 8, 9, 20, 0, 0, TimeSpan.Zero));

    // ─────────────────────────────────────────────────────────────────────────
    // It reaches the store
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_store_that_answers_is_reachable()
    {
        var store = new ProbeableStore();

        Assert.True(await Build(store, Clock()).IsReachableAsync(CancellationToken.None));
        Assert.Equal(1, store.Lookups);
    }

    /// <summary>The probe is a real lookup, and this is what says so.</summary>
    /// <remarks>
    /// Without this the whole type could be a method returning <c>true</c> and every other test here
    /// would still pass. What is asserted is that the store was asked, and asked for the documented
    /// subject rather than something a real user could own.
    /// </remarks>
    [Fact]
    public async Task It_asks_the_store_for_the_probe_subject()
    {
        var store = new ProbeableStore();

        await Build(store, Clock()).IsReachableAsync(CancellationToken.None);

        Assert.Equal(StoreReadiness.ProbeSubject, Assert.Single(store.Asked));
    }

    /// <summary>The control: no minted subject can collide with the probe's.</summary>
    [Fact]
    public void No_minted_subject_can_be_the_probe_subject()
    {
        var factory = new UlidSubjectIdFactory(Clock());

        for (var i = 0; i < 500; i++)
        {
            Assert.NotEqual(StoreReadiness.ProbeSubject, factory.Mint());
        }
    }

    [Fact]
    public async Task A_store_that_throws_is_unreachable()
    {
        var store = new ProbeableStore { Throw = new InvalidOperationException("connection refused") };

        Assert.False(await Build(store, Clock()).IsReachableAsync(CancellationToken.None));
    }

    /// <summary>A hang is an outage, and the deadline is what turns it into one.</summary>
    [Fact]
    public async Task A_store_that_hangs_is_unreachable_rather_than_hanging()
    {
        var store = new ProbeableStore { Delay = TimeSpan.FromMinutes(5) };
        var readiness = Build(store, Clock(), timeout: TimeSpan.FromMilliseconds(50));

        // The wall clock, not the injected one: the deadline is a real CancelAfter, and a test that
        // could only pass by advancing a fake clock would not be testing it.
        Assert.False(await readiness.IsReachableAsync(CancellationToken.None));
    }

    /// <summary>A caller giving up is not the store failing.</summary>
    /// <remarks>
    /// Without the <c>when</c> filter on the catch, a disconnected client would be recorded as an
    /// unreachable database - and then cached as one, so one cancelled request would make the next
    /// five seconds of monitoring lie.
    /// </remarks>
    [Fact]
    public async Task A_cancelled_caller_is_not_reported_as_an_unreachable_store()
    {
        var store = new ProbeableStore { Delay = TimeSpan.FromMinutes(5) };
        var readiness = Build(store, Clock(), timeout: TimeSpan.FromMinutes(5));

        using var caller = new CancellationTokenSource();
        var probe = readiness.IsReachableAsync(caller.Token);
        await caller.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);
    }

    /// <summary>And the instance still works afterwards.</summary>
    /// <remarks>
    /// <para>
    /// The test above asserted the symptom and missed the invariant, which is how the bug it was
    /// written for survived it. A cancelled probe threw out of <c>IsReachableAsync</c> before the
    /// line that clears <c>_probing</c>, so the flag stayed set for the life of the process; every
    /// later call then took the "somebody is already refreshing" branch and returned the cached
    /// answer forever. <b>One client disconnecting froze readiness</b>, and if it was frozen at
    /// "reachable" the monitor reported healthy through every outage after it - the failure this
    /// whole endpoint exists to remove, reintroduced by the endpoint.
    /// </para>
    /// <para>
    /// What makes this test see it and the other one not: it asks the object to do its job again.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_cancelled_caller_does_not_freeze_the_answer_for_good()
    {
        var store = new ProbeableStore();
        var clock = Clock();
        var readiness = Build(store, clock, freshFor: TimeSpan.FromSeconds(5), timeout: TimeSpan.FromMinutes(5));

        // 1. A probe that completes. This is the step the first version of this test left out, and
        //    leaving it out is why that version passed against the bug: with nothing yet known, the
        //    "somebody is already refreshing" branch cannot be reached, so a leaked flag is
        //    invisible. The bug needs an answer to be frozen *at*.
        Assert.True(await readiness.IsReachableAsync(CancellationToken.None));

        // 2. Let it go stale, then cancel a caller mid-probe.
        clock.Advance(TimeSpan.FromSeconds(5));
        store.Delay = TimeSpan.FromMinutes(5);

        using (var caller = new CancellationTokenSource())
        {
            var probe = readiness.IsReachableAsync(caller.Token);
            await caller.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);
        }

        // 3. The store goes down for real.
        store.Delay = TimeSpan.Zero;
        store.Throw = new InvalidOperationException("connection refused");

        // 4. Without the fix this answers `true` - the cached success from step 1, served forever,
        //    while the database is on fire. Asserting the harm rather than a call count, because
        //    the harm is the thing: a monitor reporting healthy through an outage is worse than no
        //    monitor, and one disconnected client was enough to cause it.
        Assert.False(await readiness.IsReachableAsync(CancellationToken.None));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // It is bounded
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Inside_the_window_the_store_is_not_touched_again()
    {
        var store = new ProbeableStore();
        var clock = Clock();
        var readiness = Build(store, clock, freshFor: TimeSpan.FromSeconds(5));

        for (var i = 0; i < 20; i++)
        {
            Assert.True(await readiness.IsReachableAsync(CancellationToken.None));
            clock.Advance(TimeSpan.FromMilliseconds(200));
        }

        // Twenty requests over four seconds, one query. This is the property that keeps a public
        // endpoint from being a way to generate database load.
        Assert.Equal(1, store.Lookups);
    }

    [Fact]
    public async Task Past_the_window_it_probes_again()
    {
        var store = new ProbeableStore();
        var clock = Clock();
        var readiness = Build(store, clock, freshFor: TimeSpan.FromSeconds(5));

        await readiness.IsReachableAsync(CancellationToken.None);
        clock.Advance(TimeSpan.FromSeconds(5));
        await readiness.IsReachableAsync(CancellationToken.None);

        Assert.Equal(2, store.Lookups);
    }

    /// <summary>A cached "unreachable" has to clear, or recovery is invisible until a restart.</summary>
    [Fact]
    public async Task It_recovers_once_the_store_does()
    {
        var store = new ProbeableStore { Throw = new InvalidOperationException("connection refused") };
        var clock = Clock();
        var readiness = Build(store, clock, freshFor: TimeSpan.FromSeconds(5));

        Assert.False(await readiness.IsReachableAsync(CancellationToken.None));

        store.Throw = null;
        clock.Advance(TimeSpan.FromSeconds(5));

        Assert.True(await readiness.IsReachableAsync(CancellationToken.None));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // On the wire
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IHost> HostWith(ProbeableStore store)
    {
        return await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(TimeProvider.System);
                    services.AddSingleton<IUserStore>(store);
                    services.AddSingleton(sp => new StoreReadiness(
                        store, TimeProvider.System, NullLogger<StoreReadiness>.Instance));
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapStoreReadiness());
                }))
            .StartAsync();
    }

    [Fact]
    public async Task A_reachable_store_answers_200()
    {
        using var host = await HostWith(new ProbeableStore());
        using var client = host.GetTestClient();

        var response = await client.GetAsync(
            new Uri("/health/ready", UriKind.Relative), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            "\"store\":\"reachable\"",
            await response.Content.ReadAsStringAsync(CancellationToken.None),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// 503, because the consumer is an uptime check and a status code is the one thing every uptime
    /// check reads. 200 with <c>ok:false</c> is a monitor that stays green through an outage.
    /// </summary>
    [Fact]
    public async Task An_unreachable_store_answers_503()
    {
        using var host = await HostWith(
            new ProbeableStore { Throw = new InvalidOperationException("connection refused") });
        using var client = host.GetTestClient();

        var response = await client.GetAsync(
            new Uri("/health/ready", UriKind.Relative), CancellationToken.None);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    /// <summary>The response is public, so it must not describe the failure.</summary>
    /// <remarks>
    /// A driver exception names hosts, databases, roles and versions. The string asserted against
    /// here is the one the fake throws; if anybody ever "improves" the endpoint by passing the
    /// message through, this is what says no.
    /// </remarks>
    [Fact]
    public async Task The_failure_response_carries_no_detail_about_the_failure()
    {
        const string Detail = "Npgsql: host=db.internal user=postgres password rejected";

        using var host = await HostWith(new ProbeableStore { Throw = new InvalidOperationException(Detail) });
        using var client = host.GetTestClient();

        var response = await client.GetAsync(
            new Uri("/health/ready", UriKind.Relative), CancellationToken.None);
        var body = await response.Content.ReadAsStringAsync(CancellationToken.None);

        Assert.DoesNotContain("Npgsql", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("db.internal", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"store\":\"unreachable\"", body, StringComparison.Ordinal);
    }
}
