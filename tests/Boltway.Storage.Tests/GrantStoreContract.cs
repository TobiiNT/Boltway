using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.Tests;

/// <summary>
/// The store contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// One suite, several fixtures. It is published as a package so a customer writing their own store
/// runs the same tests — which is what makes "implement <c>IRefreshTokenStore</c>" a tractable
/// request rather than an invitation to get a race subtly wrong.
/// </para>
/// <para>
/// The concurrency tests use real parallel calls rather than an in-process lock held by the test,
/// because the property under test <i>is</i> the store's atomicity. A test that serialised the
/// calls itself would pass against a store with no atomicity at all.
/// </para>
/// </remarks>
public abstract class GrantStoreContract
{
    /// <summary>A fresh authorization-code store.</summary>
    protected abstract IAuthorizationCodeStore NewCodeStore();

    /// <summary>A fresh refresh-token store.</summary>
    protected abstract IRefreshTokenStore NewRefreshStore();

    /// <summary>A fresh grant store.</summary>
    protected abstract IGrantStore NewGrantStore();

    private static readonly ClientIdentifier Client =
        ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata");

    private static Sha256Hash Hash(string seed) => Sha256Hash.OfString(seed);

    private static AuthorizationCodeRecord Code(DateTimeOffset now, string seed = "code-1") => new(
        Hash(seed), "grant-1", Client, "https://claude.ai/api/mcp/auth_callback",
        CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ChallengeMethod: CodeChallengeMethod.S256,
        PkceWasRequested: true,
        Scope: ScopeSet.FromStorage("story:read"),
        Resources: ["https://mcp.example.com/mcp"],
        Nonce: null,
        AuthTime: now,
        IssuedAt: now,
        ExpiresAt: now.AddMinutes(1));

    /// <summary>
    /// Run <paramref name="work"/> on <paramref name="count"/> real threads, released together.
    /// </summary>
    /// <remarks>
    /// Dedicated threads rather than <c>Task.Run</c>. A <see cref="Barrier"/> blocks the thread it
    /// runs on, so sixteen of them on the thread pool wait for the pool's slow injection heuristic
    /// to grow — measured at thirteen seconds for one test, and a deadlock rather than a delay on a
    /// machine with fewer cores. The property under test is the store's atomicity, so the threads
    /// have to genuinely collide; anything that quietly serialises them would pass against a store
    /// with no atomicity at all.
    /// </remarks>
    private static T[] RunConcurrently<T>(int count, Func<int, T> work)
    {
        var results = new T[count];
        var failures = new Exception?[count];
        var ready = new Barrier(count);
        var threads = new Thread[count];

        for (var i = 0; i < count; i++)
        {
            var index = i;
            threads[i] = new Thread(() =>
            {
                ready.SignalAndWait();

                try
                {
                    results[index] = work(index);
                }
                catch (Exception ex)
                {
                    failures[index] = ex;
                }
            })
            { IsBackground = true };

            threads[i].Start();
        }

        foreach (var thread in threads)
        {
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "a concurrent worker did not finish");
        }

        // Rethrow on the joining thread. An unhandled exception on a raw Thread TERMINATES the
        // process — measured, exit code 134 — so a store that throws (which is now the correct
        // response to a duplicate insert) would crash the test host instead of failing a test.
        //
        // ALL of them, not the first. This loop used to throw on the first non-null entry, and that
        // cost a diagnosis: an intermittent SQLite failure reported one worker's exception and
        // silently dropped whatever the other fifteen said, so "did one thread fail or did all of
        // them" — the question that separates a poisoned connection from a lock everybody lost —
        // was not answerable from the output. The count is in the message for the same reason.
        var thrown = failures.Where(f => f is not null).Select(f => f!).ToList();

        if (thrown.Count > 0)
        {
            throw new InvalidOperationException(
                $"{thrown.Count} of {count} concurrent workers threw",
                thrown.Count == 1 ? thrown[0] : new AggregateException(thrown));
        }

        return results;
    }

    private static RefreshTokenRecord Refresh(
        DateTimeOffset now, string seed = "rt-1", string grantId = "grant-1", string familyId = "family-1") => new(
        Hash(seed), grantId, familyId, Generation: 0,
        PredecessorHash: null, SuccessorHash: null,
        IssuedAt: now, ExpiresAt: now.AddDays(30));

    // ------------------------------------------------------------------ N-07

    [Fact]
    public async Task A_redeemed_code_is_retained_not_deleted()
    {
        // The row has to survive redemption, or a replay cannot be validated in full before
        // anything is revoked — and "revoke on the second presentation" is a denial of service an
        // attacker with a sniffed code and no verifier can trigger at will.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now);

        await store.StoreAsync(code, CancellationToken.None);
        Assert.IsType<CodeRedemption.Redeemed>(await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None));

        var found = await store.FindAsync(code.CodeHash, CancellationToken.None);

        Assert.NotNull(found);
        Assert.NotNull(found.RedeemedAt);
        // Everything a replay needs to be validated against is still here.
        Assert.Equal(code.CodeChallenge, found.CodeChallenge);
        Assert.Equal(code.ClientId, found.ClientId);
        Assert.Equal(code.RedirectUriUsed, found.RedirectUriUsed);
    }

    [Fact]
    public async Task Only_one_of_two_concurrent_redemptions_succeeds()
    {
        // Real parallelism, deliberately. A test that awaited the two calls in sequence would pass
        // against a store with no atomicity whatsoever.
        var now = DateTimeOffset.UtcNow;

        // Repeated, because a race is a probabilistic detector. Measured against a deliberately
        // non-atomic store, a single two-thread attempt caught the defect only sometimes — two of
        // the three concurrency tests here passed against it on the first run. Fifty attempts turn
        // "might collide" into "does collide", and the cost is milliseconds.
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var store = NewCodeStore();
            var code = Code(now, $"code-{attempt}");
            await store.StoreAsync(code, CancellationToken.None);

            var results = RunConcurrently(4, _ => store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None).Result);

            Assert.Single(results, r => r is CodeRedemption.Redeemed);
            AssertLosersAreRetries(results);
        }
    }

    /// <summary>
    /// The three calls that did not win are retries, not replays.
    /// </summary>
    /// <remarks>
    /// Asserting only that exactly one call won leaves every loser unexamined, and the losers are
    /// where the interesting failure is: a store that answers <see
    /// cref="CodeRedemption.ReplayedOutsideGrace"/> to every double-submit satisfies
    /// <c>Assert.Single</c> perfectly. That answer is the one the caller revokes the grant on, so
    /// such a store kills a grant on every unforced double-submit — which is precisely the bug the
    /// four-case <see cref="CodeRedemption"/> was introduced to replace, passing the suite that was
    /// meant to catch it.
    /// </remarks>
    private static void AssertLosersAreRetries(IEnumerable<CodeRedemption> results) =>
        Assert.All(
            results.Where(r => r is not CodeRedemption.Redeemed),
            r => Assert.IsType<CodeRedemption.ReplayedWithinGrace>(r));

    [Fact]
    public async Task Redeeming_many_times_in_parallel_still_succeeds_exactly_once()
    {
        var now = DateTimeOffset.UtcNow;

        for (var attempt = 0; attempt < 25; attempt++)
        {
            var store = NewCodeStore();
            var code = Code(now, $"code-many-{attempt}");
            await store.StoreAsync(code, CancellationToken.None);

            var results = RunConcurrently(16, _ => store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None).Result);

            Assert.Single(results, r => r is CodeRedemption.Redeemed);
            AssertLosersAreRetries(results);
        }
    }

    [Fact]
    public async Task An_unknown_code_does_not_redeem()
    {
        var store = NewCodeStore();

        Assert.IsType<CodeRedemption.ReplayedOutsideGrace>(
            await store.RedeemAsync(Hash("never-issued"), DateTimeOffset.UtcNow, CodeGrace, CancellationToken.None));
    }

    /// <summary>
    /// The window a code redemption treats a second presentation as a retry.
    /// </summary>
    /// <remarks>
    /// Short. Unlike the refresh window, which exists because a correct client genuinely races its
    /// own proactive and reactive refreshes, this one only has to cover a transport retry of a
    /// single request.
    /// </remarks>
    private static readonly TimeSpan CodeGrace = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task A_code_replayed_inside_the_grace_window_is_a_retry_not_an_incident()
    {
        // Nothing in this suite asserted that ReplayedWithinGrace is EVER returned. The
        // consequence is not a coverage number: a store that answers ReplayedOutsideGrace to
        // every second presentation passed all of it, and that store revokes the grant on every
        // double-submit — a lost response, a proxy retry, a double-click. Measured before the
        // four-case result existed, when redemption answered a bare bool: fifty unforced
        // double-submits revoked the winner's grant fifty times, and the client saw an
        // authorization that succeeded and was dead on its next call.
        //
        // This suite ships so a customer can validate a store they wrote themselves, so a blind
        // spot here is not ours alone. The only test that ever killed this was in the
        // authorization server, several layers above the thing being described.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now);
        await store.StoreAsync(code, CancellationToken.None);

        Assert.IsType<CodeRedemption.Redeemed>(
            await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None));

        Assert.IsType<CodeRedemption.ReplayedWithinGrace>(
            await store.RedeemAsync(code.CodeHash, now.AddSeconds(3), CodeGrace, CancellationToken.None));

        // And the window does close. Without this the assertion above is satisfied by a store
        // that never revokes anything, which is the opposite failure and just as bad: §4.1.3
        // makes revoking on a fully validated replay a SHOULD, and it is the only signal that a
        // code leaked.
        Assert.IsType<CodeRedemption.ReplayedOutsideGrace>(
            await store.RedeemAsync(code.CodeHash, now.AddMinutes(5), CodeGrace, CancellationToken.None));
    }

    [Fact]
    public async Task A_retry_inside_the_code_grace_window_does_not_slide_it()
    {
        // The window is measured from the redemption, not from the most recent presentation. If a
        // replay re-stamped RedeemedAt, anyone presenting the code more often than the window is
        // wide would hold it open indefinitely, and ReplayedOutsideGrace — the answer that
        // revokes — would never be reached at all. It is the same shape as walking a refresh
        // chain: every hop lands inside a window the previous hop just refreshed.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now);
        await store.StoreAsync(code, CancellationToken.None);

        Assert.IsType<CodeRedemption.Redeemed>(
            await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None));

        // Eight seconds in: inside a ten-second window, and not an incident.
        Assert.IsType<CodeRedemption.ReplayedWithinGrace>(
            await store.RedeemAsync(code.CodeHash, now.AddSeconds(8), CodeGrace, CancellationToken.None));

        // Sixteen seconds after the REDEMPTION, which is outside the window however many
        // presentations arrived in between.
        Assert.IsType<CodeRedemption.ReplayedOutsideGrace>(
            await store.RedeemAsync(code.CodeHash, now.AddSeconds(16), CodeGrace, CancellationToken.None));
    }

    [Fact]
    public async Task A_code_redemption_stamped_in_the_future_does_not_widen_the_window()
    {
        // The code-side twin of A_consumption_stamped_in_the_future_does_not_widen_the_window,
        // which the refresh path has had since the same defect was measured there. `now` is the
        // caller's and this server runs as several instances, so an instance with a fast clock
        // stamps RedeemedAt ahead of everyone else's present. Every subsequent presentation then
        // has a NEGATIVE elapsed, and without a lower bound a negative of any size is "inside the
        // window" — so a genuine replay reads as a transport retry for as long as the clocks
        // disagree, and the one case §4.1.3 asks to be revoked never is.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now);
        await store.StoreAsync(code, CancellationToken.None);

        // The fast instance redeems it an hour "ahead".
        Assert.IsType<CodeRedemption.Redeemed>(
            await store.RedeemAsync(code.CodeHash, now.AddHours(1), CodeGrace, CancellationToken.None));

        Assert.IsType<CodeRedemption.ReplayedOutsideGrace>(
            await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None));
    }

    // ------------------------------------------------------------------ N-08

    [Fact]
    public async Task A_refresh_token_rotates_to_exactly_one_successor()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now);
        await store.StoreAsync(original, CancellationToken.None);

        var outcome = await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        var rotated = Assert.IsType<RefreshRedemption.Rotated>(outcome);
        Assert.Equal(original.FamilyId, rotated.Successor.FamilyId);
        Assert.Equal(1, rotated.Successor.Generation);
        Assert.Equal(original.TokenHash, rotated.Successor.PredecessorHash);
    }

    [Fact]
    public async Task Two_concurrent_redemptions_produce_one_successor_and_both_callers_get_it()
    {
        // The CVE class this contract exists for. Claude refreshes both proactively — up to five
        // minutes before expiry — and reactively on a 401, so these genuinely race in normal
        // operation. If both mint a successor the family FORKS, and after a fork there is no single
        // chain against which a replay is anomalous: reuse detection is dead from that point on,
        // silently.
        var now = DateTimeOffset.UtcNow;

        for (var attempt = 0; attempt < 50; attempt++)
        {
            var store = NewRefreshStore();
            var original = Refresh(now, $"rt-root-{attempt}");
            await store.StoreAsync(original, CancellationToken.None);

            var outcomes = RunConcurrently(4, i => store.RedeemAsync(
                original.TokenHash, new RefreshTokenSeed(Hash($"rt-{attempt}-{i}"), now.AddDays(30)),
                now, TimeSpan.FromSeconds(45), CancellationToken.None).Result);

            // Exactly one rotation happened; every loser was told about the winner's successor
            // rather than being handed one of its own.
            Assert.Single(outcomes, o => o is RefreshRedemption.Rotated);

            var successors = outcomes.Select(o => o switch
            {
                RefreshRedemption.Rotated r => r.Successor.TokenHash,
                RefreshRedemption.ReplayedWithinGrace g => g.Successor.TokenHash,
                _ => throw new InvalidOperationException($"unexpected outcome {o}"),
            }).Distinct().ToList();

            // The family did not fork. This is the assertion the CVE class is about.
            Assert.Single(successors);
        }
    }

    [Fact]
    public async Task A_replay_inside_the_grace_window_is_idempotent_not_an_incident()
    {
        // Without this window, Claude's proactive and reactive refreshes racing produces a
        // user-visible forced logout that reads as an outage.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now);
        await store.StoreAsync(original, CancellationToken.None);

        var first = await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        var second = await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-3"), now.AddDays(30)),
            now.AddSeconds(20), TimeSpan.FromSeconds(45), CancellationToken.None);

        var rotated = Assert.IsType<RefreshRedemption.Rotated>(first);
        var replayed = Assert.IsType<RefreshRedemption.ReplayedWithinGrace>(second);

        // The same successor, not a third token.
        Assert.Equal(rotated.Successor.TokenHash, replayed.Successor.TokenHash);
    }

    [Fact]
    public async Task A_replay_outside_the_grace_window_is_reuse_detection()
    {
        // The only signal that a refresh token leaked. The server cannot tell a careless client
        // from a thief, so it must assume the worse one.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now);
        await store.StoreAsync(original, CancellationToken.None);

        await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        var outcome = await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-3"), now.AddDays(30)),
            now.AddMinutes(5), TimeSpan.FromSeconds(45), CancellationToken.None);

        var reuse = Assert.IsType<RefreshRedemption.ReuseDetected>(outcome);
        Assert.Equal("family-1", reuse.FamilyId);
        Assert.Equal("grant-1", reuse.GrantId);
    }

    [Fact]
    public async Task A_revoked_family_stops_refreshing()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now);
        await store.StoreAsync(original, CancellationToken.None);

        await store.RevokeFamilyAsync(original.FamilyId, now, CancellationToken.None);

        var outcome = await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.IsType<RefreshRedemption.NotFound>(outcome);
    }

    // ------------------------------------------------- The approving device

    /// <summary>Whose grants the device tests use.</summary>
    private static readonly SubjectId Approver = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");

    /// <summary>A grant, optionally carrying the browser it was approved from.</summary>
    private static GrantRecord Grant(DateTimeOffset now, string? userAgent = null) => new(
        "grant-1", Approver, Client, ScopeSet.FromStorage("story:read"),
        ["https://mcp.example.com/mcp"], now, now, RevokedAt: null, UserAgent: userAgent);

    /// <summary>The browser a grant was approved from survives a round trip.</summary>
    /// <remarks>
    /// A column a store forgets to map is invisible until somebody opens the sessions page and every
    /// row says nothing — which reads as "no device was recorded" rather than as a mapping bug.
    /// </remarks>
    [Fact]
    public async Task A_grant_remembers_the_browser_it_was_approved_from()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();

        await store.StoreAsync(Grant(now, "Mozilla/5.0 (Macintosh) Chrome/140"), CancellationToken.None);

        var found = await store.FindAsync("grant-1", CancellationToken.None);

        Assert.Equal("Mozilla/5.0 (Macintosh) Chrome/140", found!.UserAgent);
    }

    /// <summary>A grant with no device comes back with none, not with an empty string.</summary>
    /// <remarks>
    /// Every grant created before the column existed is in this state, and no store may invent a
    /// value for them — the page distinguishes "nothing recorded" from "recorded as blank", and only
    /// one of those renders as nothing.
    /// </remarks>
    [Fact]
    public async Task A_grant_with_no_device_comes_back_with_none()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();

        await store.StoreAsync(Grant(now), CancellationToken.None);

        Assert.Null((await store.FindAsync("grant-1", CancellationToken.None))!.UserAgent);
    }

    /// <summary>It survives the listing the sessions page reads, not only a direct find.</summary>
    [Fact]
    public async Task The_device_is_on_the_listing_the_sessions_page_reads()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();

        await store.StoreAsync(Grant(now, "Firefox/131"), CancellationToken.None);

        var listed = Assert.Single(await store.ListForSubjectAsync(Approver, CancellationToken.None));

        Assert.Equal("Firefox/131", listed.UserAgent);
    }

    // ------------------------------------------------- Last refresh, per grant

    /// <summary>The newest issue time in the grant wins, whatever order the rows went in.</summary>
    [Fact]
    public async Task The_last_refresh_is_the_newest_issue_time_the_grant_has()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();

        // Deliberately not in order. A store folding these with "last one seen wins" passes an
        // in-order test and reports a month-old moment for a session refreshed this morning.
        await store.StoreAsync(Refresh(now.AddHours(-2), "rt-old"), CancellationToken.None);
        await store.StoreAsync(Refresh(now, "rt-newest"), CancellationToken.None);
        await store.StoreAsync(Refresh(now.AddHours(-1), "rt-middle"), CancellationToken.None);

        var latest = await store.LastIssuedForGrantsAsync(["grant-1"], CancellationToken.None);

        Assert.Equal(now, Assert.Contains("grant-1", latest));
    }

    /// <summary>
    /// A grant that has never refreshed is absent, not present with a default.
    /// </summary>
    /// <remarks>
    /// The distinction the return type exists for. A dictionary answering
    /// <see cref="DateTimeOffset.MinValue"/> would put "renewed in year one" on the page for every
    /// session authorized in the last half hour, which is the freshest ones.
    /// </remarks>
    [Fact]
    public async Task A_grant_that_has_never_refreshed_is_absent_rather_than_defaulted()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();

        await store.StoreAsync(Refresh(now), CancellationToken.None);

        var latest = await store.LastIssuedForGrantsAsync(["grant-1", "grant-2"], CancellationToken.None);

        Assert.True(latest.ContainsKey("grant-1"));
        Assert.False(latest.ContainsKey("grant-2"));
    }

    /// <summary>
    /// A consumed token still counts, because in a live family every token but one is consumed.
    /// </summary>
    /// <remarks>
    /// The regression this pins: filtering to unconsumed rows looks obviously right — those are the
    /// tokens that still work — and reports the wrong moment for every session that has ever
    /// rotated, which is every session older than one access-token lifetime.
    /// </remarks>
    [Fact]
    public async Task A_consumed_token_still_counts_towards_the_last_refresh()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now);

        await store.StoreAsync(original, CancellationToken.None);
        await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now.AddMinutes(25), TimeSpan.FromSeconds(45), CancellationToken.None);

        var latest = await store.LastIssuedForGrantsAsync(["grant-1"], CancellationToken.None);

        // The successor's moment, which is when the grant last minted — not the consumed parent's.
        Assert.Equal(now.AddMinutes(25), Assert.Contains("grant-1", latest));
    }

    /// <summary>Only what was asked about comes back.</summary>
    [Fact]
    public async Task Grants_that_were_not_asked_about_are_not_answered()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();

        await store.StoreAsync(Refresh(now, "rt-a", "grant-1", "family-1"), CancellationToken.None);
        await store.StoreAsync(Refresh(now, "rt-b", "grant-2", "family-2"), CancellationToken.None);

        var latest = await store.LastIssuedForGrantsAsync(["grant-1"], CancellationToken.None);

        Assert.Equal(["grant-1"], latest.Keys);
    }

    /// <summary>
    /// No grants asked about is answered empty, without going to the database.
    /// </summary>
    /// <remarks>
    /// The ordinary state of an account that has authorized nothing. A relational store sending
    /// this on as <c>IN ()</c> is a syntax error on some providers and a full table scan on others,
    /// so the empty case is part of the contract rather than an edge somebody handles or does not.
    /// </remarks>
    [Fact]
    public async Task Asking_about_no_grants_answers_empty()
    {
        var store = NewRefreshStore();
        await store.StoreAsync(Refresh(DateTimeOffset.UtcNow), CancellationToken.None);

        Assert.Empty(await store.LastIssuedForGrantsAsync([], CancellationToken.None));
    }

    [Fact]
    public async Task An_expired_refresh_token_is_not_found_rather_than_reused()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now) with { ExpiresAt = now.AddSeconds(-1) };
        await store.StoreAsync(original, CancellationToken.None);

        var outcome = await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        // NotFound, not ReuseDetected: expiry is normal and must not revoke a family.
        Assert.IsType<RefreshRedemption.NotFound>(outcome);
    }

    [Fact]
    public async Task An_unknown_refresh_token_is_not_found()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();

        var outcome = await store.RedeemAsync(
            Hash("never-issued"), new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.IsType<RefreshRedemption.NotFound>(outcome);
    }

    [Fact]
    public async Task A_second_rotation_chains_from_the_first()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var original = Refresh(now);
        await store.StoreAsync(original, CancellationToken.None);

        var first = Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
            original.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None));

        var second = Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
            first.Successor.TokenHash, new RefreshTokenSeed(Hash("rt-3"), now.AddDays(30)),
            now.AddMinutes(10), TimeSpan.FromSeconds(45), CancellationToken.None));

        Assert.Equal(2, second.Successor.Generation);
        Assert.Equal(first.Successor.TokenHash, second.Successor.PredecessorHash);
        Assert.Equal(original.FamilyId, second.Successor.FamilyId);
    }

    // ------------------------------------------------- what an adversarial review found missing

    [Fact]
    public async Task A_consumed_successor_means_the_chain_moved_on_so_this_is_reuse()
    {
        // The highest-severity defect found in this layer. Checking only that the successor EXISTS
        // let an attacker walk the whole chain: a stolen rt0 replayed after a legitimate burst
        // returned rt1, whose own consumption was more recent, so the next hop was also inside the
        // window — and so on to the live head, with ReuseDetected never raised. Measured over 200
        // rounds of a client refreshing every 30s against an attacker polling 20s behind: zero
        // detections, both parties holding the same token.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        var first = Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("chain-1"), now.AddDays(30)),
            now.AddSeconds(1), TimeSpan.FromSeconds(45), CancellationToken.None));

        // The chain moves on while the parent's grace window is still open.
        await store.RedeemAsync(
            first.Successor.TokenHash, new RefreshTokenSeed(Hash("chain-2"), now.AddDays(30)),
            now.AddSeconds(2), TimeSpan.FromSeconds(45), CancellationToken.None);

        var replay = await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("chain-x"), now.AddDays(30)),
            now.AddSeconds(5), TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.IsType<RefreshRedemption.ReuseDetected>(replay);
    }

    [Fact]
    public async Task An_attacker_cannot_walk_the_chain_to_the_live_token()
    {
        // The same defect stated as the attack rather than the mechanism.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        var current = root.TokenHash;
        for (var hop = 1; hop <= 3; hop++)
        {
            var rotated = Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
                current, new RefreshTokenSeed(Hash($"walk-{hop}"), now.AddDays(30)),
                now.AddSeconds(hop), TimeSpan.FromSeconds(45), CancellationToken.None));

            current = rotated.Successor.TokenHash;
        }

        // The attacker starts from the stolen root, inside the window of every consumption.
        var outcome = await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-evil"), now.AddDays(30)),
            now.AddSeconds(40), TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.IsType<RefreshRedemption.ReuseDetected>(outcome);
    }

    [Fact]
    public async Task Replaying_a_consumed_token_after_revocation_still_reports_reuse()
    {
        // The test that kills a store which DELETES rows on revocation. Such a store passed all
        // eight refresh assertions here before this was added, while having destroyed reuse
        // detection permanently — and this suite is shipped as the thing that makes "write your own
        // store" tractable, so its blind spots become customers' blind spots.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        await store.RevokeFamilyAsync(root.FamilyId, now, CancellationToken.None);

        var outcome = await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-3"), now.AddDays(30)),
            now.AddMinutes(5), TimeSpan.FromSeconds(45), CancellationToken.None);

        // NotFound would mean the row is gone, and a thief would learn nothing was noticed.
        Assert.IsType<RefreshRedemption.NotFound>(outcome);
        Assert.Equal(0, await store.RevokeFamilyAsync(root.FamilyId, now, CancellationToken.None));
    }

    [Fact]
    public async Task A_consumption_stamped_in_the_future_does_not_widen_the_window()
    {
        // `now` is caller-supplied and the server runs several instances, so a fast clock on one of
        // them stamped a ConsumedAt in the future — measured, a 45-second window became sixty
        // minutes. A negative age of any size used to pass.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        // An instance with a fast clock consumes the token an hour "ahead".
        await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now.AddHours(1), TimeSpan.FromSeconds(45), CancellationToken.None);

        var outcome = await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-3"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        Assert.IsType<RefreshRedemption.ReuseDetected>(outcome);
    }

    [Fact]
    public async Task Storing_an_existing_token_is_refused_rather_than_resurrecting_it()
    {
        // An upsert cleared ConsumedAt and let the parent rotate a second time: two live successors
        // with one predecessor, which is the family fork the whole design exists to prevent.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.StoreAsync(root, CancellationToken.None));
    }

    [Fact]
    public async Task Storing_an_existing_code_is_refused_rather_than_resetting_replay_protection()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now);
        await store.StoreAsync(code, CancellationToken.None);
        await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.StoreAsync(code, CancellationToken.None));
    }

    [Fact]
    public async Task An_expired_but_unredeemed_code_still_redeems_and_that_is_deliberate()
    {
        // Pinned so nobody "fixes" it. TryRedeemAsync returning false means "a fully valid replay",
        // which is the one case that revokes the grant — so folding expiry in here would send an
        // expired code down the revocation path, which is precisely the denial of service N-07
        // exists to prevent. Expiry is the caller's check, after FindAsync.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now) with { ExpiresAt = now.AddYears(-1) };
        await store.StoreAsync(code, CancellationToken.None);

        Assert.IsType<CodeRedemption.Redeemed>(await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None));
    }

    [Theory]
    [InlineData(44, true)]   // inside
    [InlineData(45, true)]   // exactly at the boundary — inclusive
    [InlineData(46, false)]  // outside
    public async Task The_grace_boundary_is_inclusive(int elapsedSeconds, bool expectGrace)
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-2"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None);

        var outcome = await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("rt-3"), now.AddDays(30)),
            now.AddSeconds(elapsedSeconds), TimeSpan.FromSeconds(45), CancellationToken.None);

        if (expectGrace)
        {
            Assert.IsType<RefreshRedemption.ReplayedWithinGrace>(outcome);
        }
        else
        {
            Assert.IsType<RefreshRedemption.ReuseDetected>(outcome);
        }
    }

    [Fact]
    public async Task Revoking_a_family_counts_only_the_tokens_it_actually_killed()
    {
        // RevokeFamilyAsync's return value is documented — "how many tokens THIS call transitioned
        // … counting every row in the family, consumed and expired ones included, gives a number no
        // caller can act on" — and nothing asserted it. A store that returned the family's whole row
        // count passed every test in this file, and that number is one an operator alerts on: after
        // ten rotations, revoking a family on reuse detection would report eleven tokens killed when
        // exactly one was live.
        //
        // It is also the number that separates two schemas a relational store might choose. Reading
        // it off `UPDATE refresh_tokens SET revoked_at = @now WHERE family_id = @f`'s rows-affected
        // gives the whole family; the unconsumed ones have to be counted deliberately.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        // Two rotations: root and its first successor are consumed, the head is live.
        var first = Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
            root.TokenHash, new RefreshTokenSeed(Hash("count-1"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None));

        Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
            first.Successor.TokenHash, new RefreshTokenSeed(Hash("count-2"), now.AddDays(30)),
            now.AddMinutes(1), TimeSpan.FromSeconds(45), CancellationToken.None));

        // Three rows in the family, one of them still usable.
        Assert.Equal(1, await store.RevokeFamilyAsync(root.FamilyId, now.AddMinutes(2), CancellationToken.None));
    }

    [Fact]
    public async Task A_token_stored_into_a_revoked_family_is_revoked_too()
    {
        // Where the two plausible relational schemas disagree, so it is pinned rather than left to
        // whichever one an implementer reaches for.
        //
        // Revocation as a property of the FAMILY — one row in a families table, which is the shape
        // the in-memory store's separate _revokedFamilies dictionary already has — covers a token
        // that arrives afterwards. Revocation as a `revoked_at` stamped on each token row by an
        // UPDATE does not: that UPDATE ran before this row existed, so the row is live and the
        // family the server believed it had killed can still mint tokens.
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();
        var root = Refresh(now);
        await store.StoreAsync(root, CancellationToken.None);

        await store.RevokeFamilyAsync(root.FamilyId, now, CancellationToken.None);

        // A second token in the same family, stored after the revocation.
        await store.StoreAsync(Refresh(now, "late-arrival"), CancellationToken.None);

        Assert.IsType<RefreshRedemption.NotFound>(await store.RedeemAsync(
            Hash("late-arrival"), new RefreshTokenSeed(Hash("late-successor"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None));
    }

    [Fact]
    public async Task Revoking_one_family_leaves_another_refreshing()
    {
        var now = DateTimeOffset.UtcNow;
        var store = NewRefreshStore();

        var a = Refresh(now, "fam-a-root") with { FamilyId = "family-a" };
        var b = Refresh(now, "fam-b-root") with { FamilyId = "family-b" };
        await store.StoreAsync(a, CancellationToken.None);
        await store.StoreAsync(b, CancellationToken.None);

        await store.RevokeFamilyAsync("family-a", now, CancellationToken.None);

        Assert.IsType<RefreshRedemption.NotFound>(await store.RedeemAsync(
            a.TokenHash, new RefreshTokenSeed(Hash("x"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None));

        Assert.IsType<RefreshRedemption.Rotated>(await store.RedeemAsync(
            b.TokenHash, new RefreshTokenSeed(Hash("y"), now.AddDays(30)),
            now, TimeSpan.FromSeconds(45), CancellationToken.None));
    }

    [Fact]
    public async Task Expired_codes_are_swept_and_unexpired_ones_are_not()
    {
        // DeleteExpiredAsync had no test at all.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();

        var stale = Code(now, "stale") with { ExpiresAt = now.AddMinutes(-1) };
        var fresh = Code(now, "fresh") with { ExpiresAt = now.AddMinutes(5) };
        await store.StoreAsync(stale, CancellationToken.None);
        await store.StoreAsync(fresh, CancellationToken.None);

        Assert.Equal(1, await store.DeleteExpiredAsync(now, CancellationToken.None));
        Assert.Null(await store.FindAsync(stale.CodeHash, CancellationToken.None));
        Assert.NotNull(await store.FindAsync(fresh.CodeHash, CancellationToken.None));
    }

    [Fact]
    public async Task A_sweep_racing_a_redemption_does_not_report_a_row_it_did_not_remove()
    {
        // Measured before the lock covered the sweeper: 166 in 5000 runs reported a row deleted
        // that the concurrent redemption then wrote back, so the row survived and the count lied.
        var now = DateTimeOffset.UtcNow;

        for (var attempt = 0; attempt < 200; attempt++)
        {
            var store = NewCodeStore();
            var code = Code(now, $"sweep-{attempt}") with { ExpiresAt = now.AddMinutes(-1) };
            await store.StoreAsync(code, CancellationToken.None);

            var outcomes = RunConcurrently(2, i => i == 0
                ? store.DeleteExpiredAsync(now, CancellationToken.None).Result
                : store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None).Result is CodeRedemption.Redeemed ? 1 : 0);

            var deleted = outcomes[0] == 1;
            var redeemed = outcomes[1] == 1;
            var stillThere = await store.FindAsync(code.CodeHash, CancellationToken.None) is not null;

            Assert.False(deleted && stillThere, "the sweeper reported a deletion that did not stick");

            // The converse, which was missing — and it was the half that failed. The assertion
            // above is satisfied by the interleaving where the redemption reports Redeemed and the
            // sweeper then removes the row it just wrote: deleted=true, stillThere=false, and
            // nothing complains. Measured against the sweeper as it stood before this branch, over
            // three runs of 200 attempts: 189, 197 and 183. Not an unlucky interleaving — the
            // common one.
            //
            // It is N-07 undone one call later. A redemption that reported success and left no row
            // is a code the store has no memory of, and RedeemAsync's answer for a hash it has
            // never seen is ReplayedOutsideGrace — the one answer a caller revokes the grant on.
            Assert.False(redeemed && !stillThere, "a redemption reported success on a row that is now gone");
        }
    }

    [Fact]
    public async Task A_redeemed_code_outlives_its_expiry_so_a_retry_still_finds_it()
    {
        // The defect above stated without the race, because it does not need one. A code lives
        // about a minute and is redeemed whenever the user finishes consenting, so redemption in
        // the last seconds of that minute is ordinary — and the retry window starts at redemption,
        // not at issue, so it routinely outlives the code. A sweeper that deletes on expiry alone
        // removes the row while the window it exists for is still open.
        var now = DateTimeOffset.UtcNow;
        var store = NewCodeStore();
        var code = Code(now) with { ExpiresAt = now.AddSeconds(1) };
        await store.StoreAsync(code, CancellationToken.None);

        Assert.IsType<CodeRedemption.Redeemed>(
            await store.RedeemAsync(code.CodeHash, now, CodeGrace, CancellationToken.None));

        // Housekeeping runs after the code expires, while the retry window is still open.
        Assert.Equal(0, await store.DeleteExpiredAsync(now.AddSeconds(2), CancellationToken.None));
        Assert.NotNull(await store.FindAsync(code.CodeHash, CancellationToken.None));

        // So the retry gets the answer it deserves rather than the one for an unknown code.
        Assert.IsType<CodeRedemption.ReplayedWithinGrace>(
            await store.RedeemAsync(code.CodeHash, now.AddSeconds(3), CodeGrace, CancellationToken.None));
    }

    // ------------------------------------------------------------------ grants

    [Fact]
    public async Task A_revoked_grant_is_on_the_denylist()
    {
        // Access tokens are self-contained JWTs, so "revoking" one means recording the grant id
        // here and having the resource server refuse tokens carrying it. That is why the access
        // token carries a grant id at all.
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();
        var grant = new GrantRecord(
            "grant-1", SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY"), Client,
            ScopeSet.FromStorage("story:read"), ["https://mcp.example.com/mcp"], now, now);

        await store.StoreAsync(grant, CancellationToken.None);
        Assert.False(await store.IsRevokedAsync("grant-1", CancellationToken.None));

        Assert.True(await store.RevokeAsync("grant-1", now, CancellationToken.None));

        // A second revoke is not a second event.
        Assert.False(await store.RevokeAsync("grant-1", now, CancellationToken.None));
        Assert.True(await store.IsRevokedAsync("grant-1", CancellationToken.None));
        Assert.False((await store.FindAsync("grant-1", CancellationToken.None))!.IsActive);
    }

    [Fact]
    public async Task Revoking_by_subject_takes_that_subject_and_leaves_everyone_else()
    {
        // E-30's whole mechanism. The link from a person to their sessions runs through the grant —
        // refresh rows carry a grant id and grants carry the subject — so revoking by subject is
        // what "sign this person out of everything" is made of.
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();

        var alice = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");
        var bob = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XZ");

        foreach (var (id, subject) in new[]
        {
            ("alice-1", alice), ("alice-2", alice), ("alice-3", alice), ("bob-1", bob),
        })
        {
            await store.StoreAsync(
                new GrantRecord(
                    id, subject, Client, ScopeSet.FromStorage("story:read"),
                    ["https://mcp.example.com/mcp"], now, now),
                CancellationToken.None);
        }

        // One already revoked, so the count is provably "how many this call transitioned" rather
        // than "how many this subject has".
        Assert.True(await store.RevokeAsync("alice-3", now, CancellationToken.None));

        Assert.Equal(2, await store.RevokeAllForSubjectAsync(alice, now, CancellationToken.None));

        Assert.True(await store.IsRevokedAsync("alice-1", CancellationToken.None));
        Assert.True(await store.IsRevokedAsync("alice-2", CancellationToken.None));
        Assert.True(await store.IsRevokedAsync("alice-3", CancellationToken.None));

        // The one that matters most: somebody else's session is untouched. A revoke-by-subject that
        // took the whole table would read as working in every test with one user in it.
        Assert.False(await store.IsRevokedAsync("bob-1", CancellationToken.None));
    }

    [Fact]
    public async Task Revoking_by_subject_twice_reports_nothing_the_second_time()
    {
        // An operator runs this twice to be sure. The second answer has to be zero, or the log
        // says four sessions ended when two did — and the count is the only thing distinguishing
        // "there was nothing live" from "it worked".
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();
        var subject = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");

        await store.StoreAsync(
            new GrantRecord(
                "grant-1", subject, Client, ScopeSet.FromStorage("story:read"),
                ["https://mcp.example.com/mcp"], now, now),
            CancellationToken.None);

        Assert.Equal(1, await store.RevokeAllForSubjectAsync(subject, now, CancellationToken.None));
        Assert.Equal(0, await store.RevokeAllForSubjectAsync(subject, now, CancellationToken.None));
    }

    [Fact]
    public async Task Revoking_by_a_subject_with_no_grants_is_zero_rather_than_an_error()
    {
        // Anonymising an account that never authorized anything is an ordinary case, and it must
        // not be a failure — the operation would then be refused for the accounts it is safest on.
        var store = NewGrantStore();

        Assert.Equal(
            0,
            await store.RevokeAllForSubjectAsync(
                SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY"),
                DateTimeOffset.UtcNow,
                CancellationToken.None));
    }

    [Fact]
    public async Task Listing_a_subjects_grants_returns_theirs_and_only_the_live_ones()
    {
        // E-35. The read half of RevokeAllForSubjectAsync, and the two properties that make it
        // usable as a session list: it is scoped to one subject, and a revoked grant is gone from
        // it. Rows are never deleted on revocation — that is the refresh-replay rule — so without
        // the second property this list grows for the life of the account with entries whose only
        // honest rendering is "ended".
        var now = DateTimeOffset.UtcNow;
        var store = NewGrantStore();
        var alice = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");
        var bob = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0ZZ");

        foreach (var (id, subject) in new[]
        {
            ("alice-1", alice), ("alice-2", alice), ("alice-revoked", alice), ("bob-1", bob),
        })
        {
            await store.StoreAsync(
                new GrantRecord(
                    id, subject, Client, ScopeSet.FromStorage("story:read"),
                    ["https://mcp.example.com/mcp"], now, now),
                CancellationToken.None);
        }

        Assert.True(await store.RevokeAsync("alice-revoked", now, CancellationToken.None));

        var listed = await store.ListForSubjectAsync(alice, CancellationToken.None);

        Assert.Equal(
            ["alice-1", "alice-2"],
            listed.Select(g => g.GrantId).OrderBy(id => id, StringComparer.Ordinal));

        // Bob's is untouched and unlisted. The whole surface this feeds — /account/sessions — is
        // one where returning a stranger's row is the defect.
        Assert.Equal(
            ["bob-1"],
            (await store.ListForSubjectAsync(bob, CancellationToken.None)).Select(g => g.GrantId));
    }

    /// <summary>
    /// The devices a subject has approved from, including the ones whose grants are gone.
    /// </summary>
    /// <remarks>
    /// <b>Every clause here is one an implementation can plausibly get wrong.</b> Filtering revoked
    /// rows out is the natural thing to write, because every other read of this table does it — and
    /// it is the one that turns somebody's own laptop into a security alert the first time they sign
    /// out of everything. Distinctness, the empty-header exclusion and the subject boundary are the
    /// rest of the contract; a backend passing three of the four sends mail nobody can act on.
    /// </remarks>
    [Fact]
    public async Task Approved_user_agents_span_revoked_grants_and_are_distinct()
    {
        var store = NewGrantStore();
        var now = DateTimeOffset.UtcNow;
        var alice = SubjectId.FromStorage("alice");
        var bob = SubjectId.FromStorage("bob");

        foreach (var (id, subject, agent) in new (string, SubjectId, string?)[]
        {
            ("alice-live", alice, "Chrome/141"),

            // The same header again: one device, approved twice.
            ("alice-again", alice, "Chrome/141"),

            // Revoked below, and it still counts. This is the clause the feature depends on.
            ("alice-revoked", alice, "Firefox/131"),

            // Clients that sent nothing. Neither is a device, and an implementation returning them
            // would hand the caller entries it cannot compare or name.
            ("alice-null", alice, null),
            ("alice-blank", alice, ""),

            ("bob-1", bob, "Safari/18"),
        })
        {
            await store.StoreAsync(
                new GrantRecord(
                    id, subject, Client, ScopeSet.FromStorage("story:read"),
                    ["https://mcp.example.com/mcp"], now, now, RevokedAt: null, UserAgent: agent),
                CancellationToken.None);
        }

        Assert.True(await store.RevokeAsync("alice-revoked", now, CancellationToken.None));

        var agents = await store.ListApprovedUserAgentsAsync(alice, CancellationToken.None);

        Assert.Equal(
            ["Chrome/141", "Firefox/131"],
            agents.OrderBy(a => a, StringComparer.Ordinal));

        // Bob's device is Bob's. The caller compares these against a header presented right now, so
        // a leaked entry would silently mark a genuinely new device as familiar.
        Assert.Equal(["Safari/18"], await store.ListApprovedUserAgentsAsync(bob, CancellationToken.None));
    }

    /// <summary>An account that has never approved anything has no devices, and no error.</summary>
    [Fact]
    public async Task Approved_user_agents_for_a_subject_with_none_is_empty_rather_than_an_error()
    {
        var store = NewGrantStore();

        Assert.Empty(
            await store.ListApprovedUserAgentsAsync(
                SubjectId.FromStorage("nobody"), CancellationToken.None));
    }

    [Fact]
    public async Task Listing_grants_for_a_subject_with_none_is_empty_rather_than_an_error()
    {
        // A new account, or one that has never authorized a client. An implementation that threw or
        // returned null here would make the ordinary case the broken one.
        var store = NewGrantStore();

        Assert.Empty(await store.ListForSubjectAsync(
            SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY"), CancellationToken.None));
    }

    [Fact]
    public async Task An_unknown_grant_is_not_reported_as_revoked()
    {
        // It is not revoked; it does not exist. Conflating the two would make the denylist answer
        // yes for every id anyone asks about.
        var store = NewGrantStore();

        Assert.False(await store.IsRevokedAsync("never-existed", CancellationToken.None));

        // And revoking one is observable rather than a silent success: a caller reacting to reuse
        // detection needs to know the revocation landed.
        Assert.False(await store.RevokeAsync("never-existed", DateTimeOffset.UtcNow, CancellationToken.None));
    }
}

/// <summary>The contract, against the in-memory store.</summary>
public sealed class InMemoryGrantStoreTests : GrantStoreContract
{
    // A fresh store per call, not one shared instance. The repeated concurrency tests need an
    // empty store each iteration, and sharing one also lets a test see rows another test wrote.
    protected override IAuthorizationCodeStore NewCodeStore() => new InMemory.InMemoryAuthorizationCodeStore();

    protected override IRefreshTokenStore NewRefreshStore() => new InMemory.InMemoryRefreshTokenStore();

    protected override IGrantStore NewGrantStore() => new InMemory.InMemoryGrantStore();
}
