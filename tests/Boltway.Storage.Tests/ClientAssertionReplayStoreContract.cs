using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;

namespace Boltway.Storage.Tests;

/// <summary>
/// The <see cref="IClientAssertionReplayStore"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// One method carries the whole property: a claim either wins or loses, and losing is a replay.
/// Everything below is a way of getting that wrong. The relational implementation lets a unique
/// violation decide; the in-memory one lets <c>TryAdd</c> decide; neither reads first, and the
/// concurrent test is what says so.
/// </para>
/// <para>
/// <b>Expiry is not a claim rule here.</b> A store asked to claim a <c>jti</c> whose <c>exp</c> has
/// already passed still records it and still refuses the second attempt — the validator refuses an
/// expired assertion long before this store is consulted, so building an expiry check in as well
/// would put the same rule in two places and let them disagree. What the expiry <i>is</i> for is
/// <see cref="IClientAssertionReplayStore.DeleteExpiredAsync"/>, which is the only method that reads
/// it.
/// </para>
/// </remarks>
public abstract class ClientAssertionReplayStoreContract
{
    /// <summary>A fresh, empty replay store.</summary>
    protected abstract IClientAssertionReplayStore NewReplayStore();

    private static readonly ClientIdentifier Chatgpt =
        ClientIdentifier.ForCimd("https://chatgpt.com/oauth/client.json");

    private static readonly ClientIdentifier Claude =
        ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata");

    private static readonly DateTimeOffset Now = new(2026, 8, 22, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task A_jti_never_seen_is_claimed()
    {
        var store = NewReplayStore();

        Assert.True(await store.TryClaimAsync(Chatgpt, "jti-1", Now.AddMinutes(5), CancellationToken.None));
    }

    /// <summary>The point of the store: the second presentation loses.</summary>
    [Fact]
    public async Task The_same_jti_twice_is_claimed_once()
    {
        var store = NewReplayStore();

        Assert.True(await store.TryClaimAsync(Chatgpt, "jti-1", Now.AddMinutes(5), CancellationToken.None));
        Assert.False(await store.TryClaimAsync(Chatgpt, "jti-1", Now.AddMinutes(5), CancellationToken.None));
    }

    /// <summary>
    /// Two clients may use the same <c>jti</c>, because a JWT identifier is unique per issuer.
    /// </summary>
    /// <remarks>
    /// The control for the test above, and a real defect if it fails: keyed on <c>jti</c> alone, one
    /// client picking <c>"1"</c> — which nothing stops it doing — locks every other client out of
    /// that value for as long as the row lives, and the refusal reaches them as
    /// <c>invalid_client</c> on an assertion they never replayed.
    /// </remarks>
    [Fact]
    public async Task One_clients_jti_does_not_exclude_anothers()
    {
        var store = NewReplayStore();

        Assert.True(await store.TryClaimAsync(Chatgpt, "1", Now.AddMinutes(5), CancellationToken.None));
        Assert.True(await store.TryClaimAsync(Claude, "1", Now.AddMinutes(5), CancellationToken.None));
    }

    /// <summary>Identifiers are compared ordinally, so case is not folded.</summary>
    /// <remarks>
    /// A <c>jti</c> is an opaque string the client chose. Folding case would refuse an assertion
    /// nobody replayed, and the client has no way to discover why.
    /// </remarks>
    [Fact]
    public async Task Identifiers_differing_only_in_case_are_different_identifiers()
    {
        var store = NewReplayStore();

        Assert.True(await store.TryClaimAsync(Chatgpt, "AbC", Now.AddMinutes(5), CancellationToken.None));
        Assert.True(await store.TryClaimAsync(Chatgpt, "abc", Now.AddMinutes(5), CancellationToken.None));
    }

    /// <summary>
    /// Claimed concurrently, exactly one caller wins.
    /// </summary>
    /// <remarks>
    /// <b>The test the obvious implementation fails.</b> A read followed by an insert passes
    /// "claim, then claim again" — that is sequential — and loses here, where every caller reads
    /// before any of them writes. Sequential is the case that never happens during a replay attempt;
    /// this is the case that does.
    /// </remarks>
    [Fact]
    public async Task Claiming_many_times_in_parallel_succeeds_exactly_once()
    {
        var store = NewReplayStore();

        var attempts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            store.TryClaimAsync(Chatgpt, "raced", Now.AddMinutes(5), CancellationToken.None)));

        Assert.Equal(1, attempts.Count(won => won));
    }

    /// <summary>An expired row is claimable again once it has been swept, and not before.</summary>
    /// <remarks>
    /// Both halves matter. Sweeping early would reopen the replay window; never sweeping is a table
    /// that grows without bound. The store does not decide when — nothing here schedules the sweep —
    /// so what is asserted is that the method does what its name says when a deployment calls it.
    /// </remarks>
    [Fact]
    public async Task An_expired_claim_is_only_released_by_the_sweep()
    {
        var store = NewReplayStore();

        await store.TryClaimAsync(Chatgpt, "old", Now, CancellationToken.None);

        // Long past its expiry, and still claimed: expiry alone releases nothing.
        Assert.False(await store.TryClaimAsync(Chatgpt, "old", Now, CancellationToken.None));

        Assert.Equal(1, await store.DeleteExpiredAsync(Now.AddMinutes(1), CancellationToken.None));

        Assert.True(await store.TryClaimAsync(Chatgpt, "old", Now.AddMinutes(6), CancellationToken.None));
    }

    /// <summary>The sweep takes the expired rows and leaves the live ones.</summary>
    [Fact]
    public async Task The_sweep_leaves_claims_that_have_not_expired()
    {
        var store = NewReplayStore();

        await store.TryClaimAsync(Chatgpt, "expired", Now, CancellationToken.None);
        await store.TryClaimAsync(Chatgpt, "live", Now.AddMinutes(10), CancellationToken.None);

        Assert.Equal(1, await store.DeleteExpiredAsync(Now.AddMinutes(1), CancellationToken.None));

        // Still claimed, so still refused.
        Assert.False(await store.TryClaimAsync(Chatgpt, "live", Now.AddMinutes(10), CancellationToken.None));
    }

    /// <summary>Sweeping an empty store is zero rather than an error.</summary>
    [Fact]
    public async Task Sweeping_nothing_is_zero()
    {
        var store = NewReplayStore();

        Assert.Equal(0, await store.DeleteExpiredAsync(Now, CancellationToken.None));
    }
}

/// <summary>The replay contract, against the in-memory store.</summary>
public sealed class InMemoryClientAssertionReplayStoreTests : ClientAssertionReplayStoreContract
{
    /// <inheritdoc />
    protected override IClientAssertionReplayStore NewReplayStore() => new InMemoryClientAssertionReplayStore();
}
