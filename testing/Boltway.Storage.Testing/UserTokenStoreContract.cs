using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.Storage.Testing;

/// <summary>
/// The <see cref="IUserTokenStore"/> contract, run against every implementation.
/// </summary>
/// <remarks>
/// <para>
/// Four clauses, and they are <c>S-47</c> word for word: single use, hashed at rest, expiring, and
/// destroyed in bulk when the password changes by any route. Each one is here because a link that
/// survives any of them is a second key to somebody's account.
/// </para>
/// <para>
/// <b>The single-use clause is the one an implementation gets wrong.</b> The obvious shape is a read
/// followed by a delete, and it passes every test written as "redeem, then redeem again" — because
/// that is sequential. What it fails is two presentations at once, which is a person double-clicking
/// their own mail on a good day and somebody racing a stolen link on a bad one.
/// </para>
/// </remarks>
public abstract class UserTokenStoreContract
{
    /// <summary>A fresh, empty token store.</summary>
    protected abstract IUserTokenStore NewTokenStore();

    private static readonly SubjectId Ada = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY");

    private static readonly SubjectId Grace = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0ZZ");

    private static readonly DateTimeOffset Now = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);

    private static Sha256Hash HashOf(string token) => Sha256Hash.OfString(token);

    private static UserTokenRecord Reset(string token, SubjectId subject, DateTimeOffset expiresAt) =>
        new(HashOf(token), subject, UserTokenPurpose.PasswordReset, expiresAt);

    /// <summary>
    /// A hash this store never held redeems as <see langword="null"/> rather than throwing.
    /// </summary>
    [Fact]
    public async Task A_token_that_was_never_issued_is_not_redeemable()
    {
        var store = NewTokenStore();

        Assert.Null(await store.RedeemAsync(
            HashOf("never-issued"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));
    }

    /// <summary>
    /// <c>S-47</c>'s single-use clause, sequentially: the first redemption returns the record and the
    /// second finds nothing.
    /// </summary>
    [Fact]
    public async Task A_stored_token_is_redeemable_once()
    {
        var store = NewTokenStore();

        await store.StoreAsync(Reset("t1", Ada, Now.AddMinutes(15)), CancellationToken.None);

        var first = await store.RedeemAsync(
            HashOf("t1"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None);

        Assert.NotNull(first);
        Assert.Equal(Ada, first.Subject);

        // The clause the whole table exists for. A second presentation finds nothing, whether it is
        // a person clicking twice or somebody replaying a link they intercepted.
        Assert.Null(await store.RedeemAsync(
            HashOf("t1"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));
    }

    /// <summary>
    /// Single use holds under concurrency: eight simultaneous presentations of one link produce
    /// exactly one winner.
    /// </summary>
    /// <remarks>
    /// Repeated rather than run once. A store that loses this race some of the time passes a single
    /// attempt most of the time, which is indistinguishable from not testing it.
    /// </remarks>
    [Fact]
    public async Task Two_concurrent_redemptions_produce_exactly_one_winner()
    {
        // Sequential double-redemption is the easy half and the test above covers it. This is the
        // half a read-then-delete implementation fails: both callers find the row, both act, and the
        // link has been used twice.
        for (var attempt = 0; attempt < 25; attempt++)
        {
            var store = NewTokenStore();
            await store.StoreAsync(Reset("race", Ada, Now.AddMinutes(15)), CancellationToken.None);

            var racers = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
                store.RedeemAsync(HashOf("race"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None)));

            var results = await Task.WhenAll(racers);

            Assert.Equal(1, results.Count(r => r is not null));
        }
    }

    /// <summary><c>S-47</c>'s expiry clause: a token past its expiry is not redeemable.</summary>
    [Fact]
    public async Task An_expired_token_is_not_redeemable()
    {
        var store = NewTokenStore();

        await store.StoreAsync(Reset("stale", Ada, Now.AddMinutes(-1)), CancellationToken.None);

        Assert.Null(await store.RedeemAsync(
            HashOf("stale"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));
    }

    /// <summary>
    /// A verification link is not a reset link, and the refused attempt does not consume it either.
    /// </summary>
    [Fact]
    public async Task A_token_is_not_redeemable_for_another_purpose()
    {
        // The reason the purpose is stored rather than inferred from which endpoint is asking. A
        // verification link redeemable at the reset endpoint would let anyone who can receive a
        // "confirm your address" mail set the password — and that mail goes to an address somebody
        // typed, sometimes before anyone has proven it is theirs.
        var store = NewTokenStore();

        await store.StoreAsync(
            new UserTokenRecord(
                HashOf("v1"), Ada, UserTokenPurpose.EmailVerification, Now.AddHours(24), "ada@example.com"),
            CancellationToken.None);

        Assert.Null(await store.RedeemAsync(
            HashOf("v1"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));

        // And the failed attempt did not consume it: somebody probing the wrong endpoint must not be
        // able to destroy a link they could not use.
        Assert.NotNull(await store.RedeemAsync(
            HashOf("v1"), UserTokenPurpose.EmailVerification, Now, CancellationToken.None));
    }

    /// <summary>
    /// The address a verification link was sent to comes back with the redemption, in <c>Detail</c>.
    /// </summary>
    [Fact]
    public async Task A_verification_token_carries_the_address_it_was_sent_to()
    {
        var store = NewTokenStore();

        await store.StoreAsync(
            new UserTokenRecord(
                HashOf("v2"), Ada, UserTokenPurpose.EmailVerification, Now.AddHours(24), "ada@example.com"),
            CancellationToken.None);

        var redeemed = await store.RedeemAsync(
            HashOf("v2"), UserTokenPurpose.EmailVerification, Now, CancellationToken.None);

        // Round-tripped, because the caller compares it to the address on the account: somebody who
        // asks for a link, changes their address, then clicks the old link must not end up with the
        // new one marked verified.
        Assert.Equal("ada@example.com", redeemed!.Detail);
    }

    /// <summary>
    /// Storing a hash the table already holds throws rather than overwriting the record it collides
    /// with.
    /// </summary>
    [Fact]
    public async Task Storing_the_same_hash_twice_is_refused()
    {
        var store = NewTokenStore();

        await store.StoreAsync(Reset("dup", Ada, Now.AddMinutes(15)), CancellationToken.None);

        // Cannot happen with 256 bits of CSPRNG output. It throws rather than being tolerated
        // because an upsert would move somebody else's expiry, and because two implementations
        // disagreeing on identical input is what these contracts exist to prevent.
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.StoreAsync(Reset("dup", Grace, Now.AddMinutes(1)), CancellationToken.None));
    }

    /// <summary>
    /// <c>S-47</c>'s bulk-destruction clause: one subject's reset links all go and the call says how
    /// many, while their verification link and another subject's reset link stay.
    /// </summary>
    [Fact]
    public async Task Deleting_for_a_subject_destroys_that_purpose_and_leaves_the_rest()
    {
        // S-47's fourth clause. Every password change calls this, by every route, because a reset
        // link that still works afterwards is a second key held by whoever asked for it.
        var store = NewTokenStore();

        await store.StoreAsync(Reset("a1", Ada, Now.AddMinutes(15)), CancellationToken.None);
        await store.StoreAsync(Reset("a2", Ada, Now.AddMinutes(15)), CancellationToken.None);
        await store.StoreAsync(
            new UserTokenRecord(HashOf("av"), Ada, UserTokenPurpose.EmailVerification, Now.AddHours(24), "a@e"),
            CancellationToken.None);
        await store.StoreAsync(Reset("g1", Grace, Now.AddMinutes(15)), CancellationToken.None);

        Assert.Equal(
            2,
            await store.DeleteForSubjectAsync(Ada, UserTokenPurpose.PasswordReset, CancellationToken.None));

        Assert.Null(await store.RedeemAsync(
            HashOf("a1"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));
        Assert.Null(await store.RedeemAsync(
            HashOf("a2"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));

        // Ada's verification link survives — changing a password says nothing about whether an
        // address is hers — and so does Grace's reset link, which is the control that catches a
        // predicate missing its subject clause.
        Assert.NotNull(await store.RedeemAsync(
            HashOf("av"), UserTokenPurpose.EmailVerification, Now, CancellationToken.None));
        Assert.NotNull(await store.RedeemAsync(
            HashOf("g1"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));
    }

    /// <summary>
    /// Deleting for a subject holding nothing is zero rather than a failure.
    /// </summary>
    [Fact]
    public async Task Deleting_for_a_subject_with_no_tokens_is_zero_rather_than_an_error()
    {
        // Every password change calls it, and most accounts have never asked for a reset. If this
        // were a failure the ordinary case would be the broken one — and S-48 makes it worse than
        // that: the unfound path of a reset request runs this too, precisely so the timing does not
        // distinguish a real account from an invented one.
        var store = NewTokenStore();

        Assert.Equal(
            0,
            await store.DeleteForSubjectAsync(Ada, UserTokenPurpose.PasswordReset, CancellationToken.None));
    }

    /// <summary>
    /// The sweep takes the expired row, reports one, and the live link still redeems afterwards.
    /// </summary>
    [Fact]
    public async Task Expired_tokens_are_swept_and_live_ones_are_left()
    {
        var store = NewTokenStore();

        await store.StoreAsync(Reset("old", Ada, Now.AddMinutes(-1)), CancellationToken.None);
        await store.StoreAsync(Reset("live", Grace, Now.AddMinutes(15)), CancellationToken.None);

        Assert.Equal(1, await store.DeleteExpiredAsync(Now, CancellationToken.None));

        Assert.NotNull(await store.RedeemAsync(
            HashOf("live"), UserTokenPurpose.PasswordReset, Now, CancellationToken.None));
    }
}
