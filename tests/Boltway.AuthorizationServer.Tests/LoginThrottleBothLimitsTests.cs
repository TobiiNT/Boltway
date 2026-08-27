using System.Net;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// What <c>Retry-After</c> says when both limiters are blocked at once.
/// </summary>
public sealed partial class ThrottleResponseTests
{
    /// <summary>
    /// With both budgets exhausted, the caller is told to wait for the longer one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The selection reads:
    /// </para>
    /// <code>
    /// var wait = account.Allowed ? source.RetryAfter
    ///     : source.Allowed ? account.RetryAfter
    ///     : account.RetryAfter &gt; source.RetryAfter ? account.RetryAfter : source.RetryAfter;
    /// </code>
    /// <para>
    /// Mutation testing marked the third line <c>NoCoverage</c> - every mutant of it, including
    /// flipping <c>&gt;</c> to <c>&lt;</c>. No test had ever blocked both limiters at the same time.
    /// The existing pair covers one each: <c>Too_many_attempts_on_one_username</c> stays under the
    /// source budget, and <c>Too_many_attempts_from_one_source</c> spreads across usernames so no
    /// account budget is touched.
    /// </para>
    /// <para>
    /// The comment on that line states the consequence: "a caller told to wait for the shorter one
    /// comes back and is refused again by the other - which reads as a limiter that ignores its own
    /// Retry-After". Picking the smaller is not a security hole; it is a client that retries into a
    /// wall it was told had come down.
    /// </para>
    /// <para>
    /// Two rows, with the longer backoff on opposite sides, because a single row cannot tell
    /// "the larger of the two" from "always the account's" or "always the source's". Both budgets
    /// are exhausted by hammering one username: the account counter trips first, and the attempts
    /// keep counting against the source counter after it does.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(60, 5)]   // the account's backoff is the longer one
    [InlineData(5, 60)]   // the source's is
    public async Task Both_budgets_exhausted_reports_the_longer_wait(int accountSeconds, int sourceSeconds)
    {
        await using var server = await StartAsync(o =>
        {
            o.MaxAttemptsPerAccount = 2;
            o.AccountInitialBackoff = TimeSpan.FromSeconds(accountSeconds);
            o.AccountMaxBackoff = TimeSpan.FromSeconds(accountSeconds);

            o.MaxAttemptsPerClient = 4;
            o.ClientInitialBackoff = TimeSpan.FromSeconds(sourceSeconds);
            o.ClientMaxBackoff = TimeSpan.FromSeconds(sourceSeconds);
        });

        HttpResponseMessage? last = null;

        // Six attempts on one username: past 2 the account is blocked, past 4 the source is too.
        for (var i = 0; i < 6; i++)
        {
            last = await PostLoginAsync(server, Username, "wrong password");
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, last!.StatusCode);
        Assert.True(last.Headers.TryGetValues("Retry-After", out var values), "a 429 with no Retry-After");

        var seconds = int.Parse(values!.Single(), System.Globalization.CultureInfo.InvariantCulture);

        // Retry-After is whole seconds and the header is written from a remaining duration, so the
        // value can be a tick under the configured backoff. The assertion is the choice between the
        // two, which is what the mutants change - not the arithmetic of the countdown.
        var longer = Math.Max(accountSeconds, sourceSeconds);
        var shorter = Math.Min(accountSeconds, sourceSeconds);

        Assert.True(
            seconds > shorter,
            $"Retry-After was {seconds}s, which is the shorter of the two budgets ({shorter}s) "
            + $"rather than the longer ({longer}s).");

        Assert.True(seconds <= longer, $"Retry-After was {seconds}s, longer than either budget.");
    }

    /// <summary>
    /// The default concurrency bound is one per core, with a floor of two.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>Math.Max(2, Environment.ProcessorCount)</c>, mutated to <c>Math.Min</c>, survived. The
    /// remarks on that property record what the value is for, measured: a hundred concurrent posts
    /// against the shipped Argon2id parameters produced a login p50 of 4.5 s and stalled an
    /// unrelated metadata request for 4.4 s. Under <c>Min</c> the bound is 2 whatever the hardware,
    /// so a sixteen-core host runs eight times fewer hashes than it has cores for.
    /// </para>
    /// <para>
    /// Asserted as the two properties the remarks argue for rather than by restating the
    /// expression, which would be a tautology that any edit changes in lockstep.
    /// </para>
    /// <para>
    /// <b>This test cannot fail on a one- or two-core machine</b>, because <c>Max</c> and
    /// <c>Min</c> agree there. Said out loud: on a small CI runner the mutant survives this test
    /// too, and the assertion below is then vacuous rather than passing on merit.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_default_verification_bound_is_one_per_core_with_a_floor_of_two()
    {
        var options = new Boltway.AuthorizationServer.Interaction.LoginThrottleOptions();

        Assert.True(
            options.MaxConcurrentPasswordVerifications >= 2,
            "the floor of two is gone: a single-core host would serialise every sign-in");

        Assert.True(
            options.MaxConcurrentPasswordVerifications >= Environment.ProcessorCount,
            $"the bound is {options.MaxConcurrentPasswordVerifications} on a "
            + $"{Environment.ProcessorCount}-core host, so cores sit idle under load");
    }
}
