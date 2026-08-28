using System.Collections.Concurrent;
using Boltway.Identity.Subjects;

namespace Boltway.Identity.Tests;

/// <summary>A clock a test can hold still or move.</summary>
/// <remarks>
/// The same shape as the authorization server's <c>MovableClock</c>, and here rather than shared
/// because this project has no reason to reference that test assembly. Holding the clock still is
/// what makes the same-millisecond branch reachable on purpose instead of by luck - a real clock
/// gives you that branch only when two mints happen to land in one tick.
/// </remarks>
internal sealed class FixedClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    public void Set(DateTimeOffset to) => _now = to;
}

public sealed class UlidTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 4, 12, 0, 0, TimeSpan.Zero);

    private static UlidFactory Factory(out FixedClock clock)
    {
        clock = new FixedClock(Now);
        return new UlidFactory(clock);
    }

    // ------------------------------------------------------------------ A-18: the shape

    [Fact]
    public void A_minted_ulid_is_26_characters_of_crockford_base32()
    {
        var value = Factory(out _).Mint();

        Assert.Equal(26, value.Length);
        Assert.True(Ulid.IsWellFormed(value), value);
    }

    /// <summary>
    /// Nothing a minted subject contains needs escaping anywhere. A-18.
    /// </summary>
    /// <remarks>
    /// Asserted as an explicit character list rather than by re-stating the alphabet, because a test
    /// that re-states the implementation's constant passes whatever that constant becomes. These are
    /// the characters that make a connector write a sanitiser, plus the ones that would make a
    /// value unsafe in a path, a shell word or a SQL identifier.
    /// </remarks>
    [Fact]
    public void A_minted_subject_needs_no_sanitiser_anywhere()
    {
        var factory = Factory(out _);

        for (var i = 0; i < 200; i++)
        {
            var value = factory.Mint();

            foreach (var hostile in "|/\\.@%:?#&='\" \t\r\n<>[]{}(),;*+`$!~^")
            {
                Assert.DoesNotContain(hostile, value);
            }

            // I, L, O and U are excluded by Crockford base32 so that a transcribed identifier cannot
            // become a different one.
            foreach (var confusable in "ILOUilou")
            {
                Assert.DoesNotContain(confusable, value);
            }
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0123456789ABCDEFGHJKMNPQR")]      // 25 characters
    [InlineData("0123456789ABCDEFGHJKMNPQRST")]    // 27 characters
    [InlineData("0123456789ABCDEFGHJKMNPQRI")]     // I is not in the alphabet
    [InlineData("0123456789ABCDEFGHJKMNPQRU")]     // nor is U
    [InlineData("0123456789abcdefghjkmnpqrs")]     // lowercase: a second spelling of one subject
    [InlineData("0123456789ABCDEFGHJKMNPQR-")]
    [InlineData("Z123456789ABCDEFGHJKMNPQRS")]     // decodes to more than 128 bits
    public void A_string_that_is_not_a_ulid_is_not_well_formed(string? value) =>
        Assert.False(Ulid.IsWellFormed(value));

    [Fact]
    public void The_leading_character_is_bounded_because_26_characters_carry_130_bits()
    {
        // The check that a charset-only test would miss. '8' is in the alphabet, so a value starting
        // with it passes every character test and still is not a 128-bit ULID.
        Assert.False(Ulid.IsWellFormed("8123456789ABCDEFGHJKMNPQRS"));
        Assert.True(Ulid.IsWellFormed("7123456789ABCDEFGHJKMNPQRS"));
    }

    // ------------------------------------------------------------------ monotonicity

    [Fact]
    public void Ulids_minted_in_one_millisecond_still_increase()
    {
        // The clock does not move at all, so every mint here takes the same-millisecond branch. On a
        // real clock this branch is reached only when two mints happen to share a tick, which is why
        // the clock is injected.
        var factory = Factory(out _);

        var minted = Enumerable.Range(0, 500).Select(_ => factory.Mint()).ToList();

        for (var i = 1; i < minted.Count; i++)
        {
            Assert.True(
                string.CompareOrdinal(minted[i - 1], minted[i]) < 0,
                $"{minted[i - 1]} is not before {minted[i]}");
        }
    }

    [Fact]
    public void A_later_millisecond_sorts_after_an_earlier_one()
    {
        var factory = Factory(out var clock);

        var first = factory.Mint();
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var second = factory.Mint();

        Assert.True(string.CompareOrdinal(first, second) < 0, $"{first} is not before {second}");

        // The timestamp is the first ten characters, so two mints a second apart differ there and
        // not only in the random tail.
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.NotEqual(second[..10], factory.Mint()[..10], StringComparer.Ordinal);
    }

    /// <summary>
    /// A clock that steps backwards does not produce an identifier that sorts before an issued one.
    /// </summary>
    /// <remarks>
    /// Not hypothetical: an NTP correction, a VM restored from a snapshot, or a second instance with
    /// a slower clock all produce a lower reading than one already used. Trusting it would mint a
    /// subject that sorts before subjects already handed out, which is the single property this
    /// factory exists to provide.
    /// </remarks>
    [Fact]
    public void A_clock_that_moves_backwards_does_not_break_the_order()
    {
        var factory = Factory(out var clock);

        var before = factory.Mint();
        clock.Set(Now - TimeSpan.FromMinutes(5));

        var after = factory.Mint();

        Assert.True(string.CompareOrdinal(before, after) < 0, $"{before} is not before {after}");
        Assert.True(Ulid.IsWellFormed(after), after);
    }

    // ------------------------------------------------------------------ uniqueness

    [Fact]
    public void Concurrent_mints_are_all_distinct()
    {
        // One factory is shared across requests, so the read of the last timestamp and the increment
        // have to be one critical section. Without the lock two threads read the same randomness and
        // mint the same subject - and a duplicate `sub` is two users sharing one identity.
        //
        // The clock is held still deliberately: every thread lands in the same millisecond, which is
        // the branch with shared mutable state and therefore the only branch a race can be found in.
        //
        // Eight dedicated threads released together by a Barrier, rather than Parallel.For - the
        // same shape as GrantStoreContract.RunConcurrently, and for its stated reason: a Barrier
        // blocks the thread it runs on, so a thread-pool-backed version waits on the pool's slow
        // injection heuristic instead of genuinely colliding.
        //
        // It is also bounded rather than unbounded, which matters on a small machine. It was
        // suspected of a second sin - that an unbounded contended loop here was starving the
        // loopback-TLS fetches in Boltway.OAuth.Net.Tests, which time out when the solution's
        // test projects run in parallel on a loaded box. That was measured and is NOT true: the
        // unmodified base fails the same fetch test under the same load with none of this present.
        // The bound stays because it is the better pattern, not because it fixed that.
        const int Threads = 8;
        const int PerThread = 500;

        var factory = Factory(out _);
        var minted = new ConcurrentBag<string>();
        var ready = new Barrier(Threads);
        var threads = new Thread[Threads];

        for (var i = 0; i < Threads; i++)
        {
            threads[i] = new Thread(() =>
            {
                ready.SignalAndWait();

                for (var n = 0; n < PerThread; n++)
                {
                    minted.Add(factory.Mint());
                }
            })
            { IsBackground = true };

            threads[i].Start();
        }

        foreach (var thread in threads)
        {
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "a concurrent worker did not finish");
        }

        Assert.Equal(Threads * PerThread, minted.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Two_factories_on_the_same_clock_do_not_collide()
    {
        // Two processes, or two instances in one process. Their sequences share a timestamp and differ
        // only in the 80 random bits, so this is a check that the randomness is drawn per factory
        // rather than derived from the clock.
        var clock = new FixedClock(Now);
        var left = new UlidFactory(clock);
        var right = new UlidFactory(clock);

        var fromLeft = Enumerable.Range(0, 100).Select(_ => left.Mint()).ToHashSet(StringComparer.Ordinal);
        var fromRight = Enumerable.Range(0, 100).Select(_ => right.Mint()).ToList();

        Assert.DoesNotContain(fromRight, fromLeft.Contains);
    }

    // ------------------------------------------------------------------ subjects

    [Fact]
    public void A_minted_subject_id_is_a_well_formed_ulid()
    {
        var clock = new FixedClock(Now);
        var factory = new UlidSubjectIdFactory(clock);

        var subject = factory.Mint();

        Assert.True(Ulid.IsWellFormed(subject.Value), subject.Value);
    }
}
