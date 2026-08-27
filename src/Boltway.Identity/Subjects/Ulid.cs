using System.Security.Cryptography;

namespace Boltway.Identity.Subjects;

/// <summary>
/// The ULID encoding: 128 bits as 26 characters of Crockford base32.
/// </summary>
/// <remarks>
/// <para>
/// A-18 is satisfied by the <i>charset</i>, and this is where that claim is made true rather than
/// described. The alphabet omits <c>I</c>, <c>L</c>, <c>O</c> and <c>U</c>, and contains no
/// <c>|</c>, <c>/</c>, <c>.</c>, <c>@</c> or <c>%</c> - so a value from here is safe as a path
/// segment, a filename, a cache key and a column name with no sanitiser anywhere. That matters
/// because a sanitiser is a function that maps several inputs onto one output, and on an identifier
/// that is a collision waiting for the wrong two users.
/// </para>
/// <para>
/// The layout is the canonical one: 48 bits of Unix milliseconds, then 80 bits of randomness.
/// 26 characters carry 130 bits, so the leading character encodes only two significant bits and can
/// never exceed <c>'7'</c>. <see cref="IsWellFormed"/> checks that bound as well as the charset,
/// because a 26-character string of legal characters starting with <c>'Z'</c> would decode to more
/// than 128 bits and is therefore not a ULID this server minted.
/// </para>
/// </remarks>
public static class Ulid
{
    /// <summary>Characters in a ULID.</summary>
    public const int Length = 26;

    /// <summary>Characters carrying the timestamp.</summary>
    private const int TimestampLength = 10;

    /// <summary>Bytes of randomness. 80 bits, per the ULID layout.</summary>
    internal const int RandomnessBytes = 10;

    /// <summary>
    /// Crockford base32. Not RFC 4648 base32 - the excluded letters are the point.
    /// </summary>
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>
    /// Encode a timestamp and 80 bits of randomness.
    /// </summary>
    /// <param name="unixTimeMilliseconds">Milliseconds since the Unix epoch. Must fit in 48 bits.</param>
    /// <param name="randomness">Exactly <see cref="RandomnessBytes"/> bytes, most significant first.</param>
    internal static string Encode(long unixTimeMilliseconds, ReadOnlySpan<byte> randomness)
    {
        if (unixTimeMilliseconds is < 0 or > 0xFFFF_FFFF_FFFF)
        {
            throw new ArgumentOutOfRangeException(
                nameof(unixTimeMilliseconds),
                unixTimeMilliseconds,
                "A ULID timestamp is 48 bits: it cannot be negative, and it runs out in AD 10889.");
        }

        if (randomness.Length != RandomnessBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(randomness), randomness.Length, $"A ULID carries exactly {RandomnessBytes} bytes of randomness.");
        }

        Span<char> buffer = stackalloc char[Length];

        // Timestamp: 48 bits into 10 characters, left-padded with two zero bits. Written from the
        // least significant character back, so no shift ever exceeds 45.
        var remaining = unixTimeMilliseconds;
        for (var i = TimestampLength - 1; i >= 0; i--)
        {
            buffer[i] = Alphabet[(int)(remaining & 0x1F)];
            remaining >>= 5;
        }

        // Randomness: 80 bits into 16 characters, exactly, with no padding. Accumulated through a
        // bit window rather than by unrolling, because the byte and character boundaries do not line
        // up and every hand-unrolled version of this is where an off-by-one hides.
        var window = 0UL;
        var bits = 0;
        var next = TimestampLength;

        foreach (var b in randomness)
        {
            window = (window << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                bits -= 5;
                buffer[next++] = Alphabet[(int)((window >> bits) & 0x1F)];
            }
        }

        return new string(buffer);
    }

    /// <summary>
    /// Whether a string is a ULID in the form this server emits.
    /// </summary>
    /// <remarks>
    /// Uppercase only, deliberately. Crockford base32 <i>decoding</i> is case-insensitive, but
    /// accepting both cases here would mean two distinct strings naming one subject - which is the
    /// many-to-one mapping the charset was chosen to avoid in the first place. We emit uppercase, so
    /// uppercase is what is well-formed.
    /// </remarks>
    public static bool IsWellFormed(string? value)
    {
        if (value is null || value.Length != Length)
        {
            return false;
        }

        // 26 characters carry 130 bits and a ULID is 128, so the leading character is bounded. A
        // charset-only check would accept strings that decode to more than 128 bits.
        if (value[0] > '7')
        {
            return false;
        }

        foreach (var c in value)
        {
            if (Alphabet.IndexOf(c, StringComparison.Ordinal) < 0)
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// Mints ULIDs that increase, even within one millisecond.
/// </summary>
/// <remarks>
/// <para>
/// Monotonicity is not decoration on an identifier a database will index: identifiers that sort by
/// creation time keep inserts at the right-hand edge of a B-tree instead of scattered through it.
/// Within a millisecond the ULID specification says to increment the random field rather than draw
/// again, and that is what happens here - so two subjects minted in the same millisecond still order
/// correctly, and neither is predictable from the other beyond the increment.
/// </para>
/// <para>
/// <b>What this does not promise.</b> The randomness of the <i>first</i> ULID in each millisecond is
/// 80 bits from <see cref="RandomNumberGenerator"/>. Subsequent ones in that same millisecond are
/// that value plus a small integer, so an attacker holding one of them can guess its immediate
/// neighbours. That is inherent to monotonic ULIDs and is acceptable here because a subject
/// identifier is not a secret - it is an opaque name, and nothing authenticates by presenting one.
/// It would be unacceptable for anything minted by <c>OpaqueSecret</c>, which is why that type draws
/// fresh entropy every time and does not do this.
/// </para>
/// <para>
/// Thread-safe. One instance is shared across requests, so the increment and the read of the last
/// timestamp have to happen under one lock or two concurrent registrations mint the same value.
/// </para>
/// </remarks>
public sealed class UlidFactory
{
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private readonly byte[] _lastRandomness = new byte[Ulid.RandomnessBytes];
    private long _lastTimestamp = -1;

    /// <summary>Construct over a clock.</summary>
    /// <param name="time">
    /// The clock. Injected rather than <c>DateTimeOffset.UtcNow</c> so a test can hold the clock
    /// still and drive the same-millisecond branch, which is otherwise reachable only by luck.
    /// </param>
    public UlidFactory(TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        _time = time;
    }

    /// <summary>Mint the next ULID.</summary>
    public string Mint()
    {
        var now = _time.GetUtcNow().ToUnixTimeMilliseconds();

        lock (_gate)
        {
            // `<=` covers both the same millisecond and a clock that moved backwards. A backwards
            // step is real - NTP correction, a VM restored from a snapshot, a different instance's
            // clock - and reusing the last timestamp keeps the sequence monotonic through it. The
            // alternative, trusting the new lower reading, mints an identifier that sorts before one
            // already issued, which is the one property this class exists to provide.
            if (now <= _lastTimestamp)
            {
                Increment(_lastRandomness);
                return Ulid.Encode(_lastTimestamp, _lastRandomness);
            }

            _lastTimestamp = now;
            RandomNumberGenerator.Fill(_lastRandomness);

            return Ulid.Encode(now, _lastRandomness);
        }
    }

    /// <summary>
    /// Add one to an 80-bit big-endian counter.
    /// </summary>
    /// <exception cref="InvalidOperationException">The counter wrapped.</exception>
    /// <remarks>
    /// Throwing on overflow rather than wrapping. Wrapping would re-issue an identifier already
    /// minted in this millisecond, and a duplicate subject identifier is the one failure this whole
    /// type exists to prevent - so it must not be the quiet outcome. Reaching it requires 2^80
    /// registrations inside one millisecond, so the branch is unreachable in practice and is here to
    /// make that statement checkable rather than assumed.
    /// </remarks>
    private static void Increment(Span<byte> counter)
    {
        for (var i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                return;
            }
        }

        throw new InvalidOperationException(
            "The ULID randomness field wrapped within a single millisecond. Minting would repeat an "
            + "identifier that has already been issued.");
    }
}
