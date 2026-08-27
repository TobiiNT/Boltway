using System.Globalization;

namespace Boltway.Identity.Passwords;

/// <summary>
/// The cost of one Argon2id evaluation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Where the defaults come from.</b> OWASP's Password Storage Cheat Sheet gives five Argon2id
/// configurations it treats as equivalent in strength, trading memory against iterations:
/// <c>m=47104,t=1</c>, <c>m=19456,t=2</c>, <c>m=12288,t=3</c>, <c>m=9216,t=4</c> and
/// <c>m=7168,t=5</c>, all at <c>p=1</c>. This takes the second - 19 MiB, two passes - read from the
/// 2025 revision of that page. RFC 9106 §4 recommends more (2 GiB or 64 MiB at <c>p=4</c>), and that
/// recommendation is written for a machine dedicated to the hash; this server is a web process whose
/// login endpoint may be hit concurrently, and memory is per <i>in-flight</i> hash. Nineteen MiB
/// times a few dozen simultaneous logins is a number an operator can reason about; 2 GiB times the
/// same is an outage.
/// </para>
/// <para>
/// <c>p=1</c> rather than the RFC's 4, because parallelism only buys anything when the lanes get
/// real cores, and a web worker handling many requests does not have four cores to give one login.
/// At <c>p=4</c> on one core the cost is the same wall-clock work with a weaker memory-hardness
/// guarantee than <c>p=1</c> at the same <c>m</c>.
/// </para>
/// <para>
/// <b>How to revise them.</b> Construct the hasher with a different <see cref="Argon2idParameters"/>
/// and deploy. Nothing else has to happen and no stored password becomes unverifiable: every hash
/// carries the parameters it was produced with, so verification keeps using those. A hash produced
/// under weaker settings then answers <see langword="true"/> from
/// <see cref="Argon2idPasswordHasher.NeedsRehash"/>, and a caller that consults it can re-hash the
/// plaintext it just verified. The right cadence is to re-read the cheat sheet's table roughly
/// yearly and to re-measure on the target hardware, because the number that actually matters is
/// wall-clock time per hash on the machine that runs it - aim for the region of 100 ms and no more
/// than a login can afford.
/// </para>
/// </remarks>
public sealed record Argon2idParameters
{
    /// <summary>
    /// A ceiling on every cost axis, applied to parsed values as well as configured ones.
    /// </summary>
    /// <remarks>
    /// This is not a style limit. <see cref="Argon2idPasswordHasher.Verify"/> takes its cost from the
    /// <i>stored</i> string, which is the only way a cost increase can avoid invalidating existing
    /// passwords - and that makes a database column an input to an allocation. A row saying
    /// <c>m=16777216</c> would have the login endpoint try to allocate 16 GiB. The ceiling is what
    /// stops a corrupt or tampered row from being a denial of service, and it applies to configured
    /// parameters too so that the two can never disagree about what is representable.
    /// </remarks>
    public const int MaxMemoryKiB = 1024 * 1024;

    /// <summary>Ceiling on iterations. See <see cref="MaxMemoryKiB"/>.</summary>
    public const int MaxIterations = 32;

    /// <summary>Ceiling on lanes. See <see cref="MaxMemoryKiB"/>.</summary>
    public const int MaxParallelism = 16;

    /// <summary>Ceiling on salt and tag length, in bytes. See <see cref="MaxMemoryKiB"/>.</summary>
    public const int MaxLength = 64;

    /// <summary>Memory in kibibytes. Argon2's <c>m</c>.</summary>
    public required int MemoryKiB { get; init; }

    /// <summary>Passes over memory. Argon2's <c>t</c>.</summary>
    public required int Iterations { get; init; }

    /// <summary>Lanes. Argon2's <c>p</c>.</summary>
    public required int Parallelism { get; init; }

    /// <summary>Salt length in bytes. 128 bits, per RFC 9106 §3.1.</summary>
    public int SaltBytes { get; init; } = 16;

    /// <summary>Tag length in bytes.</summary>
    public int HashBytes { get; init; } = 32;

    /// <summary>The shipped defaults. See the type's remarks for where they come from.</summary>
    public static Argon2idParameters Default { get; } = new()
    {
        MemoryKiB = 19456,
        Iterations = 2,
        Parallelism = 1,
    };

    /// <summary>Check every bound, naming the axis that failed.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A parameter is outside its bounds.</exception>
    public Argon2idParameters Validated()
    {
        Require(MemoryKiB >= 8 * Parallelism && MemoryKiB <= MaxMemoryKiB, nameof(MemoryKiB), MemoryKiB);
        Require(Iterations is >= 1 && Iterations <= MaxIterations, nameof(Iterations), Iterations);
        Require(Parallelism is >= 1 && Parallelism <= MaxParallelism, nameof(Parallelism), Parallelism);

        // Eight bytes is Argon2's own minimum salt; sixteen is what we emit. Sixteen for the tag is
        // the floor at which a birthday collision stops being a consideration.
        Require(SaltBytes is >= 8 && SaltBytes <= MaxLength, nameof(SaltBytes), SaltBytes);
        Require(HashBytes is >= 16 && HashBytes <= MaxLength, nameof(HashBytes), HashBytes);

        return this;
    }

    /// <summary>Whether every bound holds, without throwing. For parsing untrusted stored values.</summary>
    public bool IsValid
    {
        get
        {
            try
            {
                _ = Validated();
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }
    }

    /// <summary>The <c>m=…,t=…,p=…</c> segment of a PHC string, in the reference implementation's order.</summary>
    internal string ToPhcSegment() => string.Create(
        CultureInfo.InvariantCulture, $"m={MemoryKiB},t={Iterations},p={Parallelism}");

    private static void Require(bool condition, string name, int value)
    {
        if (!condition)
        {
            // The value, never anything derived from a password. Nothing in this type is secret.
            throw new ArgumentOutOfRangeException(name, value, $"Argon2id parameter '{name}' is out of range.");
        }
    }
}
