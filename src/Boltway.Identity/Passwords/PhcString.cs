using System.Globalization;

namespace Boltway.Identity.Passwords;

/// <summary>A stored password hash, decomposed.</summary>
/// <param name="Parameters">The cost this hash was produced with — <b>not</b> the current configuration.</param>
/// <param name="Salt">The salt, as stored.</param>
/// <param name="Hash">The tag, as stored.</param>
public sealed record DecodedPasswordHash(Argon2idParameters Parameters, byte[] Salt, byte[] Hash);

/// <summary>
/// The PHC string format: <c>$argon2id$v=19$m=…,t=…,p=…$salt$hash</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the parameters live in the string.</b> A stored hash that records only the digest forces
/// verification to use whatever the configuration says today, so the day an operator raises the cost
/// is the day every existing password stops verifying. Carrying <c>m</c>, <c>t</c>, <c>p</c>, the
/// salt and the algorithm tag alongside the digest is what makes a cost increase a deploy rather
/// than a mass password reset — and it is why <see cref="Argon2idPasswordHasher.Verify"/> reads its
/// parameters from here and never from the hasher's own configuration.
/// </para>
/// <para>
/// <b>Why this format rather than one of our own.</b> It is what the Argon2 reference implementation
/// emits and what libsodium, passlib, and the Go and Rust implementations read. A customer migrating
/// onto this server can bring their existing column across, and one migrating away is not locked in
/// by a bespoke encoding. The alternative — a private format — costs the same code and gives that up.
/// </para>
/// <para>
/// The base64 is RFC 4648 §4 <b>without padding</b>, which is what the PHC specification requires
/// and what the reference implementation writes. Decoding round-trips and compares, so a padded, a
/// whitespace-bearing or a base64url-alphabet variant is rejected rather than silently accepted as a
/// second spelling of the same hash.
/// </para>
/// </remarks>
public static class PhcString
{
    /// <summary>The only algorithm this server writes or reads.</summary>
    private const string Algorithm = "argon2id";

    /// <summary>Argon2 version 1.3, the version every current implementation produces.</summary>
    private const int Version = 19;

    /// <summary>Render a hash for storage.</summary>
    public static string Format(Argon2idParameters parameters, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"${Algorithm}$v={Version}${parameters.ToPhcSegment()}${Unpadded(salt)}${Unpadded(hash)}");
    }

    /// <summary>
    /// Parse a stored hash.
    /// </summary>
    /// <remarks>
    /// Returns <see langword="false"/> rather than throwing, on anything malformed. The caller is a
    /// login endpoint reading a database column: a row in a format we do not recognise must fail the
    /// login, not return a 500 that an attacker can provoke and read as a signal. The cost of that
    /// choice is that genuine corruption is silent here, which is why the decoded form is public —
    /// an operator tool can call this and tell the two apart.
    /// </remarks>
    public static bool TryParse(string? encoded, out DecodedPasswordHash? decoded)
    {
        decoded = null;

        if (string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        // A leading '$' means the first field is empty, so a well-formed string has six.
        var fields = encoded.Split('$');

        if (fields.Length != 6
            || fields[0].Length != 0
            || !string.Equals(fields[1], Algorithm, StringComparison.Ordinal)
            || !string.Equals(fields[2], "v=" + Version.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
        {
            return false;
        }

        if (!TryParseCost(fields[3], out var parameters)
            || !TryDecodeCanonical(fields[4], out var salt)
            || !TryDecodeCanonical(fields[5], out var hash))
        {
            return false;
        }

        // The lengths are part of the parameters, so a stored hash whose salt or tag is a different
        // size than its own header claims is refused rather than reinterpreted.
        var withLengths = parameters! with { SaltBytes = salt!.Length, HashBytes = hash!.Length };

        if (!withLengths.IsValid)
        {
            return false;
        }

        decoded = new DecodedPasswordHash(withLengths, salt, hash);
        return true;
    }

    /// <summary>
    /// Parse <c>m=…,t=…,p=…</c>, in that order and with nothing else present.
    /// </summary>
    /// <remarks>
    /// Order-sensitive on purpose. The PHC specification lets a producer order the parameters as it
    /// likes, and accepting any order would mean two different strings encode one hash — so the
    /// string a re-encode produces would not always equal the string that was stored, and
    /// "is this the current configuration?" would have to be answered by comparing parsed values
    /// rather than by comparing text. Every implementation writes <c>m,t,p</c>; reading only that
    /// keeps the encoding canonical. The cost is refusing a hypothetical producer that reorders them.
    /// </remarks>
    private static bool TryParseCost(string segment, out Argon2idParameters? parameters)
    {
        parameters = null;

        var parts = segment.Split(',');

        if (parts.Length != 3
            || !TryParseKeyed(parts[0], 'm', out var memory)
            || !TryParseKeyed(parts[1], 't', out var iterations)
            || !TryParseKeyed(parts[2], 'p', out var parallelism))
        {
            return false;
        }

        parameters = new Argon2idParameters
        {
            MemoryKiB = memory,
            Iterations = iterations,
            Parallelism = parallelism,
        };

        return true;
    }

    private static bool TryParseKeyed(string part, char key, out int value)
    {
        value = 0;

        if (part.Length < 3 || part[0] != key || part[1] != '=')
        {
            return false;
        }

        // NumberStyles.None: no sign, no whitespace, no thousands separator. "+2", " 2" and "2 "
        // are all refused, so the parsed number and the stored text stay one-to-one.
        return int.TryParse(part.AsSpan(2), NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// Decode unpadded standard base64, refusing anything that is not the canonical spelling.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three mechanisms, and it is worth recording which does what, because a control showed the
    /// last one carrying less weight than its first description claimed. The explicit <c>=</c> test
    /// refuses padding. <see cref="Convert.TryFromBase64String"/> refuses the base64url alphabet and
    /// embedded whitespace on its own.
    /// </para>
    /// <para>
    /// What is left for the round-trip comparison is <b>non-zero trailing bits</b>, which the
    /// decoder accepts silently: a 16-byte value ends in a character carrying two significant bits
    /// and four ignored ones, so <c>…ODw</c>, <c>…ODx</c>, <c>…ODy</c> and <c>…ODz</c> all decode to
    /// the same bytes. Without this comparison those are four spellings of one salt, and re-encoding
    /// a stored hash would not reproduce the string that was stored.
    /// </para>
    /// </remarks>
    private static bool TryDecodeCanonical(string value, out byte[]? decoded)
    {
        decoded = null;

        // Bounded before anything is allocated. The input is a database column, and the padding
        // step below concatenates — so the length check has to come first or a very long field is a
        // large allocation on the login path. 86 characters is the unpadded encoding of MaxLength.
        const int MaxEncodedLength = 86;

        if (value.Length is 0 or > MaxEncodedLength || value.Contains('=', StringComparison.Ordinal))
        {
            return false;
        }

        var padding = (4 - (value.Length % 4)) % 4;

        if (padding == 3)
        {
            // A single leftover base64 character encodes no whole byte; no encoder produces it.
            return false;
        }

        Span<byte> buffer = stackalloc byte[Argon2idParameters.MaxLength];

        // A buffer of exactly MaxLength also enforces the length ceiling: anything longer cannot be
        // written and TryFromBase64String answers false rather than truncating.
        if (!Convert.TryFromBase64String(value + new string('=', padding), buffer, out var written))
        {
            return false;
        }

        var bytes = buffer[..written].ToArray();

        if (!string.Equals(Unpadded(bytes), value, StringComparison.Ordinal))
        {
            return false;
        }

        decoded = bytes;
        return true;
    }

    private static string Unpadded(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=');
}
