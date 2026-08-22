using Boltway.Identity.Passwords;

namespace Boltway.Identity.Tests;

/// <summary>
/// The stored format, on its own.
/// </summary>
/// <remarks>
/// Tested apart from the hasher because it is the part a <b>different</b> Argon2 implementation has
/// to read. A round trip through our own writer and reader would be satisfied by any private
/// encoding; these tests pin the bytes.
/// </remarks>
public sealed class PhcStringTests
{
    private static readonly Argon2idParameters Parameters = new()
    {
        MemoryKiB = 19456,
        Iterations = 2,
        Parallelism = 1,
    };

    private static byte[] Salt => [.. Enumerable.Range(0, 16).Select(i => (byte)i)];

    private static byte[] Hash => [.. Enumerable.Range(0, 32).Select(i => (byte)(255 - i))];

    [Fact]
    public void The_format_is_the_one_the_reference_implementation_writes()
    {
        // Byte-for-byte, so a change to the layout is a diff a reviewer sees rather than a
        // compatibility break discovered by a customer migrating a password column in.
        Assert.Equal(
            "$argon2id$v=19$m=19456,t=2,p=1"
            + "$AAECAwQFBgcICQoLDA0ODw"
            + "$//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA",
            PhcString.Format(Parameters, Salt, Hash));
    }

    [Fact]
    public void What_was_written_parses_back_to_what_went_in()
    {
        Assert.True(PhcString.TryParse(PhcString.Format(Parameters, Salt, Hash), out var decoded));

        Assert.Equal(19456, decoded!.Parameters.MemoryKiB);
        Assert.Equal(2, decoded.Parameters.Iterations);
        Assert.Equal(1, decoded.Parameters.Parallelism);
        Assert.Equal(Salt, decoded.Salt);
        Assert.Equal(Hash, decoded.Hash);

        // The lengths come from the fields as stored, not from the configuration, so a hash written
        // with a different salt size is described accurately rather than assumed.
        Assert.Equal(16, decoded.Parameters.SaltBytes);
        Assert.Equal(32, decoded.Parameters.HashBytes);
    }

    [Fact]
    public void A_non_default_salt_length_survives_the_round_trip()
    {
        var longSalt = new byte[32];
        Array.Fill(longSalt, (byte)7);

        Assert.True(PhcString.TryParse(
            PhcString.Format(Parameters with { SaltBytes = 32 }, longSalt, Hash), out var decoded));

        Assert.Equal(32, decoded!.Parameters.SaltBytes);
        Assert.Equal(longSalt, decoded.Salt);
    }

    /// <summary>
    /// Only the canonical spelling parses.
    /// </summary>
    /// <remarks>
    /// Two strings that decode to one hash would mean re-encoding a stored value does not always
    /// reproduce it, and "is this hash current?" is answered against the text. Each row here is a
    /// spelling some other encoder or a careless migration could produce.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]         // no leading $
    [InlineData("$argon2i$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]        // argon2i
    [InlineData("$argon2d$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]        // argon2d
    [InlineData("$argon2id$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]            // no version
    [InlineData("$argon2id$v=16$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]       // version 1.2.1
    [InlineData("$argon2id$v=19$t=1,m=64,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]       // reordered
    [InlineData("$argon2id$v=19$m=64,t=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]           // no p
    [InlineData("$argon2id$v=19$m=+64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]      // signed
    [InlineData("$argon2id$v=19$m= 64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw")]      // padded
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw==$AAECAwQFBgcICQoLDA0ODw")]     // base64 padding
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw$extra")] // seven fields
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$$AAECAwQFBgcICQoLDA0ODw")]                             // empty salt
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$")]                             // empty hash
    [InlineData("$argon2id$v=19$m=64,t=1,p=1$AAECAwQ$AAECAwQFBgcICQoLDA0ODw")]                      // 5-byte salt
    public void Anything_but_the_canonical_spelling_is_refused(string? encoded) =>
        Assert.False(PhcString.TryParse(encoded, out _));

    /// <summary>
    /// A base64 spelling with non-zero trailing bits is refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The one case only the canonical round-trip catches, and it was missing until a control found
    /// that out. Removing the round-trip comparison left every other row in this file green: padding
    /// is refused by the explicit <c>=</c> check and the base64url alphabet by
    /// <c>Convert.TryFromBase64String</c>, so the check looked load-bearing while proving nothing.
    /// </para>
    /// <para>
    /// A 16-byte salt ends in a character carrying two significant bits and four ignored ones.
    /// <c>…ODw</c>, <c>…ODx</c>, <c>…ODy</c> and <c>…ODz</c> therefore decode to identical bytes, and
    /// the decoder accepts all four — four spellings of one salt, so re-encoding a stored hash would
    /// not reproduce it.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("AAECAwQFBgcICQoLDA0ODx")]
    [InlineData("AAECAwQFBgcICQoLDA0ODy")]
    [InlineData("AAECAwQFBgcICQoLDA0ODz")]
    public void A_spelling_with_non_zero_trailing_bits_is_refused(string salt)
    {
        // The canonical spelling of the same sixteen bytes parses, so this is a test about the
        // spelling and not about the length.
        Assert.True(PhcString.TryParse(
            "$argon2id$v=19$m=64,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw", out _));

        Assert.False(PhcString.TryParse(
            $"$argon2id$v=19$m=64,t=1,p=1${salt}$AAECAwQFBgcICQoLDA0ODw", out _));
    }

    /// <summary>
    /// A base64url spelling of the salt is refused.
    /// </summary>
    /// <remarks>
    /// Its own test because the value has to be chosen to contain a character the two alphabets
    /// disagree on. Most random salts encode to the same characters either way, so a row picked at
    /// random would pass whether or not the check exists — the mistake this file's whole approach is
    /// meant to avoid.
    /// </remarks>
    [Fact]
    public void A_base64url_spelling_is_refused()
    {
        // 0xFF 0xFE encodes to "//4" in standard base64 and "__4" in base64url.
        byte[] salt = [.. Enumerable.Repeat((byte)0xFF, 16)];
        var standard = PhcString.Format(Parameters, salt, Hash);

        Assert.Contains('/', standard);
        Assert.True(PhcString.TryParse(standard, out _));

        Assert.False(PhcString.TryParse(standard.Replace('/', '_').Replace('+', '-'), out _));
    }

    [Fact]
    public void A_cost_beyond_the_ceiling_is_refused_rather_than_allocated()
    {
        // The stored string is an input to an allocation, so its bounds are checked at parse time
        // and not only where the hasher is constructed.
        Assert.False(PhcString.TryParse(
            "$argon2id$v=19$m=16777216,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw", out _));

        Assert.False(PhcString.TryParse(
            "$argon2id$v=19$m=64,t=999,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw", out _));
    }

    [Fact]
    public void A_salt_longer_than_the_ceiling_is_refused()
    {
        // 96 bytes of salt, canonically encoded, is well-formed base64 and still past the bound.
        var oversized = Convert.ToBase64String(new byte[96]).TrimEnd('=');

        Assert.False(PhcString.TryParse(
            $"$argon2id$v=19$m=64,t=1,p=1${oversized}$AAECAwQFBgcICQoLDA0ODw", out _));
    }
}
