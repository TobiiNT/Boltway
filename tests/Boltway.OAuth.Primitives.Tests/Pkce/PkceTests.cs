using Boltway.OAuth.Primitives.Pkce;

namespace Boltway.OAuth.Primitives.Tests.Pkce;

/// <summary>N-02, and the RFC 7636 grammar and transformation.</summary>
public sealed class PkceTests
{
    // RFC 7636 Appendix B, verbatim. The specification's own worked example, and the one test that
    // proves the S256 transformation is the transformation every OAuth client on earth implements
    // rather than a plausible-looking hash of the right length.
    private const string AppendixBVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string AppendixBChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public void Rfc7636_appendix_b_test_vector()
    {
        Assert.True(CodeVerifier.TryParse(AppendixBVerifier, out var verifier));

        Assert.Equal(AppendixBChallenge, verifier.ComputeS256Challenge());
    }

    [Fact]
    public void Appendix_b_verifier_satisfies_appendix_b_challenge()
    {
        Assert.True(CodeVerifier.TryParse(AppendixBVerifier, out var verifier));
        Assert.True(CodeChallenge.TryParse(AppendixBChallenge, CodeChallengeMethod.S256, out var challenge));

        Assert.True(challenge.Matches(verifier));
    }

    [Fact]
    public void A_different_verifier_does_not()
    {
        Assert.True(CodeChallenge.TryParse(AppendixBChallenge, CodeChallengeMethod.S256, out var challenge));
        Assert.True(CodeVerifier.TryParse(new string('a', 43), out var wrong));

        Assert.False(challenge.Matches(wrong));
    }

    // ------------------------------------------------------------------ the downgrade defence

    [Fact]
    public void An_absent_method_is_None_not_plain()
    {
        // RFC 7636 §4.3 says the default is "plain". This server refuses that default rather than
        // implementing it: RFC 9700 §4.8's downgrade attack is exactly an attacker stripping the
        // one parameter that selects the stronger mode.
        Assert.Equal(CodeChallengeMethod.None, CodeChallenge.ParseMethod(null));
        Assert.Equal(CodeChallengeMethod.None, CodeChallenge.ParseMethod(""));
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("PLAIN")]
    [InlineData("s256")]   // case-sensitive: RFC 7636 spells it S256
    [InlineData("S512")]
    [InlineData("none")]
    public void No_string_maps_to_a_weaker_method(string raw)
    {
        Assert.Equal(CodeChallengeMethod.None, CodeChallenge.ParseMethod(raw));
    }

    [Fact]
    public void A_challenge_is_never_accepted_under_a_non_S256_method()
    {
        Assert.False(CodeChallenge.TryParse(AppendixBChallenge, CodeChallengeMethod.None, out _));
    }

    /// <summary>
    /// A challenge in the base64url alphabet, of the right length, that is still not base64url.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TryParse</c> decodes rather than merely charset-checking, and the comment above that line
    /// says why: the alphabet alone accepts roughly three quarters of malformed challenges. Every
    /// other negative row in this file fails earlier than that - on length
    /// (<c>An_S256_challenge_is_exactly_43_characters</c>) or on a character outside the alphabet
    /// (<c>Challenge_rejects_standard_base64_and_padding</c>) - so this is the only one where the
    /// decode is the check that refuses. It came from <c>RedirectReviewRegressionTests</c>, where
    /// it was the single PKCE test in a file about redirect URIs.
    /// </para>
    /// <para>
    /// The three quarters is exact, and measured on .NET 10 rather than reasoned about. A 32-byte
    /// payload in 43 unpadded characters leaves the final sextet's low four bits zero, so only
    /// <c>A</c>, <c>Q</c>, <c>g</c> and <c>w</c> - 16 of the 64 alphabet characters counting the
    /// four bits that survive - are legal in the last position. Feeding
    /// <c>Base64Url.DecodeFromChars</c> all 64 gives 16 <c>Done</c> and 48 refusals: the framework
    /// enforces the canonical trailing bits, and that enforcement is the entire value of decoding
    /// a value whose length and alphabet have already been checked.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData('B')]   // sextet 000001
    [InlineData('P')]   // sextet 001111
    [InlineData('_')]   // sextet 111111 - the last character of the alphabet, and the last legal one
    public void A_challenge_in_the_alphabet_that_is_not_canonical_base64url_is_refused(char last)
    {
        var raw = new string('A', CodeChallenge.S256Length - 1) + last;

        // Both preconditions stated, so a later reader can see the refusal below cannot have come
        // from the length gate or the alphabet gate that precede the decode.
        Assert.Equal(CodeChallenge.S256Length, raw.Length);
        Assert.All(raw, c => Assert.True(
            c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_',
            $"'{c}' is outside the base64url alphabet."));

        Assert.False(CodeChallenge.TryParse(raw, CodeChallengeMethod.S256, out _));
    }

    [Theory]
    [InlineData('A')]   // sextet 000000
    [InlineData('Q')]   // sextet 010000
    [InlineData('g')]   // sextet 100000
    [InlineData('w')]   // sextet 110000
    public void The_same_43_characters_with_a_canonical_final_sextet_are_accepted(char last)
    {
        // The positive half of the pair above, and the reason it is a pair: without it, a TryParse
        // that refused every 'A'-heavy value for some unrelated reason would pass the negative rows
        // while proving nothing. These four are the whole set - a 32-byte payload can end in no
        // other character.
        Assert.True(CodeChallenge.TryParse(
            new string('A', CodeChallenge.S256Length - 1) + last, CodeChallengeMethod.S256, out _));
    }

    // ------------------------------------------------------------------ verifier grammar

    [Theory]
    [InlineData(42)]    // one below the RFC 7636 §4.1 minimum
    [InlineData(129)]   // one above the maximum
    [InlineData(0)]
    public void Verifier_length_bounds_are_enforced(int length)
    {
        Assert.False(CodeVerifier.TryParse(new string('a', length), out _));
    }

    [Theory]
    [InlineData(43)]
    [InlineData(128)]
    public void Both_bounds_are_inclusive(int length)
    {
        Assert.True(CodeVerifier.TryParse(new string('a', length), out _));
    }

    [Theory]
    // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~". Everything else is out.
    [InlineData('+')]
    [InlineData('/')]
    [InlineData('=')]
    [InlineData(' ')]
    [InlineData('%')]
    [InlineData('\n')]
    public void Verifier_rejects_characters_outside_the_unreserved_set(char bad)
    {
        Assert.False(CodeVerifier.TryParse(new string('a', 42) + bad, out _));
    }

    [Fact]
    public void Verifier_accepts_every_unreserved_character()
    {
        Assert.True(CodeVerifier.TryParse("-._~" + new string('a', 39), out _));
    }

    // ------------------------------------------------------------------ challenge grammar

    [Theory]
    [InlineData(42)]
    [InlineData(44)]
    public void An_S256_challenge_is_exactly_43_characters(int length)
    {
        // SHA-256 in unpadded base64url is always 43. Anything else did not come from the
        // transformation the client claims to have run.
        Assert.False(CodeChallenge.TryParse(new string('a', length), CodeChallengeMethod.S256, out _));
    }

    [Theory]
    // Standard base64 rather than base64url: the commonest real client bug. Caught here with a
    // specific error rather than surfacing later as an opaque PKCE mismatch at /token.
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw/cM")]
    [InlineData("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=")]
    public void Challenge_rejects_standard_base64_and_padding(string raw)
    {
        Assert.False(CodeChallenge.TryParse(raw, CodeChallengeMethod.S256, out _));
    }

    [Fact]
    public void A_generated_verifier_round_trips()
    {
        var verifier = CodeVerifier.Generate();

        Assert.True(CodeVerifier.TryParse(verifier.Value, out var reparsed));
        Assert.True(CodeChallenge.TryParse(verifier.ComputeS256Challenge(), CodeChallengeMethod.S256, out var challenge));
        Assert.True(challenge.Matches(reparsed));
    }

    [Fact]
    public void Generated_verifiers_are_not_repeated()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 256; i++)
        {
            Assert.True(seen.Add(CodeVerifier.Generate().Value));
        }
    }
}
