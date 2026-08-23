using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.OAuth.Primitives.Tests.Secrets;

/// <summary>N-16: minted secrets, their prefixes, and the hash that is the only persisted form.</summary>
public sealed class SecretTests
{
    [Theory]
    [InlineData(TokenPurpose.AuthorizationCode, "bw_ac_")]
    [InlineData(TokenPurpose.RefreshToken, "bw_rt_")]
    [InlineData(TokenPurpose.RegistrationAccessToken, "bw_rat_")]
    [InlineData(TokenPurpose.ClientSecret, "bw_cs_")]
    public void Each_purpose_has_its_own_wire_prefix(TokenPurpose purpose, string prefix)
    {
        var secret = OpaqueSecret.Generate(purpose);

        Assert.StartsWith(prefix, secret.Wire, StringComparison.Ordinal);
        Assert.Equal(purpose, secret.Purpose);
    }

    [Theory]
    [InlineData(TokenPurpose.AuthorizationCode, "ck_ac_")]
    [InlineData(TokenPurpose.RefreshToken, "ck_rt_")]
    [InlineData(TokenPurpose.RegistrationAccessToken, "ck_rat_")]
    [InlineData(TokenPurpose.ClientSecret, "ck_cs_")]
    public void A_secret_minted_before_the_rename_still_parses(TokenPurpose purpose, string legacy)
    {
        // `ck` is ConnectorKit, the name this project had when these prefixes reached the wire.
        // Refusing the old spelling on the deploy that changed it would sign out every session and
        // break every confidential client, so it is accepted on the way in and never minted.
        // The last 43 characters, not a split on '_': base64url's alphabet contains '_', so a
        // split takes a random suffix of the body roughly a third of the time.
        var wire = legacy + OpaqueSecret.Generate(purpose).Wire[^43..];

        Assert.True(OpaqueSecret.TryParse(wire, purpose, out var parsed));
        Assert.Equal(purpose, parsed.Purpose);
        Assert.Equal(wire, parsed.Wire);
    }

    [Fact]
    public void The_legacy_prefix_does_not_widen_what_a_purpose_accepts()
    {
        // The control for the test above, and the reason it is not a hole. Accepting a second
        // spelling must not accept a second *kind*: a registration access token under either name
        // is still refused at a refresh-token call site, which is the separation N-16 exists for.
        var body = OpaqueSecret.Generate(TokenPurpose.RegistrationAccessToken).Wire[^43..];

        Assert.False(OpaqueSecret.TryParse("ck_rat_" + body, TokenPurpose.RefreshToken, out _));
        Assert.False(OpaqueSecret.TryParse("bw_rat_" + body, TokenPurpose.RefreshToken, out _));
    }

    [Fact]
    public void A_registration_access_token_cannot_parse_as_a_refresh_token()
    {
        // The separation N-16 exists for. A registration access token is the sole authenticator for
        // full control of a client record, so a bug that let one be accepted at /token would be a
        // privilege escalation. The prefix is checked before anything hashes or touches storage,
        // so this is refused on shape rather than on a failed lookup.
        var rat = OpaqueSecret.Generate(TokenPurpose.RegistrationAccessToken);

        Assert.False(OpaqueSecret.TryParse(rat.Wire, TokenPurpose.RefreshToken, out _));
        Assert.False(OpaqueSecret.TryParse(rat.Wire, TokenPurpose.AuthorizationCode, out _));
        Assert.True(OpaqueSecret.TryParse(rat.Wire, TokenPurpose.RegistrationAccessToken, out _));
    }

    [Fact]
    public void Every_purpose_pair_is_mutually_unparseable()
    {
        // None is excluded: it is the uninitialised value, not a kind of secret, and Generate
        // refuses it.
        var purposes = Enum.GetValues<TokenPurpose>().Where(p => p != TokenPurpose.None).ToArray();

        foreach (var minted in purposes)
        {
            var secret = OpaqueSecret.Generate(minted);

            foreach (var expected in purposes)
            {
                Assert.Equal(minted == expected, OpaqueSecret.TryParse(secret.Wire, expected, out _));
            }
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("bw_rt_")]                            // prefix only
    [InlineData("bw_rt_tooshort")]
    [InlineData("bw_rt_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")]   // exactly 43 chars, not base64url
    [InlineData("nonsense")]
    public void Malformed_values_do_not_parse(string wire)
    {
        Assert.False(OpaqueSecret.TryParse(wire, TokenPurpose.RefreshToken, out _));
    }

    [Fact]
    public void A_secret_carries_256_bits_and_does_not_repeat()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 512; i++)
        {
            var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);
            Assert.True(seen.Add(secret.Wire));
            // 32 bytes -> 43 unpadded base64url characters.
            Assert.Equal("bw_rt_".Length + 43, secret.Wire.Length);
        }
    }

    [Fact]
    public void ToString_never_reveals_the_secret()
    {
        // Guards the accident, not the attacker: a structured-log property, an exception message or
        // a string interpolation would otherwise put a live refresh token in a log file.
        var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);

        Assert.DoesNotContain(secret.Wire, secret.ToString(), StringComparison.Ordinal);
        Assert.Contains("redacted", secret.ToString(), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------------- hashing

    [Fact]
    public void The_hash_matches_the_secret_it_was_made_from()
    {
        var secret = OpaqueSecret.Generate(TokenPurpose.AuthorizationCode);
        var hash = Sha256Hash.Of(secret);

        Assert.True(hash.Matches(secret));
    }

    [Fact]
    public void The_hash_does_not_match_a_different_secret()
    {
        var hash = Sha256Hash.Of(OpaqueSecret.Generate(TokenPurpose.AuthorizationCode));

        Assert.False(hash.Matches(OpaqueSecret.Generate(TokenPurpose.AuthorizationCode)));
    }

    [Fact]
    public void A_hash_is_32_bytes_and_round_trips_through_storage()
    {
        var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);
        var hash = Sha256Hash.Of(secret);

        Assert.Equal(Sha256Hash.Length, hash.Value.Length);

        var storage = hash.Value.ToArray();
        Assert.True(Sha256Hash.TryFromBytes(storage, out var rehydrated));
        Assert.Equal(hash, rehydrated);

        // The rehydrated hash must not alias the caller's buffer. A data-access layer reading into
        // a pooled or reused array would otherwise mutate a stored digest after construction, and
        // the symptom is a spurious invalid_grant rather than an exception.
        storage.AsSpan().Clear();
        Assert.Equal(hash, rehydrated);
        Assert.True(rehydrated.Matches(secret));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(31)]
    [InlineData(33)]
    public void A_wrong_length_digest_does_not_rehydrate(int? length)
    {
        var bytes = length is null ? null : new byte[length.Value];

        Assert.False(Sha256Hash.TryFromBytes(bytes, out _));
    }

    [Fact]
    public void A_default_hash_authenticates_nothing_but_still_behaves_like_a_value()
    {
        // Two properties that pull in opposite directions, and both are required.
        //
        // An uninitialised digest must never authenticate — that is the safety property, and it
        // lives on Matches. But Equals must stay reflexive, because object.Equals's contract says
        // so and every hash-based collection depends on it: a non-reflexive Equals means a
        // Dictionary cannot find a key it just stored and a HashSet accepts the same value twice.
        // The first version of this test asserted the contract violation as if it were the
        // requirement, which froze the bug in place.
        Assert.True(default(Sha256Hash).Equals(default));
        Assert.False(default(Sha256Hash).Matches(OpaqueSecret.Generate(TokenPurpose.RefreshToken)));

        var set = new HashSet<Sha256Hash> { default, default, default };
        Assert.Single(set);
    }

    [Fact]
    public void A_default_secret_names_itself_rather_than_impersonating_an_authorization_code()
    {
        // TokenPurpose.None is 0 for this reason. With AuthorizationCode at 0, the out value from a
        // FAILED TryParse described itself as an authorization code, so a caller who ignored the
        // bool got something that logged like a live code and then threw on first use.
        Assert.False(OpaqueSecret.TryParse("nonsense", TokenPurpose.RefreshToken, out var failed));

        Assert.Equal(TokenPurpose.None, failed.Purpose);
        Assert.False(failed.IsPresent);
        Assert.False(Sha256Hash.Of(OpaqueSecret.Generate(TokenPurpose.RefreshToken)).Matches(failed));
    }

    [Fact]
    public void A_secret_is_not_comparable_as_plaintext_and_is_not_a_hash_key()
    {
        // ValueType.Equals would compare the plaintext with string.Equals — variable-time, and
        // reachable through HashSet or List.Contains without anyone writing a comparison.
        var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);

        Assert.Throws<NotSupportedException>(() => secret.Equals((object)secret));
        Assert.Throws<NotSupportedException>(() => _ = secret.GetHashCode());
    }

    [Fact]
    public void The_persisted_hash_format_is_frozen()
    {
        // The digest is the ONLY persisted form of every refresh token, client secret and
        // registration access token. Any later edit to OfString — a salt, a domain-separation
        // prefix, an encoding change — invalidates every row in production simultaneously, and
        // every other test here would still pass, because they all hash and compare within one
        // process. This vector is what makes such a change fail loudly.
        Assert.Equal(
            "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
            Convert.ToHexString(Sha256Hash.OfString("hello").Value));
    }


    [Fact]
    public void A_lookup_key_that_is_not_well_formed_utf16_is_refused_rather_than_folded()
    {
        // OfString's own remarks describe this collision at length and nothing held them, which
        // mutation testing found: flipping throwOnInvalidBytes to false survived the whole suite.
        // Encoding.UTF8 replaces every lone surrogate with U+FFFD, so "\uD800", "\uDC00" and
        // "�" hash identically. This overload keys the CIMD cache by client_id, so a
        // collision is two distinct clients sharing one cache entry — one of them served the
        // other's redirect URIs.
        //
        // Throwing is right rather than harsh: ill-formed UTF-16 cannot occur in a well-formed
        // identifier, so reaching here at all is a bug at the caller.
        //
        // A Fact and not a Theory, and that is not a style choice. Written first with
        // [InlineData("\uD800")] both rows passed the ill-formed string through xUnit's data
        // serializer, which round-trips through UTF-8 and hands the test U+FFFD — already
        // repaired, so OfString had nothing to refuse and the test reported the guard missing when
        // it was present. The literal has to be constructed inside the test body.
        var highSurrogateAlone = new string((char)0xD800, 1);
        var lowSurrogateAlone = "https://x.example/" + (char)0xDC00;

        // The control for the two lines below: these really are ill-formed, so an exception can
        // only have come from the encoder rather than from some earlier validation.
        Assert.False(System.Text.Rune.TryCreate(highSurrogateAlone[0], out _));
        Assert.False(System.Text.Rune.TryCreate(lowSurrogateAlone[^1], out _));

        Assert.Throws<System.Text.EncoderFallbackException>(() => Sha256Hash.OfString(highSurrogateAlone));
        Assert.Throws<System.Text.EncoderFallbackException>(() => Sha256Hash.OfString(lowSurrogateAlone));
    }

    [Fact]
    public void Well_formed_astral_characters_still_hash()
    {
        // The other half: strictness must reject ill-formed UTF-16, not non-ASCII. A surrogate
        // PAIR is well formed, and an encoder that refused it would be a different bug wearing the
        // same fix.
        Assert.NotEqual(default(Sha256Hash), Sha256Hash.OfString("https://x.example/\U0001F600"));
    }

    [Fact]
    public void ToString_on_a_hash_is_the_digest_not_the_secret()
    {
        var secret = OpaqueSecret.Generate(TokenPurpose.RefreshToken);

        Assert.DoesNotContain(secret.Wire, Sha256Hash.Of(secret).ToString(), StringComparison.Ordinal);
    }
}
