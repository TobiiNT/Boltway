using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>RefreshTokenDeriver</c>, which had no test of any kind.
/// </summary>
/// <remarks>
/// A mutation pass removed the derivation label's separators and the key-length floor and the whole
/// suite stayed green, because nothing anywhere constructed one of these directly. The class is
/// reached only through the token endpoint, where every input is a well-formed <c>Guid.ToString("N")</c>
/// and every key comes from validated options - so the paths these tests take are exactly the ones
/// integration coverage cannot reach.
/// </remarks>
public sealed class RefreshTokenDeriverTests
{
    /// <summary>A key at the floor. Constant bytes: the tests are about the label, not the entropy.</summary>
    private static byte[] Key() => [.. Enumerable.Repeat((byte)0x2A, RefreshTokenDeriver.MinimumKeyBytes)];

    [Fact]
    public void Two_positions_whose_fields_run_together_derive_different_tokens()
    {
        // The two NUL separators ARE the injectivity argument. Without them the label is one
        // unbroken run, so family "a1" generation 2 and family "a" generation 12 both build
        // "boltway/refresha12" - one HMAC, one token, handed to two different families. That
        // is a live refresh token shared across accounts, not a hashing curiosity.
        //
        // And the collision needs no hostile input to be reachable: RefreshTokenRecord.FamilyId is
        // an unconstrained string hydrated from a customer's database column, so the "family ids
        // are hex" convention is not something this function may rely on.
        var deriver = new RefreshTokenDeriver(Key());

        Assert.NotEqual(deriver.Derive("a1", 2).Wire, deriver.Derive("a", 12).Wire, StringComparer.Ordinal);
    }

    [Fact]
    public void The_same_position_derives_the_same_token_every_time()
    {
        // The control, and the property the class exists for: two concurrent redemptions compute
        // this value independently from the same stored record, so the loser can be handed the
        // successor the winner minted instead of `invalid_grant`. Every assertion above is
        // worthless against a deriver that simply returns something different each call.
        var deriver = new RefreshTokenDeriver(Key());

        Assert.Equal(deriver.Derive("family-1", 3).Wire, deriver.Derive("family-1", 3).Wire, StringComparer.Ordinal);
        Assert.NotEqual(deriver.Derive("family-1", 3).Wire, deriver.Derive("family-1", 4).Wire, StringComparer.Ordinal);
        Assert.NotEqual(deriver.Derive("family-1", 3).Wire, deriver.Derive("family-2", 3).Wire, StringComparer.Ordinal);
    }

    [Fact]
    public void A_different_key_derives_a_different_token()
    {
        // The server key is the only thing stopping a CLIENT deriving its own successor and
        // walking the chain without ever rotating - which is the property rotation exists to
        // create.
        var wire = new RefreshTokenDeriver(Key()).Derive("family-1", 1).Wire;
        var other = new RefreshTokenDeriver([.. Enumerable.Repeat((byte)0x2B, RefreshTokenDeriver.MinimumKeyBytes)])
            .Derive("family-1", 1).Wire;

        Assert.NotEqual(wire, other, StringComparer.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    public void A_key_below_the_hmac_block_security_level_is_refused(int keyBytes)
    {
        // A short key is a brute-force target that yields every refresh token this server will
        // ever issue, for every tenant, past and future - the derivation is deterministic, so
        // recovering the key recovers the whole corpus rather than one credential. Options
        // validation checks the same floor, but that check runs only for a key that arrived
        // through options; this one is the type's own.
        var error = Assert.Throws<ArgumentOutOfRangeException>(() => new RefreshTokenDeriver(new byte[keyBytes]));

        Assert.Equal("key", error.ParamName);
    }

    [Fact]
    public void A_key_exactly_at_the_floor_is_accepted()
    {
        // The control for the theory above: the floor is a floor, not a rejection of everything.
        var secret = new RefreshTokenDeriver(new byte[RefreshTokenDeriver.MinimumKeyBytes]).Derive("family-1", 0);

        Assert.Equal(TokenPurpose.RefreshToken, secret.Purpose);
    }

    [Fact]
    public void The_legacy_spelling_is_the_same_credential_under_its_old_name()
    {
        // The property the refresh grace window depends on across the rename. A row written before
        // the `ck_` prefix was retired holds the hash of the old spelling, and the grace path
        // reconstructs a successor and fails closed when the hashes disagree. That check is only
        // safe to keep if the two spellings really are one credential - same key, same label, same
        // material - with the prefix outside the MAC. If the material differed, accepting the
        // legacy form would be accepting a second, independently-derivable token.
        var deriver = new RefreshTokenDeriver(Key());

        var current = deriver.Derive("family-1", 7).Wire;
        var legacy = deriver.DeriveLegacy("family-1", 7).Wire;

        Assert.StartsWith("bw_rt_", current, StringComparison.Ordinal);
        Assert.StartsWith("ck_rt_", legacy, StringComparison.Ordinal);
        Assert.Equal(current[^43..], legacy[^43..]);
    }

    [Fact]
    public void A_legacy_successor_still_parses_at_the_token_endpoint()
    {
        // The half that matters to the racing client: it is holding the old spelling, so the value
        // the grace path hands back has to survive TryParse the next time it is presented.
        var wire = new RefreshTokenDeriver(Key()).DeriveLegacy("family-1", 1).Wire;

        Assert.True(OpaqueSecret.TryParse(wire, TokenPurpose.RefreshToken, out var parsed));
        Assert.Equal(TokenPurpose.RefreshToken, parsed.Purpose);
    }

    [Fact]
    public void A_derived_token_parses_back_as_a_refresh_token()
    {
        // End to end: what Derive returns has to survive the round trip through the wire, because
        // the client presents it at /token and OpaqueSecret.TryParse is what accepts it.
        var wire = new RefreshTokenDeriver(Key()).Derive("family-1", 1).Wire;

        Assert.True(OpaqueSecret.TryParse(wire, TokenPurpose.RefreshToken, out var parsed));
        Assert.Equal(TokenPurpose.RefreshToken, parsed.Purpose);
    }

    [Fact]
    public void A_family_id_that_is_not_well_formed_utf16_is_refused_rather_than_folded()
    {
        // The strict encoder. Encoding.UTF8 replaces a lone surrogate with U+FFFD rather than
        // failing, and the type's own remarks record what an adversarial review measured through
        // it: "\uD800", "\uDC00" and "�" produced the same token, because all three encode
        // to the same bytes. That is the cross-family collision the separators guard against,
        // arriving through the encoder instead.
        var deriver = new RefreshTokenDeriver(Key());

        Assert.Throws<System.Text.EncoderFallbackException>(() => deriver.Derive("\uD800", 1));
    }
}
