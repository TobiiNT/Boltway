using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.OAuth.Primitives.Tests.Secrets;

/// <summary>
/// <c>OpaqueSecret.FromDerivedMaterial</c>, which had no test of any kind.
/// </summary>
/// <remarks>
/// It is <see langword="internal"/>, reached from this assembly through <c>InternalsVisibleTo</c>.
/// Being internal is itself a guard — a review found that while it was public,
/// <c>FromDerivedMaterial(RegistrationAccessToken, SHA256("user@example.com"))</c> minted a valid
/// credential for the sole authenticator of a client record — but narrowing the door says nothing
/// about what happens once you are through it, and nothing was checking that.
/// </remarks>
public sealed class DerivedSecretTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void Material_that_is_not_exactly_the_entropy_length_is_refused(int length)
    {
        // 32 bytes is exactly 43 unpadded base64url characters, and TryParse accepts a body of
        // that length and nothing else. So material of any other size mints a `bw_rt_…` this
        // server cannot parse back: a refresh token that is dead the moment it is handed out,
        // and dead in the one place a client cannot recover from — the refresh it makes after a
        // 401. The failure is silent at mint time and surfaces as invalid_grant a month later.
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, new byte[length]));

        Assert.Equal("material", error.ParamName);
    }

    [Theory]
    [InlineData(32)]
    [InlineData(16)]
    public void A_purposeless_secret_is_refused_on_the_purpose_before_the_material(int materialLength)
    {
        // TokenPurpose.None is the uninitialised value, not a kind of secret — a `default`
        // TokenPurpose reaching here means a caller lost track of what it was minting.
        //
        // Stated precisely, because the guard is not load-bearing alone: PrefixFor's switch would
        // also refuse None, so None never yields a secret either way. What this check owns is the
        // ORDER — the purpose is judged first, so a caller that got the purpose wrong is told
        // about the purpose. The 16-byte row is what distinguishes the two: without this check
        // that call reports "material", sending the caller after the wrong bug.
        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => OpaqueSecret.FromDerivedMaterial(TokenPurpose.None, new byte[materialLength]));

        Assert.Equal("purpose", error.ParamName);
    }

    [Fact]
    public void Derived_material_produces_a_secret_the_server_parses_back()
    {
        // The control. Both refusals above would pass against a method that refused everything,
        // and the accepted case carries the whole point: the wire form must be indistinguishable
        // from a generated secret, because TryParse is the only thing that sees it at /token.
        var material = new byte[32];
        material[0] = 0xFF;
        material[31] = 0x01;

        var secret = OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, material);

        Assert.StartsWith("bw_rt_", secret.Wire, StringComparison.Ordinal);
        Assert.True(OpaqueSecret.TryParse(secret.Wire, TokenPurpose.RefreshToken, out var parsed));
        Assert.Equal(TokenPurpose.RefreshToken, parsed.Purpose);
    }

    [Fact]
    public void The_same_material_produces_the_same_wire_form()
    {
        // The reason this entry point exists at all. Two concurrent redemptions of one refresh
        // token both derive the successor from the same stored record, so the loser can be given
        // the token the winner minted rather than invalid_grant. Generate cannot do this.
        var material = new byte[32];
        material[7] = 0x5C;

        Assert.Equal(
            OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, material).Wire,
            OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, material).Wire,
            StringComparer.Ordinal);
    }

    [Fact]
    public void Material_carries_into_the_wire_form_rather_than_being_discarded()
    {
        // Different material, different token. Without this the two tests above are satisfied by
        // an implementation that ignores its input entirely and returns a constant.
        var one = new byte[32];
        var two = new byte[32];
        two[31] = 0x01;

        Assert.NotEqual(
            OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, one).Wire,
            OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, two).Wire,
            StringComparer.Ordinal);
    }
}
