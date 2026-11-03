using System.Security.Cryptography;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>
/// An <see cref="RsaSecurityKey"/> built from bare <see cref="RSAParameters"/> rather than an
/// <see cref="RSA"/> instance is held to the same rules.
/// </summary>
/// <remarks>
/// Both checks matched only <c>{ Rsa: not null }</c>, so the parameters shape skipped the minimum
/// size entirely and was published with its private exponent still in it.
/// </remarks>
public sealed class RsaParametersKeyTests
{
    private static RsaSecurityKey FromParameters(int bits)
    {
        using var rsa = RSA.Create(bits);
        return new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true));
    }

    [Fact]
    public void A_short_key_given_as_parameters_is_refused() =>
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SigningKeyHandle("short", SigningAlgorithm.RS256, FromParameters(1024)));

    [Fact]
    public void A_key_given_as_parameters_is_published_without_its_private_half()
    {
        var handle = new SigningKeyHandle("p-1", SigningAlgorithm.RS256, FromParameters(3072));
        var ring = new SigningKeyRing(
            [new ManagedSigningKey(handle, SigningKeyState.Active, DateTimeOffset.UnixEpoch)]);

        var published = Assert.IsType<RsaSecurityKey>(Assert.Single(ring.PublicVerificationKeys()));

        Assert.Equal("p-1", published.KeyId);
        Assert.NotNull(published.Parameters.Modulus);
        Assert.Null(published.Parameters.D);
        Assert.Null(published.Parameters.P);
    }
}
