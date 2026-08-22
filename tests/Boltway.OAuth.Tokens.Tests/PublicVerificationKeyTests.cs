using System.Security.Cryptography;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>
/// <see cref="SigningKeyRing.PublicVerificationKeys"/> — the halves a verifier needs and no more.
/// </summary>
public sealed class PublicVerificationKeyTests
{
    /// <summary>
    /// No private material reaches a resource server.
    /// </summary>
    /// <remarks>
    /// Verification only touches the public half, so handing over the signing key would work and
    /// would put the private key on the request path of a bearer middleware. This is the object-graph
    /// form of the assertion the JWKS body already gets — that it contains none of <c>d</c>,
    /// <c>p</c>, <c>q</c>.
    /// </remarks>
    [Fact]
    public void They_carry_no_private_material()
    {
        var ring = RingOfTwo();

        var keys = ring.PublicVerificationKeys();

        Assert.NotEmpty(keys);

        foreach (var key in keys)
        {
            var rsa = Assert.IsType<RsaSecurityKey>(key);

            Assert.False(rsa.PrivateKeyStatus is PrivateKeyStatus.Exists,
                "A verification key still holds its private half.");
        }
    }

    /// <summary>
    /// Every key keeps the <c>kid</c> the token will name.
    /// </summary>
    /// <remarks>
    /// The verifier runs with <c>TryAllIssuerSigningKeys = false</c> and matches on the token's
    /// <c>kid</c> header, so a copy that lost its identifier matches nothing — and the failure reads
    /// as "no security keys were provided", which sounds like a missing key rather than an unlabelled
    /// one.
    /// </remarks>
    [Fact]
    public void They_keep_the_key_identifier()
    {
        var ring = RingOfTwo();

        var published = ring.PublishedKeys().Select(handle => handle.Kid).OrderBy(kid => kid, StringComparer.Ordinal);
        var verification = ring.PublicVerificationKeys().Select(key => key.KeyId).OrderBy(kid => kid, StringComparer.Ordinal);

        Assert.Equal(published, verification);
    }

    /// <summary>
    /// A fresh list each call, which is what lets a caller publish rather than mutate.
    /// </summary>
    [Fact]
    public void Each_call_returns_its_own_list()
    {
        var ring = RingOfTwo();

        Assert.NotSame(ring.PublicVerificationKeys(), ring.PublicVerificationKeys());
    }

    /// <summary>A published pair: one active, one retiring — both belong in JWKS and both verify.</summary>
    private static SigningKeyRing RingOfTwo()
    {
        var now = new DateTimeOffset(2026, 8, 10, 0, 0, 0, TimeSpan.Zero);

        return new SigningKeyRing(
            [
                new ManagedSigningKey(
                    new SigningKeyHandle("rsa-active", SigningAlgorithm.RS256, new RsaSecurityKey(RSA.Create(2048))),
                    SigningKeyState.Active,
                    now.AddDays(-3),
                    now.AddDays(-2)),
                new ManagedSigningKey(
                    new SigningKeyHandle("rsa-retiring", SigningAlgorithm.RS256, new RsaSecurityKey(RSA.Create(2048))),
                    SigningKeyState.Retiring,
                    now.AddDays(-30),
                    now.AddDays(-29)),
            ]);
    }
}
