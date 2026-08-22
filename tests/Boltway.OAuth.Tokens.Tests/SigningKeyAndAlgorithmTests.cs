using System.Security.Cryptography;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>
/// The two guards on what may sign a token and what may verify one.
/// </summary>
/// <remarks>
/// <c>Rfc9068ValidationParameters</c>' own header calls <c>ValidTypes</c> and <c>ValidAlgorithms</c>
/// "the two settings that matter most" and explains the attack each prevents. <c>ValidTypes</c> is
/// covered by <c>TokenConfusionTests</c>; <c>ValidAlgorithms</c> was not covered at all, and neither
/// was the RSA key-size floor.
/// </remarks>
public sealed class SigningKeyAndAlgorithmTests
{
    private static readonly IssuerString Issuer = CreateIssuer("https://auth.example.com");
    private static readonly ResourceIdentifier Resource = CreateResource("https://mcp.example.com/mcp");
    private static readonly ClientIdentifier Client =
        ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata");

    private static readonly JsonWebTokenHandler Handler = new();

    private static IssuerString CreateIssuer(string raw)
    {
        Assert.True(IssuerString.TryCreate(raw, out var issuer, out var error), error);
        return issuer;
    }

    private static ResourceIdentifier CreateResource(string raw)
    {
        Assert.True(TestResourceRegistry.TryRegister(raw, out var resource, out var error), error);
        return resource!;
    }

    // --------------------------------------------------------------- the RSA floor

    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    public void An_rsa_key_below_the_floor_is_refused(int keySizeBits)
    {
        // The signing key is the entire trust anchor: everything downstream — the resource
        // server, every relying party — decides "this token is genuine" by checking a signature
        // against the public half published in JWKS. A 1024-bit modulus is factorable, and
        // factoring it does not leak one token, it mints every token, for every subject, with a
        // valid signature and no way for any verifier to tell.
        //
        // A weak key does not arrive by malice. It arrives as an operator's `openssl genrsa 1024`
        // from a decade-old runbook — and this constructor is the only place in the solution that
        // ever looks at the size, so nothing downstream would catch it.
        using var weak = RSA.Create(keySizeBits);

        var error = Assert.Throws<ArgumentOutOfRangeException>(
            () => new SigningKeyHandle("weak", SigningAlgorithm.RS256, new RsaSecurityKey(weak)));

        Assert.Equal("key", error.ParamName);
    }

    [Fact]
    public void An_rsa_key_at_the_floor_is_accepted()
    {
        // The control: 2048 is a floor, not a rejection of RSA.
        using var rsa = RSA.Create(SigningAlgorithms.MinimumRsaKeySizeBits);

        var handle = new SigningKeyHandle("k1", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));

        Assert.Equal("k1", handle.Kid);
        Assert.Equal("k1", handle.Key.KeyId);
    }

    // --------------------------------------------------- the algorithm allow-list

    [Fact]
    public void Both_factories_pin_the_algorithm_allow_list()
    {
        // Stated directly as well as behaviourally below, because the ID-token factory and the
        // access-token factory each carry their own copy of the line and a mutation that deleted
        // both broke nothing. Unset means the algorithm is taken from the TOKEN'S OWN HEADER,
        // which is the setting's entire hazard.
        using var rsa = RSA.Create(2048);

        Assert.Equal(
            SigningAlgorithms.All,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [new RsaSecurityKey(rsa)]).ValidAlgorithms);

        Assert.Equal(
            SigningAlgorithms.All,
            Rfc9068ValidationParameters.ForIdToken(Issuer, Client, [new RsaSecurityKey(rsa)]).ValidAlgorithms);

        // And the allow-list is asymmetric-only. A symmetric entry is what makes the confusion
        // attack possible at all: the verifier is handed a PUBLIC key, and an attacker re-signs a
        // forged token using those published bytes as an HMAC secret.
        Assert.DoesNotContain("HS256", SigningAlgorithms.All, StringComparer.Ordinal);
        Assert.DoesNotContain("none", SigningAlgorithms.All, StringComparer.Ordinal);
    }

    [Fact]
    public async Task An_access_token_signed_with_an_algorithm_outside_the_list_is_refused()
    {
        // The behavioural statement, using PS256 — a legitimate JWA that this key can perform and
        // this server never issues. With the allow-list unset the verifier reads `alg` from the
        // header and validates it happily: same key, same issuer, same audience, same `typ`. The
        // token chooses its own algorithm, which is exactly the position the setting exists to
        // deny it.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var forged = Sign(key, "PS256", now);

        var result = await Handler.ValidateTokenAsync(
            forged, Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [key.Key]));

        Assert.False(result.IsValid);

        // The control, and it is what makes the refusal mean something. The same claims, the same
        // key and the same construction path, differing only in `alg`, DO validate — so the
        // rejection above is about the algorithm and not about a token this test built wrong.
        var honest = await Handler.ValidateTokenAsync(
            Sign(key, "RS256", now), Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [key.Key]));

        Assert.True(honest.IsValid, honest.Exception?.Message);
    }

    [Fact]
    public async Task An_id_token_signed_with_an_algorithm_outside_the_list_is_refused()
    {
        // The same, on the factory that had no coverage in either direction.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var forged = await Handler.ValidateTokenAsync(
            SignIdToken(key, "PS256", now), Rfc9068ValidationParameters.ForIdToken(Issuer, Client, [key.Key]));

        Assert.False(forged.IsValid);

        var honest = await Handler.ValidateTokenAsync(
            SignIdToken(key, "RS256", now), Rfc9068ValidationParameters.ForIdToken(Issuer, Client, [key.Key]));

        Assert.True(honest.IsValid, honest.Exception?.Message);
    }

    private static SigningKeyHandle NewKey()
    {
        // Not disposed: the RsaSecurityKey outlives this call and the handler needs it to verify.
        var rsa = RSA.Create(2048);
        return new SigningKeyHandle("test-key-1", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));
    }

    /// <summary>
    /// An access token signed with an arbitrary JWA name.
    /// </summary>
    /// <remarks>
    /// Hand-built rather than minted: <c>JwtTokenMinter</c> takes its algorithm from
    /// <c>SigningKeyHandle.Algorithm</c>, which is a closed enum, so there is deliberately no way
    /// to make it emit PS256. An attacker is under no such constraint.
    /// </remarks>
    private static string Sign(SigningKeyHandle key, string jwa, DateTimeOffset now) =>
        new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["iss"] = Issuer.Value,
                ["aud"] = Resource.Canonical,
                ["sub"] = "01J8XKQ7M3N4P5R6S7T8V9W0XY",
                ["client_id"] = Client.Value,
                ["iat"] = now.ToUnixTimeSeconds(),
                ["exp"] = now.AddMinutes(30).ToUnixTimeSeconds(),
                ["jti"] = "jti-forged",
            },
            SigningCredentials = new SigningCredentials(key.Key, jwa),
            TokenType = TokenTypes.AccessToken,
            Expires = null,
            IssuedAt = null,
            NotBefore = null,
        });

    private static string SignIdToken(SigningKeyHandle key, string jwa, DateTimeOffset now) =>
        new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["iss"] = Issuer.Value,
                ["aud"] = Client.Value,
                ["sub"] = "01J8XKQ7M3N4P5R6S7T8V9W0XY",
                ["iat"] = now.ToUnixTimeSeconds(),
                ["exp"] = now.AddMinutes(30).ToUnixTimeSeconds(),
            },
            SigningCredentials = new SigningCredentials(key.Key, jwa),
            TokenType = TokenTypes.IdToken,
            Expires = null,
            IssuedAt = null,
            NotBefore = null,
        });
}
