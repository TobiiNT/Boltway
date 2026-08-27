using System.Security.Cryptography;
using System.Text.Json;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>S-24 (JWKS carries public parameters only) and three-phase key rotation.</summary>
public sealed class JwksAndRotationTests
{
    private static SigningKeyHandle RsaKey(string kid = "rsa-1") =>
        new(kid, SigningAlgorithm.RS256, new RsaSecurityKey(RSA.Create(2048)));

    private static SigningKeyHandle EcKey(string kid = "ec-1") =>
        new(kid, SigningAlgorithm.ES256, new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)));

    // ------------------------------------------------------------------ S-24

    [Fact]
    public void A_published_rsa_key_carries_no_private_member()
    {
        // The failure this guards against is not subtle in consequence: publishing `d` at a public,
        // cacheable, CORS-enabled endpoint hands over the ability to mint tokens as this server.
        // It IS subtle in cause - a serializer handed a private key writes the private members
        // without being asked.
        var json = JsonWebKeySet.Render([RsaKey()]);

        foreach (var member in JsonWebKeySet.PrivateMemberNames)
        {
            Assert.DoesNotContain($"\"{member}\":", json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void An_ec_key_carries_no_private_member_either()
    {
        var json = JsonWebKeySet.Render([EcKey()]);

        foreach (var member in JsonWebKeySet.PrivateMemberNames)
        {
            Assert.DoesNotContain($"\"{member}\":", json, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_private_key_material_does_not_appear_anywhere_in_the_document()
    {
        // Stronger than checking member names: takes the actual private exponent and asserts its
        // encoding is absent from the rendered bytes. A name-only check would miss a private value
        // published under an unexpected name.
        var rsa = RSA.Create(2048);
        var key = new SigningKeyHandle("rsa-1", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));

        var json = JsonWebKeySet.Render([key]);
        var privateExponent = Convert.ToBase64String(rsa.ExportParameters(true).D!).TrimEnd('=')
            .Replace('+', '-').Replace('/', '_');

        Assert.DoesNotContain(privateExponent, json, StringComparison.Ordinal);
    }

    [Fact]
    public void A_published_key_carries_kid_use_and_alg()
    {
        var json = JsonWebKeySet.Render([RsaKey("k1")]);
        var key = JsonDocument.Parse(json).RootElement.GetProperty("keys")[0];

        // kid is what lets a verifier pick a key without trying all of them, which is what keeps a
        // rotation problem visible instead of silently absorbed.
        Assert.Equal("k1", key.GetProperty("kid").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.True(key.TryGetProperty("n", out _));
        Assert.True(key.TryGetProperty("e", out _));
    }

    [Fact]
    public void An_unrecognised_key_type_refuses_to_publish_rather_than_guessing()
    {
        // Throwing is the safe direction. The alternative is emitting something unreviewed at a
        // public endpoint, which is how a private member reaches JWKS in the first place.
        var symmetric = new SigningKeyHandle("sym-1", SigningAlgorithm.RS256, new SymmetricSecurityKey(new byte[32]));

        Assert.Throws<NotSupportedException>(() => JsonWebKeySet.Render([symmetric]));
    }

    [Fact]
    public void An_empty_ring_renders_an_empty_key_array_not_a_missing_one()
    {
        // RFC 7517 §5: the document has a "keys" member. Omitting it when there are no keys makes
        // a client's parse fail rather than telling it there is nothing to verify with.
        var json = JsonWebKeySet.Render([]);

        Assert.Equal("{\"keys\":[]}", json);
    }

    // ------------------------------------------------------------------ rotation

    private static SigningKeyRing Ring(
        DateTimeOffset now, SigningKeyRingOptions? options, params ManagedSigningKey[] keys)
    {
        var time = new FakeTimeProvider(now);
        return new SigningKeyRing(keys, options, time);
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    [Fact]
    public void A_pending_key_is_published_but_never_signs()
    {
        // The middle phase, and the reason there are three rather than two. A key that starts
        // signing the moment it exists signs tokens every verifier rejects, because their cached
        // JWKS does not contain it yet - an outage that lasts as long as the caches do and looks
        // like a signature problem rather than a timing one.
        var now = DateTimeOffset.UtcNow;
        var active = new ManagedSigningKey(RsaKey("old"), SigningKeyState.Active, now.AddDays(-30));
        var pending = new ManagedSigningKey(RsaKey("new"), SigningKeyState.Pending, now);

        var ring = Ring(now, null, active, pending);

        Assert.Equal(2, ring.PublishedKeys().Count);
        Assert.Equal("old", ring.ActiveKey(SigningAlgorithm.RS256).Kid);
    }

    [Fact]
    public void A_retiring_key_stays_published_because_its_tokens_are_still_in_flight()
    {
        var now = DateTimeOffset.UtcNow;
        var retiring = new ManagedSigningKey(RsaKey("old"), SigningKeyState.Retiring, now.AddDays(-30));
        var active = new ManagedSigningKey(RsaKey("new"), SigningKeyState.Active, now.AddDays(-1));

        var published = Ring(now, null, retiring, active).PublishedKeys();

        Assert.Equal(2, published.Count);
        Assert.Contains(published, k => k.Kid == "old");
    }

    [Fact]
    public void A_retired_key_drops_out_of_jwks()
    {
        var now = DateTimeOffset.UtcNow;
        var retired = new ManagedSigningKey(RsaKey("ancient"), SigningKeyState.Retired, now.AddDays(-90));
        var active = new ManagedSigningKey(RsaKey("current"), SigningKeyState.Active, now.AddDays(-1));

        var published = Ring(now, null, retired, active).PublishedKeys();

        Assert.Equal("current", Assert.Single(published).Kid);
    }

    [Fact]
    public void A_pending_key_cannot_activate_before_the_lead_time()
    {
        var now = DateTimeOffset.UtcNow;
        var options = new SigningKeyRingOptions { PublishLeadTime = TimeSpan.FromHours(24) };
        var pending = new ManagedSigningKey(RsaKey("new"), SigningKeyState.Pending, now.AddHours(-23));

        Assert.False(Ring(now, options, pending).CanActivate(pending));
    }

    [Fact]
    public void A_pending_key_activates_once_the_lead_time_has_passed()
    {
        var now = DateTimeOffset.UtcNow;
        var options = new SigningKeyRingOptions { PublishLeadTime = TimeSpan.FromHours(24) };
        var pending = new ManagedSigningKey(RsaKey("new"), SigningKeyState.Pending, now.AddHours(-25));

        Assert.True(Ring(now, options, pending).CanActivate(pending));
    }

    [Fact]
    public void Signing_with_no_active_key_throws_rather_than_falling_back_to_a_pending_one()
    {
        // A silent fallback would be the tempting fix and the wrong one: it produces tokens that
        // fail verification everywhere, which is a quieter failure than refusing to issue one.
        var now = DateTimeOffset.UtcNow;
        var pending = new ManagedSigningKey(RsaKey("new"), SigningKeyState.Pending, now);

        var ex = Assert.Throws<InvalidOperationException>(
            () => Ring(now, null, pending).ActiveKey(SigningAlgorithm.RS256));

        Assert.Contains("kid", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Each_algorithm_has_its_own_active_key()
    {
        var now = DateTimeOffset.UtcNow;
        var rsa = new ManagedSigningKey(RsaKey("r"), SigningKeyState.Active, now.AddDays(-1));
        var ec = new ManagedSigningKey(EcKey("e"), SigningKeyState.Active, now.AddDays(-1));

        var ring = Ring(now, null, rsa, ec);

        Assert.Equal("r", ring.ActiveKey(SigningAlgorithm.RS256).Kid);
        Assert.Equal("e", ring.ActiveKey(SigningAlgorithm.ES256).Kid);
    }

    // ------------------------------------------------------------------ the arithmetic

    [Fact]
    public void A_lead_time_below_the_floor_is_refused_and_the_message_explains_the_arithmetic()
    {
        // The floor is not arbitrary: the discovery document is served with max-age=300 and clients
        // add roughly five minutes of staleness on top. An operator who shortens this deserves to
        // be told why rather than just refused.
        var options = new SigningKeyRingOptions { PublishLeadTime = TimeSpan.FromMinutes(5) };

        Assert.False(options.TryValidate(TimeSpan.FromMinutes(30), out var error));
        Assert.Contains("max-age=300", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Retention_shorter_than_a_token_lifetime_is_refused()
    {
        var options = new SigningKeyRingOptions
        {
            PublishLeadTime = TimeSpan.FromHours(24),
            RetentionAfterRetirement = TimeSpan.FromMinutes(10),
        };

        Assert.False(options.TryValidate(TimeSpan.FromMinutes(30), out var error));
        Assert.Contains("outlive", error, StringComparison.Ordinal);
    }

    [Fact]
    public void The_defaults_validate()
    {
        Assert.True(new SigningKeyRingOptions().TryValidate(TimeSpan.FromMinutes(30), out var error), error);
    }

    [Fact]
    public async Task A_token_signed_by_the_active_key_verifies_against_the_published_set()
    {
        // The round trip that matters during rotation: a verifier holding the whole published set
        // must be able to verify anything currently being signed, including across a key change.
        var now = DateTimeOffset.UtcNow;
        var retiring = new ManagedSigningKey(RsaKey("old"), SigningKeyState.Retiring, now.AddDays(-30));
        var active = new ManagedSigningKey(RsaKey("new"), SigningKeyState.Active, now.AddDays(-2));

        var ring = Ring(now, null, retiring, active);
        var minter = new JwtTokenMinter();

        var issuer = IssuerFor("https://auth.example.com");
        var resource = TestResourceRegistry.Register("https://mcp.example.com/mcp");

        var token = minter.MintAccessToken(
            new AccessTokenDescriptor(
                issuer, resource, Primitives.Ids.SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY"),
                Primitives.Ids.ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata"),
                "grant-1", Primitives.Scopes.ScopeSet.FromStorage("story:read"),
                now, now.AddMinutes(30), "jti-1"),
            ring.ActiveKey(SigningAlgorithm.RS256));

        var result = await new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().ValidateTokenAsync(
            token.Wire,
            Rfc9068ValidationParameters.ForAccessToken(
                issuer, resource, [.. ring.PublishedKeys().Select(k => k.Key)]));

        Assert.True(result.IsValid, result.Exception?.Message);
        Assert.Equal("new", token.Kid);
    }

    private static Primitives.Ids.IssuerString IssuerFor(string raw)
    {
        Assert.True(Primitives.Ids.IssuerString.TryCreate(raw, out var issuer, out var error), error);
        return issuer;
    }
}
