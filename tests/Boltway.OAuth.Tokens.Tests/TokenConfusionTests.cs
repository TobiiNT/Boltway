using System.Security.Cryptography;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens.Tests;

/// <summary>
/// N-09 (cross-JWT confusion) and N-10 (the two audiences are not the same thing).
/// </summary>
public sealed class TokenConfusionTests
{
    private static readonly IssuerString Issuer = CreateIssuer("https://auth.example.com");
    private static readonly ResourceIdentifier Resource = CreateResource("https://mcp.example.com/mcp");
    private static readonly ClientIdentifier Client =
        ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata");

    private static IssuerString CreateIssuer(string raw)
    {
        Assert.True(IssuerString.TryCreate(raw, out var issuer, out var error), error);
        return issuer;
    }

    private static ResourceIdentifier CreateResource(string raw)
    {
        // Registration is internal, so this mirrors what the resource registry does. Outside the
        // assembly there is no way to produce one at all, which is N-01's whole mechanism.
        Assert.True(TestResourceRegistry.TryRegister(raw, out var resource, out var error), error);
        return resource!;
    }

    private static SigningKeyHandle NewKey()
    {
        var rsa = RSA.Create(2048);
        return new SigningKeyHandle("test-key-1", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));
    }

    private static readonly JwtTokenMinter Minter = new();
    private static readonly JsonWebTokenHandler Handler = new();

    private static AccessTokenDescriptor AccessToken(DateTimeOffset now) => new(
        Issuer, Resource, SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY"), Client,
        GrantId: "grant-1", ScopeSet.FromStorage("story:read story:write"),
        IssuedAt: now, ExpiresAt: now.AddMinutes(30), JwtId: "jti-1");

    private static IdTokenDescriptor IdToken(DateTimeOffset now) => new(
        Issuer, Client, SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0XY"),
        IssuedAt: now, ExpiresAt: now.AddMinutes(30));

    // ------------------------------------------------------------------ N-09

    [Fact]
    public async Task An_id_token_is_not_accepted_as_an_access_token()
    {
        // The attack N-09 exists for, and it is not exotic: the client legitimately HOLDS an ID
        // token. It is signed by the same key, carries the same iss and the same sub, and is not
        // expired. Only `typ` distinguishes it — and TokenValidationParameters.ValidTypes is unset
        // by default, so a resource server built the obvious way accepts it.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var idToken = Minter.MintIdToken(IdToken(now), key);

        var result = await Handler.ValidateTokenAsync(
            idToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [key.Key]));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task An_access_token_is_not_accepted_as_an_id_token()
    {
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var accessToken = Minter.MintAccessToken(AccessToken(now), key);

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForIdToken(Issuer, Client, [key.Key]));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_correctly_typed_access_token_validates()
    {
        // The control. Without this, the two tests above would pass on a validator that refuses
        // everything.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var accessToken = Minter.MintAccessToken(AccessToken(now), key);

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [key.Key]));

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public void An_access_token_carries_typ_at_jwt()
    {
        var minted = Minter.MintAccessToken(AccessToken(DateTimeOffset.UtcNow), NewKey());

        Assert.Equal(TokenTypes.AccessToken, new JsonWebToken(minted.Wire).Typ);
    }

    [Fact]
    public void An_id_token_carries_typ_JWT()
    {
        // The counterpart the assertion above never had. N-09 is stated in both directions by the
        // two "not accepted as" tests, but both of those ALSO fail on the audience — an ID token's
        // aud is the client and an access token's is the resource — so an ID token minted with
        // `typ: at+jwt` breaks neither of them. Measured: with the ID token's type header swapped
        // for the access token's, every pre-existing test in this file still passed.
        //
        // What that costs is the one distinction RFC 9068 §2.1 exists to make. A resource server
        // that pins `typ` and takes the audience from configuration — the shape §4 sanctions —
        // would then accept an ID token, which the client legitimately holds, as an access token.
        var minted = Minter.MintIdToken(IdToken(DateTimeOffset.UtcNow), NewKey());

        Assert.Equal(TokenTypes.IdToken, new JsonWebToken(minted.Wire).Typ);
    }

    [Fact]
    public async Task A_correctly_typed_id_token_validates()
    {
        // The control ForIdToken never had, and the reason it matters is not symmetry: without a
        // positive case, An_access_token_is_not_accepted_as_an_id_token passes just as well
        // against parameters that refuse EVERY token, including every ID token this server mints.
        // The access-token factory has had A_correctly_typed_access_token_validates since it was
        // written; this side was verified in one direction only.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var idToken = Minter.MintIdToken(IdToken(now), key);

        var result = await Handler.ValidateTokenAsync(
            idToken.Wire,
            Rfc9068ValidationParameters.ForIdToken(Issuer, Client, [key.Key]));

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    // ------------------------------------------------------------------ N-10

    [Fact]
    public void The_two_audiences_are_different_values_for_the_same_grant()
    {
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();

        var accessToken = new JsonWebToken(Minter.MintAccessToken(AccessToken(now), key).Wire);
        var idToken = new JsonWebToken(Minter.MintIdToken(IdToken(now), key).Wire);

        // The access token points at the resource; the ID token points at the client. Unifying
        // them makes every conformant relying party reject the ID token at OIDC Core §3.1.3.7
        // rule 3, and the rejection surfaces client-side with no error code we control.
        Assert.Equal("https://mcp.example.com/mcp", Assert.Single(accessToken.Audiences));
        Assert.Equal("https://claude.ai/oauth/mcp-oauth-client-metadata", Assert.Single(idToken.Audiences));
        Assert.NotEqual(Assert.Single(accessToken.Audiences), Assert.Single(idToken.Audiences));
    }

    [Fact]
    public async Task A_token_for_one_resource_is_refused_at_another()
    {
        // N-01 end to end. RFC 8707 registers no discovery flag, so a client cannot tell whether a
        // server honours `resource` — which is why a server that ignores it is a real problem
        // rather than a pedantic one: connect one malicious MCP server and its operator holds a
        // token that works at all the others.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();
        var other = CreateResource("https://other.example.com/mcp");

        var accessToken = Minter.MintAccessToken(AccessToken(now), key);

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, other, [key.Key]));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_resource_identifier_is_compared_in_full_not_by_origin()
    {
        // Comparing `aud` to the request's ORIGIN rather than the full identifier is a shipped
        // real-world bug that broke ChatGPT custom connectors. These two share an origin.
        var now = DateTimeOffset.UtcNow;
        var key = NewKey();
        var sibling = CreateResource("https://mcp.example.com/other");

        var accessToken = Minter.MintAccessToken(AccessToken(now), key);

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, sibling, [key.Key]));

        Assert.False(result.IsValid);
    }

    // ------------------------------------------------------------------ RFC 9068 shape

    [Fact]
    public void Scope_is_a_space_delimited_string_not_an_array()
    {
        // RFC 9068 §2.2.3. An array is a quiet defect: most resource servers read this with a
        // string accessor and see nothing, so the token appears to carry no scopes at all.
        var token = new JsonWebToken(Minter.MintAccessToken(AccessToken(DateTimeOffset.UtcNow), NewKey()).Wire);

        Assert.Equal("story:read story:write", token.GetClaim("scope").Value);
        // The XSD type the handler records. A JSON array would come back as an array type, which
        // is how the array-vs-string defect shows up if it is ever reintroduced.
        Assert.EndsWith("#string", token.GetClaim("scope").ValueType, StringComparison.Ordinal);
    }

    [Fact]
    public void Every_claim_rfc_9068_requires_is_present()
    {
        var token = new JsonWebToken(Minter.MintAccessToken(AccessToken(DateTimeOffset.UtcNow), NewKey()).Wire);

        foreach (var claim in new[] { "iss", "aud", "sub", "client_id", "iat", "exp", "jti" })
        {
            Assert.True(token.TryGetClaim(claim, out _), $"RFC 9068 §2.2 requires '{claim}'.");
        }
    }

    [Fact]
    public void An_access_token_names_its_grant_in_gid()
    {
        // `gid` is not on RFC 9068's required list, so the check above walks straight past it —
        // which is how renaming or dropping the claim broke no test at all.
        //
        // It is the whole of the revocation story. Access tokens are self-contained JWTs: nothing
        // is looked up when one is presented, so "revoking" one means recording its grant id on a
        // denylist and having the resource server refuse tokens that carry it. IGrantStore.
        // RevokeAsync's remarks put it plainly — this is "why the access token carries a grant id
        // at all". Without the claim the denylist is inert: it fills up correctly, matches
        // nothing, and every revoked grant's access tokens keep working until they expire. No
        // signature check, no lifetime check and no audience check notices.
        //
        // Nothing in this repository reads the claim yet; IGrantStore.IsRevokedAsync has no caller
        // in src. The denylist check belongs to the resource server, so this assertion is the only
        // thing holding the wire contract the two sides agree on.
        var token = new JsonWebToken(Minter.MintAccessToken(AccessToken(DateTimeOffset.UtcNow), NewKey()).Wire);

        Assert.True(token.TryGetClaim("gid", out var gid), "the revocation denylist has nothing to match on.");
        Assert.Equal("grant-1", gid.Value);
    }

    [Fact]
    public void An_id_token_carries_the_at_hash_it_was_given_and_omits_it_otherwise()
    {
        // OIDC Core §3.1.3.6. Dropping at_hash is invisible from the outside: it is OPTIONAL in
        // the code flow, so a relying party that verifies it when present simply stops verifying,
        // reports nothing, and the substituted-access-token case the hash exists to catch stops
        // being caught. Nothing else in either token changes.
        //
        // Both directions in one test, because "always absent" and "always present" are the two
        // ways to get this wrong and each looks correct from the other's test.
        var now = DateTimeOffset.UtcNow;
        var hash = JwtTokenMinter.ComputeAccessTokenHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");

        var withHash = new JsonWebToken(Minter.MintIdToken(IdToken(now) with { AccessTokenHash = hash }, NewKey()).Wire);
        var without = new JsonWebToken(Minter.MintIdToken(IdToken(now), NewKey()).Wire);

        Assert.Equal(hash, withHash.GetClaim("at_hash").Value);
        Assert.False(without.TryGetClaim("at_hash", out _));
    }

    [Fact]
    public void An_id_token_omits_nonce_when_the_client_sent_none()
    {
        // Never invented. The client compares this against what it stored, so a server-generated
        // value would pass a replay check the client believes it is performing.
        var token = new JsonWebToken(Minter.MintIdToken(IdToken(DateTimeOffset.UtcNow), NewKey()).Wire);

        Assert.False(token.TryGetClaim("nonce", out _));
    }

    [Fact]
    public void An_id_token_echoes_the_nonce_verbatim()
    {
        var now = DateTimeOffset.UtcNow;
        var descriptor = IdToken(now) with { Nonce = "n-0S6_WzA2Mj" };

        var token = new JsonWebToken(Minter.MintIdToken(descriptor, NewKey()).Wire);

        Assert.Equal("n-0S6_WzA2Mj", token.GetClaim("nonce").Value);
    }

    [Fact]
    public void A_claims_mapper_cannot_overwrite_a_protocol_claim()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var reserved in new[] { "aud", "iss", "sub", "scope", "client_id", "exp" })
        {
            var descriptor = AccessToken(now) with
            {
                Extra = new Dictionary<string, object?> { [reserved] = "hijacked" },
            };

            Assert.Throws<InvalidOperationException>(() => Minter.MintAccessToken(descriptor, NewKey()));
        }
    }

    [Fact]
    public void A_claims_mapper_can_add_its_own_claims()
    {
        var descriptor = AccessToken(DateTimeOffset.UtcNow) with
        {
            Extra = new Dictionary<string, object?> { ["tenant"] = "acme" },
        };

        var token = new JsonWebToken(Minter.MintAccessToken(descriptor, NewKey()).Wire);

        Assert.Equal("acme", token.GetClaim("tenant").Value);
    }

    [Fact]
    public async Task An_expired_token_is_refused()
    {
        var past = DateTimeOffset.UtcNow.AddHours(-2);
        var key = NewKey();

        var descriptor = AccessToken(past) with { ExpiresAt = past.AddMinutes(30) };
        var accessToken = Minter.MintAccessToken(descriptor, key);

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [key.Key]));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_token_signed_by_a_different_key_is_refused()
    {
        var accessToken = Minter.MintAccessToken(AccessToken(DateTimeOffset.UtcNow), NewKey());

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(Issuer, Resource, [NewKey().Key]));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task A_token_from_a_different_issuer_is_refused()
    {
        var key = NewKey();
        var accessToken = Minter.MintAccessToken(AccessToken(DateTimeOffset.UtcNow), key);

        var result = await Handler.ValidateTokenAsync(
            accessToken.Wire,
            Rfc9068ValidationParameters.ForAccessToken(
                CreateIssuer("https://evil.example.com"), Resource, [key.Key]));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void The_at_hash_is_the_left_half_of_the_sha256()
    {
        // OIDC Core §3.1.3.6. Lets a client check that the access token it got belongs with the ID
        // token it got, which is what stops a substituted access token going unnoticed.
        var hash = JwtTokenMinter.ComputeAccessTokenHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");

        Assert.Equal("77QmUPtjPfzWtF2AnpK9RQ", hash);
    }
}
