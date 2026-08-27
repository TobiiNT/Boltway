using System.Net;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// N-01's second leg and N-09, proved through a running server rather than against a parameters
/// object.
/// </summary>
/// <remarks>
/// <c>Boltway.OAuth.Tokens.Tests</c> already asserts both against
/// <c>Rfc9068ValidationParameters</c> directly. That is a real proof about the parameters and no
/// proof at all about a deployment: the middleware could ignore them, build its own, or map the
/// failure to a status code that leaves the client stuck. These tests present a token to a server
/// over HTTP and read the response, which is the only form in which either requirement is a fact
/// about the product.
/// </remarks>
public sealed class AudienceBindingTests
{
    [Fact]
    public async Task A_token_for_another_resource_gets_a_401()
    {
        // N-01: "Test: token issued for resource A presented at resource B ⇒ 401 invalid_token."
        //
        // The threat is RFC 9700 §4.9.1 access-token phishing. A user adds an attacker's MCP
        // server; the client does everything right; a server that stamped a house default audience
        // hands the attacker a token that works at every other resource the user has. RFC 8707
        // registers no discovery flag, so a client cannot tell "honoured" from "ignored" - this
        // check is the only thing standing between the two.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var elsewhere = Mint.AccessToken(audience: Build.Resolve(Build.OtherResource));

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", elsewhere);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_token", BearerChallengeTests.Parameter(response, "error"));
    }

    [Fact]
    public async Task A_token_for_another_resource_is_a_401_and_not_a_403()
    {
        // Stated separately because the distinction is the whole point and a test asserting only
        // "not 200" would pass on a 403. A 403 without error="insufficient_scope" is terminal for
        // Claude - no re-authentication prompt, permanently - so answering the wrong-audience case
        // that way leaves the user with a connector that can never recover. A 401 plus a metadata
        // pointer asks the client to go and get a token that names THIS resource, which is the one
        // thing that fixes it.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var elsewhere = Mint.AccessToken(audience: Build.Resolve(Build.OtherResource));

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", elsewhere);

        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(Build.MetadataUrl, BearerChallengeTests.Parameter(response, "resource_metadata"));
    }

    [Fact]
    public async Task The_audience_is_compared_in_full_and_not_by_origin()
    {
        // A-22. Comparing `aud` to the request's origin only is a shipped real-world bug
        // (cloudflare/workers-oauth-provider #108) that broke ChatGPT custom connectors. Same
        // origin here, different path - so a comparison that stopped at the host would accept this,
        // and every resource behind one hostname would share one audience.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var sameOriginOtherPath = Mint.AccessToken(
            audience: Build.Resolve("https://mcp.example.com/other"));

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", sameOriginOtherPath);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_audience_differing_only_by_a_trailing_slash_is_a_different_resource()
    {
        // The comparison is byte-for-byte, so https://mcp.example.com/mcp/ is not this resource.
        // C-28 is the operator-facing half of the same fact: the identifier must be the URL exactly
        // as the user types it into Claude.
        //
        // Minted outside the descriptor path, because inside it this token no longer exists:
        // TryRegister refuses the trailing-slash form at registration, so a Boltway issuer
        // cannot audience a token at it. A foreign issuer still can - its `aud` is whatever string
        // it wrote - and that is the token a resource server actually has to turn away.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var trailingSlash = Mint.AccessTokenForAudience(Build.Resource + "/");

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", trailingSlash);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task An_id_token_whose_audience_is_this_resource_is_still_refused()
    {
        // N-09: "Test asserting an ID token presented as a bearer token ⇒ 401 invalid_token."
        //
        // The audience is this resource's identifier ON PURPOSE, and it is what makes this a test
        // of N-09 rather than a second test of N-01. Everything else about this token is already
        // acceptable: same signing key, same kid, same iss, same sub, unexpired, and now the same
        // aud. `typ` is the only remaining difference - which is exactly RFC 9068 §5's cross-JWT
        // confusion - and TokenValidationParameters.ValidTypes is UNSET by default, so a resource
        // server built the obvious way accepts this.
        //
        // Measured: with an ordinary client id in `aud`, this test passes with ValidTypes set to
        // null. The version that proves something is the one below.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", Mint.IdToken(Build.Resource));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_token", BearerChallengeTests.Parameter(response, "error"));
    }

    [Fact]
    public async Task An_id_token_for_an_ordinary_client_is_refused_too()
    {
        // The everyday case, kept alongside the sharp one: a client presenting the ID token it
        // legitimately holds. It is refused on `aud` before `typ` is ever consulted, which is why
        // it cannot stand in for the test above.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await BearerChallengeTests.Get(
            fixture, "/mcp", Mint.IdToken("https://claude.ai/.well-known/oauth-client"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task The_matching_audience_is_the_control_for_all_of_the_above()
    {
        // Every test in this file asserts a refusal, and a middleware that refused everything -
        // a mis-wired key, a typo in the issuer, a validator that always threw - would make all of
        // them pass. This is the row that says the server can say yes.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", Mint.AccessToken());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
