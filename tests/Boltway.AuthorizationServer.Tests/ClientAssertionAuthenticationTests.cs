using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>private_key_jwt</c> at the token endpoint. RFC 7523 §3, OIDC Core §9.
/// </summary>
/// <remarks>
/// <para>
/// Driven through the real flow — authorize, then exchange the code with an assertion instead of a
/// secret — because what is under test is whether this server accepts a client signing with its own
/// key, and an assertion validated in isolation would prove only that the validator agrees with the
/// test's signer.
/// </para>
/// <para>
/// <b>The refusals are where the value is.</b> A verifier that accepts a correct assertion and also
/// accepts one whose audience names a different server, or whose signature is somebody else's, is
/// worse than no verifier at all — it reports a client as authenticated to every downstream check.
/// So each negative below is paired with the positive it differs from by one field.
/// </para>
/// </remarks>
public sealed class ClientAssertionAuthenticationTests
{
    private const string ClientId = "https://chatgpt.com/oauth/client.json";
    private const string JwksUri = "https://chatgpt.com/oauth/jwks.json";
    private const string RedirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>The client's key pair. The public half is what the fixture serves at its jwks_uri.</summary>
    private static readonly RSA ClientKey = RSA.Create(2048);

    private const string ClientKid = "client-1";

    /// <summary>A second pair, for the assertion nobody should accept.</summary>
    private static readonly RSA StrangerKey = RSA.Create(2048);

    private static string JwksFor(RSA key, string kid)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);

        return $$"""
            {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"{{kid}}",
             "n":"{{Base64UrlEncoder.Encode(parameters.Modulus!)}}",
             "e":"{{Base64UrlEncoder.Encode(parameters.Exponent!)}}"}]}
            """.ReplaceLineEndings(string.Empty);
    }

    private static Task<FlowFixture> StartAsync(string? jwks = null, Action<StubFetcher>? configureFetcher = null)
        => FlowFixture.StartAsync(seed =>
        {
            var now = DateTimeOffset.UtcNow;

            seed.Now = now;
            seed.SignedInUser = new(SubjectId.FromStorage("user-1"), now.AddMinutes(-1));

            seed.Client = Build.Client(ClientId, ClientType.Confidential, RedirectUri)
                with
            {
                TokenEndpointAuthMethod = ClientAuthMethod.PrivateKeyJwt,
                JwksUri = JwksUri,
            };

            var fetcher = new StubFetcher().Serve(JwksUri, jwks ?? JwksFor(ClientKey, ClientKid));
            configureFetcher?.Invoke(fetcher);
            seed.Fetcher = fetcher;

            seed.ConfigureOptions = o =>
            {
                if (!o.TokenEndpointAuthMethods.Contains(ClientAuthMethod.PrivateKeyJwt))
                {
                    o.TokenEndpointAuthMethods.Add(ClientAuthMethod.PrivateKeyJwt);
                }
            };
        });

    /// <summary>Build an assertion, varying one field at a time.</summary>
    private static string Assertion(
        FlowFixture fixture,
        RSA? key = null,
        string? kid = null,
        string? issuer = null,
        string? subject = null,
        string? audience = null,
        string? jwtId = null,
        TimeSpan? lifetime = null)
    {
        var now = DateTimeOffset.UtcNow;
        var signing = new RsaSecurityKey(key ?? ClientKey) { KeyId = kid ?? ClientKid };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer ?? ClientId,
            Audience = audience ?? Build.Issuer + "/token",
            Expires = (now + (lifetime ?? TimeSpan.FromMinutes(2))).UtcDateTime,
            IssuedAt = now.UtcDateTime,
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub"] = subject ?? ClientId,
                ["jti"] = jwtId ?? Guid.NewGuid().ToString("N"),
            },
            SigningCredentials = new SigningCredentials(signing, SecurityAlgorithms.RsaSha256),
        };

        _ = fixture;

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The point
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A client signing with its own key gets a token.</summary>
    [Fact]
    public async Task An_assertion_signed_with_the_clients_key_authenticates()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(fixture, Assertion(fixture));

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.False(string.IsNullOrEmpty(response.Body.GetProperty("access_token").GetString()));
    }

    /// <summary>The issuer identifier is accepted as the audience too. OIDC Core §9.</summary>
    /// <remarks>
    /// Both spellings are accepted because real clients send one or the other and no assertion from
    /// either vendor has been captured to say which. Asserted rather than assumed, so a change that
    /// narrows it fails here rather than at somebody's connector.
    /// </remarks>
    [Fact]
    public async Task The_issuer_is_accepted_as_an_audience_beside_the_token_endpoint()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(fixture, Assertion(fixture, audience: Build.Issuer));

        Assert.Equal(HttpStatusCode.OK, response.Status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The refusals, each one field from the test above
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>An assertion signed by a key the client never published is refused, and logged.</summary>
    /// <remarks>
    /// <para>
    /// The control without which every other test here passes on a verifier that checks nothing.
    /// </para>
    /// <para>
    /// <b>It is also the one that proves these refusals reach the log at all.</b>
    /// <c>RejectionLoggingTests</c> requires every <c>ReasonCode</c> this server emits to be forced
    /// by some test, and its table says an entry naming a test that does not actually force the log
    /// line is a promise rather than a check. So the reason is asserted here, on the wire and in the
    /// log, and the other four assertion codes are listed there against tests that force the same
    /// path one field apart.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_assertion_signed_by_a_stranger_is_refused()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(fixture, Assertion(fixture, key: StrangerKey));

        await AssertRefusedAsync(response);

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal(nameof(ReasonCode.ClientAssertionInvalid), line.Property("Reason"));
        Assert.False(string.IsNullOrEmpty(line.Property("CorrelationId")));
    }

    /// <summary>An assertion minted for a different authorization server is refused.</summary>
    [Fact]
    public async Task An_assertion_for_another_audience_is_refused()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(
            fixture, Assertion(fixture, audience: "https://someone-else.example/token"));

        await AssertRefusedAsync(response);
    }

    /// <summary>An assertion whose <c>iss</c> is not the client is refused.</summary>
    [Fact]
    public async Task An_assertion_issued_by_another_client_is_refused()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(
            fixture, Assertion(fixture, issuer: "https://claude.ai/oauth/mcp-oauth-client-metadata"));

        await AssertRefusedAsync(response);
    }

    /// <summary>
    /// An assertion whose <c>sub</c> is not the client is refused, even when <c>iss</c> is.
    /// </summary>
    /// <remarks>
    /// RFC 7523 §3 point 2. <c>TokenValidationParameters</c> has no place to express it, so it is
    /// checked in the authenticator — and this test is what says the check is there, since every
    /// other assertion in this file happens to set both fields the same way.
    /// </remarks>
    [Fact]
    public async Task An_assertion_whose_subject_is_not_the_client_is_refused()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(
            fixture, Assertion(fixture, subject: "https://claude.ai/oauth/mcp-oauth-client-metadata"));

        await AssertRefusedAsync(response);
    }

    /// <summary>An expired assertion is refused.</summary>
    [Fact]
    public async Task An_expired_assertion_is_refused()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(fixture, Assertion(fixture, lifetime: TimeSpan.FromMinutes(-10)));

        await AssertRefusedAsync(response);
    }

    /// <summary>
    /// An assertion valid for longer than this server allows is refused.
    /// </summary>
    /// <remarks>
    /// RFC 7523 requires an <c>exp</c> and says nothing about how far out. A year-long assertion is
    /// a bearer credential in everything but name — anyone who captures it authenticates as that
    /// client until it expires — and it is also the client choosing how long this server's replay
    /// table must remember it.
    /// </remarks>
    [Fact]
    public async Task An_assertion_valid_for_a_year_is_refused()
    {
        await using var fixture = await StartAsync();

        var response = await ExchangeAsync(fixture, Assertion(fixture, lifetime: TimeSpan.FromDays(365)));

        await AssertRefusedAsync(response);
    }

    /// <summary>The same assertion twice is refused the second time.</summary>
    /// <remarks>
    /// <b>The reason the replay store exists.</b> Both exchanges below present the same assertion;
    /// the first is refused for a used authorization code and the second must be refused for the
    /// assertion, so the code is minted fresh each time and only the assertion is reused.
    /// </remarks>
    [Fact]
    public async Task The_same_assertion_twice_is_refused()
    {
        await using var fixture = await StartAsync();

        var assertion = Assertion(fixture);

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(fixture, assertion)).Status);

        await AssertRefusedAsync(await ExchangeAsync(fixture, assertion));
    }

    /// <summary>An assertion with no <c>jti</c> is refused, which is stricter than the RFC.</summary>
    /// <remarks>
    /// §3 makes <c>jti</c> optional and the replay check a MAY. Accepting one without it means
    /// accepting a credential whose reuse cannot be detected — and doing so silently, which is the
    /// part that makes the stricter reading right.
    /// </remarks>
    [Fact]
    public async Task An_assertion_with_no_jti_is_refused()
    {
        await using var fixture = await StartAsync();

        var now = DateTimeOffset.UtcNow;

        var withoutJti = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = ClientId,
            Audience = Build.Issuer + "/token",
            Expires = now.AddMinutes(2).UtcDateTime,
            Claims = new Dictionary<string, object>(StringComparer.Ordinal) { ["sub"] = ClientId },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(ClientKey) { KeyId = ClientKid }, SecurityAlgorithms.RsaSha256),
        });

        var response = await ExchangeAsync(fixture, withoutJti);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_client", response.Body.GetProperty("error").GetString());

        // Named, unlike every other refusal here, and the difference is whether the client can act
        // on it. "Wrong audience" and "bad signature" are an oracle — a map of this server's
        // validation, one message at a time, to anyone willing to send assertions. "Carry a jti" is
        // a statement about the shape of the request the client just made, which it already knows,
        // and which it can fix.
        Assert.Contains(
            "jti",
            response.Body.GetProperty("error_description").GetString()!,
            StringComparison.Ordinal);
    }

    /// <summary>A client secret does not authenticate a client registered for assertions.</summary>
    [Fact]
    public async Task A_secret_does_not_stand_in_for_an_assertion()
    {
        await using var fixture = await StartAsync();

        var fields = ExchangeFields(await CodeAsync(fixture));
        fields["client_secret"] = "ck_cs_whatever";

        await AssertRefusedAsync(await PostAsync(fixture, fields));
    }

    /// <summary>An assertion of an unregistered type is refused. RFC 7521 §4.2.</summary>
    [Fact]
    public async Task An_assertion_of_the_wrong_type_is_refused()
    {
        await using var fixture = await StartAsync();

        var fields = ExchangeFields(await CodeAsync(fixture));
        fields["client_assertion"] = Assertion(fixture);
        fields["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";

        await AssertRefusedAsync(await PostAsync(fixture, fields));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The client's own keys
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A client rotating its signing key is picked up without waiting for the cache to expire.
    /// </summary>
    /// <remarks>
    /// <b>The defect this closes.</b> The key set is cached for at least five minutes, so a client
    /// that publishes a new key and signs with it would otherwise fail every authentication until
    /// the entry expired — punished for rotating correctly. An unknown <c>kid</c> is the signal, and
    /// it is the only validation failure that provokes a refetch: every other one is about the
    /// assertion rather than the key set, and refetching for those would turn a made-up <c>kid</c>
    /// into an outbound request per inbound request.
    /// </remarks>
    [Fact]
    public async Task A_client_that_rotates_its_key_is_picked_up_on_the_unknown_kid()
    {
        var rotated = RSA.Create(2048);
        StubFetcher? fetcher = null;

        await using var fixture = await StartAsync(configureFetcher: f => fetcher = f);

        // Warm the cache with the original set.
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(fixture, Assertion(fixture))).Status);

        // The client publishes a new key and signs with it. Nothing has expired — the entry is good
        // for another five minutes — so the unknown `kid` is the only thing that can provoke a
        // refetch.
        fetcher!.Serve(JwksUri, JwksFor(rotated, "client-2"));

        // Past the refetch floor. The assertion's own lifetime is judged by the system clock, which
        // this does not move — the same split IntrospectionEndpointTests documents.
        fixture.Clock.Advance(TimeSpan.FromSeconds(31));

        var response = await ExchangeAsync(fixture, Assertion(fixture, key: rotated, kid: "client-2"));

        Assert.Equal(HttpStatusCode.OK, response.Status);
    }

    /// <summary>
    /// The unknown-<c>kid</c> refetch is floored, so it cannot be provoked once per request.
    /// </summary>
    /// <remarks>
    /// <b>The bound the test above would otherwise hide.</b> That trigger is reachable by anyone who
    /// can reach the token endpoint: a syntactically valid assertion naming a random <c>kid</c>
    /// costs nothing to make, and without a floor each one is an outbound request aimed at the
    /// client's origin. So a rotation is picked up within
    /// <c>ClientKeySourceOptions.MinimumRefreshInterval</c> rather than instantly, and this is that
    /// interval being paid: one exchange, one refusal, no second fetch.
    /// </remarks>
    [Fact]
    public async Task A_rotation_inside_the_refetch_floor_is_not_picked_up_yet()
    {
        var rotated = RSA.Create(2048);
        StubFetcher? fetcher = null;

        await using var fixture = await StartAsync(configureFetcher: f => fetcher = f);

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(fixture, Assertion(fixture))).Status);

        var fetchesAfterWarming = fetcher!.Calls;

        fetcher.Serve(JwksUri, JwksFor(rotated, "client-2"));

        // No clock movement: the floor has not elapsed.
        await AssertRefusedAsync(await ExchangeAsync(fixture, Assertion(fixture, key: rotated, kid: "client-2")));

        Assert.Equal(fetchesAfterWarming, fetcher.Calls);
    }

    /// <summary>A client whose key set cannot be fetched cannot authenticate.</summary>
    [Fact]
    public async Task A_client_whose_jwks_is_unreachable_is_refused()
    {
        await using var fixture = await StartAsync(
            configureFetcher: f => f.Respond(JwksUri, new FetchOutcome.NotOk(503)));

        await AssertRefusedAsync(await ExchangeAsync(fixture, Assertion(fixture)));
    }

    /// <summary>A key set carrying nothing to verify with is refused rather than treated as absent.</summary>
    [Fact]
    public async Task A_key_set_with_no_signing_keys_is_refused()
    {
        await using var fixture = await StartAsync(jwks: """{"keys":[]}""");

        await AssertRefusedAsync(await ExchangeAsync(fixture, Assertion(fixture)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Discovery
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The method is advertised when it is offered, and absent when it is not. N-06.
    /// </summary>
    [Fact]
    public async Task The_document_advertises_the_method_only_when_it_is_offered()
    {
        await using var offered = await StartAsync();
        var methods = await MethodsAsync(offered);

        Assert.Contains("private_key_jwt", methods, StringComparer.Ordinal);

        // C-02, and the reason this assertion sits beside the one above rather than in its own
        // test: Claude selects CIMD only when the document offers `none`, and falls back to dynamic
        // registration when it does not — at a /register this server answers 404 to, on purpose. So
        // adding an auth method is one edit away from making every Claude connection fail at a
        // stage that looks nothing like the change that caused it.
        Assert.Contains("none", methods, StringComparer.Ordinal);

        await using var plain = await FlowFixture.StartAsync();

        Assert.DoesNotContain(
            "private_key_jwt",
            await MethodsAsync(plain),
            StringComparer.Ordinal);
    }

    private static async Task<string[]> MethodsAsync(FlowFixture fixture)
    {
        using var response = await fixture.Client.GetAsync("/.well-known/oauth-authorization-server");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        return [.. document.RootElement
            .GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray()
            .Select(m => m.GetString() ?? string.Empty)];
    }

    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<string> CodeAsync(FlowFixture fixture)
    {
        var query = string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(ClientId),
            "redirect_uri=" + Uri.EscapeDataString(RedirectUri),
            "code_challenge=" + Verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString("mcp:tools offline_access"),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque-state");

        var authorized = await fixture.Client.GetAsync("/authorize?" + query);
        Assert.Equal(HttpStatusCode.SeeOther, authorized.StatusCode);

        var code = HttpUtility.ParseQueryString(new Uri(authorized.Headers.Location!.ToString()).Query)["code"];
        Assert.False(string.IsNullOrEmpty(code), "no code was issued");

        return code!;
    }

    private static Dictionary<string, string> ExchangeFields(string code) =>
        new(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier.Value,
        };

    private static async Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(
        FlowFixture fixture, string assertion)
    {
        var fields = ExchangeFields(await CodeAsync(fixture));

        fields["client_assertion"] = assertion;
        fields["client_assertion_type"] = ClientAssertionAuthenticator.JwtBearerAssertionType;

        return await PostAsync(fixture, fields);
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> PostAsync(
        FlowFixture fixture, Dictionary<string, string> fields)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(fields),
        };

        using var response = await fixture.Client.SendAsync(request);

        return (
            response.StatusCode,
            JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone());
    }

    /// <summary>
    /// Refused as <c>invalid_client</c>, with a description that names no check.
    /// </summary>
    /// <remarks>
    /// The second assertion is the one worth having. Which check failed — audience, signature,
    /// expiry, replay — goes to the log, and telling the client would hand anyone willing to send
    /// assertions a map of this server's validation, one message at a time.
    /// </remarks>
    private static async Task AssertRefusedAsync((HttpStatusCode Status, JsonElement Body) response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_client", response.Body.GetProperty("error").GetString());

        var description = response.Body.GetProperty("error_description").GetString() ?? string.Empty;

        foreach (var leak in new[] { "signature", "audience", "expired", "replay", "jti", "kid" })
        {
            Assert.DoesNotContain(leak, description, StringComparison.OrdinalIgnoreCase);
        }

        await Task.CompletedTask;
    }
}
