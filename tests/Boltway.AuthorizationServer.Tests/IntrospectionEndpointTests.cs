using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// RFC 7662 introspection. E-15.
/// </summary>
/// <remarks>
/// <para>
/// <b>The test that carries the reason this endpoint exists is
/// <see cref="A_token_whose_grant_was_revoked_is_not_active"/>.</b> Access tokens are signed JWTs,
/// so a resource server verifies them offline and ending a session does not reach it until the
/// token expires. <c>IGrantStore.IsRevokedAsync</c> was written for a resource server to consult
/// and had no production caller in either repository, because nothing exposed it over the wire.
/// Everything else here is the RFC's rules about not leaking while doing it.
/// </para>
/// <para>
/// Driven through the real flow — authorize, exchange, introspect — rather than by minting a token
/// in the test. What is under test is whether this server recognises its own tokens, and a token
/// this file constructed would prove only that it recognises tokens this file constructs.
/// </para>
/// </remarks>
public sealed class IntrospectionEndpointTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>A real minted secret: the server parses before it compares, so shape matters.</summary>
    private static readonly string Secret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

    /// <summary>
    /// A fixture running at wall-clock time, unlike every other one in this suite.
    /// </summary>
    /// <remarks>
    /// <b>Deliberate, and it is the library's constraint rather than a preference.</b> This is the
    /// only endpoint that asks <c>Microsoft.IdentityModel</c> to judge a token's expiry, and
    /// <c>TokenValidationParameters.TimeProvider</c> is internal in 8.22.0 — so the library reads
    /// the system clock and cannot be told otherwise. The suite's default clock is a fixed date,
    /// which would make every token this fixture mints already expired by however long ago that
    /// date was, and every assertion below would fail for a reason that has nothing to do with
    /// introspection.
    ///
    /// <para>
    /// Pinned to one instant captured here rather than read per call, so a test cannot straddle a
    /// second boundary, and set a minute in the past for the authentication so the seeded session
    /// is not in the future.
    /// </para>
    /// </remarks>
    private static Task<FlowFixture> StartAsync(bool introspection = true) =>
        FlowFixture.StartAsync(seed =>
        {
            var now = DateTimeOffset.UtcNow;

            seed.Now = now;
            seed.SignedInUser = new(SubjectId.FromStorage("user-1"), now.AddMinutes(-1));

            seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic };

            seed.ConfigureOptions = o =>
            {
                o.IntrospectionEnabled = introspection;

                if (!o.TokenEndpointAuthMethods.Contains(ClientAuthMethod.ClientSecretBasic))
                {
                    o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretBasic);
                }
            };

            seed.ClientSecrets[ClientId] = Secret;
        });

    // ─────────────────────────────────────────────────────────────────────────
    // The point of the endpoint
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_live_access_token_is_active_and_describes_itself()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        var body = await IntrospectAsync(fixture, tokens.GetProperty("access_token").GetString()!);

        Assert.True(body.GetProperty("active").GetBoolean());
        Assert.Equal(ClientId, body.GetProperty("client_id").GetString());
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal(Build.Issuer, body.GetProperty("iss").GetString());
        Assert.Equal(Build.Resource, body.GetProperty("aud").GetString());
        Assert.Contains("mcp:tools", body.GetProperty("scope").GetString()!, StringComparison.Ordinal);
    }

    /// <summary>
    /// Ending a session makes the token dead here, while it still verifies offline.
    /// </summary>
    /// <remarks>
    /// The whole argument for the endpoint in one test. The token is untouched and its signature is
    /// as good as it was a second ago — a resource server checking it offline would still accept
    /// it, and that is exactly the gap. Asserted immediately after the revoke, with no clock
    /// movement, so nothing here is passing because the token expired.
    /// </remarks>
    [Fact]
    public async Task A_token_whose_grant_was_revoked_is_not_active()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);
        var accessToken = tokens.GetProperty("access_token").GetString()!;

        // The control: alive before the revoke, so the assertion below is about the revoke and not
        // about the token having been dead all along.
        Assert.True((await IntrospectAsync(fixture, accessToken)).GetProperty("active").GetBoolean());

        var grants = fixture.Services.GetRequiredService<IGrantStore>();
        var grant = Assert.Single(await grants.ListForSubjectAsync(
            SubjectId.FromStorage("user-1"), CancellationToken.None));

        Assert.True(await grants.RevokeAsync(grant.GrantId, fixture.Clock.GetUtcNow(), CancellationToken.None));

        var body = await IntrospectAsync(fixture, accessToken);

        Assert.False(body.GetProperty("active").GetBoolean());

        // §2.2: a false response says nothing else. A body that still carried the scope and the
        // subject would hand every detail of a revoked session to whoever presented it.
        Assert.False(body.TryGetProperty("scope", out _));
        Assert.False(body.TryGetProperty("sub", out _));
        Assert.False(body.TryGetProperty("client_id", out _));
    }

    [Fact]
    public async Task A_live_refresh_token_is_active_and_is_not_called_a_bearer_token()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        var body = await IntrospectAsync(fixture, tokens.GetProperty("refresh_token").GetString()!);

        Assert.True(body.GetProperty("active").GetBoolean());

        // Not "Bearer". A refresh token is not a credential a resource server accepts, and saying
        // Bearer here invites somebody to present one to an API.
        Assert.Equal("refresh_token", body.GetProperty("token_type").GetString());

        // No audience: a refresh token is presented to this server and to nothing else.
        Assert.False(body.TryGetProperty("aud", out _));
    }

    /// <summary>A refresh token that has been rotated away is not active.</summary>
    /// <remarks>
    /// Consumed rows are retained on purpose — reuse detection needs them — so "the store found it"
    /// is not "it works", and this is the difference.
    /// </remarks>
    [Fact]
    public async Task A_rotated_refresh_token_is_not_active()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);
        var original = tokens.GetProperty("refresh_token").GetString()!;

        using var refresh = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = original,
                ["client_id"] = ClientId,
                ["resource"] = Build.Resource,
            }),
        };

        refresh.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        var rotated = await fixture.Client.SendAsync(refresh);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);

        var body = await IntrospectAsync(fixture, original);

        Assert.False(body.GetProperty("active").GetBoolean());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §2.2 — an unusable token is not an error
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("not-a-token-at-all")]
    [InlineData("eyJhbGciOiJSUzI1NiJ9.e30.bm90LWEtc2lnbmF0dXJl")]
    [InlineData("bw_rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task A_token_this_server_cannot_vouch_for_is_inactive_rather_than_an_error(string token)
    {
        // Three shapes: nonsense, a forged JWT, and something shaped like one of our refresh
        // tokens. All three are the same answer, so a caller holding a stolen token learns only
        // that it does not work — not why, and not whether it was ever real.
        await using var fixture = await StartAsync();

        var (status, body) = await IntrospectRawAsync(fixture, token);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(body.GetProperty("active").GetBoolean());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §2.1 — authorization, and what it protects
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// An unauthenticated caller is refused, and is not told what it left out.
    /// </summary>
    /// <remarks>
    /// The order is the assertion. Client authentication runs before the <c>token</c> parameter is
    /// read, so this request — which carries neither — is answered as an authentication failure.
    /// Reporting the missing parameter first would confirm to an unauthenticated stranger that the
    /// endpoint is live and takes it, which is the scanning §2.1 exists to prevent.
    /// </remarks>
    [Fact]
    public async Task An_unauthenticated_caller_is_refused_before_the_token_parameter_is_read()
    {
        await using var fixture = await StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)),
        };

        var response = await fixture.Client.SendAsync(request);
        var body = await ReadJsonAsync(response);

        var description = body.GetProperty("error_description").GetString()!;

        // Refused for who the caller is, not for what the request left out about the token. The
        // request carries neither a credential nor a `token`, and the answer names the credential.
        Assert.Contains("client_id", description, StringComparison.Ordinal);
        Assert.DoesNotContain("token", description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_wrong_secret_is_refused()
    {
        // The control for every test above: without it, an endpoint that authenticated nobody would
        // pass all of them.
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = tokens.GetProperty("access_token").GetString()!,
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", BasicOf(ClientId, OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>
    /// An authenticated caller that sends no token is told which parameter, and the refusal is
    /// logged the way every other one on this server is.
    /// </summary>
    /// <remarks>
    /// <b>The logging half is why <c>RejectionLoggingTests</c> lists
    /// <c>ReasonCode.TokenParameterMissing</c> as covered here.</b> That file takes A-09 literally —
    /// one structured line, the right reason, a correlation id, and that id on the response the
    /// caller is holding — and its entry naming this test is worth only as much as the assertions
    /// below. So they are the same four.
    /// </remarks>
    [Fact]
    public async Task An_authenticated_caller_that_sends_no_token_is_told_so_and_it_is_logged_once()
    {
        await using var fixture = await StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (await ReadJsonAsync(response)).GetProperty("error").GetString());

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal(nameof(ReasonCode.TokenParameterMissing), line.Property("Reason"));

        var correlationId = line.Property("CorrelationId");
        Assert.False(string.IsNullOrEmpty(correlationId));

        Assert.True(response.Headers.TryGetValues("X-Request-Id", out var header));
        Assert.Equal(correlationId, header!.Single());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The flag routes as well as advertises
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// With the flag off the route does not exist, so the document and the server agree.
    /// </summary>
    /// <remarks>
    /// N-06 from the other side. <c>MetadataHonestyTests</c> catches advertised-but-unrouted; this
    /// catches routed-but-unadvertised, which is the shape that leaves a surface reachable on a
    /// deployment that believes it turned it off.
    /// </remarks>
    [Fact]
    public async Task The_endpoint_is_absent_when_the_flag_is_off()
    {
        await using var fixture = await StartAsync(introspection: false);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        Assert.Equal(HttpStatusCode.NotFound, (await fixture.Client.SendAsync(request)).StatusCode);
    }

    /// <summary>A hint that is wrong does not change the answer. §2.1.</summary>
    /// <remarks>
    /// The hint picks which lookup runs first and never which is allowed to run. A server that
    /// treated it as authoritative would report a live access token as dead for any client that
    /// labelled it carelessly.
    /// </remarks>
    [Fact]
    public async Task A_wrong_token_type_hint_does_not_change_the_answer()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        var body = await IntrospectAsync(
            fixture, tokens.GetProperty("access_token").GetString()!, hint: "refresh_token");

        Assert.True(body.GetProperty("active").GetBoolean());
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
    }

    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<JsonElement> IssueAsync(FlowFixture fixture)
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

        using var exchange = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code!,
                ["client_id"] = ClientId,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier.Value,
            }),
        };

        exchange.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        var response = await fixture.Client.SendAsync(exchange);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return await ReadJsonAsync(response);
    }

    private static async Task<JsonElement> IntrospectAsync(FlowFixture fixture, string token, string? hint = null)
    {
        var (status, body) = await IntrospectRawAsync(fixture, token, hint);

        Assert.Equal(HttpStatusCode.OK, status);
        return body;
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> IntrospectRawAsync(
        FlowFixture fixture, string token, string? hint = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal) { ["token"] = token };

        if (hint is { Length: > 0 })
        {
            fields["token_type_hint"] = hint;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(fields),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        var response = await fixture.Client.SendAsync(request);

        // Every response from here describes a live credential, so a shared proxy caching one hands
        // the next caller an answer about somebody else's token.
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        return (response.StatusCode, await ReadJsonAsync(response));
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();

    private static string BasicOf(string clientId, string secret) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}"));
}
