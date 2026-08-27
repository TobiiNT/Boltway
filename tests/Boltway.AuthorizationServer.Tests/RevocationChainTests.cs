using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.ResourceServer.Revocation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Ending a session here reaches a resource server there, over the wire, in one test.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every link in this chain had a test; the chain had none.</b>
/// <see cref="IntrospectionEndpointTests"/> asserts what <c>/introspect</c> puts in the body.
/// <c>RevocationCheckTests</c> asserts what <c>IntrospectionRevocationCheck</c> does with a body it
/// was handed. Between them sits an assumption nobody was checking: that the body one writes is the
/// body the other reads. They are separate implementations of RFC 7662 in separate packages, which
/// this repository's own rule describes as agreeing for about a month.
/// </para>
/// <para>
/// <b>So the check here is the real one, against the real endpoint.</b> No stub handler, no canned
/// JSON - <c>IntrospectionRevocationCheck</c> is constructed with a handler onto the running test
/// server and does its own HTTP, its own Basic authentication and its own parsing. A change to
/// either side that breaks the other fails here and nowhere else.
/// </para>
/// <para>
/// <b>What this file does not re-test</b> is the hop before it: that changing a password revokes
/// the grants. <see cref="UserAdministrationTests"/> owns that, it is one assembly's business, and
/// duplicating it here would add a second place to update rather than a second thing to know. The
/// production revocation path is called, not reimplemented.
/// </para>
/// </remarks>
public sealed class RevocationChainTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";
    private const string Introspection = "https://auth.example.com/introspect";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();
    private static readonly string Secret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;
    private static readonly ClaimsPrincipal Anonymous = new(new ClaimsIdentity());

    /// <summary>
    /// A session ended here is refused there, and the token is untouched throughout.
    /// </summary>
    /// <remarks>
    /// The gap this whole feature closes, end to end. The access token is a signed JWT whose
    /// signature is exactly as valid after the revoke as before it - a resource server verifying it
    /// offline would still accept it, which is why the offline answer is not the one that counts.
    /// </remarks>
    [Fact]
    public async Task A_session_ended_here_is_refused_by_a_resource_server_over_the_wire()
    {
        await using var fixture = await StartAsync();

        var token = await IssueAsync(fixture);
        var check = CheckAgainst(fixture, cacheLifetime: TimeSpan.Zero);

        // The control. Without it, a check that answered "revoked" to everything would pass the
        // assertion below - including one that could not reach the server at all, which fails open
        // and would answer false rather than true, but a broken credential is not the only way to
        // get a wrong answer for a wrong reason.
        Assert.False(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));

        await RevokeEverythingFor(fixture, "user-1");

        Assert.True(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));
    }

    /// <summary>
    /// The cache lifetime is the revocation lag, and this is what measures it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the number a user-facing sentence has to be written from.</b> "Ending a session
    /// cuts access immediately" is false while any positive answer is still cached, and the honest
    /// wording depends on how long that is - so the lag is asserted rather than assumed from
    /// reading the option's default.
    /// </para>
    /// <para>
    /// Driven by moving the clock rather than by sleeping. A test that waited thirty real seconds
    /// would be one nobody runs, and one that waited less would be flaky in exactly the direction
    /// that hides a regression.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_cached_answer_outlives_the_revoke_by_exactly_the_cache_lifetime()
    {
        await using var fixture = await StartAsync();

        var token = await IssueAsync(fixture);
        var lifetime = TimeSpan.FromSeconds(30);
        var check = CheckAgainst(fixture, lifetime);

        // Caches the live answer.
        Assert.False(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));

        await RevokeEverythingFor(fixture, "user-1");

        // Still allowed: the grant is gone, and this resource server does not know yet. Not a
        // defect - it is the trade the cache exists to make, and the reason the sentence on the
        // sessions page cannot say "immediately".
        Assert.False(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));

        // One tick before the lifetime elapses, the answer is still the cached one.
        fixture.Clock.Advance(lifetime - TimeSpan.FromSeconds(1));
        Assert.False(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));

        // And past it, the check asks again and gets the truth.
        fixture.Clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));
    }

    /// <summary>
    /// A resource server whose credential is wrong fails open against the real endpoint too.
    /// </summary>
    /// <remarks>
    /// The failure that presents as somebody else's outage. Worth driving against the real
    /// authorization server rather than a stub, because the stub was told to answer
    /// <c>invalid_client</c> and this one decides to - so this asserts that a real refusal of a real
    /// bad secret still lands in the branch that names the credential.
    /// </remarks>
    [Fact]
    public async Task A_wrong_client_secret_fails_open_rather_than_refusing_everybody()
    {
        await using var fixture = await StartAsync();

        var token = await IssueAsync(fixture);
        var check = CheckAgainst(fixture, TimeSpan.Zero, secret: OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire);

        await RevokeEverythingFor(fixture, "user-1");

        // Revoked at the authorization server, and allowed through here: the check could not ask.
        // Failing closed instead would turn one wrong secret into a total outage of the resource
        // server, which is the trade this library refuses to make silently.
        Assert.False(await check.IsRevokedAsync(token, Anonymous, CancellationToken.None));
    }

    // ─────────────────────────────────────────────────────────────────────────

    private static Task<FlowFixture> StartAsync() =>
        FlowFixture.StartAsync(seed =>
        {
            var now = DateTimeOffset.UtcNow;

            // Wall-clock, for the reason IntrospectionEndpointTests records: this is the one
            // endpoint that asks Microsoft.IdentityModel to judge expiry, and its TimeProvider is
            // internal in 8.22.0, so the library reads the system clock whatever the fixture says.
            // The fixture clock still moves - it is what the cache expires against.
            seed.Now = now;
            seed.SignedInUser = new(SubjectId.FromStorage("user-1"), now.AddMinutes(-1));

            seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic };

            seed.ConfigureOptions = o =>
            {
                o.IntrospectionEnabled = true;

                if (!o.TokenEndpointAuthMethods.Contains(ClientAuthMethod.ClientSecretBasic))
                {
                    o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretBasic);
                }
            };

            seed.ClientSecrets[ClientId] = Secret;
        });

    /// <summary>A real introspecting check, pointed at this fixture's real endpoint.</summary>
    /// <remarks>
    /// It authenticates as the same confidential client the flow used. A deployment would give the
    /// resource server a client of its own - RFC 7662 §2.1 only requires that the caller be
    /// authorized, not that it be a different principal - and registering a second one here would
    /// test the fixture's client registry rather than the seam.
    /// </remarks>
    private static IntrospectionRevocationCheck CheckAgainst(
        FlowFixture fixture, TimeSpan cacheLifetime, string? secret = null) =>
        new(
            new OneClient(fixture.NewHandler()),
            new IntrospectionOptions
            {
                Endpoint = new Uri(Introspection),
                ClientId = ClientId,
                ClientSecret = secret ?? Secret,
                CacheLifetime = cacheLifetime,
            },
            NullLogger<IntrospectionRevocationCheck>.Instance,
            fixture.Clock);

    /// <summary>The production revocation path, called rather than reimplemented.</summary>
    private static async Task RevokeEverythingFor(FlowFixture fixture, string subject)
    {
        var grants = fixture.Services.GetRequiredService<IGrantStore>();

        var revoked = await grants.RevokeAllForSubjectAsync(
            SubjectId.FromStorage(subject), fixture.Clock.GetUtcNow(), CancellationToken.None);

        // A revoke that revoked nothing would make every assertion after it pass for the wrong
        // reason - the token would be refused because it was never granted.
        Assert.True(revoked > 0, "nothing was revoked, so the assertions that follow prove nothing");
    }

    private static async Task<string> IssueAsync(FlowFixture fixture)
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

        exchange.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(ClientId)}:{Uri.EscapeDataString(Secret)}")));

        using var response = await fixture.Client.SendAsync(exchange);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var body = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        return body.RootElement.GetProperty("access_token").GetString()!;
    }

    /// <summary>A factory handing out one client over the test server's handler.</summary>
    private sealed class OneClient(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
