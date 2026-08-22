using System.Net;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// X-43 on the three surfaces that followed <c>/token</c>, and X-11 on the one that answers
/// differently.
/// </summary>
/// <remarks>
/// <para>
/// <c>/token</c> shed first and was the only one for a day. The others read stores too and turned a
/// database outage into a <c>500</c> — or, at <c>/authorize</c>, into <c>server_error</c>, which is
/// the same message in OAuth's own words. What is asserted here is one behaviour per surface plus
/// the negative direction on each, because a load-shed that also swallows defects is worse than the
/// bug it replaced.
/// </para>
/// <para>
/// <b>Each surface is broken at a different store, deliberately.</b> A single fake registered
/// everywhere would prove the endpoints share a catch; breaking the store each one actually reads
/// proves each reaches it. <c>/introspect</c> loses its token store, <c>/userinfo</c> its
/// directory, and <c>/authorize</c> loses the client resolver in one test and the code store in the
/// other — which is what puts it on either side of the line where a redirect becomes safe.
/// </para>
/// </remarks>
public sealed partial class StoreUnavailableTests
{
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    // ── /introspect ──────────────────────────────────────────────────────────

    /// <summary>A real minted secret: the server parses before it compares, so shape matters.</summary>
    private static readonly string IntrospectionSecret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

    /// <summary>
    /// A confidential client that may introspect, against a token store that never answers.
    /// </summary>
    /// <remarks>
    /// Wall-clock, like <c>IntrospectionEndpointTests</c>, and for the same library constraint:
    /// <c>Microsoft.IdentityModel</c> judges expiry against the system clock and cannot be told
    /// otherwise, so a fixture on the suite's fixed date mints tokens that are already expired.
    /// </remarks>
    private static Task<FlowFixture> UnreachableIntrospectionAsync() =>
        FlowFixture.StartAsync(seed =>
        {
            var now = DateTimeOffset.UtcNow;

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

            seed.ClientSecrets[ClientId] = IntrospectionSecret;
            seed.ConfigureServices = services =>
                services.AddSingleton<IRefreshTokenStore>(new UnreachableRefreshTokenStore());
        });

    private static HttpRequestMessage Introspect(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri("/introspect", UriKind.Relative))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = token,
            }),
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(ClientId)}:{Uri.EscapeDataString(IntrospectionSecret)}")));

        return request;
    }

    /// <summary>
    /// A revocation state that could not be read is neither <c>active</c> nor not.
    /// </summary>
    /// <remarks>
    /// This is the assertion that carries why this endpoint sheds at all. RFC 7662 §2.2 makes
    /// <c>{"active": false}</c> the answer to everything unusable, which is exactly why it must not
    /// be the answer to "the lookup failed": it is a definite statement built from no information,
    /// and a resource server acting on it drops a live session. <c>true</c> is worse in the other
    /// direction — it reports a token whose grant may have been revoked as good, on the endpoint
    /// whose whole purpose is consulting the denylist.
    /// </remarks>
    [Fact]
    public async Task An_introspection_whose_store_is_gone_answers_neither_active_nor_inactive()
    {
        await using var fixture = await UnreachableIntrospectionAsync();
        using var client = new HttpClient(fixture.NewHandler()) { BaseAddress = new Uri("https://auth.example.com") };

        using var request = Introspect(OpaqueSecret.Generate(TokenPurpose.RefreshToken).Wire);
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(string.Empty, body);
        Assert.DoesNotContain("active", body, StringComparison.Ordinal);

        Assert.NotNull(response.Headers.RetryAfter?.Delta);
        Assert.True(response.Headers.RetryAfter!.Delta!.Value > TimeSpan.Zero);
    }

    /// <summary>And it is one line, on this surface, naming X-43.</summary>
    [Fact]
    public async Task The_introspection_load_shed_is_logged_against_its_own_surface()
    {
        await using var fixture = await UnreachableIntrospectionAsync();
        using var client = new HttpClient(fixture.NewHandler()) { BaseAddress = new Uri("https://auth.example.com") };

        using var request = Introspect(OpaqueSecret.Generate(TokenPurpose.RefreshToken).Wire);
        _ = await client.SendAsync(request);

        var line = Assert.Single(fixture.Logs.Rejections);

        // Introspection, not Token. The surface is what an operator groups by, and a 503 filed
        // under the wrong endpoint sends whoever is paged to the wrong dependency.
        Assert.Equal("Introspection", line.Property("Surface"));
        Assert.Equal("StoreUnavailable", line.Property("Reason"));
        Assert.Equal("X-43", line.Property("RequirementId"));
    }

    /// <summary>
    /// An unauthenticated caller is still refused before the store is touched.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The negative direction for this surface. RFC 7662 §2.1 requires client authentication "to
    /// prevent token scanning attacks", and a shed that ran ahead of it would answer 503 to anyone
    /// at all — turning an outage into a free probe for whether the endpoint is live and what it
    /// takes. The shed is a <c>catch</c> around the handler, so it can only fire on a path the
    /// handler reached; this is what says the ordering survived.
    /// </para>
    /// <para>
    /// <c>invalid_request</c> rather than <c>invalid_client</c>, because this caller presented no
    /// credential at all rather than a wrong one — measured, not assumed. Which of the two comes
    /// back is not the point and is pinned only so that a change to it is noticed here rather than
    /// by a client.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_outage_does_not_move_the_authentication_check()
    {
        await using var fixture = await UnreachableIntrospectionAsync();
        using var client = new HttpClient(fixture.NewHandler()) { BaseAddress = new Uri("https://auth.example.com") };

        var response = await client.PostAsync(
            new Uri("/introspect", UriKind.Relative),
            new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = OpaqueSecret.Generate(TokenPurpose.RefreshToken).Wire,
            }));

        Assert.NotEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("invalid_request", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    // ── /userinfo ────────────────────────────────────────────────────────────

    /// <summary>A directory that cannot be reached.</summary>
    /// <remarks>
    /// Every method throws rather than one, because the point is the connection and not the query.
    /// Pinning the test to <c>FindBySubjectAsync</c> would pin it to which lookup the endpoint
    /// happens to make first.
    /// </remarks>
    private sealed class UnreachableUserStore : IUserStore
    {
        public Task<UserAccount?> FindBySubjectAsync(SubjectId subject, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<UserAccount?> FindByUsernameAsync(RealmId realm, string username, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<UserAccount?> FindByVerifiedEmailAsync(RealmId realm, string email, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<UserAccount?> FindByExternalLoginAsync(
            RealmId realm, string upstreamIssuer, string upstreamSubject, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task StoreAsync(UserAccount user, CancellationToken cancellationToken) => throw Unreachable();

        public Task LinkExternalLoginAsync(ExternalLogin link, CancellationToken cancellationToken) => throw Unreachable();

        public Task<IReadOnlyList<ExternalLogin>> ListExternalLoginsAsync(
            SubjectId subject, CancellationToken cancellationToken) => throw Unreachable();

        public Task<bool> SetRolesAsync(
            SubjectId subject, IReadOnlyList<string> roles, CancellationToken cancellationToken) => throw Unreachable();

        public Task<bool> StampSessionsAsync(SubjectId subject, DateTimeOffset at, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<bool> SetPasswordHashAsync(SubjectId subject, string passwordHash, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<bool> SetEnabledAsync(SubjectId subject, DateTimeOffset? disabledAt, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<bool> SetEmailAsync(SubjectId subject, string? email, bool verified, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<IReadOnlyList<UserAccount>> ListAsync(
            RealmId realm, SubjectId? after, int limit, CancellationToken cancellationToken) => throw Unreachable();

        public Task<bool> AnonymiseAsync(
            SubjectId subject, string tombstoneUsername, DateTimeOffset now, CancellationToken cancellationToken) =>
            throw Unreachable();
    }

    private const string Subject = "01J8XKQ7M3N4P5R6S7T8V9W0AD";

    private static Task<FlowFixture> UnreachableDirectoryAsync() =>
        FlowFixture.StartAsync(seed =>
        {
            seed.ConfigureOptions = o => o.UserInfoEnabled = true;

            seed.ConfigureServices = services =>
                services.AddSingleton<IUserStore>(new UnreachableUserStore());

            // A bearer principal, the way UserInfoSurfaceTests builds one: the endpoint reads
            // http.User, and standing up a real token exchange here would be testing /token again.
            seed.ConfigureApp = app => app.Use(async (http, next) =>
            {
                http.User = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(
                        [
                            new System.Security.Claims.Claim("scope", "openid"),
                            new System.Security.Claims.Claim("sub", Subject),
                        ],
                        "Bearer"));

                await next(http);
            });
        });

    /// <summary>
    /// A directory that is briefly gone must not be reported as a token that is dead.
    /// </summary>
    /// <remarks>
    /// The whole reason this surface needed the row. <c>invalid_token</c> is the nearest RFC 6750
    /// code and every conforming client treats it as "discard this and start again" — so answering
    /// it would spend a re-authorization, per session, on an outage measured in seconds. 401 is the
    /// specific wrong answer, so it is the one asserted against by name.
    /// </remarks>
    [Fact]
    public async Task A_directory_outage_is_not_reported_as_a_dead_token()
    {
        await using var fixture = await UnreachableDirectoryAsync();

        var response = await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(string.Empty, body);
        Assert.DoesNotContain("invalid_token", body, StringComparison.Ordinal);

        Assert.NotNull(response.Headers.RetryAfter?.Delta);
    }

    /// <summary>POST too, since OIDC Core §5.3.1 makes both methods this endpoint.</summary>
    /// <remarks>
    /// Both verbs map to the same handler, and asserting only GET would leave a future refactor
    /// free to wrap one of them and not the other.
    /// </remarks>
    [Fact]
    public async Task The_directory_outage_reaches_the_post_form_of_the_endpoint_too()
    {
        await using var fixture = await UnreachableDirectoryAsync();

        var response = await fixture.Client.PostAsync(
            new Uri("/userinfo", UriKind.Relative), new StringContent(string.Empty));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal("ResourceServer", line.Property("Surface"));
        Assert.Equal("X-43", line.Property("RequirementId"));
    }

    // ── /authorize, before a redirect URI is validated ───────────────────────

    /// <summary>A client store that cannot be reached.</summary>
    /// <remarks>
    /// <c>CanResolve</c> claims everything, which is what a resolver backed by a database does —
    /// a stored client id is a plain string and the only way to know whether it exists is to look.
    /// That is also why this failure lands before validation: there is no redirect URI to trust
    /// until the client behind it has been read.
    /// </remarks>
    private sealed class UnreachableClientResolver : IClientResolver
    {
        public bool CanResolve(ClientIdentifier clientId) => true;

        public ValueTask<ClientResolution> ResolveAsync(ClientIdentifier clientId, CancellationToken cancellationToken) =>
            throw Unreachable();
    }

    private static string AuthorizeUrl() =>
        "/authorize?" + string.Join(
            '&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(ClientId),
            "redirect_uri=" + Uri.EscapeDataString(RedirectUri),
            "code_challenge=" + Verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString("mcp:tools offline_access"),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque-state");

    /// <summary>
    /// 503 on our own page, carrying the code RFC 6749 registers for exactly this.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Not a redirect, and that is the security half of the assertion.</b> Reading the client is
    /// what validates the redirect URI, so a store that is down leaves the one in the query string
    /// unproven — sending the user to it would be the open redirector §4.1.2.1 forbids, with
    /// <c>state</c> attached.
    /// </para>
    /// <para>
    /// <b>503 rather than the 500 <c>server_error</c> would have carried</b>, and the code says the
    /// same thing to a machine: this request can succeed, shortly. Both halves matter — a status
    /// without the code leaves a client guessing, and the code at 500 contradicts itself.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_store_outage_before_the_redirect_is_validated_renders_here_and_says_come_back()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.ConfigureServices = services =>
        {
            services.RemoveAll<IClientResolver>();
            services.AddSingleton<IClientResolver>(new UnreachableClientResolver());
        });

        var response = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Null(response.Headers.Location);

        Assert.NotNull(response.Headers.RetryAfter?.Delta);
        Assert.True(response.Headers.RetryAfter!.Delta!.Value > TimeSpan.Zero);

        // A-12: the code and a safe description are in the body, so `curl -D-` is enough.
        Assert.Contains(
            "temporarily_unavailable",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    /// <summary>X-11, at last emitted by something.</summary>
    /// <remarks>
    /// The row has been in <c>OAuthErrors</c> since before this server had anything that could
    /// produce it, described as "dependency down, load shedding" — and a dependency going down
    /// produced X-10 instead. This is the line that says it does not any more.
    /// </remarks>
    [Fact]
    public async Task The_pre_redirect_outage_is_logged_as_the_requirement_written_for_it()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.ConfigureServices = services =>
        {
            services.RemoveAll<IClientResolver>();
            services.AddSingleton<IClientResolver>(new UnreachableClientResolver());
        });

        _ = await fixture.Client.GetAsync(AuthorizeUrl());

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal("AuthorizePreRedirect", line.Property("Surface"));
        Assert.Equal("StoreUnavailable", line.Property("Reason"));
        Assert.Equal("X-11", line.Property("RequirementId"));
        Assert.Equal("temporarily_unavailable", line.Property("Error"));

        // Not 429 and not X-31. Until this change the writer chose the row by asking whether a
        // Retry-After was set, so this refusal — which sets one — would have been answered as a
        // rate limit, and an operator reading the log during a database outage would have seen a
        // throttle. Nothing would have failed.
        Assert.Equal("503", line.Property("Status"));
    }

    // ── /authorize, once redirecting is permitted ────────────────────────────

    /// <summary>A code store that cannot be reached, which fails after validation rather than before.</summary>
    private sealed class UnreachableAuthorizationCodeStore : IAuthorizationCodeStore
    {
        public Task StoreAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<AuthorizationCodeRecord?> FindAsync(Sha256Hash codeHash, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<CodeRedemption> RedeemAsync(
            Sha256Hash codeHash, DateTimeOffset now, TimeSpan graceWindow, CancellationToken cancellationToken) =>
            throw Unreachable();

        public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken) =>
            throw Unreachable();
    }

    /// <summary>
    /// Past the line where a redirect is safe, the answer travels the redirect and keeps its state.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The client is validated, consent is already granted, and the store fails while minting the
    /// code — so <c>context.Redirect</c> is set and the boundary may use it. The client learns
    /// <c>temporarily_unavailable</c> where its own retry logic reads, rather than
    /// <c>server_error</c>, which tells it to stop.
    /// </para>
    /// <para>
    /// <b>No <c>Retry-After</c> here, deliberately.</b> It is a 303 the browser follows at once, so
    /// a header telling it to wait describes nothing it is about to do; the instruction belongs to
    /// the client and it is in the query string.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_store_outage_after_the_redirect_is_validated_goes_back_to_the_client()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureServices = services =>
                services.AddSingleton<IAuthorizationCodeStore>(new UnreachableAuthorizationCodeStore()));

        var response = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location!.ToString();

        Assert.StartsWith(RedirectUri, location, StringComparison.Ordinal);

        var query = HttpUtility.ParseQueryString(new Uri(location).Query);

        Assert.Equal("temporarily_unavailable", query["error"]);

        // RFC 9207 and §4.1.2.1: an error response carries `iss` and echoes `state`, or the client
        // that was told to verify them has to reject the one response that explains the outage.
        Assert.Equal("opaque-state", query["state"]);
        Assert.Equal(Build.Issuer, query["iss"]);

        Assert.Null(response.Headers.RetryAfter);
        Assert.Null(query["code"]);
    }

    /// <summary>
    /// An ordinary defect after validation is still <c>server_error</c>.
    /// </summary>
    /// <remarks>
    /// The negative direction, on the surface where getting it wrong is quietest: both codes travel
    /// the same 303 and a client following it sees a working redirect either way. A defect
    /// re-labelled "come back shortly" is one every client retries and no operator is paged for —
    /// and the log level moves with the code, so it would also stop being an Error line.
    /// </remarks>
    [Fact]
    public async Task A_defect_after_the_redirect_is_validated_is_still_the_servers_fault()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureServices = services =>
                services.AddSingleton<IAuthorizationCodeStore>(new BrokenAuthorizationCodeStore()));

        var response = await fixture.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("server_error", query["error"]);

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal("Unhandled", line.Property("Reason"));
        Assert.Equal("X-10", line.Property("RequirementId"));
    }

    /// <summary>A code store with a bug in it, as opposed to one that cannot be reached.</summary>
    private sealed class BrokenAuthorizationCodeStore : IAuthorizationCodeStore
    {
        public Task StoreAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken) =>
            throw new InvalidCastException("a real bug");

        public Task<AuthorizationCodeRecord?> FindAsync(Sha256Hash codeHash, CancellationToken cancellationToken) =>
            throw new InvalidCastException("a real bug");

        public Task<CodeRedemption> RedeemAsync(
            Sha256Hash codeHash, DateTimeOffset now, TimeSpan graceWindow, CancellationToken cancellationToken) =>
            throw new InvalidCastException("a real bug");

        public Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken) =>
            throw new InvalidCastException("a real bug");
    }
}
