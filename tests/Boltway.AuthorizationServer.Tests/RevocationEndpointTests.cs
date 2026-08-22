using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// RFC 7009 revocation. E-16.
/// </summary>
/// <remarks>
/// <para>
/// <b>Almost every assertion here is that the response is an empty 200</b>, which reads like a test
/// suite with nothing to say until the reason is stated: §2.2 makes the answer identical for a token
/// that was revoked, one that never existed, one already dead and — X-39 — one belonging to somebody
/// else. The endpoint's whole security property is that those four are indistinguishable, so the
/// tests that matter are the pairs: the same 200 in both cases, and a <i>different</i> observable
/// effect on the token afterwards.
/// </para>
/// <para>
/// Driven through the real flow — authorize, exchange, revoke, then try to use what was revoked —
/// for the reason <c>IntrospectionEndpointTests</c> gives: a token this file constructed would prove
/// only that the server recognises tokens this file constructs.
/// </para>
/// </remarks>
public sealed class RevocationEndpointTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private const string OtherClientId = "https://elsewhere.example/.well-known/oauth-client";
    private const string OtherRedirectUri = "https://elsewhere.example/callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private static readonly string Secret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;
    private static readonly string OtherSecret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

    /// <summary>
    /// A fixture at wall-clock time, for the reason <c>IntrospectionEndpointTests</c> documents:
    /// this endpoint validates an access token's expiry through <c>Microsoft.IdentityModel</c>,
    /// whose <c>TimeProvider</c> is internal in 8.22.0 and therefore reads the system clock.
    /// </summary>
    private static Task<FlowFixture> StartAsync(bool revocation = true) =>
        FlowFixture.StartAsync(seed =>
        {
            var now = DateTimeOffset.UtcNow;

            seed.Now = now;
            seed.SignedInUser = new(SubjectId.FromStorage("user-1"), now.AddMinutes(-1));

            seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic };

            // A second confidential client, so "somebody else's token" is a real client
            // authenticating with its own secret rather than a hypothetical.
            seed.Clients.Add(Build.Client(OtherClientId, ClientType.Confidential, OtherRedirectUri)
                with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic });

            seed.ConfigureOptions = o =>
            {
                o.RevocationEnabled = revocation;

                // Introspection is how these tests observe that a revocation took effect, rather
                // than by reaching into the store. It is the same channel a resource server uses.
                o.IntrospectionEnabled = true;

                if (!o.TokenEndpointAuthMethods.Contains(ClientAuthMethod.ClientSecretBasic))
                {
                    o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretBasic);
                }
            };

            seed.ClientSecrets[ClientId] = Secret;
            seed.ClientSecrets[OtherClientId] = OtherSecret;
        });

    // ─────────────────────────────────────────────────────────────────────────
    // The point of the endpoint
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Revoking a refresh token stops it refreshing, and takes the access token with it.
    /// </summary>
    /// <remarks>
    /// The second half is the one worth having. RFC 7009 §2.1 only permits taking the access token
    /// too; here it is not a choice, because the denylist a resource server consults is keyed on the
    /// grant and an access token is signed rather than stored. So "revoke the refresh token and
    /// leave the session running" is a state this server cannot represent, and the test says which
    /// way that resolves.
    /// </remarks>
    [Fact]
    public async Task Revoking_a_refresh_token_ends_the_session()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        var refresh = tokens.GetProperty("refresh_token").GetString()!;
        var access = tokens.GetProperty("access_token").GetString()!;

        Assert.True((await IntrospectAsync(fixture, access)).GetProperty("active").GetBoolean());

        await RevokeAsync(fixture, refresh);

        Assert.False((await IntrospectAsync(fixture, access)).GetProperty("active").GetBoolean());

        using var retry = await RefreshAsync(fixture, refresh);
        Assert.Equal(HttpStatusCode.BadRequest, retry.StatusCode);
    }

    /// <summary>Revoking an access token revokes the grant behind it, so the refresh dies too.</summary>
    [Fact]
    public async Task Revoking_an_access_token_ends_the_session()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        var refresh = tokens.GetProperty("refresh_token").GetString()!;
        var access = tokens.GetProperty("access_token").GetString()!;

        await RevokeAsync(fixture, access);

        Assert.False((await IntrospectAsync(fixture, access)).GetProperty("active").GetBoolean());

        using var retry = await RefreshAsync(fixture, refresh);
        Assert.Equal(HttpStatusCode.BadRequest, retry.StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §2.2: the answers that must be indistinguishable
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A token this server never issued is a success, not an error.</summary>
    /// <remarks>
    /// §2.2 MUST. The client asked for the token not to work; it does not work. Answering 400 would
    /// tell a caller holding a stolen string whether it was ever real.
    /// </remarks>
    [Fact]
    public async Task An_unknown_token_is_a_success()
    {
        await using var fixture = await StartAsync();

        var response = await RevokeRawAsync(fixture, "not-a-token-this-server-ever-minted");

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal(0, response.Length);
    }

    /// <summary>Revoking twice is the same answer as revoking once.</summary>
    [Fact]
    public async Task An_already_revoked_token_is_a_success()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);
        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var first = await RevokeRawAsync(fixture, refresh);
        var second = await RevokeRawAsync(fixture, refresh);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(0, second.Length);
    }

    /// <summary>
    /// Another client's token answers 200 and is left working. X-39.
    /// </summary>
    /// <remarks>
    /// <b>The two assertions have to be read together.</b> The 200 alone would be satisfied by an
    /// endpoint that revoked anything anybody presented; the still-active check alone would be
    /// satisfied by one that answered 403 and confessed. Together they are the property: the caller
    /// cannot tell "revoked" from "not yours", and nothing happened.
    /// </remarks>
    [Fact]
    public async Task Another_clients_token_is_a_success_and_is_not_revoked()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);
        var access = tokens.GetProperty("access_token").GetString()!;
        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var byAccess = await RevokeRawAsync(fixture, access, client: OtherClientId, secret: OtherSecret);
        var byRefresh = await RevokeRawAsync(fixture, refresh, client: OtherClientId, secret: OtherSecret);

        Assert.Equal(HttpStatusCode.OK, byAccess.Status);
        Assert.Equal(HttpStatusCode.OK, byRefresh.Status);

        // Untouched, by the channel a resource server would use.
        Assert.True((await IntrospectAsync(fixture, access)).GetProperty("active").GetBoolean());

        using var stillRefreshes = await RefreshAsync(fixture, refresh);
        Assert.Equal(HttpStatusCode.OK, stillRefreshes.StatusCode);
    }

    /// <summary>
    /// A refresh token already rotated away still ends the session it belongs to.
    /// </summary>
    /// <remarks>
    /// <b>This is deliberately a different answer from the one <c>/introspect</c> gives</b> about the
    /// same string: introspection reports a consumed token inactive, because its question is "would
    /// this work". Here the question is "make this stop", and what the caller is pointing at is a
    /// session whose live token is the successor. Answering 200 and leaving that session running is
    /// the one outcome this endpoint must never produce, so the consumed row is followed to its
    /// family rather than treated as unrecognised.
    /// </remarks>
    [Fact]
    public async Task A_rotated_away_refresh_token_still_ends_the_session()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        var original = tokens.GetProperty("refresh_token").GetString()!;

        using var rotated = await RefreshAsync(fixture, original);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);

        using var rotatedBody = JsonDocument.Parse(await rotated.Content.ReadAsStringAsync());
        var successor = rotatedBody.RootElement.GetProperty("refresh_token").GetString()!;

        // The one this server would now call dead.
        await RevokeAsync(fixture, original);

        using var successorRetry = await RefreshAsync(fixture, successor);
        Assert.Equal(HttpStatusCode.BadRequest, successorRetry.StatusCode);
    }

    /// <summary>A mislabelled token is still revoked. §2.1: the hint orders the search, it does not bound it.</summary>
    [Fact]
    public async Task A_wrong_token_type_hint_still_revokes()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);
        var access = tokens.GetProperty("access_token").GetString()!;

        // A refresh token announced as an access token, and the other way round.
        await RevokeAsync(fixture, tokens.GetProperty("refresh_token").GetString()!, hint: "access_token");

        Assert.False((await IntrospectAsync(fixture, access)).GetProperty("active").GetBoolean());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The errors that are errors
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A missing token is the one bad request. X-37.</summary>
    [Fact]
    public async Task A_missing_token_parameter_is_invalid_request()
    {
        await using var fixture = await StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", body.RootElement.GetProperty("error").GetString());
    }

    /// <summary>
    /// An unauthenticated caller is refused before the token parameter is looked at. X-38.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The order is the assertion.</b> Two of the requests below omit client credentials and only
    /// one of those omits the token, and they must answer identically: a server that replies "the
    /// token parameter is required" to an unauthenticated caller has confirmed the endpoint is live
    /// and takes that parameter, which is what §2.1's authentication requirement guards against.
    /// Note that this is the <i>opposite</i> ordering to the one that would fall out of writing the
    /// handler in the order the RFC lists the parameters.
    /// </para>
    /// <para>
    /// <b>A caller presenting nothing gets <c>invalid_request</c>, not <c>invalid_client</c></b>,
    /// and 400 rather than 401. Both look inverted and both are right: there is no client id
    /// anywhere in the request, so there is no client to have failed authentication (§3.2.4's
    /// missing-parameter clause), and RFC 6749 §5.2 reserves 401 for a client that authenticated by
    /// a method the server can challenge — a blanket 401 with <c>WWW-Authenticate</c> would name a
    /// scheme the caller never used. The wrong-secret case below is the one that is a 401, and the
    /// two are asserted together so neither can drift into the other.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_unauthenticated_caller_learns_nothing_about_the_parameters()
    {
        await using var fixture = await StartAsync();

        var withToken = await AttemptAsync(fixture, withToken: true, credentials: null);
        var withoutToken = await AttemptAsync(fixture, withToken: false, credentials: null);

        Assert.Equal(HttpStatusCode.BadRequest, withToken.Status);
        Assert.Equal("invalid_request", withToken.Error);

        // The refusal is identical either way, which is the property being tested: whether the
        // `token` parameter was sent is not observable before authentication succeeds.
        Assert.Equal(withToken.Status, withoutToken.Status);
        Assert.Equal(withToken.Error, withoutToken.Error);
        Assert.Equal(withToken.Description, withoutToken.Description);

        // And what it does say is about the missing client id, never about `token` — the endpoint's
        // own parameters stay unmentioned to a caller who has not authenticated.
        Assert.DoesNotContain("token", withoutToken.Description!, StringComparison.OrdinalIgnoreCase);

        // A client that did present credentials by a challengeable method gets the 401 that tells it
        // to try again — and a description that still says nothing about this endpoint's parameters.
        var wrongSecret = await AttemptAsync(
            fixture,
            withToken: true,
            credentials: BasicOf(ClientId, OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire));

        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecret.Status);
        Assert.Equal("invalid_client", wrongSecret.Error);
        Assert.DoesNotContain("token", wrongSecret.Description!, StringComparison.OrdinalIgnoreCase);

        static async Task<(HttpStatusCode Status, string? Error, string? Description)> AttemptAsync(
            FlowFixture fixture, bool withToken, string? credentials)
        {
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);

            if (withToken)
            {
                fields["token"] = "anything";
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "/revoke")
            {
                Content = new FormUrlEncodedContent(fields),
            };

            if (credentials is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            }

            using var response = await fixture.Client.SendAsync(request);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

            return (
                response.StatusCode,
                body.RootElement.GetProperty("error").GetString(),
                body.RootElement.TryGetProperty("error_description", out var description)
                    ? description.GetString()
                    : null);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The wire contract
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The success is 200, no body, <c>no-store</c>, and no content type. E-16.
    /// </summary>
    /// <remarks>
    /// <c>no-store</c> is not ceremony on an empty body: a cached 200 on a shared proxy answers the
    /// <i>next</i> revocation without it reaching this server, so a real revocation silently does
    /// nothing. The absent content type is the other half — announcing <c>application/json</c> over
    /// zero bytes gives a client a parse error where it should see a success.
    /// </remarks>
    [Fact]
    public async Task The_success_carries_no_body_and_no_store()
    {
        await using var fixture = await StartAsync();
        var tokens = await IssueAsync(fixture);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/revoke")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = tokens.GetProperty("refresh_token").GetString()!,
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
        Assert.Null(response.Content.Headers.ContentType);
    }

    /// <summary>A GET is 405, not 404: the route exists and refuses the method. §2.1 specifies POST.</summary>
    /// <remarks>
    /// This is also why <c>MetadataHonestyTests</c>'s sweep, which probes with GET, does not read a
    /// POST-only endpoint as unrouted — it treats only 404 that way.
    /// </remarks>
    [Fact]
    public async Task A_get_is_refused_by_routing()
    {
        await using var fixture = await StartAsync();

        using var response = await fixture.Client.GetAsync("/revoke");

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    /// <summary>
    /// With the flag off the path 404s and the document does not name it.
    /// </summary>
    /// <remarks>
    /// One flag, both halves — the pairing <c>MetadataHonestyTests</c> exists to protect. Asserted
    /// here as well as there because that suite proves the two agree, and this proves what they
    /// agree on.
    /// </remarks>
    [Fact]
    public async Task With_the_flag_off_it_is_neither_routed_nor_advertised()
    {
        await using var fixture = await StartAsync(revocation: false);

        using var probe = await fixture.Client.PostAsync(
            "/revoke", new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)));

        Assert.Equal(HttpStatusCode.NotFound, probe.StatusCode);

        using var discovery = await fixture.Client.GetAsync("/.well-known/oauth-authorization-server");
        using var document = JsonDocument.Parse(await discovery.Content.ReadAsStringAsync());

        Assert.False(document.RootElement.TryGetProperty("revocation_endpoint", out _));
    }

    /// <summary>With the flag on, the document names it and the confidential auth methods with it.</summary>
    [Fact]
    public async Task With_the_flag_on_the_document_names_it()
    {
        await using var fixture = await StartAsync();

        using var discovery = await fixture.Client.GetAsync("/.well-known/oauth-authorization-server");
        using var document = JsonDocument.Parse(await discovery.Content.ReadAsStringAsync());

        Assert.Equal(
            Build.Issuer + "/revoke",
            document.RootElement.GetProperty("revocation_endpoint").GetString());

        // `none` is never offered here: §2.1 requires client authentication, and an endpoint that
        // accepted an unauthenticated caller would revoke on anyone's say-so.
        var methods = document.RootElement
            .GetProperty("revocation_endpoint_auth_methods_supported")
            .EnumerateArray()
            .Select(m => m.GetString())
            .ToArray();

        Assert.DoesNotContain("none", methods, StringComparer.Ordinal);
        Assert.Contains("client_secret_basic", methods, StringComparer.Ordinal);
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

        using var response = await fixture.Client.SendAsync(exchange);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    private static async Task<HttpResponseMessage> RefreshAsync(FlowFixture fixture, string refreshToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = ClientId,
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        return await fixture.Client.SendAsync(request);
    }

    private static async Task RevokeAsync(FlowFixture fixture, string token, string? hint = null)
    {
        var response = await RevokeRawAsync(fixture, token, hint);

        Assert.Equal(HttpStatusCode.OK, response.Status);
    }

    private static async Task<(HttpStatusCode Status, long Length)> RevokeRawAsync(
        FlowFixture fixture,
        string token,
        string? hint = null,
        string client = ClientId,
        string? secret = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal) { ["token"] = token };

        if (hint is { Length: > 0 })
        {
            fields["token_type_hint"] = hint;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/revoke")
        {
            Content = new FormUrlEncodedContent(fields),
        };

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Basic", BasicOf(client, secret ?? Secret));

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        return (response.StatusCode, (await response.Content.ReadAsStringAsync()).Length);
    }

    private static async Task<JsonElement> IntrospectAsync(FlowFixture fixture, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = token,
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    /// <summary>
    /// RFC 6749 §2.3.1: both halves are form-urlencoded before the base64, and the client id here is
    /// a URL — so an unescaped one carries a colon and the server splits on the wrong one.
    /// </summary>
    private static string BasicOf(string clientId, string secret) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}"));
}
