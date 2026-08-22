using System.Net;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The authorization code flow, end to end over HTTP.
/// </summary>
/// <remarks>
/// The build order says this is where the flow first runs, and until it does, everything before it
/// is a claim. These tests exercise the two endpoints against a host wired the way a customer would
/// wire one — which is the only place a missing route, an unresolvable service or a status the
/// framework chose becomes visible.
/// </remarks>
public sealed class AuthorizationCodeFlowTests
{
    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private static string Authorize(string? overrideQuery = null)
    {
        var query = overrideQuery ?? string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString("https://claude.ai/.well-known/oauth-client"),
            "redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback"),
            "code_challenge=" + Verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString("mcp:tools offline_access"),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque-state");

        return "/authorize?" + query;
    }

    private static async Task<string> GetCodeAsync(FlowFixture fixture)
    {
        var response = await fixture.Client.GetAsync(Authorize());

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location!.ToString();
        var code = HttpUtility.ParseQueryString(new Uri(location).Query)["code"];

        Assert.False(string.IsNullOrEmpty(code), $"No code in {location}");
        return code!;
    }

    private static FormUrlEncodedContent Exchange(string code, string? verifier = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
            ["redirect_uri"] = "https://claude.ai/api/mcp/auth_callback",
            ["code_verifier"] = verifier ?? Verifier.Value,
        };

        return new FormUrlEncodedContent(fields);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();

    // ─────────────────────────────────────────────────────────────────────────
    // The happy path
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A code is issued, exchanged, and the response has everything a client needs.</summary>
    [Fact]
    public async Task A_code_can_be_exchanged_for_tokens()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var response = await fixture.Client.PostAsync("/token", Exchange(code));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        var body = await ReadJsonAsync(response);

        Assert.False(string.IsNullOrEmpty(body.GetProperty("access_token").GetString()));
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());

        // A JSON number, not a string. `"expires_in": "1800"` is a documented interop failure.
        Assert.Equal(JsonValueKind.Number, body.GetProperty("expires_in").ValueKind);
        Assert.True(body.GetProperty("expires_in").GetInt32() > 0);

        // offline_access was granted, so a refresh token must be here.
        Assert.False(string.IsNullOrEmpty(body.GetProperty("refresh_token").GetString()));

        // `openid` was not requested, so there must be no ID token. Returning one anyway hands the
        // client a second credential to mishandle for a protocol it did not ask for.
        Assert.False(body.TryGetProperty("id_token", out _));

        Assert.Equal("mcp:tools offline_access", body.GetProperty("scope").GetString());
    }

    /// <summary>
    /// The browser that approved is stamped on the grant, from the header the request carried.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The wiring test rather than the model test. `ApprovingDeviceTests` proves the header is
    /// described correctly and `MeSurfaceTests` proves the page renders it; neither would notice the
    /// endpoint reading nothing at all, which is the whole feature failing while every other
    /// assertion about it stays green.
    /// </para>
    /// <para>
    /// Read at <c>/authorize</c> and nowhere else, so this is where it has to be observed.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_grant_records_the_browser_the_authorization_arrived_in()
    {
        await using var fixture = await FlowFixture.StartAsync();

        const string Chrome =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/140.0.0.0 Safari/537.36";

        using var request = new HttpRequestMessage(HttpMethod.Get, Authorize());
        request.Headers.Add("User-Agent", Chrome);

        var response = await fixture.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var grant = Assert.Single(await fixture.Services.GetRequiredService<IGrantStore>()
            .ListForSubjectAsync(SubjectId.FromStorage("user-1"), CancellationToken.None));

        Assert.Equal(Chrome, grant.UserAgent);
    }

    /// <summary>A request with no such header records none, rather than an empty string.</summary>
    /// <remarks>
    /// The distinction the page reads: nothing recorded renders as nothing, and an empty string
    /// would render as a label with a blank after it.
    /// </remarks>
    [Fact]
    public async Task A_request_with_no_user_agent_records_none()
    {
        await using var fixture = await FlowFixture.StartAsync();

        await GetCodeAsync(fixture);

        var grant = Assert.Single(await fixture.Services.GetRequiredService<IGrantStore>()
            .ListForSubjectAsync(SubjectId.FromStorage("user-1"), CancellationToken.None));

        Assert.Null(grant.UserAgent);
    }

    /// <summary>A header longer than the cap is truncated rather than refused or stored whole.</summary>
    /// <remarks>
    /// It is caller-controlled and has no length limit of its own, so something has to bound what
    /// reaches a 256-character column. Truncating rather than refusing, because a strange header is
    /// not a reason to fail an authorization the user is in the middle of.
    /// </remarks>
    [Fact]
    public async Task An_absurdly_long_user_agent_is_truncated_rather_than_refusing_the_request()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, Authorize());
        request.Headers.Add("User-Agent", new string('a', 4096));

        var response = await fixture.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var grant = Assert.Single(await fixture.Services.GetRequiredService<IGrantStore>()
            .ListForSubjectAsync(SubjectId.FromStorage("user-1"), CancellationToken.None));

        Assert.Equal(ApprovingDevice.MaxLength, grant.UserAgent!.Length);
    }

    /// <summary>The authorization response carries <c>state</c> verbatim and RFC 9207's <c>iss</c>.</summary>
    [Fact]
    public async Task The_authorization_response_carries_state_and_iss()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(Authorize());
        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("opaque-state", query["state"]);
        Assert.Equal(Build.Issuer, query["iss"]);
    }

    /// <summary>
    /// Every redirect out of <c>/authorize</c> is a 303.
    /// </summary>
    /// <remarks>
    /// Not 302 and never 307. Under 307 the browser replays the POST body — which on the login and
    /// consent paths is the user's credentials — to the client's redirect URI, and a malicious
    /// client can then impersonate them. OAuth 2.1 §7.5.3: "only the status code 303 unambiguously
    /// enforces rewriting the HTTP POST request to an HTTP GET request."
    /// </remarks>
    [Fact]
    public async Task Every_redirect_from_authorize_is_a_303()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var success = await fixture.Client.GetAsync(Authorize());
        var error = await fixture.Client.GetAsync(Authorize(
            "response_type=token&client_id=" + Uri.EscapeDataString("https://claude.ai/.well-known/oauth-client")
            + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")));

        Assert.Equal(HttpStatusCode.SeeOther, success.StatusCode);
        Assert.Equal(HttpStatusCode.SeeOther, error.StatusCode);
    }

    /// <summary>
    /// A redirect URI that already carries a query keeps it, and the parameters are appended.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §2.3: a redirect URI "MAY include a query string component, which MUST be retained
    /// when adding additional query parameters". Concatenation would emit a second <c>?</c>, which
    /// is a legal character inside a query string — so nothing errors and the client parses one
    /// parameter whose value happens to contain the code.
    /// </remarks>
    [Fact]
    public async Task A_redirect_uri_with_an_existing_query_is_preserved()
    {
        var registered = "https://claude.ai/api/mcp/auth_callback?tenant=42";

        await using var fixture = await FlowFixture.StartAsync(
            seed => seed.Client = Build.Client(type: ClientType.Confidential, redirectUris: [registered]));

        var response = await fixture.Client.GetAsync(Authorize(
            "response_type=code"
            + "&client_id=" + Uri.EscapeDataString("https://claude.ai/.well-known/oauth-client")
            + "&redirect_uri=" + Uri.EscapeDataString(registered)
            + "&code_challenge=" + Verifier.ComputeS256Challenge()
            + "&code_challenge_method=S256&scope=mcp%3Atools"
            + "&resource=" + Uri.EscapeDataString(Build.Resource)));

        var location = new Uri(response.Headers.Location!.ToString());
        var query = HttpUtility.ParseQueryString(location.Query);

        Assert.Equal("42", query["tenant"]);
        Assert.False(string.IsNullOrEmpty(query["code"]));
        Assert.DoesNotContain("?code=", location.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A <c>state</c> containing query syntax cannot inject a parameter.
    /// </summary>
    /// <remarks>
    /// The value is opaque and caller-controlled, and it is echoed verbatim. Concatenating it would
    /// let <c>&amp;code=</c> inside it add a second code, and <c>#</c> truncate the response at the
    /// fragment boundary so <c>iss</c> silently disappears — which, for a client that must reject a
    /// response without <c>iss</c>, is a remote off switch for the flow.
    /// </remarks>
    [Fact]
    public async Task A_state_containing_query_syntax_is_encoded_not_interpreted()
    {
        await using var fixture = await FlowFixture.StartAsync();

        const string hostile = "a&code=injected&iss=evil#truncated";

        var response = await fixture.Client.GetAsync(Authorize(
            "response_type=code"
            + "&client_id=" + Uri.EscapeDataString("https://claude.ai/.well-known/oauth-client")
            + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")
            + "&code_challenge=" + Verifier.ComputeS256Challenge()
            + "&code_challenge_method=S256&scope=mcp%3Atools"
            + "&resource=" + Uri.EscapeDataString(Build.Resource)
            + "&state=" + Uri.EscapeDataString(hostile)));

        var location = new Uri(response.Headers.Location!.ToString());
        var query = HttpUtility.ParseQueryString(location.Query);

        Assert.Equal(hostile, query["state"]);
        Assert.Equal(Build.Issuer, query["iss"]);
        Assert.Equal(string.Empty, location.Fragment);
        Assert.NotEqual("injected", query["code"]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The token endpoint's transport rules
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A JSON body is <c>400</c> with an OAuth body, never <c>415</c>.
    /// </summary>
    /// <remarks>
    /// A <c>[FromBody]</c>-bound record answers 415 here, which is defensible HTTP and fatal in
    /// practice: it has no <c>error</c> member, so neither vendor's client parses it and the flow
    /// dies with nothing to debug.
    /// </remarks>
    [Fact]
    public async Task A_json_body_is_refused_with_an_oauth_error_and_not_415()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("invalid_request", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>A charset parameter on the content type does not make it a different media type.</summary>
    [Fact]
    public async Task A_form_content_type_with_a_charset_is_accepted()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);

        using var content = Exchange(code);
        content.Headers.ContentType!.CharSet = "UTF-8";

        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>An unparseable body is an OAuth error, not a 500.</summary>
    /// <remarks>
    /// <c>Request.Form</c> throws rather than returning empty, and an uncaught throw here is a 500 —
    /// which a client reads as "the server is broken" rather than "my request was".
    /// </remarks>
    [Fact]
    public async Task An_unparseable_form_body_is_an_oauth_error()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var content = new StringContent("%%%not=a%form%%", System.Text.Encoding.UTF8);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>GET is 405, so no exchange can happen with the code in a URL.</summary>
    [Fact]
    public async Task The_token_endpoint_refuses_get()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync("/token");

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    /// <summary>An unknown grant is <c>unsupported_grant_type</c>, not <c>invalid_request</c>.</summary>
    [Fact]
    public async Task An_unknown_grant_type_has_its_own_error_code()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password" });
        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal("unsupported_grant_type", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The grant's own rules
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A code is single-use.</summary>
    [Fact]
    public async Task A_code_cannot_be_exchanged_twice()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);

        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.PostAsync("/token", Exchange(code))).StatusCode);

        var replay = await fixture.Client.PostAsync("/token", Exchange(code));

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(replay)).GetProperty("error").GetString());
    }

    /// <summary>
    /// A replay with a <b>wrong verifier</b> is refused and the original tokens keep working.
    /// </summary>
    /// <remarks>
    /// N-07, and the whole reason redemption runs last. OAuth 2.1 §7.5.2: revoking on a replay that
    /// contains invalid parameters "would create a denial of service opportunity for an attacker who
    /// is able to obtain an authorization code but unable to obtain the client authentication or
    /// code_verifier" — they could kill the legitimate client's session at will. So this asserts the
    /// refusal <i>and</i> that the grant survived it.
    /// </remarks>
    [Fact]
    public async Task A_replay_with_a_wrong_verifier_does_not_revoke_the_grant()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));
        var refresh = first.GetProperty("refresh_token").GetString()!;

        var attack = await fixture.Client.PostAsync("/token", Exchange(code, CodeVerifier.Generate().Value));
        Assert.Equal("invalid_grant", (await ReadJsonAsync(attack)).GetProperty("error").GetString());

        // The legitimate client's refresh token still works, which is the half that matters.
        using var refreshBody = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refresh,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
        });

        var rotated = await fixture.Client.PostAsync("/token", refreshBody);

        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
    }

    /// <summary>A wrong verifier is <c>invalid_grant</c>.</summary>
    [Fact]
    public async Task A_wrong_verifier_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var response = await fixture.Client.PostAsync("/token", Exchange(code, CodeVerifier.Generate().Value));

        Assert.Equal("invalid_grant", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>A missing verifier is refused, because a challenge was stored.</summary>
    [Fact]
    public async Task A_missing_verifier_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
        });

        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal("invalid_grant", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>
    /// A <c>redirect_uri</c> that differs from the one used at <c>/authorize</c> is refused.
    /// </summary>
    [Fact]
    public async Task A_mismatched_redirect_uri_at_the_token_endpoint_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
            ["redirect_uri"] = "https://claude.ai/api/mcp/other_callback",
            ["code_verifier"] = Verifier.Value,
        });

        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal("invalid_grant", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    /// <summary>
    /// Omitting <c>redirect_uri</c> at the token endpoint is fine.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §10.2 makes accepting it a MUST and notes that "a client following only the OAuth
    /// 2.1 recommendations will not send the redirect_uri in the token request". Requiring it
    /// refuses the conformant client.
    /// </remarks>
    [Fact]
    public async Task Omitting_the_redirect_uri_at_the_token_endpoint_is_accepted()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
            ["code_verifier"] = Verifier.Value,
        });

        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.PostAsync("/token", content)).StatusCode);
    }

    /// <summary>
    /// The loopback client redirects to the port it asked for, and exchanges against that string.
    /// </summary>
    /// <remarks>
    /// Claude Code registers portless <c>http://localhost/callback</c> and listens on an ephemeral
    /// port. Redirecting to the registered string sends the browser to port 80; comparing the token
    /// request's <c>redirect_uri</c> against the registration fails every one of its exchanges.
    /// This is the end-to-end version of both.
    /// </remarks>
    [Fact]
    public async Task The_claude_code_loopback_flow_works_end_to_end()
    {
        await using var fixture = await FlowFixture.StartAsync(
            seed => seed.Client = Build.Client(type: ClientType.Confidential, redirectUris: ["http://localhost/callback"]));

        const string requested = "http://localhost:3118/callback";

        var response = await fixture.Client.GetAsync(Authorize(
            "response_type=code"
            + "&client_id=" + Uri.EscapeDataString("https://claude.ai/.well-known/oauth-client")
            + "&redirect_uri=" + Uri.EscapeDataString(requested)
            + "&code_challenge=" + Verifier.ComputeS256Challenge()
            + "&code_challenge_method=S256&scope=mcp%3Atools"
            + "&resource=" + Uri.EscapeDataString(Build.Resource)));

        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(requested, location, StringComparison.Ordinal);

        var code = HttpUtility.ParseQueryString(new Uri(location).Query)["code"]!;

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
            ["redirect_uri"] = requested,
            ["code_verifier"] = Verifier.Value,
        });

        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.PostAsync("/token", content)).StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Refresh
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A refresh rotates, and the loser of a racing refresh receives the <b>same</b> successor.
    /// </summary>
    /// <remarks>
    /// N-08: "two concurrent redemptions ⇒ one successor, both callers get it." The previous version
    /// of this test asserted the opposite — that the second presentation is refused — on the
    /// reasoning that any working token would fork the family. That reasoning was wrong: the grace
    /// path hands back the token that already exists, so there is one successor and no fork. And
    /// the refusal went to exactly the client that could not act on it, since Claude's proactive and
    /// reactive refreshes race in normal operation and the reactive one is racing because it just
    /// took a 401.
    /// </remarks>
    [Fact]
    public async Task A_refresh_rotates_and_a_racing_retry_gets_the_same_successor()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));
        var original = first.GetProperty("refresh_token").GetString()!;

        var rotated = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Refresh(original)));
        var successor = rotated.GetProperty("refresh_token").GetString()!;

        Assert.NotEqual(original, successor);

        // Inside the window: the same successor, not a second one and not a refusal.
        var retry = await fixture.Client.PostAsync("/token", Refresh(original));

        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(successor, (await ReadJsonAsync(retry)).GetProperty("refresh_token").GetString());

        // And the successor still works, so the retry did not consume it.
        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.PostAsync("/token", Refresh(successor))).StatusCode);
    }

    /// <summary>
    /// A second instance with a different derivation key refuses rather than issuing a corpse.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The grace branch does not read the successor's plaintext from anywhere — it recomputes it
    /// from <c>(familyId, generation)</c> under whatever key <i>this</i> process holds. On the
    /// rotation branch the derived value is the seed, so it matches by construction; here nothing
    /// guaranteed it did. A review measured the result: the client got HTTP 200, a working access
    /// token, and a refresh token whose hash is in no row. Having been told to rotate, it discards
    /// the token it had; the parent is already consumed; the family is unrecoverable, and the server
    /// logs nothing because it never sees the dud again.
    /// </para>
    /// <para>
    /// Two hosts over one <see cref="SharedStores"/> is the deployment shape that produces it — a
    /// load balancer in front of two instances, one database — and a key generated per process
    /// rather than configured is the ordinary way to get there. <c>invalid_grant</c> is the right
    /// answer because it is one the client can act on: it re-runs the authorization flow. A corpse
    /// is not.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_grace_replay_on_an_instance_with_a_different_key_is_refused_not_answered_with_a_dead_token()
    {
        var stores = new SharedStores();
        var otherKey = new byte[32];
        Array.Fill(otherKey, (byte)0xAB);

        await using var nodeA = await FlowFixture.StartAsync(s => s.Stores = stores);
        await using var nodeB = await FlowFixture.StartAsync(s =>
        {
            s.Stores = stores;
            s.DerivationKey = otherKey;
        });

        var code = await GetCodeAsync(nodeA);
        var first = await ReadJsonAsync(await nodeA.Client.PostAsync("/token", Exchange(code)));
        var original = first.GetProperty("refresh_token").GetString()!;

        // Node A rotates. The successor's hash is now in the shared store.
        await nodeA.Client.PostAsync("/token", Refresh(original));

        // The racing retry lands on node B, inside the grace window, under a key that disagrees.
        var retry = await nodeB.Client.PostAsync("/token", Refresh(original));

        Assert.Equal(HttpStatusCode.BadRequest, retry.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(retry)).GetProperty("error").GetString());
    }

    /// <summary>
    /// The control: the same two-instance replay succeeds when the key agrees.
    /// </summary>
    /// <remarks>
    /// Without this, the test above passes against a server that refuses <i>every</i> grace replay —
    /// which is the pre-N-08 behaviour it was written to prevent, and which would look identical
    /// from the outside. It also proves the sharing seam works, so a failure there cannot be read as
    /// the guard firing.
    /// </remarks>
    [Fact]
    public async Task A_grace_replay_across_two_instances_sharing_a_key_still_gets_the_same_successor()
    {
        var stores = new SharedStores();

        await using var nodeA = await FlowFixture.StartAsync(s => s.Stores = stores);
        await using var nodeB = await FlowFixture.StartAsync(s => s.Stores = stores);

        var code = await GetCodeAsync(nodeA);
        var first = await ReadJsonAsync(await nodeA.Client.PostAsync("/token", Exchange(code)));
        var original = first.GetProperty("refresh_token").GetString()!;

        var rotated = await ReadJsonAsync(await nodeA.Client.PostAsync("/token", Refresh(original)));
        var successor = rotated.GetProperty("refresh_token").GetString()!;

        var retry = await nodeB.Client.PostAsync("/token", Refresh(original));

        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(successor, (await ReadJsonAsync(retry)).GetProperty("refresh_token").GetString());

        // And what node B handed back is live, not merely equal to a string node A also printed.
        Assert.Equal(
            HttpStatusCode.OK,
            (await nodeB.Client.PostAsync("/token", Refresh(successor))).StatusCode);
    }

    /// <summary>
    /// Outside the window, the same replay revokes the whole family.
    /// </summary>
    /// <remarks>
    /// The control for the test above, and the half that carries RFC 9700 §2.2.2. Without it, the
    /// grace behaviour would be indistinguishable from "replays are always fine" — and a mutation
    /// deleting the entire reuse-detection response survived the suite before this existed.
    /// </remarks>
    [Fact]
    public async Task A_replay_outside_the_grace_window_revokes_the_family()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));
        var original = first.GetProperty("refresh_token").GetString()!;

        var rotated = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Refresh(original)));
        var successor = rotated.GetProperty("refresh_token").GetString()!;

        fixture.Clock.Advance(TimeSpan.FromMinutes(5));

        var replay = await fixture.Client.PostAsync("/token", Refresh(original));

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(replay)).GetProperty("error").GetString());

        // The live head is dead too — the whole family goes, not just the replayed token.
        var afterwards = await fixture.Client.PostAsync("/token", Refresh(successor));

        Assert.Equal(HttpStatusCode.BadRequest, afterwards.StatusCode);
    }

    /// <summary>
    /// A duplicate delivery of a valid exchange does not destroy the session it created.
    /// </summary>
    /// <remarks>
    /// The check the previous suite was missing entirely. <c>A_code_cannot_be_exchanged_twice</c>
    /// asserts the refusal and never looks at the blast radius — and measured before this fix, fifty
    /// unforced double-submits revoked the winner's grant fifty times out of fifty. An HTTP retry
    /// after a lost response is indistinguishable from a double-click, and neither is an attack.
    /// </remarks>
    [Fact]
    public async Task A_duplicate_exchange_denies_without_killing_the_grant()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));
        var refresh = first.GetProperty("refresh_token").GetString()!;

        var duplicate = await fixture.Client.PostAsync("/token", Exchange(code));

        Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(duplicate)).GetProperty("error").GetString());

        // The session the first delivery created is still alive.
        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.PostAsync("/token", Refresh(refresh))).StatusCode);
    }

    /// <summary>
    /// A replay long after the exchange does revoke the grant.
    /// </summary>
    /// <remarks>
    /// The control for the test above. Without it, "duplicate does not revoke" would pass against a
    /// server that never revokes at all — which is §4.1.3's SHOULD deleted.
    /// </remarks>
    [Fact]
    public async Task A_replay_outside_the_retry_window_revokes_the_grant()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));
        var refresh = first.GetProperty("refresh_token").GetString()!;

        // Past the 10-second retry window but inside the code's one-minute lifetime. Advancing
        // further would hit the expiry check first, which fires BEFORE redemption and deliberately
        // does not revoke — so the test would pass for the wrong reason and prove nothing about
        // replay. That ordering is N-07: an expired code must not be a way to kill a session.
        fixture.Clock.Advance(TimeSpan.FromSeconds(30));

        var replay = await fixture.Client.PostAsync("/token", Exchange(code));

        Assert.Equal("invalid_grant", (await ReadJsonAsync(replay)).GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await fixture.Client.PostAsync("/token", Refresh(refresh))).StatusCode);
    }

    /// <summary>
    /// <c>auth_time</c> is when the user authenticated, not when the token was minted.
    /// </summary>
    /// <remarks>
    /// Measured before <c>GrantRecord.AuthTime</c> existed: the refresh path passed the presented
    /// token's issue time, so a session authenticated thirty days ago reported one minutes old.
    /// Every relying party enforcing <c>max_age</c> or step-up authentication is silently defeated
    /// by that, and nothing about the token looks wrong.
    /// </remarks>
    [Fact]
    public async Task Auth_time_does_not_move_forward_on_a_refresh()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));

        var before = AuthTimeOf(first.GetProperty("access_token").GetString()!);

        fixture.Clock.Advance(TimeSpan.FromHours(6));

        var refreshed = await ReadJsonAsync(
            await fixture.Client.PostAsync("/token", Refresh(first.GetProperty("refresh_token").GetString()!)));

        Assert.Equal(before, AuthTimeOf(refreshed.GetProperty("access_token").GetString()!));
    }

    /// <summary><c>expires_in</c> agrees with the token's own lifetime.</summary>
    /// <remarks>
    /// It was computed from <c>TimeProvider.System</c> while <c>exp</c> came from the injected one.
    /// Measured with a ten-hour offset: <c>expires_in</c> of 37799 against an <c>exp - iat</c> of
    /// 1800 — a client trusting it uses a dead token for ten hours; with the offset reversed it
    /// clamps to zero and the client refresh-loops.
    /// </remarks>
    [Fact]
    public async Task Expires_in_agrees_with_the_tokens_own_exp()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var body = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));

        var claims = ClaimsOf(body.GetProperty("access_token").GetString()!);
        var lifetime = claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64();

        Assert.Equal(lifetime, body.GetProperty("expires_in").GetInt32());
    }

    private static long AuthTimeOf(string jwt) => ClaimsOf(jwt).GetProperty("auth_time").GetInt64();

    private static JsonElement ClaimsOf(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var padded = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=')
            .Replace('-', '+')
            .Replace('_', '/');

        return JsonDocument.Parse(Convert.FromBase64String(padded)).RootElement.Clone();
    }

    /// <summary>A refresh may narrow scope and may not widen it.</summary>
    /// <remarks>
    /// Widening is <c>invalid_scope</c> and never <c>invalid_grant</c>: a client reads the latter as
    /// "the refresh token is dead" and discards a live credential over a recoverable mistake.
    /// </remarks>
    [Fact]
    public async Task A_refresh_can_narrow_scope_but_not_widen_it()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await GetCodeAsync(fixture);
        var first = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Exchange(code)));
        var refresh = first.GetProperty("refresh_token").GetString()!;

        var narrowed = await ReadJsonAsync(await fixture.Client.PostAsync("/token", Refresh(refresh, "mcp:tools")));
        Assert.Equal("mcp:tools", narrowed.GetProperty("scope").GetString());

        var widened = await fixture.Client.PostAsync(
            "/token", Refresh(narrowed.GetProperty("refresh_token").GetString()!, "mcp:tools story:read"));

        Assert.Equal("invalid_scope", (await ReadJsonAsync(widened)).GetProperty("error").GetString());
    }

    /// <summary>An unknown refresh token is exactly <c>invalid_grant</c>.</summary>
    /// <remarks>
    /// The string matters: Anthropic's guidance is explicit that a client branches on it — "not
    /// <c>invalid_request</c> or a custom code" — and one that cannot recognise a dead refresh token
    /// has no recovery path.
    /// </remarks>
    [Fact]
    public async Task An_unknown_refresh_token_is_invalid_grant()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.PostAsync("/token", Refresh("ck_rt_" + new string('a', 43)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }

    private static FormUrlEncodedContent Refresh(string token, string? scope = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = token,
            ["client_id"] = "https://claude.ai/.well-known/oauth-client",
        };

        if (scope is not null)
        {
            fields["scope"] = scope;
        }

        return new FormUrlEncodedContent(fields);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Interaction
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>An anonymous browser is sent to the login page, not redirected to the client.</summary>
    [Fact]
    public async Task An_unauthenticated_request_goes_to_the_login_page()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.SignedInUser = null);

        var response = await fixture.Client.GetAsync(Authorize());

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.StartsWith("/login?returnUrl=", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    /// <summary><c>prompt=none</c> with no session is <c>login_required</c> on the redirect.</summary>
    /// <remarks>
    /// Specifically <c>login_required</c>, not <c>interaction_required</c>: relying parties doing
    /// silent renew branch on the exact string and many treat the latter as fatal.
    /// </remarks>
    [Fact]
    public async Task Prompt_none_without_a_session_is_login_required()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.SignedInUser = null);

        var response = await fixture.Client.GetAsync(Authorize() + "&prompt=none");
        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("login_required", query["error"]);
        Assert.Equal("opaque-state", query["state"]);
        Assert.Equal(Build.Issuer, query["iss"]);
    }

    /// <summary><c>prompt=none</c> that needs consent is <c>consent_required</c>.</summary>
    [Fact]
    public async Task Prompt_none_needing_consent_is_consent_required()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.Consent = ConsentDecision.Required);

        var response = await fixture.Client.GetAsync(Authorize() + "&prompt=none");
        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("consent_required", query["error"]);
    }

    /// <summary>A refused consent is <c>access_denied</c> on the redirect.</summary>
    [Fact]
    public async Task A_denied_consent_is_access_denied()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.Consent = ConsentDecision.Denied);

        var response = await fixture.Client.GetAsync(Authorize());
        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("access_denied", query["error"]);
    }

    /// <summary>A public client is asked to consent again however the policy answered. RFC 8252 §8.6.</summary>
    [Fact]
    public async Task A_public_client_is_sent_to_the_consent_page_even_when_already_granted()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(type: ClientType.Public);
            seed.Consent = ConsentDecision.AlreadyGranted;
        });

        var response = await fixture.Client.GetAsync(Authorize());

        // The fixture's policy says AlreadyGranted and the client is public, so the guard the
        // endpoint composes around it must turn that into Required — a consent page, not a code.
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.StartsWith("/consent?returnUrl=", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// A confidential client with standing consent is not asked again.
    /// </summary>
    /// <remarks>
    /// The control for the test above. Without it, that one passes just as well against an endpoint
    /// that shows the consent page unconditionally — which would assert nothing about the guard.
    /// </remarks>
    [Fact]
    public async Task A_confidential_client_with_standing_consent_is_not_asked_again()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(type: ClientType.Confidential);
            seed.Consent = ConsentDecision.AlreadyGranted;
        });

        var response = await fixture.Client.GetAsync(Authorize());

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.StartsWith("https://claude.ai/api/mcp/auth_callback?", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Headers
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The authorization endpoint carries the N-15 headers.</summary>
    [Fact]
    public async Task The_authorization_endpoint_carries_the_security_headers()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(Authorize());

        var csp = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));

        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("form-action 'self'", csp, StringComparison.Ordinal);
        Assert.Contains("base-uri 'none'", csp, StringComparison.Ordinal);
        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));

        // The Location on a success carries the authorization code, so this one is load-bearing
        // rather than hygiene.
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    /// <summary>
    /// The authorization endpoint has no CORS headers.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §3.1: "CORS MUST NOT be supported at the Authorization Endpoint as the client does
    /// not access this endpoint directly, instead the client redirects the user agent to it."
    /// </remarks>
    [Fact]
    public async Task The_authorization_endpoint_has_no_cors()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, Authorize());
        request.Headers.Add("Origin", "https://claude.ai");

        var response = await fixture.Client.SendAsync(request);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    /// <summary>The token endpoint does have CORS, because browser clients call it directly.</summary>
    [Fact]
    public async Task The_token_endpoint_allows_cross_origin_calls()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "password" });
        var response = await fixture.Client.PostAsync("/token", content);

        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }
}
