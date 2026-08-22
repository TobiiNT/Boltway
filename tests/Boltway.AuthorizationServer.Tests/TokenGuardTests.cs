using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// One test per guard whose removal killed nothing.
/// </summary>
/// <remarks>
/// A mutation pass over the token endpoint removed eleven guards and the suite stayed green for
/// eight of them. Each is a real behaviour the server gets right — every one was confirmed correct
/// by probing the endpoint directly — so these are test gaps rather than live defects. Two of them
/// were unkillable by construction: the fixture registered exactly one client, so no test could
/// present client A's credential as client B.
/// </remarks>
public sealed class TokenGuardTests
{
    private const string ClientA = "https://claude.ai/.well-known/oauth-client";
    private const string ClientB = "https://other.example/.well-known/oauth-client";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private static ClientRecord Confidential(string clientId) =>
        Build.Client(clientId, ClientType.Confidential);

    private static async Task<FlowFixture> TwoClientsAsync() =>
        await FlowFixture.StartAsync(seed => seed.Clients.Add(Confidential(ClientB)));

    private static string AuthorizeUrl(string clientId = ClientA) =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(clientId)
        + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")
        + "&code_challenge=" + Verifier.ComputeS256Challenge()
        + "&code_challenge_method=S256"
        + "&scope=" + Uri.EscapeDataString("mcp:tools offline_access")
        + "&resource=" + Uri.EscapeDataString(Build.Resource);

    private static async Task<string> CodeForAsync(FlowFixture fixture, string clientId = ClientA)
    {
        var response = await fixture.Client.GetAsync(AuthorizeUrl(clientId));
        var location = response.Headers.Location!.ToString();

        return HttpUtility.ParseQueryString(new Uri(location).Query)["code"]!;
    }

    private static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(f => new KeyValuePair<string, string>(f.Key, f.Value)));

    private static async Task<string> ErrorOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.GetProperty("error").GetString()!;

    // ─────────────────────────────────────────────────────────────────────────
    // Client binding — unkillable before the fixture had two clients
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A code issued to one client cannot be redeemed by another.</summary>
    /// <remarks>
    /// §4.1.3 requires the server to "ensure that the authorization code was issued to the
    /// authenticated confidential client, or if the client is public, ensure that the code was
    /// issued to <c>client_id</c> in the request". A code arriving from a different client is a code
    /// injection attempt.
    /// </remarks>
    [Fact]
    public async Task A_code_cannot_be_redeemed_by_a_different_client()
    {
        await using var fixture = await TwoClientsAsync();

        var code = await CodeForAsync(fixture);

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", ClientB),
            ("code_verifier", Verifier.Value)));

        Assert.Equal("invalid_grant", await ErrorOf(response));
    }

    /// <summary>And the rightful client can still redeem it afterwards.</summary>
    /// <remarks>
    /// The half that matters. A cross-client attempt must not consume the code — otherwise anyone
    /// who observes a code can burn it, which is a denial of service needing no credentials at all.
    /// </remarks>
    [Fact]
    public async Task A_cross_client_attempt_does_not_consume_the_code()
    {
        await using var fixture = await TwoClientsAsync();

        var code = await CodeForAsync(fixture);

        await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientB), ("code_verifier", Verifier.Value)));

        var rightful = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA), ("code_verifier", Verifier.Value)));

        Assert.Equal(HttpStatusCode.OK, rightful.StatusCode);
    }

    /// <summary>A refresh token issued to one client cannot be used by another.</summary>
    [Fact]
    public async Task A_refresh_token_cannot_be_used_by_a_different_client()
    {
        await using var fixture = await TwoClientsAsync();

        var code = await CodeForAsync(fixture);
        var tokens = JsonDocument.Parse(await (await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA), ("code_verifier", Verifier.Value))))
            .Content.ReadAsByteArrayAsync()).RootElement;

        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var stolen = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "refresh_token"), ("refresh_token", refresh), ("client_id", ClientB)));

        Assert.Equal("invalid_grant", await ErrorOf(stolen));

        // And the legitimate client's token survived the attempt.
        var legitimate = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "refresh_token"), ("refresh_token", refresh), ("client_id", ClientA)));

        Assert.Equal(HttpStatusCode.OK, legitimate.StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expiry
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>An expired code is refused.</summary>
    [Fact]
    public async Task An_expired_code_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await CodeForAsync(fixture);

        fixture.Clock.Advance(TimeSpan.FromMinutes(2));

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA), ("code_verifier", Verifier.Value)));

        Assert.Equal("invalid_grant", await ErrorOf(response));
    }

    /// <summary>
    /// An expired code presented with a <b>wrong</b> verifier says nothing about expiry.
    /// </summary>
    /// <remarks>
    /// The expiry check runs after PKCE, so learning that a code was genuine requires already
    /// holding a valid verifier. Reversing the order would make the distinct message an oracle for
    /// anyone who merely sniffed a code.
    /// </remarks>
    [Fact]
    public async Task Expiry_is_not_disclosed_to_a_caller_without_the_verifier()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await CodeForAsync(fixture);
        fixture.Clock.Advance(TimeSpan.FromMinutes(2));

        var body = await (await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA),
            ("code_verifier", CodeVerifier.Generate().Value)))).Content.ReadAsStringAsync();

        Assert.DoesNotContain("expired", body, StringComparison.OrdinalIgnoreCase);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Resource narrowing
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A token request cannot widen beyond the grant's resources.</summary>
    /// <remarks>
    /// RFC 8707 §2.2 permits narrowing to a subset and nothing more. <c>invalid_target</c>, never
    /// <c>invalid_grant</c> — a client reads the latter as "the credential is dead".
    /// <para>
    /// The resource named here is <b>registered</b> and merely outside this grant. Naming an
    /// unregistered one would pass without the narrowing check at all, since the registry refuses it
    /// on its own — measured, that is exactly why the mutation removing the check survived.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_token_request_cannot_widen_the_resource_set()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await CodeForAsync(fixture);

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA),
            ("code_verifier", Verifier.Value), ("resource", Build.OtherResource)));

        Assert.Equal("invalid_target", await ErrorOf(response));
    }

    /// <summary>More than one <c>resource</c> is refused rather than served a multi-audience token.</summary>
    /// <remarks>
    /// A token valid at two resources is one either can replay at the other, which is the property
    /// resource indicators exist to remove.
    /// </remarks>
    [Fact]
    public async Task More_than_one_resource_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await CodeForAsync(fixture);

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA),
            ("code_verifier", Verifier.Value),
            ("resource", Build.Resource), ("resource", Build.OtherResource)));

        Assert.Equal("invalid_target", await ErrorOf(response));
    }

    /// <summary>A resource inside the grant is accepted, so the two tests above are not vacuous.</summary>
    [Fact]
    public async Task A_resource_inside_the_grant_is_accepted()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await CodeForAsync(fixture);

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA),
            ("code_verifier", Verifier.Value), ("resource", Build.Resource)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Client authentication — an area with no coverage at all before
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Two authentication mechanisms at once is <c>invalid_request</c>, not <c>invalid_client</c>.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 §2.4: a client "MUST NOT use more than one authentication method in each request to
    /// prevent a conflict of which authentication mechanism is authoritative". §3.2.4 names the case
    /// under <c>invalid_request</c> — "utilizes more than one mechanism for authenticating the
    /// client" — and the count runs before anything is validated, because a server that validates
    /// first has already picked one.
    /// </remarks>
    [Fact]
    public async Task Presenting_two_authentication_mechanisms_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = Form(("grant_type", "refresh_token"), ("refresh_token", "x"), ("client_secret", "s")),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ClientA}:secret")));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_request", await ErrorOf(response));

        // A 400, so no challenge — the failure is the request's shape, not the credential.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    /// <summary>
    /// Every pair that includes <c>client_assertion</c> is refused too.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The count in <c>ClientAuthenticator</c> reads
    /// <c>(basic ? 1 : 0) + (hasSecretInBody ? 1 : 0) + (hasAssertion ? 1 : 0)</c>, and mutation
    /// testing turned the second <c>+</c> into <c>-</c> without a single test failing. Under the
    /// mutant, Basic plus an assertion counts as <b>0</b> and all three count as <b>1</b>, so the
    /// combinations §2.4 exists to refuse walk straight past the guard and authenticate on whichever
    /// method the client registered.
    /// </para>
    /// <para>
    /// It survived because <c>client_assertion</c> appeared nowhere in this assembly — measured with
    /// a grep, zero hits across 573 tests. The third operand of that sum had never been set, so the
    /// guard had only ever been exercised two ways out of the three it covers. The row without
    /// <c>client_assertion</c> is kept as the control: it passes under the mutant, which is what
    /// makes the other two rows the ones doing the work.
    /// </para>
    /// <para>
    /// <c>private_key_jwt</c> is not implemented and not offered, so this is conformance rather than
    /// a way in — both credentials would still have to be valid for the same client. §2.4's rule
    /// exists so that a server never has to decide which of two presented mechanisms is
    /// authoritative, and the count runs before anything is validated for exactly that reason.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(true, false, true)]    // Basic + assertion          -> mutant computes 1 + 0 - 1 = 0
    [InlineData(false, true, true)]    // body secret + assertion    -> mutant computes 0 + 1 - 1 = 0
    [InlineData(true, true, true)]     // all three                  -> mutant computes 1 + 1 - 1 = 1
    [InlineData(true, true, false)]    // the control: no assertion  -> mutant computes 1 + 1 - 0 = 2
    public async Task No_two_client_authentication_mechanisms_may_be_combined(
        bool basic, bool bodySecret, bool assertion)
    {
        await using var fixture = await FlowFixture.StartAsync();

        var fields = new List<(string, string)>
        {
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
        };

        if (bodySecret)
        {
            fields.Add(("client_secret", "ck_cs_" + new string('A', 43)));
        }

        if (assertion)
        {
            fields.Add(("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            fields.Add(("client_assertion", "eyJhbGciOiJSUzI1NiJ9.e30.signature"));
        }

        if (!basic)
        {
            fields.Add(("client_id", ClientA));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = Form([.. fields]),
        };

        if (basic)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(ClientA)}:secret")));
        }

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_request", await ErrorOf(response));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// A client registered <c>none</c> that presents an assertion is refused.
    /// </summary>
    /// <remarks>
    /// The other place <c>hasAssertion</c> is read: <c>Public</c> refuses a client that registered
    /// no authentication method but arrived bearing a credential. The <c>||</c> chain there covers
    /// three inputs and only two of them had ever been set, so the assertion arm was carried by
    /// nothing. A public client whose assertion is quietly ignored believes it authenticated while
    /// the server knows it did not.
    /// </remarks>
    [Fact]
    public async Task A_public_client_presenting_an_assertion_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync(
            seed => seed.Client = Build.Client(ClientA, ClientType.Public));

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
            ("client_id", ClientA),
            ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            ("client_assertion", "eyJhbGciOiJSUzI1NiJ9.e30.signature")));

        Assert.Equal("invalid_client", await ErrorOf(response));
    }

    /// <summary>
    /// A client registered <c>none</c> that presents a secret is refused, not quietly accepted.
    /// </summary>
    /// <remarks>
    /// Accepting it would mean the client believes it authenticated and the server knows it did
    /// not, with no way for the client to discover the disagreement.
    /// </remarks>
    [Fact]
    public async Task A_public_client_presenting_a_secret_is_refused()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "refresh_token"), ("refresh_token", "x"),
            ("client_id", ClientA), ("client_secret", "pretend")));

        Assert.Equal("invalid_client", await ErrorOf(response));
    }

    /// <summary>
    /// A malformed <c>Authorization</c> header is refused rather than treated as absent.
    /// </summary>
    /// <remarks>
    /// Falling through to <c>none</c> would be a silent downgrade: the client sent a credential and
    /// the server ignored it.
    /// </remarks>
    [Fact]
    public async Task A_malformed_authorization_header_is_refused_with_a_challenge()
    {
        await using var fixture = await FlowFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = Form(("grant_type", "refresh_token"), ("refresh_token", "x"), ("client_id", ClientA)),
        };

        request.Headers.TryAddWithoutValidation("Authorization", "Basic !!!not-base64!!!");

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_client", await ErrorOf(response));

        // Credentials arrived in the header, so §5.2 makes 401 plus a matching challenge mandatory.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.StartsWith("Basic", Assert.Single(response.Headers.GetValues("WWW-Authenticate")), StringComparison.Ordinal);
    }

    /// <summary>
    /// A <c>client_id</c> in the body that disagrees with the header is refused.
    /// </summary>
    /// <remarks>
    /// §4.1.3 binds a code to "the authenticated confidential client, or … <c>client_id</c> in the
    /// request". With two candidate identities and no rule for choosing, the binding check would be
    /// checking the wrong one.
    /// </remarks>
    [Fact]
    public async Task A_client_id_disagreeing_with_the_header_is_refused()
    {
        await using var fixture = await TwoClientsAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = Form(("grant_type", "refresh_token"), ("refresh_token", "x"), ("client_id", ClientB)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(ClientA)}:s")));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_request", await ErrorOf(response));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // X-20 — specified, mapped in the error table, and never emitted
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A client that did not declare a grant cannot use it.
    /// </summary>
    /// <remarks>
    /// X-20. <c>/authorize</c> made the equivalent check for <c>authorization_code</c> and
    /// <c>/token</c> made none at all, so a client whose metadata declared only
    /// <c>["authorization_code"]</c> could refresh freely. The error table already had the row.
    /// </remarks>
    [Fact]
    public async Task A_client_that_did_not_declare_refresh_token_cannot_refresh()
    {
        await using var fixture = await FlowFixture.StartAsync(
            seed => seed.Client = seed.Client with { GrantTypes = ["authorization_code"] });

        var code = await CodeForAsync(fixture);
        var tokens = JsonDocument.Parse(await (await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA), ("code_verifier", Verifier.Value))))
            .Content.ReadAsByteArrayAsync()).RootElement;

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens.GetProperty("refresh_token").GetString()!),
            ("client_id", ClientA)));

        Assert.Equal("unauthorized_client", await ErrorOf(response));
    }

    /// <summary>A client that declared the grant may use it, so the test above is not vacuous.</summary>
    [Fact]
    public async Task A_client_that_declared_refresh_token_may_refresh()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var code = await CodeForAsync(fixture);
        var tokens = JsonDocument.Parse(await (await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "authorization_code"), ("code", code), ("client_id", ClientA), ("code_verifier", Verifier.Value))))
            .Content.ReadAsByteArrayAsync()).RootElement;

        var response = await fixture.Client.PostAsync("/token", Form(
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens.GetProperty("refresh_token").GetString()!),
            ("client_id", ClientA)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A malformed parameter must not reach the exception boundary
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// An enormous <c>max_age</c> is <c>invalid_request</c>, not <c>server_error</c>.
    /// </summary>
    /// <remarks>
    /// <c>long</c> accepts up to 9.2e18 and <c>TimeSpan.FromSeconds</c> throws above 922337203685,
    /// so the value below used to leave the pipeline through the exception boundary. That told the
    /// client the server had broken when the request was malformed, and wrote an unbounded
    /// "unhandled exception" log line for any unauthenticated caller who asked. X-04 says
    /// <c>invalid_request</c>.
    /// </remarks>
    [Theory]
    [InlineData("922337203686")]
    [InlineData("9223372036854775807")]
    public async Task An_enormous_max_age_is_invalid_request(string maxAge)
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&max_age=" + maxAge);

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("invalid_request", query["error"]);
    }

    /// <summary>A large but usable <c>max_age</c> still works, so the bound is where it is claimed.</summary>
    [Fact]
    public async Task A_large_but_usable_max_age_is_accepted()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&max_age=" + AuthorizePipeline.MaxMaxAgeSeconds);

        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Null(query["error"]);
        Assert.NotNull(query["code"]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Two infinite loops and a requirement with no emitter
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// <c>max_age=0</c> re-authenticates once, not forever.
    /// </summary>
    /// <remarks>
    /// OIDC defines <c>max_age=0</c> as "always re-authenticate", meaning once per request. Measured
    /// before the freshness floor: any elapsed time exceeds zero, so a user who had authenticated
    /// microseconds earlier was already stale — /authorize sent them to /login, the parameter
    /// survived in the returnUrl, and they arrived back stale again. Under <c>prompt=none</c> it was
    /// a <c>login_required</c> nothing could satisfy.
    /// </remarks>
    [Fact]
    public async Task Max_age_zero_is_satisfied_by_a_fresh_authentication()
    {
        // The state the browser is in when it comes back from /login: authenticated just now. That
        // is the round trip the loop happens on — the parameter that asked for a login survives in
        // the returnUrl and has to be satisfied by the login it caused.
        await using var fixture = await FlowFixture.StartAsync(JustAuthenticated);

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&max_age=0");

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location!.ToString();

        Assert.DoesNotContain("/login", location, StringComparison.Ordinal);
        Assert.NotNull(HttpUtility.ParseQueryString(new Uri(location).Query)["code"]);
    }

    /// <summary>
    /// <c>prompt=login</c> is satisfied by an authentication that just happened.
    /// </summary>
    /// <remarks>
    /// The same loop by the other route: the parameter is carried forward in the returnUrl, so
    /// without a freshness floor the login it asked for never counts as having happened.
    /// </remarks>
    [Fact]
    public async Task Prompt_login_is_satisfied_by_a_fresh_authentication()
    {
        await using var fixture = await FlowFixture.StartAsync(JustAuthenticated);

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&prompt=login");

        var location = response.Headers.Location!.ToString();

        Assert.DoesNotContain("/login", location, StringComparison.Ordinal);
    }

    /// <summary>
    /// A stale session with <c>max_age</c> still re-authenticates, so the floor is not a bypass.
    /// </summary>
    /// <remarks>
    /// The control. Without it, "max_age=0 does not loop" would pass equally against a server that
    /// ignores <c>max_age</c> altogether — which is the mutation that used to survive.
    /// </remarks>
    [Fact]
    public async Task An_old_session_with_max_age_is_sent_to_login()
    {
        await using var fixture = await FlowFixture.StartAsync();

        fixture.Clock.Advance(TimeSpan.FromHours(2));

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&max_age=60");

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Contains("/login", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>none</c> combined with another prompt value is refused before anything acts on either.
    /// </summary>
    /// <remarks>
    /// OIDC Core §3.1.2.1 — the combination asks for "do not interact" and "definitely interact" at
    /// once. Worth its own test because it is what makes X-14 unreachable: a branch answering
    /// <c>account_selection_required</c> for <c>none select_account</c> was written, and measured to
    /// be dead, because this refusal happens first.
    /// </remarks>
    [Fact]
    public async Task Prompt_none_cannot_be_combined_with_select_account()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&prompt=" + Uri.EscapeDataString("none select_account"));

        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("invalid_request", query["error"]);
    }

    /// <summary>
    /// A bare <c>select_account</c> sends the user to the login form to pick one.
    /// </summary>
    /// <remarks>
    /// With one session per browser there is no chooser to render, so re-authenticating is the
    /// handling that actually lets the user change account. Before this, the value was read, matched
    /// nothing and fell through to issuing a code for whoever was already signed in.
    /// </remarks>
    [Fact]
    public async Task Select_account_sends_a_stale_session_to_login()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&prompt=select_account");

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Contains("/login", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    /// <summary>Seed a session that authenticated at the same instant the clock starts.</summary>
    private static void JustAuthenticated(AuthorizationServerOptionsSeed seed) =>
        seed.SignedInUser = new AuthenticatedUser(SubjectId.FromStorage("user-1"), seed.Now);

    /// <summary>No session at all, with <c>prompt=none</c>, is <c>login_required</c>.</summary>
    [Fact]
    public async Task Prompt_none_without_a_session_is_login_required()
    {
        await using var fixture = await FlowFixture.StartAsync(seed => seed.SignedInUser = null);

        var response = await fixture.Client.GetAsync(AuthorizeUrl() + "&prompt=none");

        var query = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query);

        Assert.Equal("login_required", query["error"]);
    }
}
