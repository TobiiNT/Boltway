using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Counts what the login endpoint actually asks the hasher to do.
/// </summary>
/// <remarks>
/// The instrument for the username-enumeration tests. A stopwatch answers "were these two requests
/// the same speed?", which on a shared CI machine is a question with a noisy answer; this answers
/// "did the unknown-username path do the hash work at all?", which is the property the defence
/// actually consists of and which a test can decide with no timing at all.
/// </remarks>
internal sealed class CountingPasswordHasher(IPasswordHasher inner) : IPasswordHasher
{
    private int _verifications;

    /// <summary>How many times <see cref="Verify"/> has run.</summary>
    public int Verifications => Volatile.Read(ref _verifications);

    public string Hash(string password) => inner.Hash(password);

    public bool Verify(string password, string encodedHash)
    {
        Interlocked.Increment(ref _verifications);
        return inner.Verify(password, encodedHash);
    }
}

/// <summary>
/// <c>POST /login</c>, and the whole flow it stands in the middle of.
/// </summary>
/// <remarks>
/// <para>
/// Until this file existed, <c>POST /login</c> had never been executed: it resolves
/// <c>IUserStore</c> and <c>IPasswordHasher</c> from the container and no implementation of either
/// existed anywhere in the repository, not even a test double. Every request to it threw. The route
/// was mapped, the antiforgery check was written, the 303 was correct — and none of that was
/// reachable, so the endpoint's only demonstrated behaviour was that it could not be used.
/// </para>
/// <para>
/// The fixture here differs from every other one in this assembly in one deliberate way: it does not
/// seed a signed-in user. <see cref="TestUserSession"/> hands a session over for free, which is what
/// lets the other flow tests start at <c>/authorize</c> — and it would make this file pass with the
/// login endpoint deleted. The session has to come from the cookie the endpoint sets, or nothing is
/// being tested.
/// </para>
/// </remarks>
public sealed partial class LoginFlowTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string Username = "ada";
    private const string Password = "correct horse battery staple";

    /// <summary>
    /// An account that exists and has no local password: the shape federation produces.
    /// </summary>
    /// <remarks>
    /// Seeded alongside the ordinary one because it is the second way the username oracle opens, and
    /// it survives a fix aimed only at the unknown-username case.
    /// </remarks>
    private const string FederatedOnlyUsername = "grace";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>
    /// Cheap Argon2id parameters, so a suite that logs in repeatedly does not pay 19 MiB a time.
    /// </summary>
    /// <remarks>
    /// The costs are the one thing here that is <b>not</b> production-shaped, and it is worth saying
    /// so: what these tests exercise is the wiring and the control flow, not the strength of the
    /// hash. <c>Argon2idPasswordHasherTests</c> is where the shipped parameters are pinned.
    /// </remarks>
    private static Argon2idParameters TestCost => new()
    {
        MemoryKiB = 64,
        Iterations = 1,
        Parallelism = 1,
    };

    private sealed record Server(
        FlowFixture Fixture, CountingPasswordHasher Hasher, SubjectId Subject, InMemoryUserStore Users)
        : IAsyncDisposable
    {
        public HttpClient Client => Fixture.Client;

        public ValueTask DisposeAsync() => Fixture.DisposeAsync();
    }

    private static async Task<Server> StartAsync(bool accountEnabled = true)
    {
        var hasher = new CountingPasswordHasher(new Argon2idPasswordHasher(TestCost));
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Minted, not written by hand. This is the point of A-18 landing in code: the subject the
        // whole flow carries — into the cookie, into the grant, into `sub` — is a ULID because
        // something produced one, not because a comment says so.
        var subjects = new UlidSubjectIdFactory(TimeProvider.System);
        var subject = subjects.Mint();

        await users.StoreAsync(
            new UserAccount(
                subject,
                Username,
                "ada@example.com",
                EmailVerified: true,
                PasswordHash: hasher.Hash(Password),
                DisabledAt: accountEnabled ? null : DateTimeOffset.UnixEpoch),
            CancellationToken.None);

        await users.StoreAsync(
            new UserAccount(
                subjects.Mint(), FederatedOnlyUsername, "grace@example.com", EmailVerified: true, PasswordHash: null),
            CancellationToken.None);

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Public);
            seed.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";

            // Belt and braces, and the braces are what matter: the IUserSession registration below
            // replaces TestUserSession outright, so this line alone changes nothing. Measured —
            // putting a seeded user back here left all twelve tests green, because the seeded
            // session was no longer being read. It stays so that the fixture is not describing a
            // signed-in user that nothing consults.
            seed.SignedInUser = null;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IPasswordHasher>(hasher);

                services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie(o =>
                    {
                        o.Cookie.Name = "__Host-boltway-session";
                        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                        o.Cookie.HttpOnly = true;

                        // Lax, not Strict, and the shipped CookieUserSession comment says why: the
                        // browser reaches /authorize by a top-level cross-site navigation from
                        // claude.ai, and a Strict cookie is not sent on it — so every user would
                        // look signed out on every connect.
                        o.Cookie.SameSite = SameSiteMode.Lax;
                    });

                services.AddHttpContextAccessor();

                // The real session reader, replacing the fixture's TestUserSession. Registered after
                // it, so this is the one that resolves.
                services.AddScoped<IUserSession, CookieUserSession>();
            };

            seed.ConfigureApp = app => app.UseAuthentication();
        });

        return new Server(fixture, hasher, subject, users);
    }

    // Duplicated from InteractionFlowTests rather than shared: those helpers are private to that
    // class, and widening them to reach across files would couple two suites that are otherwise
    // independent.
    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [GeneratedRegex("name=\"returnUrl\" value=\"([^\"]+)\"")]
    private static partial Regex ReturnUrlField();

    private static (string Field, string Token, string ReturnUrl) FormFields(string html)
    {
        var token = AntiforgeryField().Match(html);
        var returnUrl = ReturnUrlField().Match(html);

        Assert.True(token.Success, "The page rendered no antiforgery field.");
        Assert.True(returnUrl.Success, "The page rendered no returnUrl field.");

        return (token.Groups[1].Value, token.Groups[2].Value, HttpUtility.HtmlDecode(returnUrl.Groups[1].Value));
    }

    private static string AuthorizeUrl() =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(ClientId)
        + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")
        + "&code_challenge=" + Verifier.ComputeS256Challenge()
        + "&code_challenge_method=S256"
        + "&scope=" + Uri.EscapeDataString("mcp:tools offline_access")
        + "&resource=" + Uri.EscapeDataString(Build.Resource)
        + "&state=opaque-state";

    /// <summary>Sign in, and hand back the response so a test can assert on it.</summary>
    private static async Task<HttpResponseMessage> PostLoginAsync(
        Server server, string username, string password, string? returnUrl = null)
    {
        var page = await server.Client.GetStringAsync(
            returnUrl ?? "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

        var (field, token, form) = FormFields(page);

        return await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", form),
            new("username", username),
            new("password", password),
        ]));
    }

    // ------------------------------------------------------------------ the whole flow

    /// <summary>
    /// An anonymous browser reaches an access token: authorize, login, consent, code, token.
    /// </summary>
    /// <remarks>
    /// The end-to-end path this repository did not have. Every other flow test starts with a session
    /// already established, so the two hops in the middle — the redirect to <c>/login</c> and the
    /// POST that satisfies it — were the only part of the sequence nothing exercised.
    /// </remarks>
    [Fact]
    public async Task An_anonymous_browser_signs_in_and_completes_the_authorization()
    {
        await using var server = await StartAsync();

        // ── /authorize with no session sends the browser to the login page.
        var start = await server.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);

        var loginUrl = start.Headers.Location!.ToString();
        Assert.StartsWith("/login?returnUrl=", loginUrl, StringComparison.Ordinal);

        // ── the credentials POST. 303, so the browser re-issues as GET and the password is not
        //    re-sent to the Location — RFC 9700 §4.12.
        var signedIn = await PostLoginAsync(server, Username, Password, loginUrl);

        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);

        var backToAuthorize = signedIn.Headers.Location!.ToString();
        Assert.StartsWith("/authorize?", backToAuthorize, StringComparison.Ordinal);

        // ── /authorize again, now with the session cookie. A public client always sees consent.
        var afterLogin = await server.Client.GetAsync(backToAuthorize);

        Assert.Equal(HttpStatusCode.SeeOther, afterLogin.StatusCode);

        var consentUrl = afterLogin.Headers.Location!.ToString();
        Assert.StartsWith("/consent?returnUrl=", consentUrl, StringComparison.Ordinal);

        var consentPage = await server.Client.GetStringAsync(consentUrl);
        var (field, token, returnUrl) = FormFields(consentPage);

        var approved = await server.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", returnUrl),
            new("decision", "approve"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);

        var callback = new Uri(approved.Headers.Location!.ToString());
        var query = HttpUtility.ParseQueryString(callback.Query);

        Assert.Equal("claude.ai", callback.Host);
        Assert.Equal("opaque-state", query["state"]);

        // ── and the code exchanges.
        var tokens = await server.Client.PostAsync("/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", query["code"]!),
            new("client_id", ClientId),
            new("code_verifier", Verifier.Value),
        ]));

        Assert.Equal(HttpStatusCode.OK, tokens.StatusCode);

        // The `sub` in the issued token is the subject that was minted for this account — read out
        // of the token rather than inferred. A-18's charset promise is about what this server
        // emits, so the check belongs on the value it emitted, at the end of the path it travelled:
        // password → cookie → authorize → grant → access token.
        using var body = JsonDocument.Parse(await tokens.Content.ReadAsStringAsync());
        var subject = SubjectOf(body.RootElement.GetProperty("access_token").GetString()!);

        Assert.Equal(server.Subject.Value, subject);
        Assert.True(Ulid.IsWellFormed(subject), subject);
    }

    /// <summary>Read <c>sub</c> out of a JWT, without validating it.</summary>
    /// <remarks>
    /// Signature validation is <c>TokenConfusionTests</c>' subject, not this file's. Here the token
    /// is only a carrier, and decoding its payload is the shortest way to ask what identifier came
    /// out the far end.
    /// </remarks>
    private static string SubjectOf(string jwt)
    {
        var payload = jwt.Split('.')[1];

        Assert.True(Base64Url.TryDecode(payload, out var bytes), "the access token payload is not base64url");

        using var document = JsonDocument.Parse(bytes);

        return document.RootElement.GetProperty("sub").GetString()!;
    }

    [Fact]
    public async Task A_username_is_matched_without_regard_to_case()
    {
        await using var server = await StartAsync();

        Assert.Equal(HttpStatusCode.SeeOther, (await PostLoginAsync(server, "ADA", Password)).StatusCode);
    }

    // ------------------------------------------------------------------ refusals

    [Theory]
    [InlineData("ada", "wrong password")]
    [InlineData("nobody", "correct horse battery staple")]
    [InlineData("", "")]
    public async Task Bad_credentials_re_render_the_form_rather_than_redirecting(string username, string password)
    {
        await using var server = await StartAsync();

        var response = await PostLoginAsync(server, username, password);

        // 200 with the form again, not a redirect: a redirect would have to carry the failure in a
        // query parameter, which is a reflected value on the one page where reflection matters.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            "That username and password did not match.",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_disabled_account_cannot_sign_in_with_the_right_password()
    {
        await using var server = await StartAsync(accountEnabled: false);

        var response = await PostLoginAsync(server, Username, Password);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            "That username and password did not match.",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Disabling through the administrative surface stops a sign-in that worked a moment earlier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The pair that was missing. <c>A_disabled_account_cannot_sign_in_with_the_right_password</c>
    /// proves the endpoint honours <c>DisabledAt</c>, using a fixture that seeds it directly — which
    /// it had to, because nothing could set the field. That made the rule enforced and unsettable.
    /// </para>
    /// <para>
    /// This is the other half, and it is the only test that would fail if the setter wrote to a
    /// column the sign-in path does not read: sign in, disable, and be refused with the same
    /// password.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Disabling_an_account_stops_the_sign_in_that_worked_a_moment_ago()
    {
        await using var server = await StartAsync();

        var before = await PostLoginAsync(server, Username, Password);

        Assert.Equal(HttpStatusCode.SeeOther, before.StatusCode);

        await using (var scope = server.Fixture.Services.CreateAsyncScope())
        {
            var administration = scope.ServiceProvider
                .GetRequiredService<AuthorizationServer.Administration.UserAdministration>();

            var result = await administration.SetEnabledAsync(
                AuthorizationServer.Administration.Actor.Cli,
                OAuth.Primitives.Ids.RealmId.Default,
                Username,
                enabled: false,
                server.Fixture.Clock.GetUtcNow(),
                CancellationToken.None);

            Assert.Equal(
                AuthorizationServer.Administration.AdministrationStatus.Ok,
                result.Status);
        }

        var after = await PostLoginAsync(server, Username, Password);

        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        Assert.Contains(
            "That username and password did not match.",
            await after.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_failed_login_establishes_no_session()
    {
        // The property behind the status code. A form that re-rendered but had already signed the
        // user in would look identical to this test's eye and be a total authentication bypass, so
        // the assertion is about what /authorize does next rather than about the page.
        await using var server = await StartAsync();

        await PostLoginAsync(server, Username, "wrong password");

        var afterFailure = await server.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, afterFailure.StatusCode);
        Assert.StartsWith("/login?returnUrl=", afterFailure.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_login_post_without_an_antiforgery_token_is_refused()
    {
        // Same reasoning as the consent POST: UseAntiforgery() auto-validates only handlers that
        // BIND form data, and this one reads Request.Form by hand — so without the explicit check
        // the middleware would skip it silently.
        await using var server = await StartAsync();

        var forged = await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new("returnUrl", AuthorizeUrl()),
            new("username", Username),
            new("password", Password),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
    }

    [Fact]
    public async Task A_login_post_with_a_foreign_return_url_is_refused_before_the_credentials_are_read()
    {
        // These pages live on the one origin the user has been taught to type a password into, so a
        // redirect off it is a phishing hand-off this server performed. Correct credentials must not
        // change that.
        await using var server = await StartAsync();

        var page = await server.Client.GetStringAsync("/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));
        var (field, token, _) = FormFields(page);

        var response = await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(field, token),
            new("returnUrl", "https://evil.example/authorize"),
            new("username", Username),
            new("password", Password),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("evil.example", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ username enumeration

    /// <summary>
    /// A wrong username and a wrong password produce the same bytes.
    /// </summary>
    /// <remarks>
    /// The wording half of the defence. "No such user" and "wrong password" as distinct messages
    /// turn the login form into a directory of who has an account here, which is the input to
    /// credential stuffing and to targeted phishing.
    /// <para>
    /// The antiforgery token is masked afresh on every response, so two renders of one page are
    /// never literally byte-identical. It is replaced with a placeholder before comparing, and that
    /// substitution is the one difference this test tolerates — a fact worth stating plainly,
    /// because "byte-identical" with an unstated exemption is how a real difference hides.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_unknown_username_and_a_wrong_password_are_answered_identically()
    {
        await using var server = await StartAsync();

        var unknownUser = await PostLoginAsync(server, "no-such-person", Password);
        var wrongPassword = await PostLoginAsync(server, Username, "not the password");

        Assert.Equal(unknownUser.StatusCode, wrongPassword.StatusCode);

        var left = Mask(await unknownUser.Content.ReadAsStringAsync());
        var right = Mask(await wrongPassword.Content.ReadAsStringAsync());

        Assert.Equal(left, right, StringComparer.Ordinal);

        // Non-vacuity: the masking must not have erased the page. If the regex ever matched
        // everything, two empty strings would compare equal and this test would prove nothing.
        Assert.Contains("That username and password did not match.", left, StringComparison.Ordinal);
    }

    [GeneratedRegex("value=\"[^\"]{20,}\"")]
    private static partial Regex LongFieldValue();

    private static string Mask(string html) => LongFieldValue().Replace(html, "value=\"<masked>\"");

    /// <summary>
    /// An unknown username costs a password hash, exactly as a known one does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the assertion that makes the endpoint's <c>DummyHash</c> defence real rather than
    /// decorative. Identical <i>responses</i> are not enough: if the unknown-username path returned
    /// without hashing, it would return in microseconds where the known path takes tens of
    /// milliseconds, and that difference is the same oracle a distinct error message would be —
    /// measured in milliseconds instead of words.
    /// </para>
    /// <para>
    /// Counted rather than timed, deliberately. A wall-clock comparison on shared CI hardware is a
    /// flaky test dressed as a security guarantee. The count is what the defence <i>is</i>: delete
    /// the <c>DummyHash</c> branch and this reads zero.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_unknown_username_still_pays_for_a_password_hash()
    {
        await using var server = await StartAsync();

        var before = server.Hasher.Verifications;

        await PostLoginAsync(server, "no-such-person", Password);

        Assert.Equal(before + 1, server.Hasher.Verifications);
    }

    /// <summary>
    /// An account with no local password pays for a hash too.
    /// </summary>
    /// <remarks>
    /// The federation-only shape: the row exists, <c>PasswordHash</c> is <see langword="null"/>. It
    /// is a second, narrower oracle — it distinguishes "this person signs in with Google" from
    /// "this person has a password here" — and it survives a fix aimed only at the unknown-username
    /// case, because the account genuinely was found.
    /// </remarks>
    [Fact]
    public async Task An_account_with_no_local_password_still_pays_for_a_password_hash()
    {
        await using var server = await StartAsync();

        var before = server.Hasher.Verifications;

        var response = await PostLoginAsync(server, FederatedOnlyUsername, Password);

        Assert.Equal(before + 1, server.Hasher.Verifications);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// A rejected password is recorded once, with the id the page carries. A-09.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The one refusal in this server that is not an OAuth error response: the form is re-rendered
    /// at <c>200</c>, deliberately, because a redirect would need the failure in a query parameter
    /// and that is a reflected value on the one page where reflection matters. A-09 says <i>every</i>
    /// path, and this is the path an operator is most often asked about — a burst of these is a
    /// credential-stuffing run, and before this change there was nothing to count.
    /// </para>
    /// <para>
    /// The username goes to the log and never back to the page. Which of the three causes it was —
    /// no such account, a disabled one, a wrong password — does not, in either place: separating
    /// them in a file the operator reads would recreate the username oracle that the equalised hash
    /// timing above exists to remove, for anyone who can read logs.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_rejected_password_is_recorded_once_with_the_id_the_page_carries()
    {
        await using var server = await StartAsync();

        var response = await PostLoginAsync(server, Username, "not the password");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var line = Assert.Single(server.Fixture.Logs.Rejections);

        Assert.Equal("PasswordRejected", line.Properties.GetValueOrDefault("Reason"));
        Assert.Equal("200", line.Properties.GetValueOrDefault("Status"));
        Assert.Equal("E-20", line.Properties.GetValueOrDefault("RequirementId"));
        Assert.Contains(Username, line.Properties.GetValueOrDefault("Detail")!, StringComparison.Ordinal);

        var correlationId = line.Properties.GetValueOrDefault("CorrelationId");

        Assert.False(string.IsNullOrEmpty(correlationId));
        Assert.Equal(correlationId, response.Headers.GetValues("X-Request-Id").Single());

        // The password is nowhere. It is the field this page is about, and the one a "log what they
        // sent" instinct reaches for first.
        Assert.DoesNotContain(
            server.Fixture.Logs.Events,
            e => e.Message.Contains("not the password", StringComparison.Ordinal)
                || e.Properties.Values.Any(v => v?.Contains("not the password", StringComparison.Ordinal) is true));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // No timing assertion is committed here, and that is a decision rather than an omission.
    //
    // A wall-clock comparison of the two failure paths was run by hand — at the shipped cost, and
    // again with the DummyHash call removed as a control. The numbers are in the commit message. It
    // is not committed as a test because the threshold that would catch a missing hash is tighter
    // than the noise floor of a shared runner, and a security test that fails for unrelated reasons
    // is a security test that someone disables.
    //
    // An_unknown_username_still_pays_for_a_password_hash asserts the same property deterministically:
    // the defence IS the extra hash, and the count is what a stopwatch would have been used to infer.
    // ─────────────────────────────────────────────────────────────────────────
}
