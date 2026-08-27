using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Federation;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Federation.Oidc;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Federated sign-in, end to end, against an OpenID Connect provider this suite hosts.
/// </summary>
/// <remarks>
/// <para>
/// There is no network access to Google here and this file does not want one. The upstream is a real
/// Kestrel host over TLS on loopback, reached through the shipped <c>UpstreamEndpointClient</c> - so
/// the address check, the redirect refusal, the byte cap and the timeouts are the production ones.
/// It is also the only way to produce the cases that matter: a live provider never sends a token
/// signed with the wrong key, or <c>alg: none</c>, or the wrong <c>iss</c>.
/// </para>
/// <para>
/// The happy path is here once. Everything else in this file is a refusal, because the refusals are
/// where a federated sign-in either is or is not an account takeover.
/// </para>
/// </remarks>
public sealed partial class ExternalLoginFlowTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>Cheap Argon2id parameters. This file is about wiring, not about hash strength.</summary>
    private static Argon2idParameters TestCost => new() { MemoryKiB = 64, Iterations = 1, Parallelism = 1 };

    private sealed record Server(
        FlowFixture Fixture, FakeUpstreamProvider Upstream, InMemoryUserStore Users) : IAsyncDisposable
    {
        public HttpClient Client => Fixture.Client;

        public async ValueTask DisposeAsync()
        {
            await Fixture.DisposeAsync();
            await Upstream.DisposeAsync();
        }
    }

    /// <summary>What a test wants the server and the upstream to start with.</summary>
    private sealed class Setup
    {
        /// <summary>What to do with an upstream identity nothing is linked to.</summary>
        public UnknownExternalIdentityPolicy UnknownIdentity { get; set; } = UnknownExternalIdentityPolicy.Refuse;

        /// <summary>Register a password hasher, so the page offers a password form too.</summary>
        public bool LocalPasswords { get; set; } = true;

        /// <summary>Discover the upstream's endpoints rather than configuring them.</summary>
        public bool Discover { get; set; } = true;

        /// <summary>Replace the shipped provider, for the availability tests.</summary>
        public IExternalIdentityProvider? Provider { get; set; }

        /// <summary>An audit store to register, for the tests that read what was recorded.</summary>
        /// <remarks>
        /// Absent by default, because the code treats it as optional: a deployment that registered
        /// none gets no record rather than a failed sign-in, and that is the shape most run.
        /// </remarks>
        public IAdminAuditStore? Audit { get; set; }

        /// <summary>Role definitions to store before the server starts.</summary>
        public IReadOnlyList<RoleDefinition>? Roles { get; set; }

        /// <summary>The deployment's default roles for new accounts, when it declares any.</summary>
        public AccountDefaults? Defaults { get; set; }


        /// <summary>Seed accounts and links before the server starts.</summary>
        public Func<InMemoryUserStore, FakeUpstreamProvider, Task>? Seed { get; set; }

        /// <summary>
        /// Extra middleware, for the tests that need to tamper with a pending request.
        /// </summary>
        /// <remarks>
        /// The return-URL gate inside <c>Resume</c> runs a second time on a value that was already
        /// gated when it was written, so no ordinary request can reach it with a bad value. Proving
        /// that second gate does anything means planting one, which needs a middleware.
        /// </remarks>
        public Action<IApplicationBuilder>? ConfigureApp { get; set; }
    }

    private static async Task<Server> StartAsync(Action<Setup>? configure = null)
    {
        var setup = new Setup();
        configure?.Invoke(setup);

        var upstream = await FakeUpstreamProvider.StartAsync();
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        foreach (var role in setup.Roles ?? [])
        {
            await roles.StoreAsync(role, CancellationToken.None);
        }

        if (setup.Seed is { } seed)
        {
            await seed(users, upstream);
        }

        var fixture = await FlowFixture.StartAsync(f =>
        {
            f.Client = Build.Client(ClientId, ClientType.Public);
            f.ScopeDescriptions["mcp:tools"] = "Use the tools this server provides";
            f.SignedInUser = null;

            f.ConfigureOptions = o => o.ExternalLogin.UnknownIdentity = setup.UnknownIdentity;

            f.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);

                if (setup.LocalPasswords)
                {
                    services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher(TestCost));
                }
                else
                {
                    // Removed rather than never added: the shared fixture registers the shipped
                    // hasher for every other suite in this assembly. A federation-only deployment is
                    // a host with no IPasswordHasher at all, and that is the shape being built here.
                    services.RemoveAll<IPasswordHasher>();
                }

                services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));

                if (setup.Audit is { } auditStore)
                {
                    services.AddSingleton(auditStore);
                }

                if (setup.Defaults is { } defaults)
                {
                    services.AddSingleton(defaults);
                }

                // Registered before AddExternalIdentityProvider, whose registration is TryAdd - so
                // this one wins and every outbound request in this suite goes to the fake upstream
                // through an injected resolver rather than to DNS.
                services.AddSingleton<IUpstreamEndpointClient>(new UpstreamEndpointClient(
                    FakeUpstreamProvider.TransportOptions(),
                    FakeUpstreamProvider.Resolver,
                    TimeProvider.System));

                if (setup.Provider is { } provider)
                {
                    services.AddSingleton(provider);
                }
                else
                {
                    services.AddExternalIdentityProvider(upstream.Options(setup.Discover));
                }

                services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie(o =>
                    {
                        o.Cookie.Name = "__Host-boltway-session";
                        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                        o.Cookie.HttpOnly = true;
                        o.Cookie.SameSite = SameSiteMode.Lax;
                    });

                services.AddHttpContextAccessor();
                services.AddScoped<IUserSession, CookieUserSession>();
            };

            // Composed, not assigned. This line used to overwrite whatever a test had set, so a
            // Setup.ConfigureApp silently did nothing and its tests 404'd on their own middleware.
            f.ConfigureApp = app =>
            {
                app.UseAuthentication();
                setup.ConfigureApp?.Invoke(app);
            };
        });

        return new Server(fixture, upstream, users);
    }

    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [GeneratedRegex("name=\"returnUrl\" value=\"([^\"]+)\"")]
    private static partial Regex ReturnUrlField();

    private static string AuthorizeUrl() =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(ClientId)
        + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri)
        + "&code_challenge=" + Verifier.ComputeS256Challenge()
        + "&code_challenge_method=S256"
        + "&scope=" + Uri.EscapeDataString("mcp:tools offline_access")
        + "&resource=" + Uri.EscapeDataString(Build.Resource)
        + "&state=opaque-state";

    /// <summary>The upstream authorization request the server composed, and what it committed to.</summary>
    private sealed record Challenge(string Location, string State, string Nonce, string CodeChallenge, string RedirectUri);

    /// <summary>
    /// Walk from an anonymous <c>/authorize</c> to the redirect that leaves for the upstream.
    /// </summary>
    /// <remarks>
    /// It goes through the real login page and posts the real form, rather than calling
    /// <c>/external/google/start</c> directly, because the page offering the method is half of what
    /// is under test - a start endpoint nobody can reach from the sign-in page is not a feature.
    /// </remarks>
    /// <summary>
    /// Signing in with a provider works from a sign-in page reached by hand.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This endpoint gated the sign-in intent on <c>returnUrl</c> being <c>/authorize</c>, with a
    /// comment saying that was "the same rule POST /login follows". It had not been the same rule
    /// since <c>/login</c> learned to resume the self-service pages, and the comment claiming they
    /// agreed is what kept the drift invisible.
    /// </para>
    /// <para>
    /// It became reachable the moment a bare <c>GET /login</c> started defaulting its
    /// <c>returnUrl</c> to <c>/me</c>: the page then rendered a provider button whose own endpoint
    /// answered <c>400</c>, so "sign in with Google" from a hand-typed <c>/login</c> was an error
    /// page. Measured on the running deployment, by pressing it.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("/me")]
    [InlineData("/me/password")]
    [InlineData("/me/sessions")]
    [InlineData("/me/consents")]
    public async Task A_sign_in_may_return_anywhere_the_sign_in_page_may_return(string returnUrl)
    {
        await using var server = await StartAsync();

        var response = await StartWithReturnUrlAsync(server, returnUrl);

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.StartsWith(server.Upstream.Issuer, response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// And nowhere else - the list is the gate, not a suggestion.
    /// </summary>
    /// <remarks>
    /// The half that must not move. This endpoint is reached from the page a password is typed on,
    /// so a <c>returnUrl</c> naming somewhere off this origin would make it a redirector on exactly
    /// the origin a user has been taught to trust.
    /// </remarks>
    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    [InlineData("/admin/users")]
    [InlineData("")]
    public async Task A_sign_in_may_not_return_anywhere_else(string returnUrl)
    {
        await using var server = await StartAsync();

        var response = await StartWithReturnUrlAsync(server, returnUrl);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>Post the provider form with a chosen <c>returnUrl</c>, as a browser would.</summary>
    private static async Task<HttpResponseMessage> StartWithReturnUrlAsync(Server server, string returnUrl)
    {
        var page = await server.Client.GetStringAsync("/login?returnUrl=" + Uri.EscapeDataString("/me"));
        var token = AntiforgeryField().Match(page);

        Assert.True(token.Success, "the sign-in page rendered no antiforgery field");

        return await server.Client.PostAsync(
            "/external/google/start",
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, token.Groups[2].Value),
                new("returnUrl", returnUrl),
            ]));
    }

    /// <summary>
    /// A page offering a provider names that provider in <c>form-action</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The defect this closes was invisible to every check that existed. The button is a form that
    /// posts same-origin and is answered <c>303</c> to the upstream, and Chrome and Safari apply
    /// <c>form-action</c> to the redirect a submission follows - so under the shipped
    /// <c>form-action 'self'</c> the browser refused the navigation and reported nothing. Measured
    /// on a running deployment by pressing "Link Google" and watching the page not move; every
    /// <c>curl</c> check of the same flow passed, because <c>curl</c> does not enforce CSP.
    /// </para>
    /// <para>
    /// Asserted on the header rather than on the markup, because the markup was never wrong.
    /// </para>
    /// <para>
    /// <b>The account page is not covered here and calls the same two methods.</b> Asserting on it
    /// needs a real cookie - this suite registers <c>CookieUserSession</c>, so a seeded session is
    /// not read - and the plumbing to sign in with a password first is more than the one line it
    /// would be checking. Named rather than left as an absence somebody has to notice.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_sign_in_page_names_the_provider_in_form_action()
    {
        await using var server = await StartAsync();

        var page = await server.Client.GetAsync("/login?returnUrl=" + Uri.EscapeDataString("/me"));

        Assert.Contains(
            server.Upstream.Issuer,
            string.Join(' ', page.Headers.GetValues("Content-Security-Policy")),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The policy still names the provider when discovery has not answered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The back door into the defect the widening exists to close. Discovery is a network fetch
    /// behind a cache, so a container's first render - or any render after the cache expires and
    /// the fetch fails - would answer null and ship the strict policy, and the button would go back
    /// to silently doing nothing while every page and redirect stayed correct.
    /// </para>
    /// <para>
    /// The fixture's upstream is configured with its endpoints rather than discovered, and this
    /// asks for the one case that has no endpoints to configure: discovery on, and the upstream
    /// refusing to serve it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_policy_names_the_provider_even_when_discovery_fails()
    {
        await using var server = await StartAsync(s => s.Discover = true);

        server.Upstream.Behaviour.DiscoveryUnavailable = true;

        var page = await server.Client.GetAsync("/login?returnUrl=" + Uri.EscapeDataString("/me"));

        Assert.Contains(
            server.Upstream.Issuer,
            string.Join(' ', page.Headers.GetValues("Content-Security-Policy")),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A federated sign-in begun from a hand-typed sign-in page lands back on the account page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The gate on this <c>returnUrl</c> runs twice - once when the round trip starts and once when
    /// it comes back, deliberately, because "validated when it was written" is a claim about a
    /// request that is over. Widening the first and leaving the second is what shipped: the user was
    /// allowed to leave, authenticated at Google, came back, <b>was signed in</b>, and then got
    /// "this page was opened without a valid authorization request".
    /// </para>
    /// <para>
    /// The worst shape a refusal can have - the side effect happened and the page says nothing did,
    /// because <c>SignInAsync</c> runs before <c>Resume</c>. Measured on the running deployment; the
    /// cookie was set and the browser was on an error page.
    /// </para>
    /// <para>
    /// It survived the fix to the first gate because the test written with it stopped at the
    /// redirect <i>to</i> the upstream. This one walks the whole round trip, which is the only shape
    /// that could have caught it.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("/me")]
    [InlineData("/me/sessions")]
    public async Task A_federated_sign_in_returns_to_the_page_it_started_from(string returnUrl)
    {
        var subject = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0BB");

        await using var server = await StartAsync(s =>
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user"));

        var challenge = await BeginWithReturnUrlAsync(server, returnUrl);

        Assert.NotNull(challenge);

        var callback = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.Equal(returnUrl, callback.Headers.Location!.ToString());
    }

    /// <summary>And the gate on the way back is still a gate.</summary>
    /// <remarks>
    /// The pending record is written into an authenticated cookie, so no ordinary request reaches
    /// this with a bad value - which is exactly why the second check has to be proved rather than
    /// assumed. <c>ConfigureApp</c> is how the suite plants one.
    /// </remarks>
    [Fact]
    public async Task A_federated_sign_in_may_not_return_off_the_allowed_list()
    {
        var subject = SubjectId.FromStorage("01J8XKQ7M3N4P5R6S7T8V9W0CC");

        await using var server = await StartAsync(s =>
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user"));

        var challenge = await BeginWithReturnUrlAsync(server, "/admin/users");

        // Refused at the start, so the round trip never happens - the same list, both ends.
        Assert.Null(challenge);
    }

    /// <summary>Start a federated sign-in with a chosen <c>returnUrl</c>, or null when refused.</summary>
    private static async Task<Challenge?> BeginWithReturnUrlAsync(Server server, string returnUrl)
    {
        var page = await server.Client.GetStringAsync("/login?returnUrl=" + Uri.EscapeDataString("/me"));
        var token = AntiforgeryField().Match(page);

        Assert.True(token.Success, "the sign-in page rendered no antiforgery field");

        var response = await server.Client.PostAsync(
            "/external/google/start",
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, token.Groups[2].Value),
                new("returnUrl", returnUrl),
            ]));

        if (response.StatusCode is not HttpStatusCode.SeeOther)
        {
            return null;
        }

        var location = response.Headers.Location!.ToString();
        var query = HttpUtility.ParseQueryString(new Uri(location).Query);

        return new Challenge(
            location, query["state"]!, query["nonce"]!, query["code_challenge"]!, query["redirect_uri"]!);
    }

    /// <summary>
    /// Attaching an upstream identity leaves a record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Linking adds a credential that signs in forever, and it recorded nothing - while changing a
    /// password, asking for a reset link and verifying an address all did. Noticed when a user
    /// linked Google, the page said nothing, and there was nowhere to look to find out whether it
    /// had happened.
    /// </para>
    /// <para>
    /// The detail carries the upstream issuer and subject because "which Google account" is the
    /// question people ask, and an operator cannot otherwise tell one link from a second one made a
    /// minute later. Neither is a credential: reaching this code requires the upstream to have
    /// signed a token for that subject.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Linking_records_which_identity_was_attached()
    {
        const string Password = "correct horse battery staple";

        var hasher = new Argon2idPasswordHasher(TestCost);
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();
        var audit = new InMemoryAdminAuditStore();

        await using var server = await StartAsync(s =>
        {
            s.Audit = audit;
            s.Seed = async (users, _) => await users.StoreAsync(
                new UserAccount(subject, "ada", "ada@example.com", EmailVerified: true, hasher.Hash(Password)),
                CancellationToken.None);
        });

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var loginPage = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(loginPage);
        var returnUrl = ReturnUrlField().Match(loginPage);

        var signedIn = await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("username", "ada"),
            new("password", Password),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);

        var linkPage = await server.Client.GetStringAsync(
            "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));
        var linkToken = AntiforgeryField().Match(linkPage);

        var began = await server.Client.PostAsync("/external/google/link", new FormUrlEncodedContent(
        [
            new(linkToken.Groups[1].Value, linkToken.Groups[2].Value),
            new("returnUrl", "/me"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, began.StatusCode);

        var location = began.Headers.Location!.ToString();
        var query = HttpUtility.ParseQueryString(new Uri(location).Query);

        Assert.Equal(
            HttpStatusCode.SeeOther,
            (await CallbackAsync(server, new Challenge(
                location, query["state"]!, query["nonce"]!, query["code_challenge"]!, query["redirect_uri"]!)))
                .StatusCode);

        var entries = await audit.ReadAsync(new AuditQuery(), CancellationToken.None);
        var entry = Assert.Single(
            entries, e => string.Equals(e.Action, "user.external.link", StringComparison.Ordinal));

        Assert.Equal(subject.Value, entry.TargetSubject?.Value);
        Assert.Equal(AdminAuditOutcome.Succeeded, entry.Outcome);
        Assert.Contains(server.Upstream.Issuer, entry.Detail!, StringComparison.Ordinal);
        Assert.Contains(server.Upstream.Behaviour.Subject, entry.Detail!, StringComparison.Ordinal);
    }

    private static async Task<Challenge> BeginAsync(Server server, string? path = null)
    {
        var start = await server.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);

        var loginUrl = start.Headers.Location!.ToString();
        var page = await server.Client.GetStringAsync(loginUrl);

        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        Assert.True(token.Success, "the sign-in page rendered no antiforgery field");
        Assert.True(returnUrl.Success, "the sign-in page rendered no returnUrl field");

        var response = await server.Client.PostAsync(
            path ?? "/external/google/start",
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, token.Groups[2].Value),
                new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            ]));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var location = response.Headers.Location!.ToString();
        var query = HttpUtility.ParseQueryString(new Uri(location).Query);

        return new Challenge(
            location,
            query["state"]!,
            query["nonce"]!,
            query["code_challenge"]!,
            query["redirect_uri"]!);
    }

    /// <summary>Tell the upstream what the server committed to, then drive the callback.</summary>
    private static async Task<HttpResponseMessage> CallbackAsync(
        Server server, Challenge challenge, string? state = null, string query = "code=upstream-code")
    {
        server.Upstream.Behaviour.Nonce ??= challenge.Nonce;
        server.Upstream.Behaviour.ExpectedCodeChallenge ??= challenge.CodeChallenge;
        server.Upstream.Behaviour.ExpectedRedirectUri ??= challenge.RedirectUri;

        return await server.Client.GetAsync(
            "/external/google/callback?" + query
            + "&state=" + Uri.EscapeDataString(state ?? challenge.State));
    }

    private static async Task LinkAsync(
        InMemoryUserStore users, FakeUpstreamProvider upstream, SubjectId subject, string username)
    {
        await users.StoreAsync(
            new UserAccount(subject, username, null, EmailVerified: false, PasswordHash: null),
            CancellationToken.None);

        await users.LinkExternalLoginAsync(
            new ExternalLogin(upstream.Issuer, upstream.Behaviour.Subject, subject), CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // the whole flow
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// An anonymous browser signs in through the upstream and completes the authorization.
    /// </summary>
    /// <remarks>
    /// The path a real user takes: <c>/authorize</c> with no session, the sign-in page, the form
    /// that leaves for the upstream, the callback, the consent page, and a token. The upstream
    /// enforces PKCE and the exact <c>redirect_uri</c> at its token endpoint, so a defect in either
    /// fails here rather than being asserted about separately.
    /// </remarks>
    [Fact]
    public async Task An_anonymous_browser_signs_in_through_the_upstream_and_gets_a_token()
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user"));

        var challenge = await BeginAsync(server);

        // The upstream authorization request is a correct OAuth 2.1 one, and every rule this server
        // enforces on its own clients is on it.
        var query = HttpUtility.ParseQueryString(new Uri(challenge.Location).Query);

        Assert.StartsWith(server.Upstream.Issuer + "/authorize?", challenge.Location, StringComparison.Ordinal);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal(server.Upstream.ClientId, query["client_id"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("openid", query["scope"]);
        Assert.Equal(Build.Issuer + "/external/google/callback", query["redirect_uri"]);
        Assert.NotEqual(challenge.State, challenge.Nonce);
        Assert.True(challenge.State.Length >= 43, "state is not 256 bits of base64url");
        Assert.True(challenge.Nonce.Length >= 43, "nonce is not 256 bits of base64url");

        var callback = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.StartsWith("/authorize?", callback.Headers.Location!.ToString(), StringComparison.Ordinal);

        // The exchange really happened, and it carried the credential the way the options said.
        var exchange = Assert.Single(server.Upstream.TokenRequests);

        Assert.Equal("authorization_code", exchange["grant_type"]);
        Assert.Equal("upstream-code", exchange["code"]);
        Assert.Equal(server.Upstream.ClientId, exchange["client_id"]);
        Assert.Equal(server.Upstream.ClientSecret, exchange["client_secret"]);

        // ── and the authorization completes as it would after a password sign-in.
        var afterLogin = await server.Client.GetAsync(callback.Headers.Location!.ToString());

        Assert.Equal(HttpStatusCode.SeeOther, afterLogin.StatusCode);

        var consentPage = await server.Client.GetStringAsync(afterLogin.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(consentPage);
        var returnUrl = ReturnUrlField().Match(consentPage);

        var approved = await server.Client.PostAsync("/consent", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("decision", "approve"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);

        var code = HttpUtility.ParseQueryString(
            new Uri(approved.Headers.Location!.ToString()).Query)["code"];

        var tokens = await server.Client.PostAsync("/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code!),
            new("client_id", ClientId),
            new("code_verifier", Verifier.Value),
        ]));

        Assert.Equal(HttpStatusCode.OK, tokens.StatusCode);

        // The `sub` in the token is the ULID this server minted, never the upstream's subject. D-10.
        using var body = System.Text.Json.JsonDocument.Parse(await tokens.Content.ReadAsStringAsync());
        var accessToken = body.RootElement.GetProperty("access_token").GetString()!;
        var payload = System.Text.Json.JsonDocument.Parse(
            Decode(accessToken.Split('.')[1]));

        Assert.Equal(subject.Value, payload.RootElement.GetProperty("sub").GetString());
        Assert.DoesNotContain(
            server.Upstream.Behaviour.Subject, accessToken, StringComparison.Ordinal);
    }

    private static byte[] Decode(string base64Url) =>
        OAuth.Primitives.Encoding.Base64Url.TryDecode(base64Url, out var bytes)
            ? bytes
            : throw new InvalidOperationException("not base64url");

    /// <summary>The endpoints can be configured outright, and then nothing fetches discovery.</summary>
    /// <remarks>
    /// The control for the discovery path: with all three configured, the discovery counter stays at
    /// zero, which is what an air-gapped or tightly-egressed deployment is buying.
    /// </remarks>
    [Fact]
    public async Task Configured_endpoints_mean_no_discovery_request_is_ever_made()
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
        {
            s.Discover = false;
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user");
        });

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.Equal(0, server.Upstream.DiscoveryFetches);
        Assert.Equal(1, server.Upstream.JwksFetches);
    }

    /// <summary>Discovery is used, and the document's issuer is checked against the configured one.</summary>
    [Fact]
    public async Task A_discovery_document_naming_another_issuer_is_refused()
    {
        await using var server = await StartAsync();

        server.Upstream.Behaviour.ForcedDiscoveryIssuer = "https://elsewhere.example";

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());

        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        var response = await server.Client.PostAsync("/external/google/start", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
        ]));

        // Refused before the browser goes anywhere, because the document names the endpoints this
        // server is about to send a credential to.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertRejected(server, "ExternalProviderUnavailable");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // the ID token
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every way an ID token can be wrong is refused, and none of them signs anybody in.
    /// </summary>
    /// <remarks>
    /// One test over a table rather than one test each, so a regression reports the whole list. Each
    /// row is a mutation of a token that is otherwise valid and would sign the user in - the happy
    /// path above is the control that says so.
    /// </remarks>
    [Theory]
    [InlineData("wrong signing key", "ExternalIdentityTokenRejected")]
    [InlineData("alg none", "ExternalIdentityTokenRejected")]
    [InlineData("wrong issuer", "ExternalIdentityTokenRejected")]
    [InlineData("wrong audience", "ExternalIdentityTokenRejected")]
    [InlineData("expired", "ExternalIdentityTokenRejected")]
    [InlineData("no subject", "ExternalIdentityTokenRejected")]
    [InlineData("no nonce", "ExternalNonceMismatch")]
    [InlineData("another session's nonce", "ExternalNonceMismatch")]
    [InlineData("no id token", "ExternalIdentityTokenMissing")]
    [InlineData("token endpoint refuses", "ExternalTokenExchangeFailed")]
    public async Task A_bad_upstream_response_is_refused_and_signs_nobody_in(string mutation, string reason)
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user"));

        var challenge = await BeginAsync(server);
        var behaviour = server.Upstream.Behaviour;

        switch (mutation)
        {
            case "wrong signing key": behaviour.SignWithWrongKey = true; break;
            case "alg none": behaviour.UseAlgNone = true; break;
            case "wrong issuer": behaviour.ForcedIssuer = "https://elsewhere.example"; break;
            case "wrong audience": behaviour.ForcedAudience = "some-other-client"; break;
            case "expired": behaviour.Expired = true; break;
            case "no subject": behaviour.OmitSubject = true; break;
            case "no nonce": behaviour.OmitNonce = true; break;
            case "another session's nonce": behaviour.Nonce = "a-nonce-from-another-browser"; break;
            case "no id token": behaviour.OmitIdToken = true; break;
            case "token endpoint refuses": behaviour.TokenEndpointStatus = 400; break;
            default: throw new InvalidOperationException(mutation);
        }

        var callback = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, reason);

        // No session was established: /authorize still sends the browser to sign in.
        var after = await server.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, after.StatusCode);
        Assert.StartsWith("/login?", after.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // state, and the pending request
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_callback_with_no_state_is_refused()
    {
        await using var server = await StartAsync();

        var challenge = await BeginAsync(server);
        var callback = await server.Client.GetAsync("/external/google/callback?code=upstream-code");

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalStateMismatch");
        Assert.Empty(server.Upstream.TokenRequests);
    }

    [Fact]
    public async Task A_callback_carrying_another_browsers_state_is_refused()
    {
        // Two servers so there are genuinely two browsers: each fixture has its own cookie jar, and
        // the pending request is bound to the cookie rather than to anything the upstream returns.
        await using var mine = await StartAsync();
        await using var theirs = await StartAsync();

        var mineChallenge = await BeginAsync(mine);
        var theirsChallenge = await BeginAsync(theirs);

        Assert.NotEqual(mineChallenge.State, theirsChallenge.State);

        var callback = await CallbackAsync(mine, mineChallenge, state: theirsChallenge.State);

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(mine, "ExternalStateMismatch");
        Assert.Empty(mine.Upstream.TokenRequests);
    }

    [Fact]
    public async Task A_replayed_callback_finds_no_pending_request()
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user"));

        var challenge = await BeginAsync(server);

        Assert.Equal(HttpStatusCode.SeeOther, (await CallbackAsync(server, challenge)).StatusCode);

        // The same URL again. The cookie was deleted when it was read, so `state` has nothing to be
        // compared against - which is what makes a captured callback worth exactly one use.
        var replay = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        AssertRejected(server, "ExternalPendingRequestMissing");
    }

    [Fact]
    public async Task A_callback_with_no_cookie_at_all_is_refused()
    {
        await using var server = await StartAsync();

        var challenge = await BeginAsync(server);

        // A fresh client is a fresh browser: it holds no pending request, and the `state` it
        // presents is a real one taken from somewhere else.
        using var stranger = server.Fixture.NewClient();

        var callback = await stranger.GetAsync(
            "/external/google/callback?code=upstream-code&state=" + Uri.EscapeDataString(challenge.State));

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalPendingRequestMissing");
    }

    [Fact]
    public async Task An_upstream_error_is_reported_and_no_code_is_exchanged()
    {
        await using var server = await StartAsync();

        var challenge = await BeginAsync(server);

        var callback = await CallbackAsync(
            server, challenge, query: "error=access_denied&error_description=user+cancelled");

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalAuthorizationDenied");
        Assert.Empty(server.Upstream.TokenRequests);
    }

    [Fact]
    public async Task An_error_on_an_unbound_callback_is_refused_as_a_state_mismatch()
    {
        // The ordering that matters: `state` is checked before `error` is read. An error on a
        // callback nothing is bound to is anybody's error, and acting on it would let a stranger
        // choose what this endpoint renders.
        await using var server = await StartAsync();

        _ = await BeginAsync(server);

        var callback = await server.Client.GetAsync(
            "/external/google/callback?error=access_denied&state=not-the-one");

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalStateMismatch");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // account resolution
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_unlinked_identity_is_refused_by_default()
    {
        await using var server = await StartAsync();

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalIdentityUnlinked");
    }

    /// <summary>
    /// A matching email address does <b>not</b> reach an existing account.
    /// </summary>
    /// <remarks>
    /// The classic federated account takeover, asserted directly: an upstream asserts the victim's
    /// address, and the attacker gets their own new account rather than the victim's. Note that
    /// <c>email_verified</c> is <see langword="true"/> here - the upstream says so, which is exactly
    /// the claim that is not evidence.
    /// </remarks>
    [Fact]
    public async Task An_upstream_identity_with_a_local_accounts_email_never_reaches_that_account()
    {
        var victim = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
        {
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision;

            // The victim's username *is* their email address, which is how most deployments look.
            // That is deliberate: it means the only lookup this store offers that could reach them -
            // FindByUsernameAsync - would find them if anything on this path called it with the
            // email claim. Nothing does, and this test is what says so.
            s.Seed = async (users, _) => await users.StoreAsync(
                new UserAccount(
                    victim, "victim@example.com", "victim@example.com", EmailVerified: true, PasswordHash: "x"),
                CancellationToken.None);
        });

        server.Upstream.Behaviour.Email = "victim@example.com";
        server.Upstream.Behaviour.EmailVerified = true;
        server.Upstream.Behaviour.Subject = "attacker-at-upstream";

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);

        var provisioned = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, "attacker-at-upstream", CancellationToken.None);

        Assert.NotNull(provisioned);
        Assert.NotEqual(victim.Value, provisioned!.Subject.Value);

        // The victim's account is untouched and still has its password.
        var untouched = await server.Users.FindBySubjectAsync(victim, CancellationToken.None);

        Assert.Equal("x", untouched!.PasswordHash);
        Assert.Equal("victim@example.com", untouched.Email);

        // And the provisioned account carries the same email address without that meaning anything.
        // The value is copied for the `email` claim; nothing resolves an account by it.
        Assert.Equal("victim@example.com", provisioned.Email);
    }

    /// <summary>
    /// The only way to look an account up by address requires the address to be verified.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test used to assert that <c>IUserStore</c> had <b>no</b> email lookup at all, on the
    /// reasoning that an absent method cannot be called from anywhere - the structural half of the
    /// account-linking argument, and the stronger half. It was right for as long as it held.
    /// </para>
    /// <para>
    /// It stopped holding when signing in with a verified address became a feature, because the
    /// sign-in form needs precisely the lookup federation must not have. Measured, before that
    /// existed: <c>/forgot</c> accepted an address, <c>/login</c> did not, and somebody who reset
    /// their password by email could not then use it to sign in.
    /// </para>
    /// <para>
    /// <b>So the absence rule became an allowlist of one, and the real guard moved to the call
    /// site</b> - <c>StructuralRuleTests.Only_the_sign_in_form_resolves_an_account_by_address</c>,
    /// which names who may call it and fails if federation ever does. That is the narrower claim and
    /// the one that was always the point: the attack is an attacker registering the victim's address
    /// at an upstream that does not verify it and being handed the account, and what prevents it is
    /// that no federation path resolves anything by address.
    /// </para>
    /// <para>
    /// What stays here is the half a call-site rule cannot state: any <i>new</i> email lookup on
    /// this interface is a violation, whatever calls it, because a lookup that does not require
    /// verification is the takeover regardless of who is holding it.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_only_lookup_by_address_is_the_one_that_requires_verification()
    {
        var lookups = typeof(IUserStore).GetMethods()
            .Where(m => m.Name.StartsWith("Find", StringComparison.Ordinal))
            .ToList();

        // The control. A prefix that stopped matching would leave an empty list and report a pass,
        // which is the one way an absence assertion fails silently.
        Assert.Contains(lookups, m => m.Name == "FindBySubjectAsync");

        var byEmail = lookups
            .Where(m => m.Name.Contains("Email", StringComparison.OrdinalIgnoreCase)
                && !m.Name.Contains("ExternalLogin", StringComparison.Ordinal))
            .Select(m => m.Name)
            .ToList();

        // Named, not counted. "At most one" would be satisfied by replacing the verified lookup
        // with an unverified one, which is the takeover with the same arity.
        Assert.Equal(["FindByVerifiedEmailAsync"], byEmail);

        // And the one that exists says so in its name. A lookup called FindByEmailAsync could not
        // be told apart from this one by any rule written here, which is why the name carries the
        // condition rather than only the documentation.
        Assert.Contains(
            lookups,
            m => string.Equals(m.Name, "FindByVerifiedEmailAsync", StringComparison.Ordinal));

        // The control: the reflection actually sees this interface's methods.
        Assert.Contains(
            typeof(IUserStore).GetMethods(),
            m => string.Equals(m.Name, "FindByExternalLoginAsync", StringComparison.Ordinal));
    }

    /// <summary>
    /// A callback for one scheme cannot complete a round trip started with another.
    /// </summary>
    /// <remarks>
    /// It costs nothing today, with one provider registered, and it is the check that stops being
    /// free the moment a second one is. Without it, a pending request minted for provider A could be
    /// completed at provider B's callback - and B would validate a token from B against a
    /// <c>nonce</c> A issued, which succeeds.
    /// </remarks>
    [Fact]
    public async Task A_callback_at_another_providers_scheme_is_refused()
    {
        await using var server = await StartAsync();

        var challenge = await BeginAsync(server);

        var callback = await server.Client.GetAsync(
            "/external/facebook/callback?code=upstream-code&state=" + Uri.EscapeDataString(challenge.State));

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalStateMismatch");
        Assert.Empty(server.Upstream.TokenRequests);
    }

    [Fact]
    public async Task Provisioning_mints_a_ulid_subject_and_no_password()
    {
        await using var server = await StartAsync(s => s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision);

        server.Upstream.Behaviour.Email = "new@example.com";

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);

        var account = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, server.Upstream.Behaviour.Subject, CancellationToken.None);

        Assert.NotNull(account);
        Assert.True(Ulid.IsWellFormed(account!.Subject.Value), account.Subject.Value);
        Assert.Null(account.PasswordHash);
        Assert.Equal("new@example.com", account.Email);
        Assert.True(account.EmailVerified);

        // No defaults declared, so nothing was assigned - the pin for the pair of tests below.
        Assert.Empty(account.Roles);
    }

    /// <summary>
    /// A deployment that declares default roles gives them to every provisioned account.
    /// </summary>
    /// <remarks>
    /// The other half of AccountDefaults: `CreateAsync` fills the role its caller did not name, and
    /// a provisioned account has no caller at all - so without this, turning provisioning on had
    /// every sign-up land on the floor while DEFAULT_ROLES said otherwise.
    /// </remarks>
    [Fact]
    public async Task A_provisioned_account_holds_the_deployments_default_roles()
    {
        var audit = new InMemoryAdminAuditStore();

        await using var server = await StartAsync(s =>
        {
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision;
            s.Roles = [new RoleDefinition("member", "member", [])];
            s.Defaults = new AccountDefaults(["member"]);
            s.Audit = audit;
        });

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);

        var account = await server.Users.FindByExternalLoginAsync(
            RealmId.Default, server.Upstream.Issuer, server.Upstream.Behaviour.Subject,
            CancellationToken.None);

        Assert.Equal(["member"], account!.Roles);

        // The trail says the deployment chose, the same marker CreateAsync writes.
        var entries = await audit.ReadAsync(new AuditQuery(), CancellationToken.None);
        var provisioned = Assert.Single(entries, e => e.Action == "user.external.provision");
        Assert.Contains("role=member (defaulted)", provisioned.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A default naming a role nothing defines costs the account the assignment, never the person
    /// their sign-in.
    /// </summary>
    /// <remarks>
    /// The caller here is a stranger mid-OAuth who can fix nothing, so the failure lands where it
    /// can be acted on - an error log naming the role - and the account proceeds holding nothing,
    /// which is the floor and the direction this tree already fails in.
    /// </remarks>
    [Fact]
    public async Task A_default_naming_no_definition_still_signs_the_person_in()
    {
        await using var server = await StartAsync(s =>
        {
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision;
            s.Defaults = new AccountDefaults(["ghost"]);
        });

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);

        var account = await server.Users.FindByExternalLoginAsync(
            RealmId.Default, server.Upstream.Issuer, server.Upstream.Behaviour.Subject,
            CancellationToken.None);

        Assert.NotNull(account);
        Assert.Empty(account!.Roles);
    }

    [Fact]
    public async Task A_disabled_linked_account_cannot_sign_in()
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s => s.Seed = async (users, upstream) =>
        {
            await users.StoreAsync(
                new UserAccount(
                    subject, "disabled-user", null, EmailVerified: false, PasswordHash: null,
                    DisabledAt: DateTimeOffset.UnixEpoch),
                CancellationToken.None);

            await users.LinkExternalLoginAsync(
                new ExternalLogin(upstream.Issuer, upstream.Behaviour.Subject, subject), CancellationToken.None);
        });

        var callback = await CallbackAsync(server, await BeginAsync(server));

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalAccountDisabled");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // linking
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Linking_requires_a_session_and_attaches_the_identity_to_it()
    {
        const string Password = "correct horse battery staple";

        var hasher = new Argon2idPasswordHasher(TestCost);
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s => s.Seed = async (users, _) => await users.StoreAsync(
            new UserAccount(subject, "ada", "ada@example.com", EmailVerified: true, hasher.Hash(Password)),
            CancellationToken.None));

        // Sign in with the password first - that is the whole point of the link flow, and the
        // condition that makes it safe where matching on email is not.
        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        var signedIn = await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("username", "ada"),
            new("password", Password),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);

        // Now link, from a page the account is signed in to. The link flow may return to any local
        // path, because it is started from the customer's own application rather than from an
        // authorization request.
        var linkPage = await server.Client.GetStringAsync(
            "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));
        var linkToken = AntiforgeryField().Match(linkPage);

        var began = await server.Client.PostAsync("/external/google/link", new FormUrlEncodedContent(
        [
            new(linkToken.Groups[1].Value, linkToken.Groups[2].Value),
            new("returnUrl", "/error"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, began.StatusCode);

        var query = HttpUtility.ParseQueryString(new Uri(began.Headers.Location!.ToString()).Query);
        var challenge = new Challenge(
            began.Headers.Location!.ToString(),
            query["state"]!,
            query["nonce"]!,
            query["code_challenge"]!,
            query["redirect_uri"]!);

        var callback = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.Equal("/error", callback.Headers.Location!.ToString());

        var linked = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, server.Upstream.Behaviour.Subject, CancellationToken.None);

        Assert.Equal(subject.Value, linked!.Subject.Value);
    }

    [Fact]
    public async Task Linking_without_a_session_is_refused_before_the_browser_leaves()
    {
        await using var server = await StartAsync();

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);

        var response = await server.Client.PostAsync("/external/google/link", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", "/error"),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertRejected(server, "ExternalLinkRequiresSession");
    }

    /// <summary>
    /// An upstream identity already linked elsewhere is refused rather than re-pointed.
    /// </summary>
    /// <remarks>
    /// Moving a link is how whoever controls an upstream subject lands the next federated sign-in
    /// inside somebody else's data, so the answer is a refusal even though the person driving the
    /// browser is authenticated as the target account.
    /// </remarks>
    [Fact]
    public async Task Linking_an_identity_that_belongs_to_another_account_is_refused()
    {
        const string Password = "correct horse battery staple";

        var hasher = new Argon2idPasswordHasher(TestCost);
        var mine = new UlidSubjectIdFactory(TimeProvider.System).Mint();
        var theirs = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s => s.Seed = async (users, upstream) =>
        {
            await users.StoreAsync(
                new UserAccount(mine, "ada", null, EmailVerified: false, hasher.Hash(Password)),
                CancellationToken.None);

            await users.StoreAsync(
                new UserAccount(theirs, "grace", null, EmailVerified: false, PasswordHash: null),
                CancellationToken.None);

            await users.LinkExternalLoginAsync(
                new ExternalLogin(upstream.Issuer, upstream.Behaviour.Subject, theirs), CancellationToken.None);
        });

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("username", "ada"),
            new("password", Password),
        ]));

        var linkPage = await server.Client.GetStringAsync(
            "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));
        var linkToken = AntiforgeryField().Match(linkPage);

        var began = await server.Client.PostAsync("/external/google/link", new FormUrlEncodedContent(
        [
            new(linkToken.Groups[1].Value, linkToken.Groups[2].Value),
            new("returnUrl", "/error"),
        ]));

        var query = HttpUtility.ParseQueryString(new Uri(began.Headers.Location!.ToString()).Query);

        var callback = await CallbackAsync(
            server,
            new Challenge(
                began.Headers.Location!.ToString(),
                query["state"]!,
                query["nonce"]!,
                query["code_challenge"]!,
                query["redirect_uri"]!));

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalIdentityLinkedElsewhere");

        // Still theirs.
        var linked = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, server.Upstream.Behaviour.Subject, CancellationToken.None);

        Assert.Equal(theirs.Value, linked!.Subject.Value);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // the redirect surface
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_start_with_a_foreign_return_url_is_refused()
    {
        await using var server = await StartAsync();

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);

        var response = await server.Client.PostAsync("/external/google/start", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", "https://evil.example/authorize"),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("evil.example", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        AssertRejected(server, "ReturnUrlInvalid");
    }

    [Fact]
    public async Task A_start_without_an_antiforgery_token_is_refused()
    {
        await using var server = await StartAsync();

        var response = await server.Client.PostAsync("/external/google/start", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>("returnUrl", AuthorizeUrl())]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertRejected(server, "AntiforgeryTokenInvalid");
    }

    /// <summary>
    /// Nothing the upstream sends can steer the final redirect.
    /// </summary>
    /// <remarks>
    /// The open-redirect question, asked directly. The callback is handed every parameter an attacker
    /// might hope is a redirect target, and the browser still goes to the local URL from the cookie.
    /// </remarks>
    [Fact]
    public async Task The_upstream_cannot_choose_where_the_browser_goes_next()
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user"));

        var challenge = await BeginAsync(server);

        var callback = await CallbackAsync(
            server,
            challenge,
            query: "code=upstream-code"
                + "&returnUrl=" + Uri.EscapeDataString("https://evil.example/")
                + "&redirect_uri=" + Uri.EscapeDataString("https://evil.example/")
                + "&next=" + Uri.EscapeDataString("//evil.example"));

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.StartsWith("/authorize?", callback.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("evil.example", callback.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // the sign-in page
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_sign_in_page_offers_the_provider_and_the_password_form()
    {
        await using var server = await StartAsync();

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());

        Assert.Contains("action=\"/external/google/start\"", page, StringComparison.Ordinal);
        Assert.Contains("Sign in with Google", page, StringComparison.Ordinal);
        Assert.Contains("name=\"password\"", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// A federation-only deployment renders no password form and still signs people in.
    /// </summary>
    /// <remarks>
    /// The deployment shape the startup condition was changed for. A password form that cannot
    /// succeed is worse than no form: the user concludes they have forgotten a password they never
    /// had.
    /// </remarks>
    [Fact]
    public async Task A_federation_only_deployment_renders_no_password_form()
    {
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await using var server = await StartAsync(s =>
        {
            s.LocalPasswords = false;
            s.Seed = (users, upstream) => LinkAsync(users, upstream, subject, "federated-user");
        });

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());

        Assert.DoesNotContain("name=\"password\"", page, StringComparison.Ordinal);
        Assert.Contains("action=\"/external/google/start\"", page, StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.SeeOther, (await CallbackAsync(server, await BeginAsync(server))).StatusCode);
    }

    [Fact]
    public async Task A_password_post_to_a_federation_only_deployment_is_refused_rather_than_crashing()
    {
        await using var server = await StartAsync(s => s.LocalPasswords = false);

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        var response = await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("username", "ada"),
            new("password", "anything"),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertRejected(server, "LocalPasswordSignInUnavailable");
    }

    /// <summary>A provider that says it is unavailable renders disabled, with its reason. A-11.</summary>
    [Fact]
    public async Task An_unavailable_provider_renders_disabled_with_its_reason()
    {
        await using var server = await StartAsync(s =>
            s.Provider = new UnavailableProvider("Google sign-in is off for this workspace."));

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());

        // Present, disabled, and the reason is on the page - never silently absent.
        Assert.Contains("action=\"/external/google/start\"", page, StringComparison.Ordinal);
        Assert.Contains("disabled", page, StringComparison.Ordinal);
        Assert.Contains("Google sign-in is off for this workspace.", page, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unavailable_provider_refuses_a_start_that_was_posted_anyway()
    {
        await using var server = await StartAsync(s =>
            s.Provider = new UnavailableProvider("Google sign-in is off for this workspace."));

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        var response = await server.Client.PostAsync("/external/google/start", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertRejected(server, "ExternalProviderUnavailable");
    }

    [Fact]
    public async Task An_unknown_scheme_is_refused()
    {
        await using var server = await StartAsync();

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        var response = await server.Client.PostAsync("/external/facebook/start", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
        ]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertRejected(server, "ExternalProviderUnknown");
    }

    /// <summary>The A-11 control: a provider that reports available renders enabled.</summary>
    /// <remarks>
    /// Without this, "the disabled attribute is on the page" is also true of a page that always
    /// renders it, and the test above would pass with the availability check deleted.
    /// </remarks>
    [Fact]
    public async Task An_available_provider_renders_without_the_disabled_attribute()
    {
        await using var server = await StartAsync();

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());

        Assert.DoesNotContain("disabled", page, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared assertions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The last rejection the server logged says this, and the id is on the response.</summary>
    /// <remarks>
    /// A-09 applies to every federation refusal like any other. Asserted on the <i>last</i> line
    /// rather than on a single one because a flow test makes several requests before the one it is
    /// about, and some of those legitimately log - a refused start after a login page, for instance.
    /// </remarks>
    private static void AssertRejected(Server server, string reason)
    {
        var rejections = server.Fixture.Logs.Rejections;

        Assert.NotEmpty(rejections);
        Assert.Equal(reason, rejections[^1].Property("Reason"));
        Assert.False(string.IsNullOrEmpty(rejections[^1].Property("CorrelationId")));
    }

    /// <summary>A provider that is configured and unavailable, for A-11.</summary>
    private sealed class UnavailableProvider(string reason) : IExternalIdentityProvider
    {
        public string Scheme => "google";

        public string DisplayName => "Google";


        public string Issuer => "https://upstream.invalid";

        public ValueTask<ProviderAvailability> GetAvailabilityAsync(
            ExternalProviderContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(ProviderAvailability.Disabled(reason));

        public ValueTask<string?> GetChallengeOriginAsync(CancellationToken cancellationToken) =>

            ValueTask.FromResult<string?>(null);


        public ValueTask<ExternalChallenge> BeginAsync(
            ExternalLoginContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("BeginAsync must not be reached for a disabled provider.");

        public ValueTask<ExternalLoginResult> CompleteAsync(
            ExternalCallbackContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("CompleteAsync must not be reached for a disabled provider.");
    }
}
