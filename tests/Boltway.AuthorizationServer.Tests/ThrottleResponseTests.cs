using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Net;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// X-31 on the wire: 429, a <c>Retry-After</c>, and no invented <c>error</c> code.
/// </summary>
/// <remarks>
/// <para>
/// The body shape is the one this surface already uses - the HTML error page on our own origin -
/// because both endpoints here are reached by a browser. X-31's row gives <c>json</c> for its
/// delivery and that row is written for the registration endpoints, which this server does not
/// route: <c>RegistrationProfile.DynamicRegistration</c> is refused at startup.
/// </para>
/// <para>
/// There is deliberately no <c>error</c> in the response, and that is X-31's own column rather than
/// an omission. See <c>AuthorizeHtmlError.Throttled</c> and the note in <c>OAuthErrors</c>.
/// </para>
/// </remarks>
public sealed partial class ThrottleResponseTests
{
    private const string ClaudeId = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    private const string Username = "ada";
    private const string Password = "correct horse battery staple";

    /// <summary>Cheap Argon2id, so a suite that logs in repeatedly does not pay 19 MiB a time.</summary>
    private static Argon2idParameters TestCost => new() { MemoryKiB = 64, Iterations = 1, Parallelism = 1 };

    // ─────────────────────────────────────────────────────────────────────────
    // /authorize
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A <c>client_id</c> whose document keeps failing gets 429 with a <c>Retry-After</c>.
    /// </summary>
    /// <remarks>
    /// Measured before this existed: fifty sequential anonymous requests with the same failing
    /// <c>client_id</c> produced fifty outbound fetches and fifty identical 400s, so each request
    /// was a fresh probe of whatever host the identifier named.
    /// </remarks>
    [Fact]
    public async Task A_repeatedly_failing_client_id_is_answered_429_with_a_retry_after()
    {
        var fetcher = new ConcurrentStubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(503));

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Clients.Clear();
            seed.Fetcher = fetcher;
        });

        var statuses = new List<HttpStatusCode>();
        string? retryAfter = null;
        string? lastBody = null;

        for (var i = 0; i < 20; i++)
        {
            var response = await fixture.Client.GetAsync(new Uri(AuthorizeUrl(ClaudeId), UriKind.Relative));

            statuses.Add(response.StatusCode);
            lastBody = await response.Content.ReadAsStringAsync();

            if (response.Headers.TryGetValues("Retry-After", out var values))
            {
                retryAfter = values.First();
            }
        }

        Assert.Equal(3, fetcher.Calls);
        Assert.Equal(3, statuses.Count(s => s == HttpStatusCode.BadRequest));
        Assert.Equal(17, statuses.Count(s => s == HttpStatusCode.TooManyRequests));

        Assert.NotNull(retryAfter);
        Assert.True(
            int.TryParse(retryAfter, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds) && seconds > 0,
            $"Retry-After was '{retryAfter}', which is not the delta-seconds form RFC 9110 section 10.2.3 requires.");

        // X-31 carries no `error`, so none of the wire strings may appear in the body. Checked
        // against the two that would plausibly be reached for by someone filling the gap.
        Assert.DoesNotContain("invalid_client", lastBody, StringComparison.Ordinal);
        Assert.DoesNotContain("temporarily_unavailable", lastBody, StringComparison.Ordinal);

        // A-12: the body still has to say what happened and carry the correlation id.
        Assert.Contains("failed repeatedly", lastBody, StringComparison.Ordinal);
        Assert.Contains("Reference:", lastBody, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control: a healthy client is untouched by any of this.
    /// </summary>
    /// <remarks>
    /// A limiter that refused everything would satisfy the test above. Fifty authorizations at the
    /// shipped defaults, one fetch, fifty redirects into the flow - which is also the C-29 argument:
    /// a limit that trips on ordinary vendor traffic is worse than no limit.
    /// </remarks>
    [Fact]
    public async Task Fifty_authorizations_by_a_healthy_client_are_one_fetch_and_no_refusals()
    {
        var fetcher = new ConcurrentStubFetcher();
        _ = fetcher.Serve(
            ClaudeId,
            $$"""{"client_id":"{{ClaudeId}}","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}""",
            TimeSpan.FromSeconds(300));

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Clients.Clear();
            seed.Fetcher = fetcher;
        });

        for (var i = 0; i < 50; i++)
        {
            var response = await fixture.Client.GetAsync(new Uri(AuthorizeUrl(ClaudeId), UriKind.Relative));

            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        }

        Assert.Equal(1, fetcher.Calls);
    }

    private static string AuthorizeUrl(string clientId) =>
        "/authorize?response_type=code"
        + "&client_id=" + Uri.EscapeDataString(clientId)
        + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")
        + "&scope=" + Uri.EscapeDataString("mcp:tools")
        + "&resource=" + Uri.EscapeDataString(Build.Resource)
        + "&state=opaque"
        + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        + "&code_challenge_method=S256";

    // ─────────────────────────────────────────────────────────────────────────
    // /login
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The per-account budget refuses further attempts, and refuses them without hashing.
    /// </summary>
    /// <remarks>
    /// Both halves matter. The status is what a client sees; the hash count is what the server
    /// spends, and it is the number the whole exercise is about - a refusal that still paid 19 MiB
    /// and 95 ms would be a slower way to be flooded.
    /// </remarks>
    [Fact]
    public async Task Too_many_attempts_on_one_username_are_refused_without_hashing()
    {
        await using var server = await StartAsync(o => o.MaxAttemptsPerAccount = 5);

        var statuses = new List<HttpStatusCode>();
        int? hashesAtRefusal = null;

        for (var i = 0; i < 12; i++)
        {
            var response = await PostLoginAsync(server, Username, "wrong password");

            statuses.Add(response.StatusCode);

            if (response.StatusCode is HttpStatusCode.TooManyRequests)
            {
                hashesAtRefusal ??= server.Hasher.Verifications;
                Assert.True(response.Headers.TryGetValues("Retry-After", out _), "a 429 with no Retry-After");
            }
        }

        Assert.Equal(5, statuses.Count(s => s == HttpStatusCode.OK));
        Assert.Equal(7, statuses.Count(s => s == HttpStatusCode.TooManyRequests));

        Assert.NotNull(hashesAtRefusal);
        Assert.Equal(hashesAtRefusal, server.Hasher.Verifications);
    }

    /// <summary>
    /// The per-source budget catches an attacker spreading across usernames.
    /// </summary>
    /// <remarks>
    /// The per-account limit alone is defeated by a list of usernames, which is what credential
    /// stuffing has. Each attempt below uses a name that has never been seen, so only the source
    /// counter can refuse it.
    /// </remarks>
    [Fact]
    public async Task Too_many_attempts_from_one_source_are_refused_whatever_the_username()
    {
        await using var server = await StartAsync(o =>
        {
            o.MaxAttemptsPerAccount = 1000;
            o.MaxAttemptsPerClient = 5;
        });

        var statuses = new List<HttpStatusCode>();

        for (var i = 0; i < 12; i++)
        {
            statuses.Add((await PostLoginAsync(
                server, "victim" + i.ToString(CultureInfo.InvariantCulture), "wrong password")).StatusCode);
        }

        Assert.Equal(5, statuses.Count(s => s == HttpStatusCode.OK));
        Assert.Equal(7, statuses.Count(s => s == HttpStatusCode.TooManyRequests));
    }

    /// <summary>
    /// The control for both budgets: an ordinary sign-in, and a few fumbled ones, are untouched.
    /// </summary>
    /// <remarks>
    /// At the shipped numbers - ten a quarter of an hour per username, thirty per source - someone
    /// who mistypes their password four times still signs in on the fifth attempt. A limiter that
    /// refused that would be worse than none.
    /// </remarks>
    [Fact]
    public async Task Four_fumbled_attempts_and_then_the_right_password_still_signs_in()
    {
        await using var server = await StartAsync();

        for (var i = 0; i < 4; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await PostLoginAsync(server, Username, "wrong")).StatusCode);
        }

        Assert.Equal(HttpStatusCode.SeeOther, (await PostLoginAsync(server, Username, Password)).StatusCode);
    }

    /// <summary>
    /// A correct password clears the account budget, and does <b>not</b> clear the source budget.
    /// </summary>
    /// <remarks>
    /// The second half is the one worth a test. Resetting the source counter on success would hand
    /// an attacker who holds one valid credential a reset button: run to the limit, sign in once,
    /// run again. The account counter is different - the proof that the attempts were this user's
    /// own is the password they just got right.
    /// <para>
    /// The attempts after the success use fresh usernames on purpose, so each has its own untouched
    /// account budget and the only counter that can refuse is the source one. Written the obvious
    /// way first - all attempts on the same username - this test passed with the source counter
    /// reset as well, because the account budget was doing the refusing.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_success_clears_the_account_budget_but_not_the_source_budget()
    {
        await using var server = await StartAsync(o =>
        {
            o.MaxAttemptsPerAccount = 3;
            o.MaxAttemptsPerClient = 8;
        });

        // Two failures, then the right password. The account budget is now clear - three more
        // attempts on this username would be allowed.
        _ = await PostLoginAsync(server, Username, "wrong");
        _ = await PostLoginAsync(server, Username, "wrong");
        Assert.Equal(HttpStatusCode.SeeOther, (await PostLoginAsync(server, Username, Password)).StatusCode);

        // Five attempts on names that have never been seen. Each has its own account budget, so
        // only the source counter is accumulating: it is now at eight, its whole allowance.
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(
                HttpStatusCode.OK,
                (await PostLoginAsync(server, "fresh" + i.ToString(CultureInfo.InvariantCulture), "wrong")).StatusCode);
        }

        // A ninth, on yet another fresh name. Nothing about the account can refuse this one.
        Assert.Equal(HttpStatusCode.TooManyRequests, (await PostLoginAsync(server, "fresh-last", "wrong")).StatusCode);
    }

    /// <summary>
    /// The throttle cannot tell an existing account from an invented one, and neither can a caller.
    /// </summary>
    /// <remarks>
    /// The username oracle, rebuilt one layer up. A limiter keyed on accounts that exist would
    /// refuse quickly for a real name and never for an invented one, which is the difference the
    /// endpoint's <c>DummyHash</c> exists to erase. The counter is keyed on the submitted string, so
    /// both are refused at the same attempt with the same response.
    /// </remarks>
    [Fact]
    public async Task A_real_username_and_an_invented_one_are_throttled_identically()
    {
        await using var server = await StartAsync(o => o.MaxAttemptsPerAccount = 3);

        var real = new List<HttpStatusCode>();
        var invented = new List<HttpStatusCode>();

        for (var i = 0; i < 6; i++)
        {
            real.Add((await PostLoginAsync(server, Username, "wrong")).StatusCode);
        }

        for (var i = 0; i < 6; i++)
        {
            invented.Add((await PostLoginAsync(server, "no-such-person", "wrong")).StatusCode);
        }

        Assert.Equal(real, invented);
    }

    /// <summary>
    /// Case is folded, so alternating capitalisation does not buy a fresh budget.
    /// </summary>
    /// <remarks>
    /// <c>IUserStore</c> matches usernames case-insensitively, so <c>ADA</c> and <c>ada</c> are one
    /// account. A limiter comparing them ordinally would give each spelling its own budget, and the
    /// per-account limit would be worth a factor of 2^n on a name of n letters.
    /// </remarks>
    [Fact]
    public async Task Case_does_not_buy_a_fresh_budget()
    {
        await using var server = await StartAsync(o => o.MaxAttemptsPerAccount = 3);

        _ = await PostLoginAsync(server, "ada", "wrong");
        _ = await PostLoginAsync(server, "ADA", "wrong");
        _ = await PostLoginAsync(server, "Ada", "wrong");

        Assert.Equal(HttpStatusCode.TooManyRequests, (await PostLoginAsync(server, "aDa", "wrong")).StatusCode);
    }

    /// <summary>
    /// Concurrent verifications are bounded, and the requests that do not fit are shed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The bound the failed-attempt counters cannot provide: a hundred requests that arrive together
    /// have all been admitted before any of them has failed. Measured on the unbounded endpoint,
    /// four cores, shipped Argon2id: a hundred concurrent posts ran a hundred hashes with a peak of
    /// seventeen in flight, took 4.9 s, and stalled an unrelated discovery request for 4.4 s.
    /// </para>
    /// <para>
    /// The queue timeout is zero here, so the shed path is reached without sleeping: whatever cannot
    /// have a slot immediately is refused. In the shipped configuration it waits two seconds first.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task In_flight_password_verifications_are_bounded()
    {
        await using var server = await StartAsync(o =>
        {
            o.MaxConcurrentPasswordVerifications = 2;
            o.VerificationQueueTimeout = TimeSpan.Zero;

            // Out of the way, so what is measured is the concurrency bound and not the counters.
            o.MaxAttemptsPerAccount = 10_000;
            o.MaxAttemptsPerClient = 10_000;
        });

        var page = await server.Client.GetStringAsync(
            new Uri("/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl(ClaudeId)), UriKind.Relative));

        var (field, token, returnUrl) = FormFields(page);

        server.Hasher.Block();

        var flood = Enumerable.Range(0, 40).Select(_ => Task.Run(async () =>
            await server.Client.PostAsync(
                new Uri("/login", UriKind.Relative),
                new FormUrlEncodedContent(
                [
                    new(field, token),
                    new("returnUrl", returnUrl),
                    new("username", Username),
                    new("password", "wrong"),
                ])))).ToArray();

        // Everything that could not have a slot is already refused; the two holding slots are
        // waiting on the hasher. The deadline is the difference between this test failing and this
        // test hanging: with the bound removed all forty requests take a slot, none of them
        // completes, and an unbounded spin here never reaches the assertions it exists to make.
        var deadline = System.Diagnostics.Stopwatch.StartNew();

        while (flood.Count(t => t.IsCompleted) < 38 && deadline.Elapsed < TimeSpan.FromSeconds(20))
        {
            await Task.Delay(10);
        }

        server.Hasher.Release();

        var responses = await Task.WhenAll(flood);

        Assert.True(
            server.Hasher.Peak <= 2,
            $"{server.Hasher.Peak.ToString(CultureInfo.InvariantCulture)} verifications ran at once against a bound of 2");

        Assert.Equal(38, responses.Count(r => r.StatusCode is HttpStatusCode.TooManyRequests));
        Assert.All(
            responses.Where(r => r.StatusCode is HttpStatusCode.TooManyRequests),
            r => Assert.True(r.Headers.TryGetValues("Retry-After", out _)));
    }

    /// <summary>The control: with slots free, the same flood is not shed at all.</summary>
    [Fact]
    public async Task The_concurrency_bound_does_not_shed_when_there_is_room()
    {
        await using var server = await StartAsync(o =>
        {
            o.MaxConcurrentPasswordVerifications = 8;
            o.MaxAttemptsPerAccount = 10_000;
            o.MaxAttemptsPerClient = 10_000;
        });

        var responses = new List<HttpStatusCode>();

        for (var i = 0; i < 20; i++)
        {
            responses.Add((await PostLoginAsync(server, Username, "wrong")).StatusCode);
        }

        Assert.All(responses, s => Assert.Equal(HttpStatusCode.OK, s));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Harness
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Counts verifications, tracks the high-water mark, and can be held open.</summary>
    private sealed class GatedHasher(IPasswordHasher inner) : IPasswordHasher, IDisposable
    {
        private readonly ManualResetEventSlim _gate = new(initialState: true);

        public void Dispose() => _gate.Dispose();
        private int _verifications;
        private int _inFlight;
        private int _peak;

        public int Verifications => Volatile.Read(ref _verifications);

        public int Peak => Volatile.Read(ref _peak);

        public void Block() => _gate.Reset();

        public void Release() => _gate.Set();

        public string Hash(string password) => inner.Hash(password);

        public bool Verify(string password, string encodedHash)
        {
            _ = Interlocked.Increment(ref _verifications);
            var now = Interlocked.Increment(ref _inFlight);

            int seen;
            while (now > (seen = Volatile.Read(ref _peak)))
            {
                _ = Interlocked.CompareExchange(ref _peak, now, seen);
            }

            try
            {
                _gate.Wait();
                return inner.Verify(password, encodedHash);
            }
            finally
            {
                _ = Interlocked.Decrement(ref _inFlight);
            }
        }
    }

    private sealed record Server(FlowFixture Fixture, GatedHasher Hasher) : IAsyncDisposable
    {
        public HttpClient Client => Fixture.Client;

        public ValueTask DisposeAsync() => Fixture.DisposeAsync();
    }

    private static async Task<Server> StartAsync(Action<LoginThrottleOptions>? configure = null)
    {
        var hasher = new GatedHasher(new Argon2idPasswordHasher(TestCost));
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        await users.StoreAsync(
            new UserAccount(
                new UlidSubjectIdFactory(TimeProvider.System).Mint(),
                Username,
                "ada@example.com",
                EmailVerified: true,
                PasswordHash: hasher.Hash(Password)),
            CancellationToken.None);

        var throttle = new LoginThrottleOptions();
        configure?.Invoke(throttle);

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClaudeId, ClientType.Public);
            seed.SignedInUser = null;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton(throttle);
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IPasswordHasher>(hasher);

                services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie(o =>
                    {
                        o.Cookie.Name = "__Host-boltway-session";
                        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                        o.Cookie.SameSite = SameSiteMode.Lax;
                    });

                services.AddHttpContextAccessor();
                services.AddScoped<IUserSession, CookieUserSession>();
            };

            seed.ConfigureApp = app =>
            {
                // TestServer leaves the remote address null, and one null address is one bucket for
                // every test in this class. A fixed address is what a single attacker looks like.
                app.Use(async (context, next) =>
                {
                    context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
                    await next(context);
                });

                app.UseAuthentication();
            };
        });

        return new Server(fixture, hasher);
    }

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

    private static async Task<HttpResponseMessage> PostLoginAsync(Server server, string username, string password)
    {
        var page = await server.Client.GetStringAsync(
            new Uri("/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl(ClaudeId)), UriKind.Relative));

        var (field, token, returnUrl) = FormFields(page);

        return await server.Client.PostAsync(
            new Uri("/login", UriKind.Relative),
            new FormUrlEncodedContent(
            [
                new(field, token),
                new("returnUrl", returnUrl),
                new("username", username),
                new("password", password),
            ]));
    }
}
