using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Claims;
using System.Text;
using Boltway.ResourceServer.DependencyInjection;
using Boltway.ResourceServer.Diagnostics;
using Boltway.ResourceServer.Revocation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// The revocation seam, and the introspection check that ships behind it.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this closes.</b> A signed access token verifies offline, so ending a session on the
/// authorization server reached no resource server until the token expired — up to thirty minutes,
/// which is thirty minutes of access somebody believed they had cut. The authorization server's own
/// denylist was written for a resource server to consult and had no caller in either repository.
/// </para>
/// <para>
/// <b>The fail-open tests are the ones to read first.</b> The behaviour they pin is deliberate and
/// is the kind that looks like a bug to whoever finds it next: when the authorization server cannot
/// be reached, the request is allowed through. What makes that defensible rather than negligent is
/// the warning, so every one of those tests asserts the log line as well as the answer.
/// </para>
/// </remarks>
public sealed class RevocationCheckTests
{
    // ─────────────────────────────────────────────────────────────────────────
    // Through the gate
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_revoked_token_is_a_401_that_tells_the_client_to_authorize_again()
    {
        await using var fixture = await ResourceServerFixture.StartAsync(
            configureServices: services => services.AddSingleton<IAccessTokenRevocationCheck>(new Fixed(revoked: true)));

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", Mint.AccessToken());

        // A 401 and not a 403. A 403 without `insufficient_scope` is terminal for Claude — no
        // re-authentication prompt, permanently — and re-authorizing is exactly what fixes this.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_token", BearerChallengeTests.Parameter(response, "error"));

        // The pointer, without which a client has nowhere to go.
        Assert.Equal(Build.MetadataUrl, BearerChallengeTests.Parameter(response, "resource_metadata"));

        // And the description says what happened, unlike every other invalid-token case. The caller
        // is holding a token that is not corrupt and whose clock is not wrong; without this they
        // have no way to tell a revoked session from a broken deployment.
        Assert.Contains(
            "authorize again",
            BearerChallengeTests.Parameter(response, "error_description")!,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_check_that_says_the_token_stands_lets_the_request_through()
    {
        // The control. Without it a middleware that refused every request would pass the test above.
        await using var fixture = await ResourceServerFixture.StartAsync(
            configureServices: services => services.AddSingleton<IAccessTokenRevocationCheck>(new Fixed(revoked: false)));

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", Mint.AccessToken());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task With_no_check_registered_nothing_is_asked_and_the_request_is_served()
    {
        // The behaviour every deployment had before this seam existed, and the reason it is a seam
        // rather than a default: a resource server that suddenly required an authorization server
        // to be reachable on every request would be a new outage mode arriving with an upgrade.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", Mint.AccessToken());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>An invalid token is never asked about.</summary>
    /// <remarks>
    /// The check runs after every offline check has passed, so the round trip is spent only on
    /// tokens that were going to be accepted. Asking first would put an authorization-server call
    /// on the path of every expired token and every forged one, which is the traffic a scanner
    /// generates.
    /// </remarks>
    [Fact]
    public async Task A_token_that_fails_validation_is_never_asked_about()
    {
        var check = new Fixed(revoked: true);

        await using var fixture = await ResourceServerFixture.StartAsync(
            configureServices: services => services.AddSingleton<IAccessTokenRevocationCheck>(check));

        var elsewhere = Mint.AccessToken(audience: Build.Resolve(Build.OtherResource));

        using var response = await BearerChallengeTests.Get(fixture, "/mcp", elsewhere);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, check.Calls);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The introspection check itself
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_active_token_is_not_revoked_and_the_answer_is_reused()
    {
        var server = new StubIntrospection("""{"active":true}""");
        var check = Check(server);

        Assert.False(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));
        Assert.False(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));

        // One round trip for two requests. The cache is the reason this can sit in front of every
        // call without putting the authorization server on the critical path of each one.
        Assert.Equal(1, server.Calls);
    }

    [Fact]
    public async Task A_second_token_is_asked_about_separately()
    {
        // The control for the cache: keyed per token, so one caller's live answer is never another
        // caller's. A single shared entry would make one person's session decide everybody's.
        var server = new StubIntrospection("""{"active":true}""");
        var check = Check(server);

        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);
        await check.IsRevokedAsync("token-b", Anonymous, CancellationToken.None);

        Assert.Equal(2, server.Calls);
    }

    [Fact]
    public async Task An_inactive_token_is_revoked()
    {
        var check = Check(new StubIntrospection("""{"active":false}"""));

        Assert.True(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));
    }

    /// <summary>A revoked answer is not cached, so nothing keeps a session dead by accident.</summary>
    /// <remarks>
    /// Only live answers are stored. The cache exists to spare a round trip on the hot path, and
    /// the hot path is tokens that work — a revoked one is refused immediately and its client
    /// re-authorizes, so caching that answer would optimise the case that stops happening.
    /// </remarks>
    [Fact]
    public async Task A_revoked_answer_is_asked_again_rather_than_remembered()
    {
        var server = new StubIntrospection("""{"active":false}""");
        var check = Check(server);

        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);
        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);

        Assert.Equal(2, server.Calls);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Failing open, loudly
    // ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, "could not be reached")]
    [InlineData("""{"nope":true}""", "no boolean `active` member")]
    [InlineData("not json at all", "not JSON")]
    public async Task An_unusable_answer_lets_the_request_through_and_says_so(string? body, string expected)
    {
        // Three ways to get no answer, all of them the same decision: allow the request, and write
        // a warning naming the cause. Failing closed here would take the resource server down with
        // the authorization server — they share a host in the deployment this was built for, so an
        // ordinary deploy would log everybody out several times.
        var log = new Recorder();
        var check = Check(new StubIntrospection(body), log);

        Assert.False(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));

        var (level, message) = Assert.Single(log.Lines);

        Assert.Equal(LogLevel.Warning, level);
        Assert.Contains(expected, message, StringComparison.Ordinal);

        // The line has to say what the exposure is, not just that something failed. Somebody
        // reading it at 2am needs to know that revocation is not taking effect right now.
        Assert.Contains("until the token expires", message, StringComparison.Ordinal);
    }

    /// <summary>
    /// This resource server's own credential being wrong is named as that, not as an outage.
    /// </summary>
    /// <remarks>
    /// The failure mode this separates out: a wrong secret makes revocation quietly do nothing
    /// forever, and it looks exactly like an authorization server having a bad day. One is fixed by
    /// waiting and the other never is.
    /// </remarks>
    [Fact]
    public async Task A_refused_credential_is_reported_as_a_credential_problem()
    {
        var log = new Recorder();
        var check = Check(new StubIntrospection("""{"error":"invalid_client"}""", HttpStatusCode.Unauthorized), log);

        Assert.False(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));

        var (_, message) = Assert.Single(log.Lines);

        Assert.Contains("this resource server's own client credential", message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_registration_missing_its_endpoint_or_credential_fails_at_startup()
    {
        // Rather than failing open on every request while logging a warning that blames the
        // authorization server, which is a configuration error wearing an outage's clothes.
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddIntrospectionRevocationCheck(o => o.ClientId = "resource-server");

        var error = Assert.Throws<InvalidOperationException>(
            () => services.BuildServiceProvider().GetRequiredService<IAccessTokenRevocationCheck>());

        Assert.Contains("Endpoint", error.Message, StringComparison.Ordinal);
        Assert.Contains("ClientSecret", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("ClientId", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A refusal whose body is not an OAuth error reports the status, not the parse failure.
    /// </summary>
    /// <remarks>
    /// The shape this pins: a proxy in front of the authorization server answering with an HTML
    /// error page. Checking the status after parsing reported that as a malformed introspection
    /// response, which sends whoever reads the line looking at the wrong server.
    /// </remarks>
    [Fact]
    public async Task A_refusal_that_is_not_an_oauth_error_body_reports_the_status()
    {
        var log = new Recorder();
        var check = Check(new StubIntrospection("<html>502 Bad Gateway</html>", HttpStatusCode.BadGateway), log);

        Assert.False(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));

        var (_, message) = Assert.Single(log.Lines);

        Assert.Contains("BadGateway", message, StringComparison.Ordinal);
        Assert.DoesNotContain("not JSON", message, StringComparison.Ordinal);
    }


    // ─────────────────────────────────────────────────────────────────────────
    // Counting the fail-opens
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Every way of failing open is counted, under a reason bounded enough to be a tag.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the instrument the whole meter exists for.</b> The warning above it has always
    /// been written; what it lacked was a reader. A deployment that chose fail-open accepted a risk
    /// whose size it could not then state, and "is revocation working" stayed <i>assumed</i>.
    /// </para>
    /// <para>
    /// The reason is asserted separately from the message because the two have different jobs and
    /// different limits: the message carries the exception text and must stay unbounded, the tag
    /// must not. A tag built from <c>ex.Message</c> would produce one series per remote failure.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(null, HttpStatusCode.OK, FailedOpenReason.Unreachable)]
    [InlineData("""{"nope":true}""", HttpStatusCode.OK, FailedOpenReason.MalformedResponse)]
    [InlineData("not json at all", HttpStatusCode.OK, FailedOpenReason.NotJson)]
    [InlineData("""{"error":"invalid_client"}""", HttpStatusCode.Unauthorized, FailedOpenReason.CredentialRejected)]
    [InlineData("<html>502 Bad Gateway</html>", HttpStatusCode.BadGateway, FailedOpenReason.Refused)]
    public async Task Failing_open_is_counted_under_a_reason(string? body, HttpStatusCode status, string expected)
    {
        using var metrics = new ResourceServerMetrics();
        using var instruments = new Instruments(ResourceServerMetrics.MeterName);

        var check = Check(new StubIntrospection(body, status), metrics: metrics);

        Assert.False(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));

        var (_, value, tags) = Assert.Single(instruments.Counts);

        Assert.Equal(1, value);
        Assert.Equal(RevocationOutcome.FailedOpen, tags["outcome"]);
        Assert.Equal(expected, tags["reason"]);
    }

    /// <summary>
    /// A cache hit is a different outcome from an answer, because the alert divides by one and not
    /// the other.
    /// </summary>
    /// <remarks>
    /// The number worth alerting on is fail-opens over the decisions that actually asked. Cache hits
    /// dominate a busy resource server, so folding them in with <c>live</c> would put a
    /// hit-rate-shaped denominator under a reliability number — the ratio would fall whenever
    /// traffic rose, and rise whenever it dropped, with revocation behaving identically throughout.
    /// </remarks>
    [Fact]
    public async Task A_reused_answer_is_counted_apart_from_one_that_was_asked_for()
    {
        using var metrics = new ResourceServerMetrics();
        using var instruments = new Instruments(ResourceServerMetrics.MeterName);

        var server = new StubIntrospection("""{"active":true}""");
        var check = Check(server, metrics: metrics);

        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);
        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);

        // One round trip, two decisions — the same asymmetry the cache test above asserts, now
        // visible in the series rather than only in the stub's call count.
        Assert.Equal(1, server.Calls);

        Assert.Equal(
            [RevocationOutcome.Live, RevocationOutcome.Cached],
            instruments.Counts.Select(c => c.Tags["outcome"]));
    }

    [Fact]
    public async Task A_grant_that_is_gone_is_counted_as_revoked_rather_than_as_a_failure()
    {
        // The control that keeps the fail-open number meaningful: a working authorization server
        // saying "this grant is gone" is revocation succeeding, and counting it beside the
        // unreachable cases would make the one series nobody may misread into a mixture.
        using var metrics = new ResourceServerMetrics();
        using var instruments = new Instruments(ResourceServerMetrics.MeterName);

        var check = Check(new StubIntrospection("""{"active":false}"""), metrics: metrics);

        Assert.True(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));

        var (_, _, tags) = Assert.Single(instruments.Counts);

        Assert.Equal(RevocationOutcome.Revoked, tags["outcome"]);
        Assert.False(tags.ContainsKey("reason"));
    }

    /// <summary>The ask is timed, including the ones that failed.</summary>
    /// <remarks>
    /// A timeout is the slowest ask there is, and it is the shape of failure the histogram gives
    /// warning of: an authorization server drifting towards the configured timeout produces no
    /// fail-opens at all until it produces nothing else. Dropping the failures would trim exactly
    /// the tail worth watching.
    /// </remarks>
    [Fact]
    public async Task An_ask_is_timed_whether_or_not_it_answered()
    {
        using var metrics = new ResourceServerMetrics();
        using var instruments = new Instruments(ResourceServerMetrics.MeterName);

        var check = Check(new StubIntrospection("""{"active":true}"""), metrics: metrics);
        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);

        var failing = Check(new StubIntrospection(null), metrics: metrics);
        await failing.IsRevokedAsync("token-b", Anonymous, CancellationToken.None);

        Assert.Equal(
            [RevocationOutcome.Live, RevocationOutcome.FailedOpen],
            instruments.Recorded.Select(r => r.Tags["outcome"]));

        // A cache hit is not an ask, so it contributes no duration — otherwise the histogram would
        // report the latency of a dictionary lookup as the authorization server's.
        await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None);

        Assert.Equal(2, instruments.Recorded.Count);
    }

    [Fact]
    public async Task With_no_meter_the_check_still_works()
    {
        // The seam is optional, and this is what says so. Every deployment that predates the meter
        // constructs this type with three arguments.
        var check = Check(new StubIntrospection("""{"active":false}"""));

        Assert.True(await check.IsRevokedAsync("token-a", Anonymous, CancellationToken.None));
    }

    // ─────────────────────────────────────────────────────────────────────────

    private static readonly ClaimsPrincipal Anonymous = new(new ClaimsIdentity());

    private static IntrospectionRevocationCheck Check(
        StubIntrospection server,
        ILogger<IntrospectionRevocationCheck>? log = null,
        ResourceServerMetrics? metrics = null) =>
        new(
            new OneClient(server),
            new IntrospectionOptions
            {
                Endpoint = new Uri("https://auth.example.com/introspect"),
                ClientId = "resource-server",
                ClientSecret = "s3cret",
            },
            log ?? NullLogger<IntrospectionRevocationCheck>.Instance,
            clock: null,
            metrics: metrics);

    /// <summary>A revocation check that always says the same thing, and counts.</summary>
    private sealed class Fixed(bool revoked) : IAccessTokenRevocationCheck
    {
        internal int Calls { get; private set; }

        public ValueTask<bool> IsRevokedAsync(string token, ClaimsPrincipal principal, CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult(revoked);
        }
    }

    /// <summary>A factory that hands out one client over the stub handler.</summary>
    /// <remarks>
    /// The check takes a factory rather than a client, because it is the one type allowed to touch
    /// <c>System.Net.Http</c> and resolving the client anywhere else would need a second exception
    /// to that rule. This is the smallest factory that satisfies it.
    /// </remarks>
    private sealed class OneClient(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://auth.example.com") };
    }

    /// <summary>An introspection endpoint that answers with one canned body, or not at all.</summary>
    /// <remarks>
    /// A null body means the request throws, which is the transport failure — a restart, a deploy,
    /// a network blip — that the fail-open path exists for.
    /// </remarks>
    private sealed class StubIntrospection(string? body, HttpStatusCode status = HttpStatusCode.OK)
        : HttpMessageHandler
    {
        internal int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;

            if (body is null)
            {
                throw new HttpRequestException("the connection was refused");
            }

            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>Keeps what was logged, so the warning is asserted rather than assumed.</summary>
    private sealed class Recorder : ILogger<IntrospectionRevocationCheck>
    {
        internal List<(LogLevel Level, string Message)> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel level) => true;

        public void Log<TState>(
            LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> format)
        {
            ArgumentNullException.ThrowIfNull(format);
            Lines.Add((level, format(state, error)));
        }
    }
    /// <summary>Keeps what a meter published, so a counter is asserted rather than assumed.</summary>
    /// <remarks>
    /// <para>
    /// A <see cref="MeterListener"/> rather than a package. <c>Microsoft.Extensions.Diagnostics.Testing</c>
    /// would do this with less code, and adding a dependency to fifteen shipped packages for one
    /// test file is a worse trade than twenty lines here.
    /// </para>
    /// <para>
    /// <b>Filtered by meter name, which is also a check on it.</b> A rename would leave this
    /// collecting nothing and every assertion below counting an empty list — so the tests fail
    /// rather than pass vacuously, which is the opposite of what a listener that took everything
    /// would do.
    /// </para>
    /// </remarks>
    private sealed class Instruments : IDisposable
    {
        private readonly MeterListener _listener = new();

        internal Instruments(string meterName)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (string.Equals(instrument.Meter.Name, meterName, StringComparison.Ordinal))
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };

            _listener.SetMeasurementEventCallback<long>(
                (instrument, value, tags, _) => Counts.Add((instrument.Name, value, Read(tags))));

            _listener.SetMeasurementEventCallback<double>(
                (instrument, value, tags, _) => Recorded.Add((instrument.Name, value, Read(tags))));

            _listener.Start();
        }

        internal List<(string Instrument, long Value, Dictionary<string, string?> Tags)> Counts { get; } = [];

        internal List<(string Instrument, double Value, Dictionary<string, string?> Tags)> Recorded { get; } = [];

        /// <summary>Copy the tags out of the span, which does not outlive the callback.</summary>
        private static Dictionary<string, string?> Read(ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var copy = new Dictionary<string, string?>(StringComparer.Ordinal);

            foreach (var tag in tags)
            {
                copy[tag.Key] = tag.Value?.ToString();
            }

            return copy;
        }

        public void Dispose() => _listener.Dispose();
    }
}
