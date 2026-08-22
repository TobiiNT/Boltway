using System.Net;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Token;
using Boltway.Identity.Passwords;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Keeps cookies across requests, the way a browser does.
/// </summary>
/// <remarks>
/// <c>GetTestClient()</c> hands back an <see cref="HttpClient"/> with no cookie jar, so a
/// <c>Set-Cookie</c> from the consent GET never comes back on the POST. Every antiforgery check
/// then fails, and every session looks signed out — which reads as a product bug and is a fixture
/// that is not simulating a browser.
/// </remarks>
internal sealed class CookieJarHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    private readonly CookieContainer _cookies = new();

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var header = _cookies.GetCookieHeader(uri);

        if (!string.IsNullOrEmpty(header))
        {
            request.Headers.Remove("Cookie");
            request.Headers.TryAddWithoutValidation("Cookie", header);
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            foreach (var cookie in setCookies)
            {
                // Stored under the name the server sent, prefix included. Stripping "__Host-" here
                // replayed the cookie under a name the antiforgery system never looks for, so every
                // POST failed its check — a fixture bug that presents exactly as a product one.
                _cookies.SetCookies(uri, cookie);
            }
        }

        return response;
    }
}

/// <summary>
/// A clock a test can move.
/// </summary>
/// <remarks>
/// Written here rather than taken from a package because it needs to do one thing. Its existence is
/// the point of the endpoints taking an injected <see cref="TimeProvider"/>: before they did, the
/// time axis could not be driven from an HTTP test at all, so every time-shaped guard — code
/// expiry, <c>max_age</c>, the refresh grace window — was unverified end to end.
/// </remarks>
internal sealed class MovableClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    /// <summary>Move forward.</summary>
    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>A user session the test controls.</summary>
internal sealed class TestUserSession(AuthenticatedUser? current) : IUserSession
{
    /// <summary>Who is signed in, or <see langword="null"/> for an anonymous browser.</summary>
    /// <summary>
    /// Who is signed in, per host.
    /// </summary>
    /// <remarks>
    /// An instance field, not a static. It was static, and xUnit runs test <i>classes</i> in
    /// parallel — so the moment a second class used this fixture, two hosts shared one signed-in
    /// user and tests began failing in whichever class lost the race. Predicted by review before it
    /// happened, and then measured: two classes, and the failures moved between runs.
    /// </remarks>
    public AuthenticatedUser? Current { get; } = current;

    public ValueTask<AuthenticatedUser?> GetAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(Current);
}

/// <summary>A consent policy the test controls.</summary>
internal sealed class TestConsentPolicy(ConsentDecision decision) : IConsentPolicy
{
    /// <summary>What the policy answers.</summary>
    /// <summary>What this host's policy answers. Per instance, for the reason above.</summary>
    public ConsentDecision Decision { get; } = decision;

    public ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken) =>
        ValueTask.FromResult(Decision);
}

/// <summary>
/// The secrets registered clients hold. Empty unless a test seeds one.
/// </summary>
/// <remarks>
/// <para>
/// This used to return <see langword="null"/> unconditionally, under the summary "No client has a
/// secret; everything in these tests is a public client." That was true of the fixture and false of
/// the server, and it silently removed a whole authentication method from the suite: with no secret
/// ever stored, <c>SecretAsync</c> could only ever reach its "no secret is stored for this client"
/// refusal, so <b>no confidential client ever authenticated successfully over HTTP by either
/// <c>client_secret_basic</c> or <c>client_secret_post</c></b>.
/// </para>
/// <para>
/// Mutation testing is what surfaced it, as a cluster rather than a single mutant: Stryker marked
/// the <c>Authenticated(...)</c> success branch <c>NoCoverage</c>, and every guard on the road to
/// it survived — the strict-UTF-8 decode of the Basic payload, the <c>':'</c> split, the
/// <c>separator + 1</c> that cuts the secret out, and the <c>usedHeader</c> flag that decides which
/// method gets reported. None of them could be killed by a suite in which the road was never
/// travelled.
/// </para>
/// </remarks>
internal sealed class TestClientSecretStore(IDictionary<string, string> secrets) : IClientSecretStore
{
    public Task<Sha256Hash?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult(secrets.TryGetValue(clientId.Value, out var secret)
            ? Sha256Hash.OfString(secret)
            : (Sha256Hash?)null);
}

/// <summary>A consent store that grants whatever it is asked for.</summary>
internal sealed class TestConsentStore : IConsentStore
{
    private readonly Dictionary<string, ConsentRecord> _records = new(StringComparer.Ordinal);

    public Task<ConsentRecord?> FindAsync(SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult(_records.GetValueOrDefault(subject.Value + "|" + clientId.Value));

    public Task<ConsentRecord> GrantAsync(
        SubjectId subject,
        ClientIdentifier clientId,
        OAuth.Primitives.Scopes.ScopeSet scope,
        IReadOnlyList<string> resources,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var record = new ConsentRecord(subject, clientId, scope, resources, now);
        _records[subject.Value + "|" + clientId.Value] = record;
        return Task.FromResult(record);
    }

    public Task<IReadOnlyList<ConsentRecord>> ListAsync(
        SubjectId subject, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ConsentRecord>>(
            [.. _records.Values.Where(r => r.Subject == subject).OrderByDescending(r => r.GrantedAt)]);

    public Task<bool> RevokeAsync(SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult(_records.Remove(subject.Value + "|" + clientId.Value));
}

/// <summary>
/// A whole authorization server, over real HTTP.
/// </summary>
/// <remarks>
/// Built the way a customer's host would build it, because the failures step 6 is about are wiring
/// failures: a route that does not exist, a service that cannot be resolved, a status the framework
/// chose. None of them are visible from a unit test of a handler.
/// </remarks>
internal sealed class FlowFixture : IAsyncDisposable
{
    private readonly IHost _host;

    private FlowFixture(IHost host, HttpClient client)
    {
        _host = host;
        Client = client;
    }

    /// <summary>A client that does not follow redirects, so each hop is observable.</summary>
    public HttpClient Client { get; }

    /// <summary>
    /// Everything the server logged, captured through the real <see cref="ILoggerProvider"/> seam.
    /// </summary>
    /// <remarks>
    /// On every fixture rather than behind a flag. A-09 is a property of every rejection path, and
    /// a sink that only exists in the tests that ask for it cannot notice a path that stopped
    /// logging — which is how twenty-five of them came to log nothing at all.
    /// </remarks>
    public LogSink Logs { get; private set; } = null!;

    /// <summary>The server's clock, movable.</summary>
    public MovableClock Clock { get; private set; } = null!;

    /// <summary>The resolver behind the fixture, so a test can change a client mid-flow.</summary>
    public TestClientResolver Clients { get; private set; } = null!;

    /// <summary>Disable a client, as an administrator would while a consent page sat open.</summary>
    public void DisableClient(string clientId) => Clients.Disable(clientId);

    /// <summary>
    /// The running host's container, for a test that has to act as an operator mid-flow.
    /// </summary>
    /// <remarks>
    /// Narrow on purpose. It exists so a test can disable an account between two sign-ins through
    /// the same object graph the deployment uses — reaching into the store directly would prove the
    /// fixture agrees with itself rather than that the administrative surface reaches the sign-in
    /// path.
    /// </remarks>
    public IServiceProvider Services => _host.Services;

    private IHost Host => _host;

    /// <summary>
    /// A second browser against the same server: its own cookie jar, no shared state.
    /// </summary>
    /// <remarks>
    /// Needed to ask "what happens to a request carrying somebody else's <c>state</c>", which is not
    /// a question the fixture's own client can answer — it holds the pending-request cookie, and the
    /// whole point of the binding is that the cookie is what makes the state mean anything.
    /// </remarks>
    /// <summary>A raw handler onto this server, with no cookie jar in front of it.</summary>
    /// <remarks>
    /// For a caller that is not a browser. A resource server introspecting a token authenticates
    /// with its client credential on every request and has no session to carry, so putting the
    /// cookie jar in the way would model something that does not exist.
    /// </remarks>
    public HttpMessageHandler NewHandler() => Host.GetTestServer().CreateHandler();

    public HttpClient NewClient() =>
        new(new CookieJarHandler(Host.GetTestServer().CreateHandler()))
        {
            BaseAddress = new Uri("https://auth.example.com"),
        };

    public static async Task<FlowFixture> StartAsync(Action<AuthorizationServerOptionsSeed>? configure = null)
    {
        var seed = new AuthorizationServerOptionsSeed();
        configure?.Invoke(seed);

        var clock = new MovableClock(seed.Now);
        var resolver = new TestClientResolver([.. seed.Clients]);
        var sink = new LogSink();

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();

                    // Registered before anything else, and at Trace, so a test asserting "one line"
                    // is measuring the server rather than the level filter.
                    services.AddSingleton<ILoggerProvider>(sink);
                    services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace));

                    services.AddSingleton(TestKeys.Ring());
                    services.AddSingleton<TimeProvider>(clock);

                    services.AddSingleton<IClientResolver>(resolver);

                    // The CIMD profile is the default, so AddBoltwayAuthorizationServer below
                    // registers a resolver that dereferences any client_id the TestClientResolver
                    // does not know. Supplying the fetcher here means this suite is hermetic by
                    // construction rather than by the accident that every client_id it currently
                    // uses happens to be seeded — the default refuses every URL.
                    services.AddSingleton(seed.Fetcher);
                    services.AddSingleton<IResourceRegistry>(new TestResourceRegistry().Add(Build.Resource, "mcp:tools").Add(Build.OtherResource, "mcp:tools"));
                    // Instances when a test shares them across two hosts, types otherwise — so an
                    // ordinary fixture still gets a clean set per test and cannot leak state sideways.
                    if (seed.Stores is { } shared)
                    {
                        services.AddSingleton<IGrantStore>(shared.Grants);
                        services.AddSingleton<IAuthorizationCodeStore>(shared.Codes);
                        services.AddSingleton<IRefreshTokenStore>(shared.RefreshTokens);
                        services.AddSingleton<IConsentStore>(shared.Consents);
                    }
                    else
                    {
                        services.AddSingleton<IGrantStore, InMemoryGrantStore>();
                        services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
                        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
                        services.AddSingleton<IConsentStore, TestConsentStore>();
                    }

                    // Registered for every fixture rather than only the private_key_jwt ones. It is
                    // consulted only by that method, and a startup check refuses the method without
                    // it — which this fixture triggered the first time an assertion test ran, being
                    // precisely the "host wiring stores by hand" the check's message names.
                    services.AddSingleton<Abstractions.Stores.IClientAssertionReplayStore>(
                        seed.Stores?.ClientAssertions ?? new InMemoryClientAssertionReplayStore());

                    services.AddSingleton<IConsentPolicy>(_ => new TestConsentPolicy(seed.Consent));
                    services.AddSingleton<IClientSecretStore>(new TestClientSecretStore(seed.ClientSecrets));
                    services.AddScoped<IUserSession>(_ => new TestUserSession(seed.SignedInUser));

                    // IUserStore is required at Map time whatever a deployment authenticates with.
                    // IPasswordHasher is not — a federation-only deployment registers none, and the
                    // startup condition accepts that as long as an IExternalIdentityProvider is
                    // there. It is registered here because most tests in this assembly want the
                    // ordinary shape; the federation suite removes it to build the other one.
                    //
                    // The shipped implementations, because a double here would test the fixture
                    // rather than the wiring.
                    services.AddSingleton<IUserStore>(new InMemoryUserStore());
                    services.AddSingleton<IRoleStore>(new InMemoryRoleStore());
                    services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());

                    // Last, so a test can replace any of the above. The login tests need the real
                    // cookie session rather than the seeded one — a test that asserts /login
                    // establishes a session cannot use a fixture that hands the session over for
                    // free, since it would pass with the endpoint deleted.
                    seed.ConfigureServices?.Invoke(services);


                    services.AddBoltwayAuthorizationServer(o =>
                    {
                        o.Issuer = Build.Issuer;
                        o.ScopesSupported.Add("openid");
                        o.ScopesSupported.Add("offline_access");
                        o.ScopesSupported.Add("mcp:tools");
                        o.RefreshTokenDerivationKey = seed.DerivationKey;

                        foreach (var (scope, description) in seed.ScopeDescriptions)
                        {
                            o.ScopeDescriptions[scope] = description;
                        }

                        seed.ConfigureOptions?.Invoke(o);
                    });
                })
                .Configure(app =>
                {
                    app.UseRouting();

                    // Between routing and the endpoints, which is where UseAuthentication belongs.
                    // The default pipeline has none: every other test supplies its session through
                    // TestUserSession, so nothing reads a cookie back.
                    seed.ConfigureApp?.Invoke(app);

                    app.UseEndpoints(e => e.MapBoltwayAuthorizationServer());
                }))
            .StartAsync();

        var client = new HttpClient(new CookieJarHandler(host.GetTestServer().CreateHandler()));

        // https, because the server means it. The antiforgery cookie is Secure and __Host- prefixed,
        // and TestServer's default http base address makes the antiforgery system throw rather than
        // silently issue a cookie a browser would reject. A fixture on http would have been testing
        // a deployment shape this server refuses to be.
        client.BaseAddress = new Uri("https://auth.example.com");

        return new FlowFixture(host, client) { Clock = clock, Clients = resolver, Logs = sink };
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}

/// <summary>What a test wants the server to start with.</summary>
internal sealed class AuthorizationServerOptionsSeed
{
    /// <summary>
    /// The one registered client. <b>Confidential by default, and that is a statement about
    /// what is not built yet.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// More than one may be registered — <see cref="Clients"/> — because a fixture with a single
    /// client makes cross-client attacks unrepresentable. Measured: with one client, mutations
    /// removing the code's and the refresh token's client-binding checks could not be killed by any
    /// test, because no test could present client A's credential as client B.
    /// </para>
    /// <para>
    /// A <i>public</i> client is sent to the consent page on every authorization, however the
    /// policy answered — RFC 8252 §8.6, enforced by the guard the endpoint composes. Since
    /// <c>/consent</c> (E-09) is not implemented, a public client cannot reach a code here, so the
    /// flow tests would have nowhere to go.
    /// </para>
    /// <para>
    /// Both vendors' MCP clients are public. So what these tests prove is that the two endpoints
    /// are correct, <b>not</b> that Claude or ChatGPT can complete a connection today — that needs
    /// the consent page. <c>A_public_client_is_sent_to_the_consent_page_even_when_already_granted</c>
    /// is what pins the behaviour they will actually hit.
    /// </para>
    /// <para>
    /// The type is Confidential while the authentication method stays <c>None</c>, which is a
    /// legitimate combination rather than a fudge: the consent guard keys off the client
    /// <i>type</i> and the authenticator keys off the registered <i>method</i>. They are independent
    /// axes, and this fixture exercises that.
    /// </para>
    /// </remarks>
    public ClientRecord Client
    {
        get => Clients[0];
        set => Clients[0] = value;
    }

    /// <summary>Every registered client. The first is the one the flow helpers use.</summary>
    public IList<ClientRecord> Clients { get; } = [Build.Client(type: ClientType.Confidential)];

    /// <summary>
    /// What the CIMD resolver's outbound fetches answer. Refuses everything unless a test replaces it.
    /// </summary>
    /// <remarks>
    /// Registered as <c>ISafeHttpFetcher</c> before <c>AddBoltwayAuthorizationServer</c>, whose
    /// CIMD registration uses <c>TryAdd</c> — so this wins, and no test in this assembly can open a
    /// socket by forgetting to seed a client.
    /// </remarks>
    public ISafeHttpFetcher Fetcher { get; set; } = new NoNetworkFetcher();

    /// <summary>Who is signed in when the authorization request arrives.</summary>
    public AuthenticatedUser? SignedInUser { get; set; } =
        new(SubjectId.FromStorage("user-1"), new DateTimeOffset(2026, 8, 4, 11, 0, 0, TimeSpan.Zero));

    /// <summary>Human descriptions for scopes, as the consent page renders them.</summary>
    public IDictionary<string, string> ScopeDescriptions { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>What the consent policy answers.</summary>
    public ConsentDecision Consent { get; set; } = ConsentDecision.AlreadyGranted;

    /// <summary>
    /// Client secrets, keyed by client id, in the wire form a client presents.
    /// </summary>
    /// <remarks>
    /// Empty by default, which keeps every existing fixture a public-client fixture. A test that
    /// seeds one gets a client that can actually authenticate — the case the suite could not
    /// express at all until mutation testing showed the success branch of <c>SecretAsync</c> had
    /// never executed. The value must be a real <c>ck_cs_</c> secret: the server parses it as an
    /// <c>OpaqueSecret</c> before comparing, so an arbitrary string fails on shape and never
    /// reaches the hash comparison the test means to exercise.
    /// </remarks>
    public IDictionary<string, string> ClientSecrets { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

    /// <summary>
    /// Extra service registrations, applied after the fixture's own and before the server's.
    /// </summary>
    /// <remarks>
    /// A hook rather than a flag, because what the login tests need — a user store, a password
    /// hasher, cookie authentication, and the real <see cref="IUserSession"/> in place of
    /// <see cref="TestUserSession"/> — is a set that would otherwise mean four booleans here and a
    /// dependency on the identity assembly from this file.
    /// </remarks>
    public Action<IServiceCollection>? ConfigureServices { get; set; }

    /// <summary>Extra middleware, between <c>UseRouting</c> and the endpoints.</summary>
    public Action<IApplicationBuilder>? ConfigureApp { get; set; }

    /// <summary>
    /// Extra server options, applied inside <c>AddBoltwayAuthorizationServer</c>.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="ConfigureServices"/> because <c>ExternalLoginOptions</c> is a nested
    /// object on the server's own options and is validated with them. A test that registered its own
    /// copy in the container instead would be configuring something the server does not read.
    /// </remarks>
    public Action<AuthorizationServerOptions>? ConfigureOptions { get; set; }

    /// <summary>Where the server's clock starts. After the seeded session's authentication.</summary>
    public DateTimeOffset Now { get; set; } = new(2026, 8, 4, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The refresh-token derivation key. Settable so a test can stand up a second instance that
    /// disagrees with the first.
    /// </summary>
    /// <remarks>
    /// The disagreement is the point. Both this option's XML doc and <c>RefreshTokenDeriver</c>'s
    /// require the key to be identical across every instance, and nothing verifies it — it is a bare
    /// <c>byte[]</c> property, which is the shape that invites
    /// <c>RandomNumberGenerator.GetBytes(32)</c> at startup. Until this seam existed the failure that
    /// produces was untestable, because one fixture is one process is one key.
    /// </remarks>
    public byte[] DerivationKey { get; set; } = Build.DerivationKey;

    /// <summary>
    /// Stores to share with another fixture, or <see langword="null"/> for a private set.
    /// </summary>
    /// <remarks>
    /// Two fixtures over one <see cref="SharedStores"/> is two authorization-server instances behind
    /// a load balancer sharing one database — the deployment shape this server is written for, and
    /// the one in which two racing refreshes land on <i>different</i> nodes by default. That is what
    /// makes them racers.
    /// </remarks>
    public SharedStores? Stores { get; set; }
}

/// <summary>One set of stores, shared by more than one fixture.</summary>
/// <remarks>
/// Held as instances rather than as types because <c>AddSingleton&lt;IGrantStore,
/// InMemoryGrantStore&gt;()</c> gives each host its own, and two hosts with private stores cannot
/// represent a multi-instance deployment at all.
/// </remarks>
internal sealed class SharedStores
{
    public InMemoryGrantStore Grants { get; } = new();

    public InMemoryAuthorizationCodeStore Codes { get; } = new();

    public InMemoryRefreshTokenStore RefreshTokens { get; } = new();

    public TestConsentStore Consents { get; } = new();

    /// <summary>
    /// Shared like the rest, which is what lets a test show a replay crossing two instances.
    /// </summary>
    /// <remarks>
    /// The in-memory replay store is per process, and a fleet of <i>n</i> replicas therefore admits
    /// <i>n</i> uses of one assertion. Sharing this instance is how a fixture models the deployment
    /// where that hole is closed — a single store behind two hosts — rather than the one where it is
    /// not.
    /// </remarks>
    public InMemoryClientAssertionReplayStore ClientAssertions { get; } = new();
}
