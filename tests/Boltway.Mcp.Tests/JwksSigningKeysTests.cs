using System.Text;
using Boltway.Mcp;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;
using RsOptions = Boltway.ResourceServer.Configuration.ProtectedResourceOptions;

namespace Boltway.Mcp.Tests;

/// <summary>
/// The DI seam that points a resource server's verification keys at the authorization server's
/// JWKS, and the startup decision it carries.
/// </summary>
/// <remarks>
/// These replace the tests for a <c>JwksRefresher</c> that lived in this package and duplicated
/// <see cref="JwksKeySource"/>. The properties worth keeping are the same three the old suite
/// asserted — a key set with nothing usable is fatal at startup, one with a key in it starts and
/// installs, and a failed fetch is fatal too — because they are the decision, not the
/// implementation. What is new is the fourth: the wiring resolves at all.
/// </remarks>
public sealed class JwksSigningKeysTests
{
    private const string Issuer = "https://auth.example.com";

    /// <summary>A JWKS the source should accept, from a real RSA key rather than a literal.</summary>
    private static string GoodJwks()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var jwk = Microsoft.IdentityModel.Tokens.JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = "k1" });
        jwk.Use = "sig";
        jwk.Alg = "RS256";

        return $$"""{"keys":[{{System.Text.Json.JsonSerializer.Serialize(new
        {
            kty = jwk.Kty, kid = jwk.Kid, use = jwk.Use, alg = jwk.Alg, n = jwk.N, e = jwk.E,
        })}}]}""";
    }

    private static FetchOutcome.Ok Json(string body)
    {
        _ = MediaType.TryParse("application/json", out var contentType);

        return new FetchOutcome.Ok(Encoding.UTF8.GetBytes(body), contentType, ETag: null, MaxAge: null);
    }

    private static string Discovery() =>
        $$"""{"issuer":"{{Issuer}}","jwks_uri":"{{Issuer}}/.well-known/jwks.json"}""";

    /// <summary>
    /// Builds a host wired the way a connector would wire one, with the guarded client replaced by
    /// a scripted one. The replacement is registered <i>before</i> the extension runs, so this also
    /// exercises the TryAdd: a deployment that brings its own transport keeps it.
    /// </summary>
    private static IHost Host(FetchOutcome jwks, FetchOutcome? discovery = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IUpstreamEndpointClient>(
            new ScriptedUpstream(discovery ?? Json(Discovery()), jwks));
        services.AddSingleton<IHostLifetime, NoopLifetime>();
        services.AddJwksSigningKeys(Issuer);

        return new HostBuilder()
            .ConfigureServices((_, s) =>
            {
                foreach (var d in services) s.Add(d);
            })
            .Build();
    }

    // -----------------------------------------------------------------------

    /// <summary>
    /// A 200 whose body parses to no signing key. Each of these is a successful fetch that
    /// withdraws everything, which is the case a two-valued "worked or failed" reading misses.
    /// </summary>
    public static TheoryData<string> NothingUsable() =>
    [
        """{"keys":[]}""",
        "{}",
        """{"error":"service unavailable"}""",
        """{"keys":[{"kty":"oct","k":"AA"}]}""",
    ];

    [Theory]
    [MemberData(nameof(NothingUsable))]
    public async Task A_key_set_with_nothing_usable_is_fatal_at_startup(string body)
    {
        using var host = Host(Json(body));

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => host.StartAsync(CancellationToken.None));

        Assert.Contains("401 that re-authenticating cannot fix", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Control for the theory above: a key set with a key in it starts, and the key reaches the
    /// options the validator reads. Without this the theory would pass against a wiring that
    /// refused everything.
    /// </summary>
    [Fact]
    public async Task A_key_set_with_a_key_in_it_starts_and_is_installed()
    {
        using var host = Host(Json(GoodJwks()));

        await host.StartAsync(CancellationToken.None);

        var options = host.Services.GetRequiredService<IOptions<RsOptions>>().Value;
        Assert.NotNull(options.SigningKeySource);
        Assert.Single(options.SigningKeySource!());

        await host.StopAsync(CancellationToken.None);
    }

    /// <summary>Control for the other direction: a fetch that failed is fatal too.</summary>
    [Fact]
    public async Task A_failed_fetch_is_fatal_at_startup()
    {
        using var host = Host(new FetchOutcome.NotOk(503));

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => host.StartAsync(CancellationToken.None));

        Assert.Contains("401 that re-authenticating cannot fix", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The wiring resolves without anything else registered, and that is the regression this test
    /// exists for. Moving the fetch behind the guarded client made this extension depend on
    /// <see cref="IUpstreamEndpointClient"/>, which at the time only the federation package
    /// registered — so a connector that called this and nothing else got an unresolvable
    /// dependency at startup. Nothing here registers a transport.
    /// </summary>
    [Fact]
    public void The_wiring_resolves_with_nothing_else_registered()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJwksSigningKeys(Issuer);

        using var provider = services.BuildServiceProvider(validateScopes: true);

        Assert.NotNull(provider.GetRequiredService<IUpstreamEndpointClient>());
        Assert.NotNull(provider.GetRequiredService<JwksKeySource>());
        Assert.NotNull(provider.GetRequiredService<IOptions<RsOptions>>().Value.SigningKeySource);
    }

    /// <summary>
    /// A bad issuer fails at wiring time. A configuration typo should fail the deploy rather than
    /// one caller's token validation, and this is the only moment at which that is still cheap.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not-a-url")]
    [InlineData("http://auth.example.com")]
    public void An_unusable_issuer_is_refused_where_it_is_configured(string issuer)
    {
        var thrown = Assert.Throws<ArgumentException>(
            () => new ServiceCollection().AddJwksSigningKeys(issuer));

        Assert.Equal("issuer", thrown.ParamName);
    }

    // -----------------------------------------------------------------------

    /// <summary>The guarded client, scripted: one answer for discovery, one for the key set.</summary>
    private sealed class ScriptedUpstream(FetchOutcome discovery, FetchOutcome jwks) : IUpstreamEndpointClient
    {
        public Task<FetchOutcome> GetAsync(UpstreamDocumentRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(request.Url.ToString().Contains("openid-configuration", StringComparison.Ordinal)
                ? discovery
                : jwks);

        // Not reachable: this seam reads documents and never posts a credentialed form. Throwing
        // rather than answering plausibly, so a future caller that does POST is a failed test.
        public Task<FetchOutcome> PostFormAsync(UpstreamFormRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException("The key source fetches documents only.");
    }

    /// <summary>Keeps <c>IHost.StartAsync</c> from waiting on a console lifetime.</summary>
    private sealed class NoopLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
