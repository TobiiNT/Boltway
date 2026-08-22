using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Boltway.Mcp;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using RsOptions = Boltway.ResourceServer.Configuration.ProtectedResourceOptions;

namespace Boltway.Mcp.Tests;

/// <summary>
/// What <see cref="JwksRefresher"/> does with a fetch that succeeded and produced no key.
/// </summary>
/// <remarks>
/// A refresh has three outcomes and only two were distinguished: it fails, it succeeds with keys,
/// or it succeeds with none. The third arrived as the second — a rotation that happened to withdraw
/// everything — so an empty or unparsable key set came up clean at startup with zero keys trusted,
/// and withdrew a working key mid-flight at Information level. Both are the failure the class doc
/// says this type exists to prevent: a 401 that re-authenticating cannot fix.
/// </remarks>
public sealed class JwksRefreshTests
{
    /// <summary>A JWKS the refresher should accept, from a real RSA key rather than a literal.</summary>
    private static string GoodJwks()
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = "k1" });
        jwk.Use = "sig";
        jwk.Alg = "RS256";

        return $$"""{"keys":[{{JsonSerializer.Serialize(new
        {
            kty = jwk.Kty,
            kid = jwk.Kid,
            use = jwk.Use,
            alg = jwk.Alg,
            n = jwk.N,
            e = jwk.E,
        })}}]}""";
    }

    private static JwksRefresher Refresher(Upstream upstream, RsOptions options, TimeSpan? interval = null) =>
        new(upstream, Options.Create(options), NullLogger<JwksRefresher>.Instance,
            "https://auth.example.com", interval ?? TimeSpan.FromMinutes(5));

    /// <summary>A 200 carrying <paramref name="body"/>, as the guarded client would report it.</summary>
    private static FetchOutcome.Ok Json(string body)
    {
        _ = MediaType.TryParse("application/json", out var contentType);

        return new FetchOutcome.Ok(Encoding.UTF8.GetBytes(body), contentType, ETag: null, MaxAge: null);
    }

    // A 200 whose body parses to no signing key. Each of these reached the old code as a
    // successful refresh; the last is a set holding a key that is not one you can verify with.
    public static TheoryData<string> NothingUsable() =>
    [
        """{"keys":[]}""",
        "{}",
        """{"error":"service unavailable"}""",
        """{"keys":[{"kty":"oct","k":"AA"}]}""",
    ];

    /// <summary>Startup refuses it, which is what "deliberately fatal" was already supposed to mean.</summary>
    [Theory]
    [MemberData(nameof(NothingUsable))]
    public async Task A_key_set_with_nothing_usable_is_fatal_at_startup(string body)
    {
        var refresher = Refresher(new Upstream(Json(body)), new RsOptions());

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => refresher.StartAsync(CancellationToken.None));

        Assert.Contains("no usable signing key", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Control for the pair above: a key set with a key in it still starts, and installs it.
    /// Without this the test would pass just as well against a refresher that refused everything.
    /// </summary>
    [Fact]
    public async Task A_key_set_with_a_key_in_it_starts_and_is_installed()
    {
        var options = new RsOptions();
        var refresher = Refresher(new Upstream(Json(GoodJwks())), options);

        await refresher.StartAsync(CancellationToken.None);
        await refresher.StopAsync(CancellationToken.None);

        Assert.Single(options.SigningKeySource!());
    }

    /// <summary>
    /// Control for the other direction: the fatal branch existed and worked for a fetch that
    /// failed. It is the 200-with-no-key case it did not cover, so a transport failure must still
    /// throw after the change.
    /// </summary>
    /// <remarks>
    /// The exception type moved from <c>HttpRequestException</c> to <c>InvalidOperationException</c>
    /// when the fetch moved behind the guarded client, and that is the guarded client's contract
    /// rather than a weakening: it <i>reports</i> a refusal as a <c>FetchOutcome</c> instead of
    /// throwing, so that a caller has to decide what a failure means rather than inherit a decision
    /// from the transport. Here the decision is unchanged — startup is still fatal.
    /// </remarks>
    [Fact]
    public async Task A_failed_fetch_is_still_fatal_at_startup()
    {
        var refresher = Refresher(new Upstream(new FetchOutcome.NotOk(500)), new RsOptions());

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => refresher.StartAsync(CancellationToken.None));

        Assert.Contains("could not be fetched", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Mid-flight, the keys already trusted survive it. Withdrawing every key at once is the
    /// outage; keeping them until a refresh actually produces some is the same thing the existing
    /// catch does for a fetch that failed, which is why this case is thrown rather than returned.
    /// </summary>
    [Fact]
    public async Task An_empty_refresh_mid_flight_keeps_the_keys_already_trusted()
    {
        var options = new RsOptions();
        var upstream = new Upstream(Json(GoodJwks()));
        var refresher = Refresher(upstream, options, TimeSpan.FromMilliseconds(50));

        await refresher.StartAsync(CancellationToken.None);
        Assert.Single(options.SigningKeySource!());

        // Every fetch from here on is the empty set. Waiting on the handler rather than on a
        // duration, so this does not become a test that passes when the machine is fast.
        upstream.Outcome = Json("""{"keys":[]}""");
        await upstream.NextRequest.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Single(options.SigningKeySource!());

        await refresher.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// The guarded client, scripted. Answers every document request with <see cref="Outcome"/>, which
    /// a test may move mid-flight, and signals each call so a test can wait on the refresher having
    /// fetched rather than on a duration.
    /// </summary>
    private sealed class Upstream(FetchOutcome outcome) : IUpstreamEndpointClient
    {
        private TaskCompletionSource _next = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FetchOutcome Outcome { get; set; } = outcome;

        /// <summary>Completes on the next fetch this client serves.</summary>
        public Task NextRequest => Volatile.Read(ref _next).Task;

        public Task<FetchOutcome> GetAsync(UpstreamDocumentRequest request, CancellationToken cancellationToken)
        {
            var answer = Outcome;

            Interlocked.Exchange(ref _next, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously))
                .TrySetResult();

            return Task.FromResult(answer);
        }

        // Not reachable: a refresher reads a document and never posts a credentialed form. Throwing
        // rather than returning something plausible, so a future caller that does POST is a failed
        // test rather than a silent answer nobody wrote.
        public Task<FetchOutcome> PostFormAsync(UpstreamFormRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException("The refresher fetches documents only.");
    }
}
