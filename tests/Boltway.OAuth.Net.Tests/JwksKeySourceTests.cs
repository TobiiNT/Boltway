using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Boltway.OAuth.Primitives.Http;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Net.Tests;

/// <summary>
/// The refresher that keeps a resource server accepting tokens across a key rotation.
/// </summary>
/// <remarks>
/// <para>
/// The defect this type exists to remove is not a crash. It is a resource server that has been
/// correct for months, rejecting every token from the minute the authorization server rotated,
/// with a diagnosis — <c>IDX10500</c> — that reads like a missing key rather than a stale one. So
/// the assertions worth making are about the <i>states</i> around a fetch, not about the fetch: an
/// empty snapshot, a stale one, a failed refresh, and a document that parses to nothing.
/// </para>
/// <para>
/// <b>Three of these use a scripted client rather than a socket, and one does not.</b> The scripted
/// ones drive time and failure — a real listener cannot be made to fail in eight specific ways
/// without becoming the thing under test. The last one goes through the real
/// <see cref="GuardedTransport"/> against real TLS, because "the wire path works" is not something
/// a double can establish, and this file would otherwise prove only that a state machine agrees
/// with itself.
/// </para>
/// </remarks>
public sealed class JwksKeySourceTests : IDisposable
{
    private const string Issuer = "https://as.example.test";

    private readonly List<IDisposable> _disposables = [];

    public void Dispose()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }
    }

    /// <summary>A client that answers from a script, and counts what it was asked for.</summary>
    private sealed class ScriptedClient(Dictionary<string, FetchOutcome> answers) : IUpstreamEndpointClient
    {
        private readonly Dictionary<string, FetchOutcome> _answers = answers;

        public List<string> Requested { get; } = [];

        public Dictionary<string, FetchOutcome> Answers => _answers;

        public Task<FetchOutcome> GetAsync(UpstreamDocumentRequest request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);
            Requested.Add(request.Url.Value);

            return Task.FromResult(
                _answers.TryGetValue(request.Url.Value, out var answer)
                    ? answer
                    : new FetchOutcome.NotOk(404));
        }

        public Task<FetchOutcome> PostFormAsync(UpstreamFormRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException("A key source never posts.");
    }

    private static FetchOutcome.Ok Json(string body)
    {
        _ = MediaType.TryParse("application/json", out var contentType);

        return new FetchOutcome.Ok(Encoding.UTF8.GetBytes(body), contentType, ETag: null, MaxAge: null);
    }

    private static string DiscoveryDocument(string issuer, string jwksUri) =>
        $$"""{"issuer":"{{issuer}}","jwks_uri":"{{jwksUri}}"}""";

    /// <summary>A JWKS carrying one usable RSA signing key, plus whatever extra members are asked for.</summary>
    private static string KeySet(string kid, string? extraKey = null)
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);

        var key = $$"""
            {"kty":"RSA","use":"sig","alg":"RS256","kid":"{{kid}}",
             "n":"{{Base64UrlEncoder.Encode(parameters.Modulus!)}}",
             "e":"{{Base64UrlEncoder.Encode(parameters.Exponent!)}}"}
            """;

        return $$"""{"keys":[{{key}}{{(extraKey is null ? "" : "," + extraKey)}}]}""";
    }

    private static (JwksKeySource Source, ScriptedClient Client, MovableClock Clock) NewSource(
        string? discoveryBody = null,
        string? jwksBody = null,
        JwksKeySourceOptions? options = null)
    {
        const string JwksUrl = Issuer + "/.well-known/jwks.json";

        var answers = new Dictionary<string, FetchOutcome>(StringComparer.Ordinal)
        {
            [Issuer + "/.well-known/openid-configuration"] =
                Json(discoveryBody ?? DiscoveryDocument(Issuer, JwksUrl)),
            [JwksUrl] = Json(jwksBody ?? KeySet("k1")),
        };

        var client = new ScriptedClient(answers);
        var clock = new MovableClock(DateTimeOffset.Parse("2026-08-22T00:00:00Z", null));

        _ = IssuerString.TryCreate(Issuer, out var issuer, out _);

        return (new JwksKeySource(issuer, client, options, clock), client, clock);
    }

    /// <summary>
    /// Before anything is fetched there are no keys, and asking does not throw or block.
    /// </summary>
    /// <remarks>
    /// The empty snapshot is deliberately not an exception. A resource server that has not fetched
    /// yet rejects tokens, which is right; a resource server that throws out of its key lookup
    /// returns 500 to a caller holding a perfectly good token, which is not.
    /// </remarks>
    [Fact]
    public void A_cold_source_has_no_keys_and_answers_anyway()
    {
        var (source, _, _) = NewSource();
        _disposables.Add(source);

        // Status first, and the order is the assertion rather than style. CurrentKeys() starts a
        // background refresh on a stale snapshot — that is its documented job — so a status read
        // after it races that refresh instead of describing the cold state. Against a scripted
        // client the refresh wins often enough that this failed on a loaded machine while passing
        // everywhere else, which is the worst version of a broken test.
        Assert.Equal(0, source.Status.KeyCount);
        Assert.Null(source.Status.LastSuccessAt);

        Assert.Empty(source.CurrentKeys());
    }

    /// <summary>Discovery is read, the issuer checked, and the key set fetched from what it names.</summary>
    [Fact]
    public async Task A_refresh_walks_discovery_to_the_key_set()
    {
        var (source, client, _) = NewSource();
        _disposables.Add(source);

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Refreshed, refresh.Outcome);
        Assert.Equal(1, refresh.KeyCount);
        Assert.Single(source.CurrentKeys());

        Assert.Equal(
            [Issuer + "/.well-known/openid-configuration", Issuer + "/.well-known/jwks.json"],
            client.Requested);
    }

    /// <summary>
    /// A discovery document naming a different issuer is refused, and no key is fetched from it.
    /// </summary>
    /// <remarks>
    /// OIDC Discovery §4.3. The member this check guards names the URL whose contents will verify
    /// every token this resource server accepts, so a document that is not about the configured
    /// issuer must not get as far as being read for it. The second assertion is the load-bearing
    /// one: refusing after the fetch would still have made the request.
    /// </remarks>
    [Fact]
    public async Task A_discovery_document_for_another_issuer_is_refused_before_its_jwks_uri_is_read()
    {
        var (source, client, _) = NewSource(
            discoveryBody: DiscoveryDocument("https://elsewhere.example.test", "https://elsewhere.example.test/jwks"));
        _disposables.Add(source);

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Failed, refresh.Outcome);
        Assert.Contains("declares issuer", refresh.Detail, StringComparison.Ordinal);
        Assert.Empty(source.CurrentKeys());

        Assert.DoesNotContain("https://elsewhere.example.test/jwks", client.Requested, StringComparer.Ordinal);
    }

    /// <summary>A configured JWKS URL means no discovery request is ever made.</summary>
    [Fact]
    public async Task A_configured_jwks_uri_skips_discovery_entirely()
    {
        var (source, client, _) = NewSource(
            options: new JwksKeySourceOptions { JwksUri = Issuer + "/.well-known/jwks.json" });
        _disposables.Add(source);

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Refreshed, refresh.Outcome);
        Assert.Equal([Issuer + "/.well-known/jwks.json"], client.Requested);
    }

    /// <summary>
    /// A failed fetch keeps the keys already held, and says so rather than emptying the snapshot.
    /// </summary>
    /// <remarks>
    /// This is the same shape as <c>IntrospectionRevocationCheck</c> failing open, and it wants the
    /// same alert: the keys held are still the ones the authorization server published, and
    /// rejecting every token because a refresh failed converts a fetch problem into a total outage.
    /// What must not happen is silence, which is why the failure and its time are on
    /// <see cref="JwksKeySource.Status"/>.
    /// </remarks>
    [Fact]
    public async Task A_failed_refresh_keeps_the_keys_it_already_had()
    {
        var (source, client, clock) = NewSource();
        _disposables.Add(source);

        await source.RefreshAsync(CancellationToken.None);
        var before = source.CurrentKeys();

        client.Answers[Issuer + "/.well-known/jwks.json"] = new FetchOutcome.NotOk(503);
        clock.Advance(TimeSpan.FromMinutes(10));

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Failed, refresh.Outcome);
        Assert.Equal(1, refresh.KeyCount);
        Assert.Same(before, source.CurrentKeys());
        Assert.Equal("jwks fetch: status 503", source.Status.LastFailureDetail);
        Assert.NotNull(source.Status.LastFailureAt);
    }

    /// <summary>
    /// A key set that parses to no signing keys is a failure, not an empty snapshot.
    /// </summary>
    /// <remarks>
    /// At this layer a document carrying only encryption keys — or one served by something that is
    /// not the authorization server at all — is indistinguishable from a rotation that removed
    /// every key, and only one of those readings is safe to act on.
    /// </remarks>
    [Fact]
    public async Task A_key_set_with_nothing_to_verify_with_does_not_replace_good_keys()
    {
        var (source, client, clock) = NewSource();
        _disposables.Add(source);

        await source.RefreshAsync(CancellationToken.None);

        client.Answers[Issuer + "/.well-known/jwks.json"] = Json("""{"keys":[]}""");
        clock.Advance(TimeSpan.FromMinutes(10));

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Failed, refresh.Outcome);
        Assert.Equal("jwks document carries no signing keys", refresh.Detail);
        Assert.Single(source.CurrentKeys());
    }

    /// <summary>Inside its lifetime, a second refresh makes no request at all.</summary>
    [Fact]
    public async Task A_fresh_snapshot_is_not_refetched()
    {
        var (source, client, clock) = NewSource();
        _disposables.Add(source);

        await source.RefreshAsync(CancellationToken.None);
        var requestsAfterFirst = client.Requested.Count;

        clock.Advance(TimeSpan.FromMinutes(1));
        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.StillFresh, refresh.Outcome);
        Assert.Equal(requestsAfterFirst, client.Requested.Count);
    }

    /// <summary>
    /// Past the lifetime, the new key set replaces the old one — which is the rotation this exists for.
    /// </summary>
    [Fact]
    public async Task Past_the_lifetime_a_rotated_key_set_is_picked_up()
    {
        var (source, client, clock) = NewSource();
        _disposables.Add(source);

        await source.RefreshAsync(CancellationToken.None);
        Assert.Equal("k1", source.CurrentKeys()[0].KeyId);

        client.Answers[Issuer + "/.well-known/jwks.json"] = Json(KeySet("k2"));
        clock.Advance(TimeSpan.FromMinutes(6));

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Refreshed, refresh.Outcome);
        Assert.Equal("k2", source.CurrentKeys()[0].KeyId);
    }

    /// <summary>
    /// After a failure, the retry interval bounds how often a dead authorization server is asked.
    /// </summary>
    /// <remarks>
    /// The case this is really about is a cold start against an authorization server that is down.
    /// The snapshot is empty, so every inbound request finds the source due for a refresh; without a
    /// floor, a resource server under load becomes a load generator aimed at the one component every
    /// one of its own requests already depends on.
    /// </remarks>
    [Fact]
    public async Task A_failure_is_not_retried_until_the_retry_interval_has_passed()
    {
        var (source, client, clock) = NewSource();
        _disposables.Add(source);

        client.Answers[Issuer + "/.well-known/openid-configuration"] = new FetchOutcome.NotOk(500);

        var first = await source.RefreshAsync(CancellationToken.None);
        Assert.Equal(JwksRefreshOutcome.Failed, first.Outcome);

        var requests = client.Requested.Count;

        clock.Advance(TimeSpan.FromSeconds(31));
        var second = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.BackingOff, second.Outcome);
        Assert.Equal(requests, client.Requested.Count);

        clock.Advance(TimeSpan.FromSeconds(30));
        var third = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Failed, third.Outcome);
        Assert.True(client.Requested.Count > requests);
    }

    /// <summary>
    /// <c>CurrentKeys</c> is the request path, so it starts a refresh rather than waiting for one.
    /// </summary>
    /// <remarks>
    /// The assertion is deliberately two-part: the call returns the stale snapshot <i>immediately</i>
    /// — the request that noticed is not the one that pays — and the new keys are in place shortly
    /// afterwards for the requests that follow.
    /// </remarks>
    [Fact]
    public async Task Reading_a_stale_snapshot_starts_a_refresh_without_waiting_for_it()
    {
        var (source, client, clock) = NewSource();
        _disposables.Add(source);

        await source.RefreshAsync(CancellationToken.None);
        client.Answers[Issuer + "/.well-known/jwks.json"] = Json(KeySet("k2"));
        clock.Advance(TimeSpan.FromMinutes(6));

        // Returns the old snapshot, and does not block on the fetch it just started. This half is
        // the one with no timing in it: it is true on the first call or not at all.
        Assert.Equal("k1", source.CurrentKeys()[0].KeyId);

        // Thirty seconds to observe work that takes microseconds, because the refresh runs on the
        // thread pool and this suite is one of fourteen assemblies the solution runs at once — under
        // that contention a queued work item can wait far longer than the operation itself. The
        // ceiling is not a guess at how long the fetch takes; it is a bound on how long a starved
        // pool may take to get to it. A source that never starts the refresh still fails, just
        // later, and the assertion below names both keys when it does.
        var deadline = DateTime.UtcNow.AddSeconds(30);

        while (source.CurrentKeys()[0].KeyId is "k1" && DateTime.UtcNow < deadline)
        {
            await Task.Delay(25);
        }

        Assert.Equal("k2", source.CurrentKeys()[0].KeyId);
    }

    /// <summary>
    /// An unset issuer and an unusable configured URL are both refused at construction.
    /// </summary>
    /// <remarks>
    /// Refuse-at-startup, on the precedent every other misconfiguration here follows: the
    /// alternative is a resource server that binds, serves its metadata document, and rejects every
    /// token — which presents as an authentication problem rather than as the configuration error it
    /// is.
    /// </remarks>
    [Fact]
    public void An_unusable_configuration_is_refused_at_construction()
    {
        var client = new ScriptedClient([]);

        Assert.Throws<ArgumentException>(() => new JwksKeySource(default, client));

        _ = IssuerString.TryCreate(Issuer, out var issuer, out _);

        Assert.Throws<ArgumentException>(
            () => new JwksKeySource(issuer, client, new JwksKeySourceOptions { JwksUri = "http://as.example.test/jwks" }));
    }

    /// <summary>
    /// The whole path, over real TLS through the real guarded transport.
    /// </summary>
    /// <remarks>
    /// Everything above is a state machine agreeing with itself. This is the one that would catch a
    /// wrong <c>FetchPurpose</c> cap, a transport that refuses the address, or a response this code
    /// cannot actually read — none of which a scripted client can fail on.
    /// </remarks>
    [Fact]
    public async Task The_whole_path_works_over_a_real_connection()
    {
        var keySet = KeySet("live-1");

        using var listener = new PathListener();

        // The discovery document has to name the port, and the port is only known once the socket is
        // bound — so the responder is set after construction rather than passed into it.
        var origin = $"https://localhost:{listener.Port}";

        listener.Respond = request => request.Contains("openid-configuration", StringComparison.Ordinal)
            ? DiscoveryDocument(origin, origin + "/jwks")
            : keySet;

        var http = new UpstreamEndpointClient(
            new UpstreamEndpointClientOptions
            {
                AllowPrivateAddresses = true,
                ConnectTimeout = TimeSpan.FromSeconds(30),
                TotalTimeout = TimeSpan.FromSeconds(60),
                SslOptionsForTests = TlsTestCertificate.ClientOptions(),
            },
            new LoopbackResolver());

        _disposables.Add(http);

        _ = IssuerString.TryCreate(origin, out var issuer, out _);

        using var source = new JwksKeySource(issuer, http);

        var refresh = await source.RefreshAsync(CancellationToken.None);

        Assert.Equal(JwksRefreshOutcome.Refreshed, refresh.Outcome);
        Assert.Equal(1, refresh.KeyCount);
        Assert.Equal("live-1", source.CurrentKeys()[0].KeyId);
    }

    private sealed class LoopbackResolver : IAddressResolver
    {
        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
    }

    /// <summary>A TLS listener that answers differently per request path, for the two-hop fetch.</summary>
    private sealed class PathListener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _stop = new();

        public PathListener()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _socket.Listen(8);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;

            _ = Task.Run(AcceptAsync, _stop.Token);
        }

        public int Port { get; }

        /// <summary>What to answer, given the whole request. Set after construction; see the test.</summary>
        public Func<string, string> Respond { get; set; } = _ => "{}";

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                Socket client;

                try
                {
                    client = await _socket.AcceptAsync(_stop.Token);
                }
                catch
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            await using var tls = await TlsTestCertificate.WrapAsync(client, _stop.Token);

                            var buffer = new byte[16 * 1024];
                            var read = await tls.ReadAsync(buffer, _stop.Token);
                            var request = Encoding.UTF8.GetString(buffer, 0, read);
                            var bytes = Encoding.UTF8.GetBytes(Respond(request));
                            var head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                + $"Content-Length: {bytes.Length}\r\nConnection: close\r\n\r\n";

                            await tls.WriteAsync(
                                new ReadOnlyMemory<byte>([.. Encoding.UTF8.GetBytes(head), .. bytes]), _stop.Token);
                        }
                        catch
                        {
                            // The client hanging up is not this listener's problem to report.
                        }
                    }
                }, _stop.Token);
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _socket.Dispose();
            _stop.Dispose();
        }
    }
}
