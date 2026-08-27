using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Boltway.OAuth.Net;

namespace Boltway.OAuth.Net.Tests;

/// <summary>
/// The credentialed POST, against a real TLS listener that records what it was sent.
/// </summary>
/// <remarks>
/// <para>
/// The whole reason this file exists is that <c>SafeHttpFetcher</c> is GET-only by construction -
/// <c>HttpMethod.Get</c> was hardcoded - and federation needs a POST carrying a client secret. The
/// interesting assertions are therefore not "the POST arrives" but the two properties that make it
/// safe to have added: the guards that still apply, and the fact that the secret reaches the socket
/// and nowhere else.
/// </para>
/// <para>
/// Every listener here speaks real TLS and every request goes through the real
/// <see cref="GuardedTransport"/>. A test double for the transport would prove nothing about the
/// thing the architecture rule exists to protect.
/// </para>
/// </remarks>
public sealed class UpstreamEndpointClientTests : IDisposable
{
    private const string Secret = "ck_upstream_sEcReT_do_not_log_9f3a2b";

    /// <summary>A TLS listener that captures the whole request and answers one canned response.</summary>
    private sealed class RecordingListener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _stop = new();
        private readonly Func<byte[]> _respond;

        public RecordingListener(Func<byte[]> respond)
        {
            _respond = respond;
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _socket.Listen(8);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;

            _ = Task.Run(AcceptAsync, _stop.Token);
        }

        public int Port { get; }

        /// <summary>Everything the client sent, headers and body, as one string.</summary>
        public string Received { get; private set; } = string.Empty;

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                Socket client;
                try { client = await _socket.AcceptAsync(_stop.Token); }
                catch { return; }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            await using var tls = await TlsTestCertificate.WrapAsync(client, _stop.Token);

                            var buffer = new byte[16 * 1024];
                            var read = await tls.ReadAsync(buffer, _stop.Token);

                            // One read is enough: these requests are a few hundred bytes and arrive
                            // in a single segment on loopback. A short read would show up as a
                            // missing assertion rather than a silent pass, because every test below
                            // asserts on specific content.
                            Received = Encoding.UTF8.GetString(buffer, 0, read);

                            await tls.WriteAsync(_respond(), _stop.Token);
                        }
                        catch
                        {
                            // Expected when the client hangs up on a capped or refused response.
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

    private sealed class FixedResolver(IPAddress answer) : IAddressResolver
    {
        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([answer]);
    }

    private static byte[] Response(string status, string body, string? extraHeader = null)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var head = new StringBuilder()
            .Append("HTTP/1.1 ").Append(status).Append("\r\n")
            .Append("Content-Type: application/json\r\n")
            .Append("Content-Length: ").Append(bytes.Length).Append("\r\n");

        if (extraHeader is not null)
        {
            head.Append(extraHeader).Append("\r\n");
        }

        head.Append("Connection: close\r\n\r\n");

        return [.. Encoding.UTF8.GetBytes(head.ToString()), .. bytes];
    }

    private readonly List<IDisposable> _disposables = [];

    private UpstreamEndpointClient NewClient(bool allowPrivateAddresses = true)
    {
        var client = new UpstreamEndpointClient(
            new UpstreamEndpointClientOptions
            {
                AllowPrivateAddresses = allowPrivateAddresses,
                ConnectTimeout = TimeSpan.FromSeconds(30),
                TotalTimeout = TimeSpan.FromSeconds(60),
                SslOptionsForTests = TlsTestCertificate.ClientOptions(),
            },
            new FixedResolver(IPAddress.Loopback));

        _disposables.Add(client);
        return client;
    }

    private static UpstreamFormRequest TokenRequest(
        int port,
        UpstreamClientAuthMethod method = UpstreamClientAuthMethod.ClientSecretPost,
        bool withSecret = true)
    {
        Assert.True(AbsoluteHttpsUrl.TryCreate($"https://probe.example:{port}/token", out var url));

        return new UpstreamFormRequest(
            url,
            FetchPurpose.UpstreamTokenExchange,
            [
                new("grant_type", "authorization_code"),
                new("code", "upstream-code"),
                new("redirect_uri", "https://auth.example.com/external/google/callback"),
                new("code_verifier", "verifier-value"),
            ])
        {
            ClientId = "client-at-upstream",
            ClientSecret = withSecret ? new UpstreamClientSecret(Secret) : null,
            AuthMethod = method,
        };
    }

    // ------------------------------------------------------------------ the POST itself

    [Fact]
    public async Task A_client_secret_post_exchange_sends_the_form_and_the_credential_in_the_body()
    {
        using var listener = new RecordingListener(() => Response("200 OK", "{\"id_token\":\"x\"}"));

        var outcome = await NewClient().PostFormAsync(TokenRequest(listener.Port), CancellationToken.None);

        Assert.IsType<FetchOutcome.Ok>(outcome);

        Assert.StartsWith("POST /token HTTP/1.1", listener.Received, StringComparison.Ordinal);
        Assert.Contains("grant_type=authorization_code", listener.Received, StringComparison.Ordinal);
        Assert.Contains("code=upstream-code", listener.Received, StringComparison.Ordinal);
        Assert.Contains("code_verifier=verifier-value", listener.Received, StringComparison.Ordinal);
        Assert.Contains("client_id=client-at-upstream", listener.Received, StringComparison.Ordinal);

        // The credential is on the wire, which is the one place it is supposed to be.
        Assert.Contains("client_secret=" + Secret, listener.Received, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization:", listener.Received, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_client_secret_basic_exchange_sends_the_credential_in_the_header_and_not_the_body()
    {
        using var listener = new RecordingListener(() => Response("200 OK", "{\"id_token\":\"x\"}"));

        var outcome = await NewClient().PostFormAsync(
            TokenRequest(listener.Port, UpstreamClientAuthMethod.ClientSecretBasic), CancellationToken.None);

        Assert.IsType<FetchOutcome.Ok>(outcome);

        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            Uri.EscapeDataString("client-at-upstream") + ":" + Uri.EscapeDataString(Secret)));

        Assert.Contains("Authorization: Basic " + expected, listener.Received, StringComparison.Ordinal);

        // Not in both places. Sending it twice would be a second copy to leak and some upstreams
        // reject a request that authenticates two ways.
        Assert.DoesNotContain("client_secret=", listener.Received, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_public_upstream_client_sends_no_credential_at_all()
    {
        using var listener = new RecordingListener(() => Response("200 OK", "{\"id_token\":\"x\"}"));

        var outcome = await NewClient().PostFormAsync(
            TokenRequest(listener.Port, withSecret: false), CancellationToken.None);

        Assert.IsType<FetchOutcome.Ok>(outcome);
        Assert.Contains("client_id=client-at-upstream", listener.Received, StringComparison.Ordinal);
        Assert.DoesNotContain("client_secret", listener.Received, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization:", listener.Received, StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------------ the guards that still apply

    [Fact]
    public async Task A_redirect_from_the_token_endpoint_is_reported_and_not_followed()
    {
        // The sharpest of the retained guards. AllowAutoRedirect defaults to true in .NET, and a
        // followed 302 would re-send the whole request - credential included - to whatever Location
        // named. There is no legitimate redirect on this path.
        using var listener = new RecordingListener(
            () => Response("302 Found", "", "Location: https://evil.example/collect"));

        var outcome = await NewClient().PostFormAsync(TokenRequest(listener.Port), CancellationToken.None);

        var redirected = Assert.IsType<FetchOutcome.Redirected>(outcome);

        Assert.Equal(302, redirected.Status);
        Assert.Equal("https://evil.example/collect", redirected.Location);
    }

    [Fact]
    public async Task A_token_response_over_the_cap_is_refused_while_being_read()
    {
        using var listener = new RecordingListener(() => Response("200 OK", new string('x', 4096)));

        Assert.True(AbsoluteHttpsUrl.TryCreate($"https://probe.example:{listener.Port}/token", out var url));

        var request = new UpstreamFormRequest(url, FetchPurpose.UpstreamTokenExchange, [])
        {
            ClientId = "client-at-upstream",
            ClientSecret = new UpstreamClientSecret(Secret),
            MaxBytes = 1024,
        };

        Assert.IsType<FetchOutcome.TooLarge>(await NewClient().PostFormAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task A_non_200_from_the_token_endpoint_is_a_status_and_not_a_body()
    {
        // An upstream answering `invalid_grant` is a 400, and the caller has to be able to tell that
        // apart from a transport failure - one is the code being wrong, the other is the network.
        using var listener = new RecordingListener(
            () => Response("400 Bad Request", "{\"error\":\"invalid_grant\"}"));

        var outcome = await NewClient().PostFormAsync(TokenRequest(listener.Port), CancellationToken.None);

        Assert.Equal(400, Assert.IsType<FetchOutcome.NotOk>(outcome).Status);
    }

    [Fact]
    public async Task A_private_address_is_blocked_when_the_deployment_has_not_opted_in()
    {
        // The one guard that differs from the CIMD fetcher. Every other test in this file passes
        // AllowPrivateAddresses = true precisely because this refuses loopback.
        using var listener = new RecordingListener(() => Response("200 OK", "{}"));

        var outcome = await NewClient(allowPrivateAddresses: false)
            .PostFormAsync(TokenRequest(listener.Port), CancellationToken.None);

        var blocked = Assert.IsType<FetchOutcome.Blocked>(outcome);

        Assert.Equal(BlockReason.SpecialUseAddress, blocked.Reason);
        Assert.Equal(string.Empty, listener.Received);
    }

    /// <summary>
    /// And the shipped default is the refusing one.
    /// </summary>
    /// <remarks>
    /// A separate test because the one above does not prove it, and that was measured rather than
    /// reasoned: flipping the default to <see langword="true"/> left it green, because it passes the
    /// value explicitly. "Blocked when you ask for blocking" and "blocked unless you ask for the
    /// opposite" are different claims, and only the second one is what a deployment gets by not
    /// thinking about it.
    /// </remarks>
    [Fact]
    public void The_default_is_to_block_private_addresses()
    {
        Assert.False(new UpstreamEndpointClientOptions().AllowPrivateAddresses);

        // The same default the CIMD fetcher has, for different reasons - see the two option
        // classes. Asserted together so a change to either is a change to this line.
        Assert.False(new SafeHttpFetcherOptions().AllowPrivateAddresses);
    }

    [Fact]
    public async Task A_discovery_get_carries_no_body_and_no_credential()
    {
        using var listener = new RecordingListener(() => Response("200 OK", "{\"issuer\":\"https://probe.example\"}"));

        Assert.True(AbsoluteHttpsUrl.TryCreate(
            $"https://probe.example:{listener.Port}/.well-known/openid-configuration", out var url));

        var outcome = await NewClient().GetAsync(
            new UpstreamDocumentRequest(url, FetchPurpose.UpstreamDiscovery), CancellationToken.None);

        Assert.IsType<FetchOutcome.Ok>(outcome);
        Assert.StartsWith("GET /.well-known/openid-configuration", listener.Received, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, listener.Received, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization:", listener.Received, StringComparison.OrdinalIgnoreCase);
    }

    // ------------------------------------------------------------------ the secret goes nowhere else

    /// <summary>
    /// No failure outcome carries anything derived from the credential.
    /// </summary>
    /// <remarks>
    /// The sweep rather than one case, because the leak that matters is the one on a path nobody
    /// thought about. Each row below is a different failure branch of the transport, and the outcome
    /// is rendered whole - every property of the record - and searched.
    /// </remarks>
    [Fact]
    public async Task No_outcome_from_a_credentialed_post_contains_the_secret()
    {
        List<string> leaks = [];

        // 200, a 4xx, a redirect, an over-cap body, a refused address, and a connection that is not
        // there at all - which is the branch whose detail is an exception message.
        (string Name, Func<Task<FetchOutcome>> Act)[] cases =
        [
            ("ok", () => WithListener(() => Response("200 OK", "{\"id_token\":\"x\"}"))),
            ("not-ok", () => WithListener(() => Response("400 Bad Request", "{\"error\":\"invalid_client\"}"))),
            ("redirect", () => WithListener(() => Response("302 Found", "", "Location: https://evil.example/"))),
            ("too-large", () => WithListener(() => Response("200 OK", new string('x', 64 * 1024)))),
            ("blocked", () => NewClient(allowPrivateAddresses: false)
                .PostFormAsync(TokenRequest(1), CancellationToken.None)),
            ("transport", () => NewClient().PostFormAsync(TokenRequest(UnusedPort()), CancellationToken.None)),
        ];

        foreach (var (name, act) in cases)
        {
            var outcome = await act();
            var rendered = Render(outcome);

            if (rendered.Contains(Secret, StringComparison.Ordinal))
            {
                leaks.Add($"  {name}: {outcome.GetType().Name} renders the secret");
            }
        }

        Assert.True(
            leaks.Count == 0,
            "A fetch outcome carries the upstream client secret:" + Environment.NewLine
            + string.Join(Environment.NewLine, leaks));
    }

    /// <summary>The control for the sweep above: the search would find the secret if it were there.</summary>
    /// <remarks>
    /// Without this, "no outcome contains the secret" is also what a broken <c>Render</c> reports -
    /// which is the failure mode <c>LESSONS.md</c> is entirely about. This asserts the instrument
    /// works by handing it something that does contain the value.
    /// </remarks>
    [Fact]
    public void The_leak_search_can_see_a_secret_when_there_is_one()
    {
        var planted = new FetchOutcome.TransportFailed("connection refused while sending " + Secret);

        Assert.Contains(Secret, Render(planted), StringComparison.Ordinal);
    }

    private async Task<FetchOutcome> WithListener(Func<byte[]> respond)
    {
        using var listener = new RecordingListener(respond);

        Assert.True(AbsoluteHttpsUrl.TryCreate($"https://probe.example:{listener.Port}/token", out var url));

        var request = new UpstreamFormRequest(url, FetchPurpose.UpstreamTokenExchange, [])
        {
            ClientId = "client-at-upstream",
            ClientSecret = new UpstreamClientSecret(Secret),
            MaxBytes = 4096,
        };

        return await NewClient().PostFormAsync(request, CancellationToken.None);
    }

    /// <summary>Every field of an outcome as text: the record's own rendering plus its type name.</summary>
    private static string Render(FetchOutcome outcome) => outcome.GetType().Name + "|" + outcome;

    private static int UnusedPort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    // ------------------------------------------------------------------ the secret type itself

    /// <summary>
    /// The secret renders as a placeholder and serializes as nothing.
    /// </summary>
    /// <remarks>
    /// <c>OpaqueSecret</c>'s doc comment records that a <c>ToString</c> override alone is not the
    /// defence - a reflecting serializer or a structured-logging destructurer never calls it. The
    /// answer here was to give the type no public member carrying the value, and this measures that
    /// rather than assuming it.
    /// </remarks>
    [Fact]
    public void An_upstream_client_secret_never_renders_its_value()
    {
        var secret = new UpstreamClientSecret(Secret);

        Assert.DoesNotContain(Secret, secret.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, $"{secret}", StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, JsonSerializer.Serialize(secret), StringComparison.Ordinal);

        // Reflection over public members, which is what a structured-logging provider does.
        foreach (var property in typeof(UpstreamClientSecret).GetProperties())
        {
            Assert.DoesNotContain(
                Secret,
                property.GetValue(secret)?.ToString() ?? string.Empty,
                StringComparison.Ordinal);
        }

        foreach (var field in typeof(UpstreamClientSecret).GetFields())
        {
            Assert.DoesNotContain(
                Secret,
                field.GetValue(secret)?.ToString() ?? string.Empty,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void An_upstream_client_secret_refuses_to_be_empty()
    {
        // An empty secret is not "no secret": several upstreams treat an empty client_secret as a
        // presented credential and answer invalid_client, which reads as a wrong secret rather than
        // a missing one. A deployment with no secret passes null.
        Assert.Throws<ArgumentException>(() => new UpstreamClientSecret(string.Empty));
        Assert.Throws<ArgumentNullException>(() => new UpstreamClientSecret(null!));
    }

    public void Dispose()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }
    }
}
