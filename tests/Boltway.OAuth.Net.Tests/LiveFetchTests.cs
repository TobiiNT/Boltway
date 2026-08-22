using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Boltway.OAuth.Net;

namespace Boltway.OAuth.Net.Tests;

/// <summary>
/// Fetches that actually complete, against real listeners.
/// </summary>
/// <remarks>
/// The original SSRF suite never completed a single fetch — every case was refused at the address
/// check — so <c>TooLarge</c>, <c>Timeout</c>, <c>Redirected</c> and <c>NotOk</c> were all
/// unreachable, including the two N-05 itself names. Worse, the test asserting the TOCTOU property
/// resolved to a blocked address, so <c>SendAsync</c> was never called and <c>ConnectCallback</c>
/// never ran: it passed with the callback deleted and <c>AllowAutoRedirect</c> back on, which is to
/// say it asserted nothing at all.
/// <para>
/// The listeners speak real TLS with a certificate generated at run time, trusted through an
/// internal seam on the options. Anything less would not exercise the code path under test: the
/// fetcher accepts only <c>https</c> URLs, which is itself one of the guarantees.
/// </para>
/// </remarks>
public sealed class LiveFetchTests : IDisposable
{
    /// <summary>A listener that answers one canned response, and counts connections.</summary>
    private sealed class Listener : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _stop = new();

        public Listener(IPAddress address, Func<byte[]> respond, int delayMs = 0)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(address, 0));
            _socket.Listen(8);
            Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
            Address = address;

            _ = Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    Socket client;
                    try { client = await _socket.AcceptAsync(_stop.Token); }
                    catch { return; }

                    Connections++;

                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            var buffer = new byte[4096];
                            try
                            {
                                await using var tls = await TlsTestCertificate.WrapAsync(client, _stop.Token);

                                // Serve requests until the peer hangs up, so a pooled connection
                                // can actually be reused.
                                while (!_stop.IsCancellationRequested)
                                {
                                    var read = await tls.ReadAsync(buffer, _stop.Token);
                                    if (read == 0)
                                    {
                                        break;
                                    }

                                    if (delayMs > 0)
                                    {
                                        await Task.Delay(delayMs, _stop.Token);
                                    }

                                    await tls.WriteAsync(respond(), _stop.Token);
                                }
                            }
                            catch
                            {
                                // The fetcher hanging up mid-response is the expected outcome in
                                // the cap and timeout cases.
                            }
                        }
                    }, _stop.Token);
                }
            }, _stop.Token);
        }

        public int Port { get; }

        public IPAddress Address { get; }

        public int Connections { get; private set; }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _stop.Cancel();
            _socket.Dispose();
            _stop.Dispose();
        }

        private bool _disposed;
    }

    private sealed class SequenceResolver(params IPAddress[] answers) : IAddressResolver
    {
        private int _index;

        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            var answer = answers[Math.Min(_index++, answers.Length - 1)];
            return Task.FromResult<IReadOnlyList<IPAddress>>([answer]);
        }
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

        // keep-alive, deliberately. With "Connection: close" the server hangs up after every
        // response, so HttpClient's pool never reuses anything and the connect-pinning test passes
        // whether or not pooling is disabled — which is to say it proves nothing.
        head.Append("Connection: keep-alive\r\n\r\n");

        return [.. Encoding.UTF8.GetBytes(head.ToString()), .. bytes];
    }

    private readonly List<IDisposable> _disposables = [];

    /// <summary>A fetcher against the loopback TLS listener.</summary>
    /// <param name="timeout">
    /// Only the one test that is <i>about</i> the budget passes this. For everything else the
    /// default is deliberately far larger than the production one.
    /// </param>
    /// <remarks>
    /// <para>
    /// This file was flaky against the production budgets — measured at 4 failures in ~8
    /// full-solution runs, always <c>FetchOutcome.Timeout</c> where <c>Ok</c> was expected, and
    /// never once when this project ran alone. Nothing is wrong with the fetcher: a real TLS
    /// handshake against a loopback listener does not reliably complete on a machine running five
    /// worktrees' builds at load average 40+.
    /// </para>
    /// <para>
    /// <b>Both budgets have to move, and the first attempt moved only one.</b> Raising
    /// <c>TotalTimeout</c> to 60 s left the failures in place, and the reason was visible in the
    /// run: the test failed after <i>3 seconds</i>, which is <see cref="SafeHttpFetcherOptions.ConnectTimeout"/>,
    /// not the total. The elapsed time in the failure was the evidence that the diagnosis was wrong,
    /// and it was there to read before the change was made.
    /// </para>
    /// <para>
    /// Raising them does not weaken anything, because the production numbers are not what these
    /// tests assert — they assert redirect refusal, address pinning, byte caps and status handling,
    /// all budget-independent. <c>A_slow_response_is_a_timeout</c> passes its own 400 ms and is the
    /// one test that would notice, which is what keeps this from hiding a regression.
    /// </para>
    /// </remarks>
    private SafeHttpFetcher NewFetcher(IAddressResolver resolver, TimeSpan? timeout = null)
    {
        var fetcher = new SafeHttpFetcher(
            new SafeHttpFetcherOptions
            {
                AllowPrivateAddresses = true,
                ConnectTimeout = TimeSpan.FromSeconds(30),
                TotalTimeout = timeout ?? TimeSpan.FromSeconds(60),
                SslOptionsForTests = TlsTestCertificate.ClientOptions(),
            },
            resolver);

        _disposables.Add(fetcher);
        return fetcher;
    }

    private async Task<FetchOutcome> FetchAsync(Listener listener, IAddressResolver resolver, int maxBytes = 5 * 1024)
    {
        Assert.True(AbsoluteHttpsUrl.TryCreate($"https://probe.example:{listener.Port}/c.json", out var url));

        return await NewFetcher(resolver).FetchAsync(
            new SafeFetchRequest(url, FetchPurpose.ClientIdMetadataDocument, maxBytes), CancellationToken.None);
    }

    // ------------------------------------------------------------------ connect pinning (F3)

    [Fact]
    public async Task Each_fetch_connects_to_the_address_resolved_for_that_fetch()
    {
        // The test the review asked for, and it failed before PooledConnectionLifetime was set to
        // zero. ConnectCallback runs once per CONNECTION and its InitialRequestMessage is the
        // request that opened it, so with pooling on, the second fetch reused a connection
        // validated for the first — measured as three fetches to .1/.2/.2 all served by .1.
        // Both listeners share ONE port on two loopback addresses, because that is the condition
        // the bug needed: HttpClient's pool is keyed on (scheme, host, port), so a second fetch to
        // the same key reuses the first connection regardless of which address was validated.
        using var first = new Listener(IPAddress.Parse("127.0.0.1"), () => Response("200 OK", "{\"n\":1}"));
        using var sameSecond = new ListenerOnPort(
            IPAddress.Parse("127.0.0.2"), first.Port, () => Response("200 OK", "{\"n\":2}"));

        var resolver = new SequenceResolver(IPAddress.Parse("127.0.0.1"), IPAddress.Parse("127.0.0.2"));
        var fetcher = NewFetcher(resolver);

        Assert.True(AbsoluteHttpsUrl.TryCreate($"https://probe.example:{first.Port}/c.json", out var url));
        var request = new SafeFetchRequest(url, FetchPurpose.ClientIdMetadataDocument);

        await fetcher.FetchAsync(request, CancellationToken.None);
        await fetcher.FetchAsync(request, CancellationToken.None);

        // Each fetch opened its own connection to its own address. With pooling on, sameSecond
        // never saw a connection at all.
        Assert.Equal(1, first.Connections);
        Assert.Equal(1, sameSecond.Connections);
    }

    /// <summary>A listener bound to a specific port, so two addresses can share one pool key.</summary>
    private sealed class ListenerOnPort : IDisposable
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _stop = new();

        public ListenerOnPort(IPAddress address, int port, Func<byte[]> respond)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(new IPEndPoint(address, port));
            _socket.Listen(8);

            _ = Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    Socket client;
                    try { client = await _socket.AcceptAsync(_stop.Token); }
                    catch { return; }

                    Connections++;
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                        var buffer = new byte[4096];
                        try
                        {
                            await using var tls = await TlsTestCertificate.WrapAsync(client, _stop.Token);

                            while (!_stop.IsCancellationRequested)
                            {
                                var read = await tls.ReadAsync(buffer, _stop.Token);
                                if (read == 0)
                                {
                                    break;
                                }

                                await tls.WriteAsync(respond(), _stop.Token);
                            }
                        }
                        catch { /* expected on hang-up */ }
                        }
                    }, _stop.Token);
                }
            }, _stop.Token);
        }

        public int Connections { get; private set; }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _stop.Cancel();
            _socket.Dispose();
            _stop.Dispose();
        }

        private bool _disposed;
    }

    // ------------------------------------------------------------------ outcomes never reached before

    [Fact]
    public async Task A_body_over_the_cap_is_refused_while_being_read()
    {
        // N-05 names this case: "6 KB doc rejected". The cap is on bytes received, so the declared
        // Content-Length is irrelevant.
        using var listener = new Listener(IPAddress.Loopback, () => Response("200 OK", new string('x', 6144)));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback), maxBytes: 5120);

        Assert.IsType<FetchOutcome.TooLarge>(outcome);
    }

    [Fact]
    public async Task A_body_exactly_at_the_cap_is_accepted()
    {
        using var listener = new Listener(IPAddress.Loopback, () => Response("200 OK", new string('x', 5120)));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback), maxBytes: 5120);

        var ok = Assert.IsType<FetchOutcome.Ok>(outcome);
        Assert.Equal(5120, ok.Body.Length);
    }

    [Fact]
    public async Task A_redirect_is_reported_and_not_followed()
    {
        // The other case N-05 names. A public host answering 302 to the metadata endpoint is the
        // whole reason AllowAutoRedirect is off.
        using var listener = new Listener(
            IPAddress.Loopback,
            () => Response("302 Found", "", "Location: http://169.254.169.254/latest/meta-data/"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        var redirected = Assert.IsType<FetchOutcome.Redirected>(outcome);
        Assert.Equal(302, redirected.Status);
        Assert.Contains("169.254.169.254", redirected.Location, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("404 Not Found", 404)]
    [InlineData("500 Internal Server Error", 500)]
    [InlineData("204 No Content", 204)]
    public async Task Only_200_is_accepted(string status, int expected)
    {
        using var listener = new Listener(IPAddress.Loopback, () => Response(status, "{}"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.Equal(expected, Assert.IsType<FetchOutcome.NotOk>(outcome).Status);
    }

    [Fact]
    public async Task A_slow_response_hits_the_budget()
    {
        using var listener = new Listener(IPAddress.Loopback, () => Response("200 OK", "{}"), delayMs: 5000);

        Assert.True(AbsoluteHttpsUrl.TryCreate($"https://probe.example:{listener.Port}/c.json", out var url));

        var outcome = await NewFetcher(new SequenceResolver(IPAddress.Loopback), TimeSpan.FromMilliseconds(400))
            .FetchAsync(new SafeFetchRequest(url, FetchPurpose.ClientIdMetadataDocument), CancellationToken.None);

        Assert.IsType<FetchOutcome.Timeout>(outcome);
    }

    [Fact]
    public async Task A_content_type_with_a_charset_parameter_is_json()
    {
        // The §10 measurement: chatgpt.com serves application/json; charset=utf-8.
        using var listener = new Listener(IPAddress.Loopback, () => Response("200 OK", "{}"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.True(Assert.IsType<FetchOutcome.Ok>(outcome).ContentType.IsJson);
    }

    // ------------------------------------------------------------------ freshness, as a shared cache

    /// <summary>
    /// <c>s-maxage</c> wins over <c>max-age</c>, because everything behind this transport is a
    /// shared cache.
    /// </summary>
    /// <remarks>
    /// RFC 9111 §5.2.2.10. The numbers are deliberately far apart and the assertion is the smaller
    /// one: reading <c>max-age</c> here holds an origin's document for an hour it asked shared caches
    /// to hold for a minute, which is an hour of acting on a redirect URI or a key it has replaced.
    /// This read <c>CacheControl?.MaxAge</c> — the private-cache directive — until it was measured
    /// against better-auth's documented behaviour and found to be the wrong member.
    /// </remarks>
    [Fact]
    public async Task Shared_max_age_wins_over_max_age()
    {
        using var listener = new Listener(
            IPAddress.Loopback,
            () => Response("200 OK", "{}", "Cache-Control: max-age=3600, s-maxage=60"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.Equal(TimeSpan.FromSeconds(60), Assert.IsType<FetchOutcome.Ok>(outcome).MaxAge);
    }

    /// <summary>With no <c>s-maxage</c>, <c>max-age</c> is what there is.</summary>
    /// <remarks>
    /// The control for the test above. Without it, a transport that read <c>s-maxage</c> and
    /// discarded <c>max-age</c> entirely would pass — and would then report "said nothing" for the
    /// overwhelmingly common header, dropping every origin onto the caller's floor.
    /// </remarks>
    [Fact]
    public async Task Max_age_is_used_when_there_is_no_shared_max_age()
    {
        using var listener = new Listener(
            IPAddress.Loopback,
            () => Response("200 OK", "{}", "Cache-Control: max-age=600"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.Equal(TimeSpan.FromSeconds(600), Assert.IsType<FetchOutcome.Ok>(outcome).MaxAge);
    }

    /// <summary><c>Expires</c> is read only when neither directive is present. §5.3.</summary>
    /// <remarks>
    /// Its absence cost the <i>origin</i> rather than this server: with no freshness at all the
    /// caller falls back to its own floor, so a document published with a day's <c>Expires</c> and
    /// no <c>Cache-Control</c> was refetched on that floor instead. Measured against the response's
    /// own <c>Date</c> where it sends one, so the answer does not import clock skew between the two
    /// machines — which is why this listener sends both and the assertion is exact.
    /// </remarks>
    [Fact]
    public async Task Expires_is_the_fallback_and_is_measured_from_the_responses_own_date()
    {
        const string Date = "Sat, 22 Aug 2026 12:00:00 GMT";
        const string Expires = "Sat, 22 Aug 2026 14:00:00 GMT";

        using var listener = new Listener(
            IPAddress.Loopback,
            () => Response("200 OK", "{}", $"Date: {Date}\r\nExpires: {Expires}"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.Equal(TimeSpan.FromHours(2), Assert.IsType<FetchOutcome.Ok>(outcome).MaxAge);
    }

    /// <summary>An <c>Expires</c> in the past is zero, not null and not negative.</summary>
    /// <remarks>
    /// "Stale" and "said nothing" are different answers, and a caller's floor must apply to the
    /// second only. Null here would hand a document its origin has already expired the same minimum
    /// lifetime as one that carried no freshness information at all.
    /// </remarks>
    [Fact]
    public async Task An_expires_in_the_past_is_zero_rather_than_absent()
    {
        using var listener = new Listener(
            IPAddress.Loopback,
            () => Response(
                "200 OK",
                "{}",
                "Date: Sat, 22 Aug 2026 12:00:00 GMT\r\nExpires: Sat, 22 Aug 2026 11:00:00 GMT"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.Equal(TimeSpan.Zero, Assert.IsType<FetchOutcome.Ok>(outcome).MaxAge);
    }

    /// <summary>No freshness at all stays null, so the caller's floor is what applies.</summary>
    [Fact]
    public async Task A_response_with_no_freshness_reports_none()
    {
        using var listener = new Listener(IPAddress.Loopback, () => Response("200 OK", "{}"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback));

        Assert.Null(Assert.IsType<FetchOutcome.Ok>(outcome).MaxAge);
    }

    // ------------------------------------------------------------------ argument validation (F4)

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void A_non_positive_cap_is_refused_at_construction(int maxBytes)
    {
        // int.MaxValue overflowed the read-buffer sizing and threw out of FetchAsync; a negative
        // value produced a zero-length buffer and reported an empty document as success.
        Assert.True(AbsoluteHttpsUrl.TryCreate("https://example.com/c.json", out var url));

        Assert.Throws<ArgumentOutOfRangeException>(
            () => new SafeFetchRequest(url, FetchPurpose.ClientIdMetadataDocument, maxBytes));
    }

    [Fact]
    public async Task An_enormous_cap_does_not_overflow()
    {
        using var listener = new Listener(IPAddress.Loopback, () => Response("200 OK", "{}"));

        var outcome = await FetchAsync(listener, new SequenceResolver(IPAddress.Loopback), maxBytes: int.MaxValue);

        Assert.IsType<FetchOutcome.Ok>(outcome);
    }

    public void Dispose()
    {
        foreach (var disposable in _disposables)
        {
            disposable.Dispose();
        }
    }
}


/// <summary>A self-signed certificate for the loopback listeners in this file.</summary>
internal static class TlsTestCertificate
{
    private static readonly X509Certificate2 Certificate = Create();

    private static X509Certificate2 Create()
    {
        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest("CN=probe.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("probe.example");
        request.CertificateExtensions.Add(names.Build());

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        // Windows needs the key exported and reimported to be usable by SslStream; harmless
        // elsewhere.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), password: null);
    }

    internal static SslClientAuthenticationOptions ClientOptions() => new()
    {
        TargetHost = "probe.example",

        // Trust exactly this certificate and nothing else. Not a blanket accept-anything: the point
        // is to exercise the real TLS path, so a wrong certificate must still fail.
        RemoteCertificateValidationCallback = (_, presented, _, _) =>
            presented is not null && presented.GetCertHashString() == Certificate.GetCertHashString(),
    };

    internal static async Task<SslStream> WrapAsync(Socket client, CancellationToken cancellationToken)
    {
        var stream = new SslStream(new NetworkStream(client, ownsSocket: false), leaveInnerStreamOpen: false);

        await stream.AuthenticateAsServerAsync(
            new SslServerAuthenticationOptions { ServerCertificate = Certificate }, cancellationToken);

        return stream;
    }
}
