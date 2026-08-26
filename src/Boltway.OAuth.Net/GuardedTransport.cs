using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using Boltway.OAuth.Primitives.Http;

namespace Boltway.OAuth.Net;

/// <summary>
/// A request body, for the one caller that sends one.
/// </summary>
/// <remarks>
/// <para>
/// A plain class rather than a record, and that is not a style choice: a record synthesizes
/// <see cref="object.ToString"/> over every member, so a record here would render the form fields —
/// which on the upstream token exchange include the authorization code and, under
/// <c>client_secret_post</c>, the client secret. One <c>$"{body}"</c> in a diagnostic would be the
/// whole leak. This type has no <c>ToString</c> of its own and inherits the one that prints the type
/// name.
/// </para>
/// <para>
/// <see langword="internal"/>, so a body can only be assembled inside this assembly — which is where
/// the guards are.
/// </para>
/// </remarks>
internal sealed class GuardedRequestBody
{
    internal GuardedRequestBody(
        IReadOnlyList<KeyValuePair<string, string>> form, string? authorizationHeader)
    {
        Form = form;
        AuthorizationHeader = authorizationHeader;
    }

    /// <summary>The <c>application/x-www-form-urlencoded</c> fields.</summary>
    internal IReadOnlyList<KeyValuePair<string, string>> Form { get; }

    /// <summary>A complete <c>Authorization</c> header value, or <see langword="null"/>.</summary>
    internal string? AuthorizationHeader { get; }
}

/// <summary>
/// The hardened socket path both outbound clients share.
/// </summary>
/// <remarks>
/// <para>
/// Extracted when the upstream identity-provider client landed, because the alternative was a second
/// <see cref="SocketsHttpHandler"/> configured by hand. Every line in the handler below exists
/// because the default is wrong, and a second copy is a second place for one of them to be omitted
/// — which would produce a client that follows redirects, or resolves the host twice, and still sits
/// inside <c>Boltway.OAuth.Net</c> where the architecture rule reports it as guarded.
/// </para>
/// <para>
/// What it does <b>not</b> hold is policy: the outbound budget, the byte cap, the total timeout and
/// whether private addresses are reachable are decided by the caller, because the two callers
/// dereference URLs of very different provenance. See <see cref="SafeHttpFetcher"/> and
/// <see cref="UpstreamEndpointClient"/> for the two sets and the argument for each.
/// </para>
/// </remarks>
internal sealed class GuardedTransport : IDisposable
{
    private readonly HttpClient _client;
    private readonly IAddressResolver _resolver;
    private readonly bool _allowPrivateAddresses;

    internal GuardedTransport(
        TimeSpan connectTimeout,
        bool allowPrivateAddresses,
        IAddressResolver resolver,
        SslClientAuthenticationOptions? sslOptionsForTests)
    {
        _resolver = resolver;
        _allowPrivateAddresses = allowPrivateAddresses;

        var handler = new SocketsHttpHandler
        {
            // The default is true. This single line is the difference between a fetcher and an
            // SSRF primitive with a public trigger.
            AllowAutoRedirect = false,

            UseCookies = false,
            UseProxy = false,
            Credentials = null,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = connectTimeout,

            // No connection reuse, and this is load-bearing rather than tuning.
            //
            // ConnectCallback runs once per CONNECTION, and its InitialRequestMessage is the
            // request that opened it. With pooling on, a second fetch to the same host:port reuses
            // a connection validated for a DIFFERENT request — measured: three fetches resolving
            // to .1, .2, .2 were all served by .1, with ConnectCallback running once. The default
            // idle timeout is 60s, so an attacker re-triggering /authorize once a minute pins the
            // server's connection to an address of their choosing indefinitely.
            //
            // It is not a live SSRF today, because the RFC 6890 check runs unconditionally before
            // every send — but "the value connected to is the value validated" was simply untrue,
            // and that sentence is the entire claim this class makes. These fetches are
            // low-volume and cached; a fresh connection each time is the right price.
            PooledConnectionLifetime = TimeSpan.Zero,

            // Keep this a fetcher rather than an outbound-DoS amplifier. The default is unbounded.
            MaxConnectionsPerServer = 4,

            // Connect only to an address this class has already checked. The URL's host is never
            // resolved by the HTTP stack itself, so there is no second lookup to poison.
            ConnectCallback = ConnectToValidatedAddressAsync,
        };

        if (sslOptionsForTests is not null)
        {
            handler.SslOptions = sslOptionsForTests;
        }

        _client = new HttpClient(handler, disposeHandler: true);
    }

    /// <summary>
    /// Resolve, check every address, send, and read at most <paramref name="maxBytes"/>.
    /// </summary>
    /// <param name="url">Where to send it.</param>
    /// <param name="body">A form body and its credential, or <see langword="null"/> for a GET.</param>
    /// <param name="maxBytes">Cap on bytes <b>read</b>.</param>
    /// <param name="budget">Total time for DNS, connect, TLS and body.</param>
    /// <param name="cancellationToken">The caller's cancellation.</param>
    /// <remarks>
    /// Nothing from <paramref name="body"/> reaches a <see cref="FetchOutcome"/>. The only failure
    /// case that carries text from outside this method is
    /// <see cref="FetchOutcome.TransportFailed"/>, whose detail is the transport exception's
    /// message — a DNS, TCP or TLS failure, which is about the connection and never about what was
    /// going to be written on it.
    /// </remarks>
    internal async Task<FetchOutcome> SendAsync(
        AbsoluteHttpsUrl url,
        GuardedRequestBody? body,
        int maxBytes,
        TimeSpan budget,
        CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(budget);

        try
        {
            var addresses = await _resolver.ResolveAsync(url.Host, timeout.Token);

            if (addresses.Count == 0)
            {
                return new FetchOutcome.Blocked(BlockReason.DnsFailed, $"'{url.Host}' did not resolve.");
            }

            // Every address must be acceptable, not merely one of them. A host answering with one
            // public and one private address would otherwise be fetchable, and which one gets used
            // is not ours to decide.
            foreach (var address in addresses)
            {
                if (!_allowPrivateAddresses && SpecialUseAddresses.IsBlocked(address))
                {
                    // The same refusal either way - what differs is what the server is entitled to
                    // say about it, and whether it is worth keeping a client broken over.
                    return SpecialUseAddresses.IsLinkLocal(address)
                        ? new FetchOutcome.Blocked(
                            BlockReason.LinkLocalAddress,
                            $"'{url.Host}' resolves to {address}, which is link-local (RFC 3927) - "
                                + "where the cloud instance-metadata endpoint lives. No public name "
                                + "resolves there legitimately.")
                        : new FetchOutcome.Blocked(
                            BlockReason.SpecialUseAddress,
                            $"'{url.Host}' resolves to {address}, which is a special-use address "
                                + "(RFC 6890). That is equally what a filtered resolver, a host "
                                + "nobody has configured yet, and an attacker aiming a fetch at "
                                + "this machine look like from here.");
                }
            }

            using var message = new HttpRequestMessage(
                body is null ? HttpMethod.Get : HttpMethod.Post, url.Value);

            message.Headers.Add("Accept", "application/json");
            message.Options.Set(ValidatedAddressKey, addresses[0]);

            if (body is not null)
            {
                message.Content = new FormUrlEncodedContent(body.Form);

                if (body.AuthorizationHeader is { } authorization)
                {
                    // TryAddWithoutValidation, so a malformed credential is refused by the remote
                    // end rather than by an exception here — an ArgumentException out of the header
                    // collection renders the offending value in its message, and this is the one
                    // value that must never appear in an exception.
                    message.Headers.TryAddWithoutValidation("Authorization", authorization);
                }
            }

            using var response = await _client.SendAsync(
                message, HttpCompletionOption.ResponseHeadersRead, timeout.Token);

            var status = (int)response.StatusCode;

            if (status is >= 300 and < 400)
            {
                return new FetchOutcome.Redirected(status, response.Headers.Location?.OriginalString);
            }

            if (status != 200)
            {
                return new FetchOutcome.NotOk(status);
            }

            var read = await ReadCappedAsync(response, maxBytes, timeout.Token);
            if (read is null)
            {
                return new FetchOutcome.TooLarge(maxBytes);
            }

            // A missing or unparseable Content-Type leaves `default(MediaType)`, which reports
            // IsJson false — so the caller decides what to do about it. Refusing the body here
            // would be wrong: whether a document must be JSON is the caller's rule, not the
            // transport's.
            _ = MediaType.TryParse(response.Content.Headers.ContentType?.ToString(), out var contentType);

            return new FetchOutcome.Ok(
                read,
                contentType,
                response.Headers.ETag?.Tag,
                Freshness(response));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new FetchOutcome.Timeout(Stopwatch.GetElapsedTime(started));
        }
        catch (HttpRequestException ex)
        {
            return new FetchOutcome.TransportFailed(ex.Message);
        }
        catch (SocketException ex)
        {
            return new FetchOutcome.TransportFailed(ex.Message);
        }
    }

    /// <summary>
    /// How long this response may be reused, read the way a <b>shared</b> cache must read it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>s-maxage</c> first, and that is the correction this method exists for.</b> This was
    /// <c>response.Headers.CacheControl?.MaxAge</c>, which is the directive for a <i>private</i>
    /// cache. Everything caching behind this transport is shared by construction — one process
    /// holding one origin's document on behalf of every user of that client — and RFC 9111 §5.2.2.10
    /// says <c>s-maxage</c> overrides <c>max-age</c> for exactly that case. An origin publishing
    /// <c>s-maxage=60, max-age=3600</c> is telling shared caches sixty seconds; reading the wrong
    /// member holds its document for an hour, which is an hour of acting on a redirect URI or a key
    /// it has already replaced.
    /// </para>
    /// <para>
    /// <c>Expires</c> last, and only when neither directive is present — §5.3. Its absence was
    /// costing the other side rather than us: with no freshness at all the caller falls back to its
    /// own floor, so an origin that publishes only <c>Expires</c> a day out was being refetched on
    /// that floor instead. LESSONS #9's conduct point is about being wrong in that direction.
    /// </para>
    /// <para>
    /// A past or unparseable <c>Expires</c> returns <see cref="TimeSpan.Zero"/> rather than a
    /// negative span or null: §5.3 makes an <c>Expires</c> in the past mean stale, and "stale" and
    /// "said nothing" are different answers — a caller's floor should apply to the second, not be
    /// silently handed the first.
    /// </para>
    /// </remarks>
    private static TimeSpan? Freshness(HttpResponseMessage response)
    {
        var control = response.Headers.CacheControl;

        if (control?.SharedMaxAge is { } shared)
        {
            return shared;
        }

        if (control?.MaxAge is { } maxAge)
        {
            return maxAge;
        }

        if (response.Content.Headers.Expires is not { } expires)
        {
            return null;
        }

        // Against the origin's own Date where it sent one: the two travel together and comparing
        // Expires to this machine's clock imports whatever clock skew exists between them.
        var from = response.Headers.Date ?? DateTimeOffset.UtcNow;
        var remaining = expires - from;

        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    /// <summary>
    /// Read at most <paramref name="maxBytes"/>, counting what actually arrives.
    /// </summary>
    /// <returns>The body, or <see langword="null"/> if it exceeded the cap.</returns>
    private static async Task<byte[]?> ReadCappedAsync(
        HttpResponseMessage response, int maxBytes, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);

        var buffer = new byte[(int)Math.Min((long)maxBytes + 1, 64 * 1024)];
        using var accumulated = new MemoryStream();

        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            // Strictly greater: reading exactly maxBytes is fine, one more is not. The count is of
            // bytes received, so a lying Content-Length buys nothing.
            if (accumulated.Length + read > maxBytes)
            {
                return null;
            }

            accumulated.Write(buffer, 0, read);
        }

        return accumulated.ToArray();
    }

    private static readonly HttpRequestOptionsKey<IPAddress> ValidatedAddressKey = new("ck.validated-address");

    private async ValueTask<Stream> ConnectToValidatedAddressAsync(
        SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        // The address was checked in SendAsync and carried here on the request, so the value
        // connected to is the value validated — there is no second DNS lookup between the two.
        if (!context.InitialRequestMessage.Options.TryGetValue(ValidatedAddressKey, out var address))
        {
            throw new InvalidOperationException(
                "No validated address on this request. Every request must go through SendAsync, " +
                "which is what performs the RFC 6890 check.");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _client.Dispose();
}
