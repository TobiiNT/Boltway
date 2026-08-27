using System.Net;
using System.Net.Sockets;
using Boltway.OAuth.Net.RateLimiting;

namespace Boltway.OAuth.Net;

/// <summary>Knobs for <see cref="SafeHttpFetcher"/>.</summary>
public sealed class SafeHttpFetcherOptions
{
    /// <summary>Time allowed to open the TCP connection.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Total budget: DNS, connect, TLS and body.
    /// </summary>
    /// <remarks>
    /// Deliberately small. The CIMD fetch happens <i>inside</i> <c>/authorize</c>, and the client
    /// treats the whole authorization step as terminal after about ten seconds - so an outbound
    /// fetch that takes longer than a few seconds has already cost the user the flow, and failing
    /// fast leaves room to serve a stale cache entry instead.
    /// </remarks>
    public TimeSpan TotalTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Permit connections to loopback and private addresses. Development only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A developer running a client on <c>localhost</c> genuinely needs this. CIMD section 8.6
    /// permits the exception for local development and says an implementation <b>MUST NOT</b> apply
    /// it in production, which is not a style note: the flag does not merely relax loopback, it
    /// short-circuits the RFC 6890 special-use check entirely, so
    /// <c>http://169.254.169.254/latest/meta-data/</c> becomes reachable and <c>/authorize</c>
    /// becomes an unauthenticated port scanner for anyone who can reach it.
    /// </para>
    /// <para>
    /// <b>The guard is at the DI registration, not here.</b> <c>AddCimdClientResolver</c> refuses to
    /// build a fetcher with this set unless <c>IHostEnvironment.IsDevelopment()</c>. A caller who
    /// constructs <see cref="SafeHttpFetcher"/> directly - as the test suite deliberately does - is
    /// not covered, and cannot be.
    /// </para>
    /// <para>
    /// This paragraph previously claimed that composition validation already refused such a host. It
    /// did not; a review started a Production host with the flag set and fetched a link-local
    /// address through an anonymous request. The claim was also duplicated into the test that proves
    /// the bypass, so both places a reviewer would check asserted the same false thing.
    /// </para>
    /// </remarks>
    public bool AllowPrivateAddresses { get; set; }

    /// <summary>
    /// How many fetches this instance will make to one remote host inside
    /// <see cref="HostRateLimitWindow"/>. X-31.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Keyed on the host alone, not host and port, and that is the point rather than an
    /// approximation. The measured shape of the abuse is one anonymous
    /// <c>GET /authorize?client_id=https://victim:&lt;port&gt;/c</c> per port: fifty ports produced
    /// fifty connections with host and port preserved. Counting per host:port would give each port
    /// its own budget and bound nothing. Counting per host means a scan of <i>n</i> ports spends one
    /// host budget, and so does a flood of <i>n</i> distinct paths on one victim.
    /// </para>
    /// <para>
    /// Sixty per minute is chosen against the CIMD cache, which is the only thing that fetches
    /// through <i>this</i> client: a resolved document is cached for at least 300 s (S-30's floor),
    /// so one legitimate <c>client_id</c> costs at most one fetch per five minutes <i>per instance</i>.
    /// Sixty a minute therefore leaves room for roughly three hundred distinct clients published on
    /// one host to all refresh inside the same minute - which no vendor arrangement resembles, since
    /// the two live vendors publish two documents each - while capping what one instance can be made
    /// to send at one victim.
    /// </para>
    /// <para>
    /// <b>Per instance, and per client.</b> A fleet of <i>n</i> replicas will send up to <i>n</i>
    /// times this. <see cref="UpstreamEndpointClient"/> carries its own, separate budget, so the two
    /// do not share a counter - see the note there for why that is right rather than an oversight.
    /// </para>
    /// </remarks>
    public int MaxFetchesPerHostPerWindow { get; set; } = 60;

    /// <summary>The window <see cref="MaxFetchesPerHostPerWindow"/> counts in.</summary>
    public TimeSpan HostRateLimitWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How long a host stays refused once it has exceeded its budget.
    /// </summary>
    /// <remarks>
    /// Flat rather than escalating: the budget exists to bound outbound volume, not to punish, and a
    /// legitimate deployment that grew past sixty clients on one host should recover at the next
    /// window rather than be pushed into a longer and longer refusal.
    /// </remarks>
    public TimeSpan HostRateLimitBackoff { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How many remote hosts may be tracked at once. Attacker-chosen, so bounded.</summary>
    public int MaxTrackedHosts { get; set; } = 4_096;

    /// <summary>
    /// TLS settings, for tests that need to trust a certificate generated at run time.
    /// </summary>
    /// <remarks>
    /// <c>internal</c>, and visible only to this assembly's test project and to the authorization
    /// server's, which drives a federation flow against a loopback identity provider it stands up
    /// itself. It exists because the alternatives are worse: without it the only tests that can run
    /// are ones refused at the address check, which is exactly how the first version of this suite
    /// ended up never completing a single fetch - so <c>TooLarge</c>, <c>Timeout</c>,
    /// <c>Redirected</c> and <c>NotOk</c> were all unreachable, and the test claiming to prove
    /// connect-pinning proved nothing because <c>SendAsync</c> was never called.
    /// <para>
    /// It is not reachable from a customer's code and not settable from configuration, so it cannot
    /// weaken a deployment. Certificate validation is otherwise the framework default: measured
    /// during review, connecting to a raw <see cref="IPAddress"/> still validates the chain <i>and</i>
    /// the name against the URL's host.
    /// </para>
    /// </remarks>
    internal System.Net.Security.SslClientAuthenticationOptions? SslOptionsForTests { get; set; }
}

/// <summary>
/// The one outbound HTTP client that may be pointed at a URL the server does not control.
/// </summary>
/// <remarks>
/// <para>
/// Every defence here exists because a stock <c>HttpClient</c> gets it wrong by default: redirects
/// are followed, the host is resolved a second time by the HTTP stack, <c>Content-Length</c> is
/// trusted, and responses are transparently decompressed. All four are handled in
/// <see cref="GuardedTransport"/>, which this class and <see cref="UpstreamEndpointClient"/> share;
/// the comments there say what each line is for.
/// </para>
/// <para>
/// What is specific to <i>this</i> class is the trust level. The URLs it dereferences are
/// <b>attacker-supplied by design</b>: a CIMD <c>client_id</c> is a URL sent by whoever is starting
/// an authorization flow, and <c>jwks_uri</c> and <c>logo_uri</c> are read out of a document that was
/// itself fetched from an attacker-chosen host. So the RFC 6890 address check is on unless a
/// developer explicitly turns it off, and the outbound budget is charged before DNS.
/// </para>
/// </remarks>
public sealed class SafeHttpFetcher : ISafeHttpFetcher, IDisposable
{
    private readonly SafeHttpFetcherOptions _options;
    private readonly GuardedTransport _transport;
    private readonly KeyedRateLimiter _perHost;

    /// <summary>Create a fetcher.</summary>
    /// <param name="options">The budgets and timeouts, or the defaults.</param>
    /// <param name="resolver">The address resolver, or DNS.</param>
    /// <param name="time">
    /// The clock the outbound budget counts on. Injected so the window is testable without sleeping;
    /// <see cref="TimeProvider.System"/> when a caller does not supply one, which is the case only
    /// for a hand-constructed fetcher - the DI registration passes the host's.
    /// </param>
    public SafeHttpFetcher(
        SafeHttpFetcherOptions? options = null, IAddressResolver? resolver = null, TimeProvider? time = null)
    {
        _options = options ?? new SafeHttpFetcherOptions();

        _perHost = new KeyedRateLimiter(
            time ?? TimeProvider.System,
            new KeyedRateLimiterOptions
            {
                Window = _options.HostRateLimitWindow,
                PermitsPerWindow = _options.MaxFetchesPerHostPerWindow,
                InitialBackoff = _options.HostRateLimitBackoff,
                MaxBackoff = _options.HostRateLimitBackoff,
                MaxTrackedKeys = _options.MaxTrackedHosts,
            });

        _transport = new GuardedTransport(
            _options.ConnectTimeout,
            _options.AllowPrivateAddresses,
            resolver ?? new DnsAddressResolver(),
            _options.SslOptionsForTests);
    }

    /// <inheritdoc />
    public async Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Before DNS, so a caller who can make this server look a host up cannot make it look one
        // up without limit either. The counter is charged whether the fetch would have succeeded or
        // failed, because the cost being bounded is the outbound request, not the answer.
        var permit = _perHost.Acquire(request.Url.Host);

        if (!permit.Allowed)
        {
            return new FetchOutcome.RateLimited(
                permit.RetryAfter,
                $"this instance has reached its outbound budget for '{Echo(request.Url.Host)}'");
        }

        return await _transport.SendAsync(
            request.Url,
            body: null,
            request.MaxBytes,
            request.Timeout ?? _options.TotalTimeout,
            cancellationToken);
    }

    /// <summary>Bound a caller-supplied host before it goes into a message. A host may be 253 bytes.</summary>
    internal static string Echo(string value) => value.Length <= 140 ? value : value[..140];

    /// <inheritdoc />
    public void Dispose() => _transport.Dispose();
}

/// <summary>Resolves a host to addresses. A seam so tests can drive the address checks.</summary>
public interface IAddressResolver
{
    /// <summary>Resolve, or return empty.</summary>
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>The real resolver.</summary>
public sealed class DnsAddressResolver : IAddressResolver
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        // A literal address needs no lookup, and Dns.GetHostAddressesAsync would happily accept it
        // and hand back something else on some platforms.
        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }

        try
        {
            return await Dns.GetHostAddressesAsync(host, cancellationToken);
        }
        catch (SocketException)
        {
            return [];
        }
        catch (ArgumentException)
        {
            // Dns throws ArgumentOutOfRangeException for a host over 255 characters, and the host
            // comes from an attacker-supplied URL. Uncaught it escaped FetchAsync entirely, which
            // inside /authorize is a 500 on demand.
            return [];
        }
    }
}
