using System.Net;
using System.Net.Sockets;
using Boltway.OAuth.Net.RateLimiting;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>Knobs for <see cref="LoginThrottle"/>. X-31.</summary>
/// <remarks>
/// Registered with <c>TryAddSingleton</c>, so a host that adds its own instance before calling
/// <c>AddBoltwayAuthorizationServer</c> keeps it - the same seam
/// <c>SafeHttpFetcherOptions</c> uses.
/// </remarks>
public sealed class LoginThrottleOptions
{
    /// <summary>
    /// How many sign-in attempts one submitted username may make inside <see cref="AccountWindow"/>.
    /// </summary>
    /// <remarks>
    /// Ten in a quarter of an hour. A person signing in makes one; a person who has forgotten which
    /// password they used makes three or four. Ten is comfortably above that and far below what
    /// guessing needs.
    /// </remarks>
    public int MaxAttemptsPerAccount { get; set; } = 10;

    /// <summary>The window <see cref="MaxAttemptsPerAccount"/> counts in.</summary>
    public TimeSpan AccountWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an account is refused the first time it goes over.</summary>
    public TimeSpan AccountInitialBackoff { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// The longest an account is ever refused.
    /// </summary>
    /// <remarks>
    /// Five minutes, and it is deliberately short. Counting per submitted username means anyone can
    /// aim attempts at anyone else's account, so a long lockout is a denial-of-service tool handed
    /// to the attacker. Five minutes costs a guessing attack three orders of magnitude of throughput
    /// and costs a targeted user five minutes.
    /// </remarks>
    public TimeSpan AccountMaxBackoff { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How many sign-in attempts one source may make inside <see cref="ClientWindow"/>.
    /// </summary>
    /// <remarks>
    /// Thirty in a quarter of an hour - two a minute - because a source is not a person. An office
    /// or a household behind one address is several people, and a deployment behind a proxy that
    /// does not forward the client address is <i>everybody</i> behind one key. See
    /// <see cref="ClientKey"/>.
    /// </remarks>
    public int MaxAttemptsPerClient { get; set; } = 30;

    /// <summary>The window <see cref="MaxAttemptsPerClient"/> counts in.</summary>
    public TimeSpan ClientWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long a source is refused the first time it goes over.</summary>
    public TimeSpan ClientInitialBackoff { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>The longest a source is refused. It doubles per consecutive breach up to this.</summary>
    public TimeSpan ClientMaxBackoff { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How many password verifications may run at once.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the bound that matters under a burst, and the failed-attempt limits above are not a
    /// substitute for it: a hundred requests that arrive simultaneously have all been admitted
    /// before any of them has failed. Measured on four cores with the shipped Argon2id parameters
    /// (m=19456, t=2, p=1): a hundred concurrent posts produced a hundred hashes, a login p50 of
    /// 4.5 s, and a single unrelated <c>GET /.well-known/oauth-authorization-server</c> that took
    /// 4.4 s against a 0.3 ms median. Three hundred produced a 16 s flood and a 10.8 s stall.
    /// </para>
    /// <para>
    /// One per core. Argon2id at these parameters is CPU-bound and allocates 19 MiB for the duration
    /// of each hash, so more in flight than there are cores buys no throughput and costs both memory
    /// and - because the hash is synchronous - a blocked thread-pool thread each.
    /// </para>
    /// </remarks>
    public int MaxConcurrentPasswordVerifications { get; set; } = Math.Max(2, Environment.ProcessorCount);

    /// <summary>
    /// How long a request will wait for a verification slot before being shed.
    /// </summary>
    /// <remarks>
    /// Waiting is right up to a point - a queue of two seconds at four hashes per 95 ms is roughly
    /// eighty requests deep, which absorbs an ordinary spike without anybody seeing an error. Past
    /// that, shedding with a <c>Retry-After</c> is the honest answer: the alternative is a queue
    /// that grows without bound and a user watching a spinner for a response that will arrive after
    /// they have given up.
    /// </remarks>
    public TimeSpan VerificationQueueTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>What a shed request is told to wait. Not a window, so it does not escalate.</summary>
    public TimeSpan OverloadRetryAfter { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How many usernames and sources may be tracked at once, each.</summary>
    public int MaxTrackedKeys { get; set; } = 16_384;

    /// <summary>
    /// How to identify the source of a request, when the remote address is not it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read this before deploying behind a proxy.</b> The default is
    /// <see cref="ConnectionInfo.RemoteIpAddress"/>, which behind a reverse proxy or a load balancer
    /// that does not populate it is the <i>proxy's</i> address - so every user in the deployment
    /// shares one bucket, thirty attempts across all of them exhausts it, and the per-source limit
    /// becomes an outage. The framework's answer is <c>UseForwardedHeaders</c> with
    /// <c>KnownProxies</c> configured, which sets <c>RemoteIpAddress</c> to the real client and
    /// needs nothing here.
    /// </para>
    /// <para>
    /// This hook is for a deployment whose front end carries the client identity somewhere else. It
    /// receives the whole <see cref="HttpContext"/> and must return a stable, low-cardinality string.
    /// Returning something the caller controls - a header nothing validates - makes the limit
    /// bypassable by setting it to a fresh value per request.
    /// </para>
    /// </remarks>
    public Func<HttpContext, string>? ClientKey { get; set; }
}

/// <summary>What the throttle decided about one sign-in attempt.</summary>
/// <param name="Allowed">Whether the attempt may proceed to a password verification.</param>
/// <param name="RetryAfter">How long to wait, when it may not.</param>
/// <param name="Description">
/// What was exceeded, in words, safe to put in a response body. Deliberately says nothing that
/// depends on whether the account exists - see <see cref="LoginThrottle"/>.
/// </param>
public readonly record struct LoginAdmission(bool Allowed, TimeSpan RetryAfter, string Description);

/// <summary>
/// Bounds what <c>POST /login</c> can be made to do. X-31.
/// </summary>
/// <remarks>
/// <para>
/// Three separate limits, because they fail in different directions. A per-account counter stops a
/// slow guessing attack on one person. A per-source counter stops one attacker spreading across many
/// accounts. Neither does anything about a hundred requests arriving in the same millisecond - every
/// one of them is admitted before any has been counted as a failure - and that is what the
/// concurrency bound is for.
/// </para>
/// <para>
/// <b>The counters are keyed on the submitted username, not on a resolved account, and that is a
/// security property rather than a shortcut.</b> A limiter keyed on accounts that exist would refuse
/// quickly for a real username and slowly for an invented one, which is the same username oracle the
/// endpoint's <c>DummyHash</c> exists to close, rebuilt one layer up. Keying on the submitted string
/// means a throttled unknown username and a throttled known one are indistinguishable, and it also
/// means the counter has to be bounded and normalised - see <see cref="Key"/>.
/// </para>
/// <para>
/// <b>All of it is per process.</b> Two instances behind a load balancer enforce twice these numbers
/// and share no state, so an attacker spreading attempts across the fleet gets the fleet's worth. It
/// bounds what one instance can be made to spend, which is where the CPU and the memory are; it is
/// not a fleet-wide account lockout and must not be described as one.
/// </para>
/// </remarks>
public sealed class LoginThrottle : IDisposable
{
    private readonly LoginThrottleOptions _options;
    private readonly KeyedRateLimiter _accounts;
    private readonly KeyedRateLimiter _sources;
    private readonly SemaphoreSlim _verifications;

    /// <summary>Create a throttle.</summary>
    /// <param name="time">The clock. Injected so every window here is testable without sleeping.</param>
    /// <param name="options">The limits, or the defaults.</param>
    public LoginThrottle(TimeProvider time, LoginThrottleOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(time);

        _options = options ?? new LoginThrottleOptions();

        _accounts = new KeyedRateLimiter(time, new KeyedRateLimiterOptions
        {
            Window = _options.AccountWindow,
            PermitsPerWindow = _options.MaxAttemptsPerAccount,
            InitialBackoff = _options.AccountInitialBackoff,
            MaxBackoff = _options.AccountMaxBackoff,
            MaxTrackedKeys = _options.MaxTrackedKeys,
        });

        _sources = new KeyedRateLimiter(time, new KeyedRateLimiterOptions
        {
            Window = _options.ClientWindow,
            PermitsPerWindow = _options.MaxAttemptsPerClient,
            InitialBackoff = _options.ClientInitialBackoff,
            MaxBackoff = _options.ClientMaxBackoff,
            MaxTrackedKeys = _options.MaxTrackedKeys,
        });

        _verifications = new SemaphoreSlim(
            _options.MaxConcurrentPasswordVerifications, _options.MaxConcurrentPasswordVerifications);
    }

    /// <summary>How long a shed request is told to wait.</summary>
    public TimeSpan OverloadRetryAfter => _options.OverloadRetryAfter;

    /// <summary>
    /// Count one sign-in attempt and say whether it may reach a password verification.
    /// </summary>
    /// <param name="username">The username as submitted. Normalised and bounded here, not by the caller.</param>
    /// <param name="http">The request, for the source key.</param>
    /// <remarks>
    /// Both counters are charged, not just the first one to refuse: an attacker who has exhausted a
    /// victim's account budget must not get their own source budget back for free.
    /// </remarks>
    public LoginAdmission Admit(string? username, HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        var account = _accounts.Acquire("u:" + Key(username));
        var source = _sources.Acquire("c:" + SourceKey(http));

        if (account.Allowed && source.Allowed)
        {
            return new LoginAdmission(true, TimeSpan.Zero, string.Empty);
        }

        // The longer of the two, because a caller told to wait for the shorter one comes back and is
        // refused again by the other - which reads as a limiter that ignores its own Retry-After.
        var wait = account.Allowed ? source.RetryAfter
            : source.Allowed ? account.RetryAfter
            : account.RetryAfter > source.RetryAfter ? account.RetryAfter : source.RetryAfter;

        // One sentence for both cases. Naming which limit fired would say whether the attempts that
        // exhausted it were aimed at this username or merely came from here, and an attacker
        // learning "my attempts against this name are being counted separately" is a small step
        // towards learning the name exists.
        return new LoginAdmission(
            false, wait, "Too many sign-in attempts. Wait before trying again.");
    }

    /// <summary>
    /// Forget an account's attempts, on proof they were legitimate.
    /// </summary>
    /// <remarks>
    /// The account counter only. The source counter is deliberately <b>not</b> reset by a successful
    /// sign-in: an attacker holding one valid credential would otherwise clear their own budget
    /// after every run of failures, which turns the per-source limit off for exactly the caller it
    /// exists to bound.
    /// </remarks>
    public void RecordSuccess(string? username) => _accounts.Reset("u:" + Key(username));

    /// <summary>
    /// Take one of the password-verification slots, or answer that the server is at capacity.
    /// </summary>
    /// <returns>
    /// A handle to release when the verification is done, or <see langword="null"/> when the wait
    /// timed out and the request should be shed.
    /// </returns>
    /// <remarks>
    /// The wait uses the real clock rather than the injected <see cref="TimeProvider"/>, because it
    /// is an I/O wait for a slot and not a policy window. A test drives the shed path by setting
    /// <see cref="LoginThrottleOptions.VerificationQueueTimeout"/> to zero and holding the slots,
    /// which needs no sleeping either.
    /// </remarks>
    public async ValueTask<IDisposable?> TryEnterVerificationAsync(CancellationToken cancellationToken)
    {
        var entered = await _verifications.WaitAsync(_options.VerificationQueueTimeout, cancellationToken);

        return entered ? new Slot(_verifications) : null;
    }

    /// <inheritdoc />
    public void Dispose() => _verifications.Dispose();

    /// <summary>
    /// Normalise a submitted username into a counter key.
    /// </summary>
    /// <remarks>
    /// Case-folded, because <c>IUserStore</c> matches case-insensitively - a limiter that did not
    /// would be defeated by alternating capitalisation. Bounded, because the value is a form field
    /// and an unbounded one is a dictionary key an attacker chooses the size of. A missing username
    /// is its own bucket rather than being skipped: an empty submission is still an attempt.
    /// </remarks>
    private static string Key(string? username)
    {
        var value = username ?? string.Empty;

        return (value.Length <= 256 ? value : value[..256]).ToUpperInvariant();
    }

    /// <summary>
    /// The source bucket for a request.
    /// </summary>
    /// <remarks>
    /// IPv6 is counted per /64 rather than per address, because a single subscriber is routinely
    /// given a whole /64 and counting per address would let one host rotate through 2^64 buckets.
    /// IPv4 is counted per address. A request with no remote address - which is what a
    /// <c>TestServer</c> and some proxy configurations produce - shares one bucket, and that is
    /// stated rather than hidden: it is a configuration to fix, not a mode to rely on.
    /// </remarks>
    private string SourceKey(HttpContext http)
    {
        if (_options.ClientKey is { } custom)
        {
            return custom(http);
        }

        return DefaultSourceKey(http);
    }

    /// <summary>
    /// The source bucket, by the rule described on <see cref="LoginThrottleOptions.ClientKey"/>.
    /// </summary>
    /// <param name="http">The request.</param>
    /// <remarks>
    /// Internal and shared rather than copied, because <see cref="RecoveryThrottle"/> wants the same
    /// rule and a second copy of "how do we identify a caller" is a second thing to keep in step -
    /// the /64 folding in particular is the sort of detail that gets fixed in one place.
    /// </remarks>
    internal static string DefaultSourceKey(HttpContext http)
    {
        var address = http.Connection.RemoteIpAddress;

        if (address is null)
        {
            return "no-remote-address";
        }

        if (address.AddressFamily is not AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);

        return new IPAddress(bytes).ToString() + "/64";
    }

    private sealed class Slot(SemaphoreSlim semaphore) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                _ = semaphore.Release();
            }
        }
    }
}
