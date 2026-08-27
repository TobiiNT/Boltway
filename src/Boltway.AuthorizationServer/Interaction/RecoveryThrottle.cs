using Boltway.OAuth.Net.RateLimiting;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>What bounds the public recovery endpoints.</summary>
/// <remarks>
/// Smaller numbers than <see cref="LoginThrottleOptions"/>'s, because the operations are rarer and
/// the failure is louder: a wrong password costs the person a retry, and an unwanted reset mail
/// costs them an inbox and costs the deployment its sending reputation.
/// </remarks>
public sealed class RecoveryThrottleOptions
{
    /// <summary>How many reset requests one submitted identifier may make in the window. Three.</summary>
    /// <remarks>
    /// A person who has forgotten their password asks once, does not find the mail, and asks again.
    /// Three covers that. It is counted on the <i>submitted</i> string rather than on a resolved
    /// account, for the reason <c>LoginThrottle</c> gives: a limiter that fired quickly for a real
    /// address and slowly for an invented one would rebuild the oracle <c>S-48</c> exists to close,
    /// one layer up.
    /// </remarks>
    public int MaxRequestsPerAccount { get; set; } = 3;

    /// <summary>The window it counts in. Fifteen minutes.</summary>
    public TimeSpan AccountWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an identifier is refused the first time it goes over.</summary>
    public TimeSpan AccountInitialBackoff { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The longest an identifier is ever refused. Fifteen minutes.
    /// </summary>
    /// <remarks>
    /// Longer than the sign-in throttle's five, and it can be: refusing to <i>send a mail</i> for
    /// fifteen minutes is not the denial of service that refusing to <i>let somebody sign in</i>
    /// would be. The person still has their password if they remember it, and the link they already
    /// asked for still works.
    /// </remarks>
    public TimeSpan AccountMaxBackoff { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How many recovery requests one source may make in the window. Ten.</summary>
    /// <remarks>
    /// A source is not a person - an office behind one address is several - but ten reset requests
    /// a quarter of an hour from one address is already far more than a workplace produces, and the
    /// thing being bounded is outbound mail somebody else pays for.
    /// </remarks>
    public int MaxRequestsPerClient { get; set; } = 10;

    /// <summary>The window it counts in.</summary>
    public TimeSpan ClientWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long a source is refused the first time it goes over.</summary>
    public TimeSpan ClientInitialBackoff { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>The longest a source is ever refused.</summary>
    public TimeSpan ClientMaxBackoff { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>How a source is identified. Defaults to the sign-in throttle's rule.</summary>
    public Func<HttpContext, string>? ClientKey { get; set; }
}

/// <summary>
/// Bounds what the public recovery endpoints can be made to send. <c>X-31</c>, §3.1.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>E-39</c> sends mail to an address chosen by the caller</b>, which makes it an outbound spam
/// vector aimed at whoever the caller likes, paid for by the deployment and charged against its
/// sending reputation. It is the one endpoint on this server where the cost of an unbounded request
/// lands on somebody who is not making it.
/// </para>
/// <para>
/// Two counters, the same pair and the same reasoning as <see cref="LoginThrottle"/>: per submitted
/// identifier, to stop one mailbox being flooded, and per source, to stop one caller spraying across
/// many. Neither names which fired, because saying "your attempts against this address are being
/// counted" is a step towards learning the address is registered.
/// </para>
/// <para>
/// <b>All of it is per process</b> - <c>X-31</c>, restated because a throttle reads like a
/// guarantee. A fleet of <i>n</i> replicas sends <i>n</i> times each number. Put a shared limiter in
/// front, or accept the multiple knowingly.
/// </para>
/// </remarks>
public sealed class RecoveryThrottle
{
    private readonly RecoveryThrottleOptions _options;
    private readonly KeyedRateLimiter _accounts;
    private readonly KeyedRateLimiter _sources;

    /// <summary>Create a throttle.</summary>
    /// <param name="time">The clock. Injected so every window here is testable without sleeping.</param>
    /// <param name="options">The limits, or the defaults.</param>
    public RecoveryThrottle(TimeProvider time, RecoveryThrottleOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(time);

        _options = options ?? new RecoveryThrottleOptions();

        _accounts = new KeyedRateLimiter(time, new KeyedRateLimiterOptions
        {
            PermitsPerWindow = _options.MaxRequestsPerAccount,
            Window = _options.AccountWindow,
            InitialBackoff = _options.AccountInitialBackoff,
            MaxBackoff = _options.AccountMaxBackoff,
        });

        _sources = new KeyedRateLimiter(time, new KeyedRateLimiterOptions
        {
            PermitsPerWindow = _options.MaxRequestsPerClient,
            Window = _options.ClientWindow,
            InitialBackoff = _options.ClientInitialBackoff,
            MaxBackoff = _options.ClientMaxBackoff,
        });
    }

    /// <summary>Whether this request may proceed.</summary>
    /// <param name="identifier">What the caller typed - a handle, an address, or nothing.</param>
    /// <param name="http">The request, for the source bucket.</param>
    public LoginAdmission Admit(string? identifier, HttpContext http)
    {
        ArgumentNullException.ThrowIfNull(http);

        var account = _accounts.Acquire("r:" + Key(identifier));
        var source = _sources.Acquire("rc:" + SourceKey(http));

        if (account.Allowed && source.Allowed)
        {
            return new LoginAdmission(true, TimeSpan.Zero, string.Empty);
        }

        var wait = account.Allowed ? source.RetryAfter
            : source.Allowed ? account.RetryAfter
            : account.RetryAfter > source.RetryAfter ? account.RetryAfter : source.RetryAfter;

        return new LoginAdmission(
            false,
            wait,
            "Too many requests. Wait " + (int)Math.Ceiling(wait.TotalSeconds) + " seconds and try again.");
    }

    /// <summary>Case-folded and bounded, the same way the sign-in throttle keys a username.</summary>
    private static string Key(string? identifier)
    {
        var value = identifier ?? string.Empty;

        return (value.Length <= 256 ? value : value[..256]).ToUpperInvariant();
    }

    /// <summary>
    /// The source bucket, defaulting to the sign-in throttle's rule.
    /// </summary>
    /// <remarks>
    /// IPv6 per /64 rather than per address - a subscriber is routinely given a whole /64 - and IPv4
    /// per address. A request with no remote address shares one bucket, which is a configuration to
    /// fix rather than a mode to rely on.
    /// </remarks>
    private string SourceKey(HttpContext http)
    {
        if (_options.ClientKey is { } custom)
        {
            return custom(http);
        }

        return LoginThrottle.DefaultSourceKey(http);
    }
}
