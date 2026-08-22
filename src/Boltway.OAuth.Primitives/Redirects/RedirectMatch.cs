namespace Boltway.OAuth.Primitives.Redirects;

/// <summary>
/// The outcome of matching a requested redirect URI against a client's registrations.
/// </summary>
/// <remarks>
/// <para>
/// A successful match is <b>proof</b> that redirecting is now permitted, and it is the only thing
/// downstream that can authorize an error to be delivered by redirect rather than rendered as HTML
/// (N-11). That makes forging one equivalent to defeating the ordering rule, so the factories are
/// <see langword="internal"/> and <see cref="RedirectUriMatcher.Match"/> is the only caller.
/// </para>
/// <para>
/// An architecture test asserts that call-site count, because <see langword="internal"/> alone would
/// still let any other file in this assembly mint one. C# has no friend-class, so the guarantee is
/// "one call site, enforced over the compiled IL" rather than a language feature.
/// </para>
/// </remarks>
public readonly struct RedirectMatch
{
    private RedirectMatch(bool matched, RedirectMatchKind kind, RegisteredRedirectUri registration, string requestedValue)
    {
        Matched = matched;
        Kind = kind;
        Registration = registration;
        RequestedValue = requestedValue;
    }

    /// <summary>Whether the request matched a registration.</summary>
    public bool Matched { get; }

    /// <summary>Which rule matched. Recorded so the decision is auditable after the fact.</summary>
    public RedirectMatchKind Kind { get; }

    /// <summary>The registration that matched.</summary>
    public RegisteredRedirectUri Registration { get; }

    /// <summary>
    /// The value to actually redirect to: the <b>requested</b> string, not the registered one.
    /// </summary>
    /// <remarks>
    /// This distinction is load-bearing for RFC 8252 §7.3. The client registered
    /// <c>http://127.0.0.1/callback</c> with no port and is listening on an ephemeral one, so
    /// redirecting to the registered string would send the browser to port 80 where nothing is
    /// listening. The port came from the request and the response has to carry it back.
    /// </remarks>
    public string RequestedValue { get; }

    /// <summary>No registration matched. The only value constructible from outside this assembly.</summary>
    public static RedirectMatch None => default;

    internal static RedirectMatch Exact(RegisteredRedirectUri registration, string requestedValue) =>
        new(true, RedirectMatchKind.Exact, registration, requestedValue);

    internal static RedirectMatch LoopbackPortIgnored(RegisteredRedirectUri registration, string requestedValue) =>
        new(true, RedirectMatchKind.LoopbackPortIgnored, registration, requestedValue);
}

/// <summary>Which rule produced a match.</summary>
public enum RedirectMatchKind
{
    /// <summary>No match.</summary>
    None = 0,

    /// <summary>RFC 3986 §6.2.1 Simple String Comparison. The path for every https client.</summary>
    Exact = 1,

    /// <summary>RFC 8252 §7.3 loopback exception: everything compared except the port.</summary>
    LoopbackPortIgnored = 2,
}
