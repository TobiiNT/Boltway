using System.Diagnostics;
using System.Text;

using Boltway.OAuth.Net.RateLimiting;

namespace Boltway.OAuth.Net;

/// <summary>
/// The secret this server holds at an upstream identity provider.
/// </summary>
/// <remarks>
/// <para>
/// A type rather than a <see cref="string"/>, because the difference between the two is where the
/// value is allowed to go. <see cref="UpstreamEndpointClient"/> is the only code that can read it -
/// <see cref="Reveal"/> is <see langword="internal"/> to this assembly - so "the secret is only ever
/// written to the upstream token endpoint" is a property of the type system rather than of every
/// call site's discipline.
/// </para>
/// <para>
/// <c>OpaqueSecret</c> records why a <see cref="ToString"/> override is not on its own a defence:
/// it stops string interpolation and does nothing about <c>JsonSerializer.Serialize</c>, Serilog's
/// <c>{@value}</c> destructuring, or any structured-logging provider that reflects over properties.
/// The answer taken here is that <b>this type has no public members carrying the value at all</b> -
/// no property, no field, no getter - so a reflecting serializer finds nothing to write and emits
/// <c>{}</c>. There is a test that measures exactly that rather than assuming it.
/// </para>
/// <para>
/// What this type does <b>not</b> do is protect the value in memory. It is a managed
/// <see cref="string"/> on the heap for the lifetime of the process, subject to being copied by the
/// GC and written to a crash dump. A <c>SecureString</c> would not change that on .NET and is
/// documented by Microsoft as not doing so; the defence that matters here is that the value has one
/// reader.
/// </para>
/// </remarks>
public sealed class UpstreamClientSecret
{
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private readonly string _value;

    /// <summary>Wrap a configured secret.</summary>
    /// <param name="value">The secret, as the upstream issued it.</param>
    /// <exception cref="ArgumentException">The value is null or empty.</exception>
    public UpstreamClientSecret(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);

        _value = value;
    }

    /// <summary>The secret. Readable only inside the assembly that puts it on the wire.</summary>
    internal string Reveal() => _value;

    /// <summary>A placeholder. Never the value.</summary>
    public override string ToString() => "<upstream client secret>";

    /// <summary>Reference equality, deliberately.</summary>
    /// <remarks>
    /// Two <see cref="UpstreamClientSecret"/> instances holding the same string are not equal, and
    /// that is on purpose: a value-equality operator is a comparison of the plaintext, and the one
    /// place this codebase compares a secret it does so with
    /// <c>CryptographicOperations.FixedTimeEquals</c> over a hash. Nothing needs to compare these.
    /// </remarks>
    public override bool Equals(object? obj) => ReferenceEquals(this, obj);

    /// <inheritdoc />
    public override int GetHashCode() => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(this);
}

/// <summary>How this server authenticates itself at an upstream token endpoint.</summary>
/// <remarks>
/// Both are RFC 6749 §2.3.1. The specification says a server that supports password-based client
/// authentication MUST support HTTP Basic and MAY support the body form, and in practice which one
/// works is a property of the upstream: Google documents the body form, and several enterprise
/// products accept only Basic. So this is configuration, not a preference.
/// </remarks>
public enum UpstreamClientAuthMethod
{
    /// <summary><c>client_secret_post</c>: the credential is a form field.</summary>
    ClientSecretPost = 0,

    /// <summary><c>client_secret_basic</c>: the credential is an <c>Authorization: Basic</c> header.</summary>
    ClientSecretBasic = 1,
}

/// <summary>Knobs for <see cref="UpstreamEndpointClient"/>.</summary>
public sealed class UpstreamEndpointClientOptions
{
    /// <summary>Time allowed to open the TCP connection.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Total budget: DNS, connect, TLS and body.
    /// </summary>
    /// <remarks>
    /// Larger than <see cref="SafeHttpFetcherOptions.TotalTimeout"/>, and for a stated reason. That
    /// budget is small because the CIMD fetch happens inside <c>/authorize</c>, where the client
    /// abandons the whole authorization after about ten seconds. These fetches happen on the
    /// federation callback, where the only party waiting is a browser that has just come back from
    /// the upstream - so a slower answer is worth having, and failing at three seconds against a
    /// provider having a bad minute would strand a user who did nothing wrong.
    /// </remarks>
    public TimeSpan TotalTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Permit connections to loopback and private addresses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Off by default, and that is a decision rather than a copy of the CIMD setting.</b> The
    /// argument for leaving the RFC 6890 check on here is not the one that applies to a CIMD
    /// <c>client_id</c>: nobody supplies these URLs from a request, and the SSRF trigger that
    /// justifies the check over there does not exist.
    /// </para>
    /// <para>
    /// What does exist is that the operator configures <i>one</i> URL - the issuer - and everything
    /// else this client dereferences comes out of a document fetched from it. An OIDC discovery
    /// document names <c>token_endpoint</c> and <c>jwks_uri</c>, and those are not required to be
    /// same-origin with the issuer: Google's are on three different hosts, so an origin check is not
    /// available as an alternative. That makes the address check the only thing standing between "an
    /// upstream, or anyone who can answer as one, names <c>169.254.169.254</c>" and this server
    /// POSTing its client secret there.
    /// </para>
    /// <para>
    /// An on-premises identity provider on a private address is a legitimate deployment and this is
    /// how it is enabled. It costs one line of configuration and the operator making that choice
    /// knows their network; the same setting arrived at by default would be a choice nobody made.
    /// </para>
    /// </remarks>
    public bool AllowPrivateAddresses { get; set; }

    /// <summary>
    /// How many requests this instance will make to one upstream host per <see cref="RateLimitWindow"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate counter from <see cref="SafeHttpFetcherOptions.MaxFetchesPerHostPerWindow"/>, and
    /// deliberately so. Sharing one would let anonymous CIMD traffic - which anyone can generate by
    /// sending a <c>client_id</c> - exhaust the budget that federated sign-in needs, so a flood
    /// aimed at the authorization endpoint would take down sign-in for everyone. Two counters means
    /// each bounds its own outbound volume and neither can spend the other's.
    /// </para>
    /// <para>
    /// The number is sized against sign-in volume rather than against document caching: one
    /// federated sign-in costs one token exchange, plus a JWKS fetch only when the cache is cold or
    /// the upstream has rotated a key. Six hundred a minute is roughly ten sign-ins a second through
    /// one instance, which is far above anything this product's deployments resemble and still a
    /// bound on what one instance can be made to send.
    /// </para>
    /// </remarks>
    public int MaxRequestsPerHostPerWindow { get; set; } = 600;

    /// <summary>The window <see cref="MaxRequestsPerHostPerWindow"/> counts in.</summary>
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How long an upstream host stays refused once it has exceeded its budget.</summary>
    public TimeSpan RateLimitBackoff { get; set; } = TimeSpan.FromSeconds(30);

    /// <inheritdoc cref="SafeHttpFetcherOptions.SslOptionsForTests" />
    internal System.Net.Security.SslClientAuthenticationOptions? SslOptionsForTests { get; set; }
}

/// <summary>A GET of an operator-configured document: discovery, or JWKS.</summary>
/// <remarks>
/// A class rather than a record for the same reason <c>GuardedRequestBody</c> is: nothing here
/// should acquire a synthesized <see cref="object.ToString"/> that renders its members, because the
/// sibling request type below holds a credential and the two are read together.
/// </remarks>
public sealed class UpstreamDocumentRequest
{
    /// <summary>Construct.</summary>
    /// <param name="url">The document URL.</param>
    /// <param name="purpose">What it is for. Selects the byte cap.</param>
    public UpstreamDocumentRequest(AbsoluteHttpsUrl url, FetchPurpose purpose)
    {
        Url = url;
        Purpose = purpose;
    }

    /// <summary>The document URL.</summary>
    public AbsoluteHttpsUrl Url { get; }

    /// <summary>What it is for.</summary>
    public FetchPurpose Purpose { get; }

    /// <summary>Cap on bytes read. Defaults from <see cref="Purpose"/>.</summary>
    public int MaxBytes { get; init; }

    /// <summary>Total budget, or the client's default.</summary>
    public TimeSpan? Timeout { get; init; }
}

/// <summary>A credentialed form POST to an operator-configured token endpoint.</summary>
public sealed class UpstreamFormRequest
{
    /// <summary>Construct.</summary>
    /// <param name="url">The token endpoint.</param>
    /// <param name="purpose">What it is for. Selects the byte cap.</param>
    /// <param name="fields">
    /// The form fields, <b>excluding</b> client authentication. <c>client_id</c> and
    /// <c>client_secret</c> are added by this client according to <see cref="AuthMethod"/>, so a
    /// caller cannot put the secret in the wrong place or forget it.
    /// </param>
    public UpstreamFormRequest(
        AbsoluteHttpsUrl url, FetchPurpose purpose, IReadOnlyList<KeyValuePair<string, string>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        Url = url;
        Purpose = purpose;
        Fields = fields;
    }

    /// <summary>The token endpoint.</summary>
    public AbsoluteHttpsUrl Url { get; }

    /// <summary>What it is for.</summary>
    public FetchPurpose Purpose { get; }

    /// <summary>The form fields, excluding client authentication.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Fields { get; }

    /// <summary>This server's client identifier at the upstream.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The secret, or <see langword="null"/> for a public client at the upstream.
    /// </summary>
    /// <remarks>
    /// Nullable because a public upstream client is a real configuration - an upstream that supports
    /// PKCE and issues no secret - and because a deployment that has not configured one should send
    /// no credential rather than an empty one, which some providers accept as authentication.
    /// </remarks>
    public UpstreamClientSecret? ClientSecret { get; init; }

    /// <summary>How to present the credential.</summary>
    public UpstreamClientAuthMethod AuthMethod { get; init; }

    /// <summary>Cap on bytes read. Defaults from <see cref="Purpose"/>.</summary>
    public int MaxBytes { get; init; }

    /// <summary>Total budget, or the client's default.</summary>
    public TimeSpan? Timeout { get; init; }
}

/// <summary>
/// Talks to an upstream identity provider's endpoints.
/// </summary>
/// <remarks>
/// <para>
/// The second outbound client, and the reason it is a second one rather than a method on
/// <see cref="ISafeHttpFetcher"/> is that the two fetches are not the same trust. A CIMD document is
/// dereferenced from a URL an unauthenticated request supplied; an upstream token endpoint is a URL
/// the operator configured, and this client carries a credential to it. Merging them would produce
/// one type with a per-request "is this attacker-supplied" flag, which is precisely the shape where
/// the wrong flag eventually gets passed.
/// </para>
/// <para>
/// It lives in <c>Boltway.OAuth.Net</c> because
/// <c>StructuralRuleTests.Only_the_guarded_fetcher_touches_system_net_http</c> allows no other
/// assembly to reach <c>System.Net.Http</c> at all, and the exception list for that rule is empty.
/// Federation needed a POST; the answer is to extend the guarded assembly, not to add an exception.
/// </para>
/// <para>
/// The guards it keeps and the one it changes:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>Redirects are not followed</b>, unchanged. A 302 from a token endpoint would carry the
/// credential to wherever <c>Location</c> pointed if the handler followed it, and .NET's default is
/// to follow. There is no legitimate redirect on this path.
/// </description></item>
/// <item><description>
/// <b>The byte cap and the timeout</b> stay, sized differently - see the options.
/// </description></item>
/// <item><description>
/// <b>The connection is pinned to the validated address</b>, unchanged, so there is no second DNS
/// lookup between the check and the socket.
/// </description></item>
/// <item><description>
/// <b>Private-address blocking is on by default and can be switched off.</b> That is the one
/// deliberate difference, and <see cref="UpstreamEndpointClientOptions.AllowPrivateAddresses"/>
/// carries the argument.
/// </description></item>
/// </list>
/// <para>
/// <b>The credential never leaves this file except onto the socket.</b> It arrives as an
/// <see cref="UpstreamClientSecret"/>, whose value only this assembly can read; it is written into
/// a form field or an <c>Authorization</c> header inside <see cref="PostFormAsync"/>; and no
/// <see cref="FetchOutcome"/> this method returns contains anything derived from it. This class
/// logs nothing - it takes no logger - so there is no line for it to appear in.
/// </para>
/// </remarks>
public sealed class UpstreamEndpointClient : IUpstreamEndpointClient, IDisposable
{
    /// <summary>Byte cap for a discovery or JWKS document.</summary>
    /// <remarks>
    /// Generous next to the 5 KB CIMD default because a JWKS legitimately carries several keys
    /// through a rotation, and because the document is not attacker-supplied - the cost being
    /// bounded here is a misbehaving or compromised upstream sending an unbounded body, not a
    /// stranger choosing the URL.
    /// </remarks>
    public const int DocumentByteCap = 32 * 1024;

    /// <summary>Byte cap for a token response.</summary>
    /// <remarks>
    /// A token response is an ID token, an access token and a few short fields. 16 KB is several
    /// times the largest realistic one and still a bound.
    /// </remarks>
    public const int TokenResponseByteCap = 16 * 1024;

    private readonly UpstreamEndpointClientOptions _options;
    private readonly GuardedTransport _transport;
    private readonly KeyedRateLimiter _perHost;

    /// <summary>Create a client.</summary>
    /// <param name="options">The budgets and timeouts, or the defaults.</param>
    /// <param name="resolver">The address resolver, or DNS.</param>
    /// <param name="time">The clock the outbound budget counts on.</param>
    public UpstreamEndpointClient(
        UpstreamEndpointClientOptions? options = null,
        IAddressResolver? resolver = null,
        TimeProvider? time = null)
    {
        _options = options ?? new UpstreamEndpointClientOptions();

        _perHost = new KeyedRateLimiter(
            time ?? TimeProvider.System,
            new KeyedRateLimiterOptions
            {
                Window = _options.RateLimitWindow,
                PermitsPerWindow = _options.MaxRequestsPerHostPerWindow,
                InitialBackoff = _options.RateLimitBackoff,
                MaxBackoff = _options.RateLimitBackoff,
            });

        _transport = new GuardedTransport(
            _options.ConnectTimeout,
            _options.AllowPrivateAddresses,
            resolver ?? new DnsAddressResolver(),
            _options.SslOptionsForTests);
    }

    /// <inheritdoc />
    public async Task<FetchOutcome> GetAsync(UpstreamDocumentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Refused(request.Url) is { } refusal)
        {
            return refusal;
        }

        return await _transport.SendAsync(
            request.Url,
            body: null,
            request.MaxBytes > 0 ? request.MaxBytes : DocumentByteCap,
            request.Timeout ?? _options.TotalTimeout,
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<FetchOutcome> PostFormAsync(UpstreamFormRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Refused(request.Url) is { } refusal)
        {
            return refusal;
        }

        var fields = new List<KeyValuePair<string, string>>(request.Fields.Count + 2);
        fields.AddRange(request.Fields);

        string? authorization = null;

        if (request.ClientSecret is { } secret)
        {
            if (request.AuthMethod is UpstreamClientAuthMethod.ClientSecretBasic)
            {
                // RFC 6749 §2.3.1: both halves are form-urlencoded before they are joined by a colon
                // and base64'd. Skipping that step is the classic interop bug for a secret
                // containing `+` or `/`, and it fails as "invalid_client" against a correct server.
                authorization = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(
                    Uri.EscapeDataString(request.ClientId) + ":" + Uri.EscapeDataString(secret.Reveal())));

                // §2.3.1 again: `client_id` is still sent in the body by many deployments, and some
                // upstreams require it. It is not the credential, so this is safe and it is what
                // makes one configuration work against both strict and lenient servers.
                fields.Add(new("client_id", request.ClientId));
            }
            else
            {
                fields.Add(new("client_id", request.ClientId));
                fields.Add(new("client_secret", secret.Reveal()));
            }
        }
        else
        {
            fields.Add(new("client_id", request.ClientId));
        }

        return await _transport.SendAsync(
            request.Url,
            new GuardedRequestBody(fields, authorization),
            request.MaxBytes > 0 ? request.MaxBytes : TokenResponseByteCap,
            request.Timeout ?? _options.TotalTimeout,
            cancellationToken);
    }

    /// <summary>Charge the outbound budget, or say how long to wait.</summary>
    /// <remarks>
    /// Before DNS, like the CIMD budget, and for the same reason: the cost being bounded is the
    /// outbound request rather than the answer.
    /// </remarks>
    private FetchOutcome.RateLimited? Refused(AbsoluteHttpsUrl url)
    {
        var permit = _perHost.Acquire(url.Host);

        return permit.Allowed
            ? null
            : new FetchOutcome.RateLimited(
                permit.RetryAfter,
                $"this instance has reached its upstream budget for '{SafeHttpFetcher.Echo(url.Host)}'");
    }

    /// <inheritdoc />
    public void Dispose() => _transport.Dispose();
}

/// <summary>
/// Talks to an upstream identity provider.
/// </summary>
/// <remarks>
/// A seam so a deployment can substitute the transport - and, more importantly, so a test can drive
/// a federation flow without a network. The implementation shipped in the box is
/// <see cref="UpstreamEndpointClient"/> and it is the only one that may exist outside a test:
/// <c>StructuralRuleTests.Only_the_guarded_fetcher_touches_system_net_http</c> means any other
/// implementation in <c>src/</c> would have to reach the network some other way, and there is none.
/// </remarks>
public interface IUpstreamEndpointClient
{
    /// <summary>Fetch a document, or explain why not.</summary>
    Task<FetchOutcome> GetAsync(UpstreamDocumentRequest request, CancellationToken cancellationToken);

    /// <summary>POST a credentialed form, or explain why not.</summary>
    Task<FetchOutcome> PostFormAsync(UpstreamFormRequest request, CancellationToken cancellationToken);
}
