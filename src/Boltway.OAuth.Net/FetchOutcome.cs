using Boltway.OAuth.Primitives.Http;

namespace Boltway.OAuth.Net;

/// <summary>What the server was trying to fetch. Chooses the budget and the size cap.</summary>
public enum FetchPurpose
{
    /// <summary>A CIMD document, dereferenced from a <c>client_id</c> on an authorization request.</summary>
    ClientIdMetadataDocument,

    /// <summary>A client's <c>jwks_uri</c>, for <c>private_key_jwt</c> verification.</summary>
    JwksUri,

    /// <summary>A client's <c>logo_uri</c>, proxied so the consent page never hotlinks it.</summary>
    LogoUri,

    /// <summary>An upstream identity provider's discovery document.</summary>
    UpstreamDiscovery,

    /// <summary>
    /// An upstream identity provider's signing keys, for validating an ID token it issued.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="JwksUri"/>, which is a <i>client's</i> key set read out of a
    /// document fetched from an attacker-chosen host. This one is reached from an operator-configured
    /// issuer and goes through <see cref="UpstreamEndpointClient"/>, which has different budgets and
    /// a different address policy.
    /// </remarks>
    UpstreamJwks,

    /// <summary>
    /// An upstream identity provider's token endpoint, exchanging an authorization code.
    /// </summary>
    /// <remarks>
    /// The only purpose whose request carries a credential of this server's, and the only one that
    /// is a POST.
    /// </remarks>
    UpstreamTokenExchange,

    /// <summary>
    /// The authorization server's own discovery document, fetched by a <i>resource</i> server.
    /// </summary>
    /// <remarks>
    /// Named apart from <see cref="UpstreamDiscovery"/> rather than reusing it. The transport and
    /// the address policy are the same; the direction is not. "Upstream" is this server acting as a
    /// relying party against somebody else's identity provider, and this is a resource server
    /// reading the keys of the authorization server it is deployed beside. A purpose is what a log
    /// line and a metric are grouped by, so two directions sharing one name is two things nobody can
    /// tell apart at three in the morning.
    /// </remarks>
    AuthorizationServerDiscovery,

    /// <summary>
    /// The authorization server's signing keys, fetched by a <i>resource</i> server that verifies
    /// its access tokens offline.
    /// </summary>
    /// <remarks>
    /// See <see cref="AuthorizationServerDiscovery"/> for why this is not <see cref="UpstreamJwks"/>,
    /// and <see cref="JwksUri"/> for the third case — a client's key set, read from a host an
    /// attacker chose, which is the one with the tight budgets.
    /// </remarks>
    AuthorizationServerJwks,
}

/// <summary>Why a fetch was refused before any connection was made.</summary>
public enum BlockReason
{
    /// <summary>Not a permitted URL shape.</summary>
    NotAnHttpsUrl,

    /// <summary>The host did not resolve.</summary>
    DnsFailed,

    /// <summary>An address is special-use. RFC 6890.</summary>
    /// <remarks>
    /// <para>
    /// <strong>What produced it cannot be told from here.</strong> A name in public DNS resolving
    /// to <c>0.0.0.0</c> or <c>127.0.0.1</c> is what a DNS blocklist answers with, what a host
    /// nobody has configured yet answers with, and what an attacker aiming a fetch at this machine
    /// arranges — the three are the same observation. RFC 1918 is ordinary split-horizon DNS for a
    /// name a company hosts internally. The fetch is refused for all of them, and the refusal says
    /// what was seen rather than what it means.
    /// </para>
    /// <para>
    /// Do not read <c>0.0.0.0</c> as a harmless sinkhole. Measured on 2026-08-26, Linux 6.18:
    /// connecting to it reaches a service bound to <c>127.0.0.1</c>.
    /// </para>
    /// </remarks>
    SpecialUseAddress,

    /// <summary>An address is link-local, which is where the cloud metadata endpoint lives.</summary>
    /// <remarks>
    /// Split from <see cref="SpecialUseAddress" /> because it is the one part of the blocklist with
    /// no innocent reading: <c>169.254.0.0/16</c> and <c>fe80::/10</c> are not what a filtered
    /// resolver answers with, not split-horizon DNS, and not an unconfigured host. It is the case
    /// the SSRF blocklist exists for, and the only one this server will say so about.
    /// </remarks>
    LinkLocalAddress,
}

/// <summary>A request to fetch an attacker-supplied URL.</summary>
/// <param name="Url">The URL. Its type is the proof it is <c>https</c> and well-formed.</param>
/// <param name="Purpose">What it is for.</param>
/// <param name="MaxBytes">Cap on bytes <b>read</b>, not on the declared <c>Content-Length</c>.</param>
/// <param name="Timeout">Total budget including DNS, connect, TLS and body.</param>
public sealed record SafeFetchRequest(
    AbsoluteHttpsUrl Url,
    FetchPurpose Purpose,
    int MaxBytes = 5 * 1024,
    TimeSpan? Timeout = null)
{
    /// <summary>Cap on bytes read. Must be positive.</summary>
    /// <remarks>
    /// Validated because both edges were wrong: <c>int.MaxValue</c> overflowed the read-buffer
    /// sizing and threw out of <c>FetchAsync</c>, and a negative value produced a zero-length
    /// buffer and a silent empty document reported as success.
    /// </remarks>
    public int MaxBytes { get; } = MaxBytes > 0
        ? MaxBytes
        : throw new ArgumentOutOfRangeException(nameof(MaxBytes), MaxBytes, "MaxBytes must be positive.");
}

/// <summary>
/// The result of a guarded fetch. A closed set, because every branch has a distinct response.
/// </summary>
/// <remarks>
/// Separate cases rather than an exception and a status, because the caller genuinely does
/// different things: a <see cref="Redirected"/> CIMD document is a specification violation to
/// report, a <see cref="Timeout"/> is a case for serving a stale cache entry, and a
/// <see cref="Blocked"/> carrying <see cref="BlockReason.LinkLocalAddress"/> is worth an alert
/// because nothing benign resolves a public name into link-local space.
///
/// This paragraph used to say that of <see cref="Blocked"/> as a whole — "it means someone pointed
/// the server at a private address" — which is an inference from one lookup stated as a fact about
/// somebody else's network. A filtered resolver, split-horizon DNS and an attack are the same
/// observation from here. <c>LESSONS.md</c> is twelve instances of that mistake and this was the
/// thirteenth.
/// </remarks>
public abstract record FetchOutcome
{
    private FetchOutcome() { }

    /// <summary>200, within budget and under the cap.</summary>
    public sealed record Ok(byte[] Body, MediaType ContentType, string? ETag, TimeSpan? MaxAge) : FetchOutcome;

    /// <summary>Refused before any socket was opened.</summary>
    public sealed record Blocked(BlockReason Reason, string Detail) : FetchOutcome;

    /// <summary>
    /// The server answered with a redirect, which is not followed.
    /// </summary>
    /// <remarks>
    /// The CIMD draft §5 says a client metadata document MUST be retrieved without following
    /// redirects, and the reason is exactly SSRF: a public host answering 302 to
    /// <c>http://169.254.169.254/</c> would otherwise walk the fetcher straight past the address
    /// check, because the check ran on the first hop. <c>AllowAutoRedirect</c> defaults to
    /// <see langword="true"/> in .NET, so a stock <c>HttpClient</c> has this hole open.
    /// </remarks>
    public sealed record Redirected(int Status, string? Location) : FetchOutcome;

    /// <summary>A non-200 status. Only 200 is acceptable for these documents.</summary>
    public sealed record NotOk(int Status) : FetchOutcome;

    /// <summary>The body exceeded the cap while being read.</summary>
    public sealed record TooLarge(int BytesRead) : FetchOutcome;

    /// <summary>The budget expired.</summary>
    public sealed record Timeout(TimeSpan Elapsed) : FetchOutcome;

    /// <summary>The connection failed or TLS did not establish.</summary>
    public sealed record TransportFailed(string Detail) : FetchOutcome;

    /// <summary>
    /// Refused by this server's own outbound budget for the remote host. X-31.
    /// </summary>
    /// <remarks>
    /// Its own case rather than a <see cref="Blocked"/> reason, because the caller answers it
    /// differently: <see cref="Blocked"/> means the URL will never be fetchable and the request is
    /// wrong, whereas this means the request is fine and arrived too fast, which is a 429 with a
    /// <c>Retry-After</c> rather than a 400. Folding the two together would tell a client to fix a
    /// <c>client_id</c> that has nothing wrong with it.
    /// </remarks>
    /// <param name="RetryAfter">How long until this host's budget refills.</param>
    /// <param name="Detail">Which budget refused it, for the log and the description.</param>
    public sealed record RateLimited(TimeSpan RetryAfter, string Detail) : FetchOutcome;
}

/// <summary>
/// Fetches a URL the server does not control.
/// </summary>
/// <remarks>
/// The single outbound HTTP surface. An architecture test asserts that no assembly other than
/// <c>Boltway.OAuth.Net</c> references <c>System.Net.Http</c> at all, and the exception list
/// for that rule is empty — which is what makes "every outbound fetch is guarded" checkable rather
/// than a claim. An allowlist would be a place to add an entry.
/// </remarks>
public interface ISafeHttpFetcher
{
    /// <summary>Fetch, or explain why not.</summary>
    Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken cancellationToken);
}
