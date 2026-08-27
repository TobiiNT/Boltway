using System.Text;
using System.Text.Json;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Net;

/// <summary>How a <see cref="JwksKeySource"/> finds and refreshes an authorization server's keys.</summary>
public sealed class JwksKeySourceOptions
{
    /// <summary>
    /// How long a fetched key set is used before a refresh is started.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Five minutes, and the number is derived rather than chosen.</b> A signing key ring
    /// publishes a key for at least <c>PublishLeadTime</c> before it signs anything - 24 hours by
    /// default, with a floor of ten minutes. So the question this interval answers is not "how fast
    /// can we notice a new key" but "can we notice it inside the shortest lead time a deployment is
    /// allowed to configure". Five is inside ten with the margin a failed fetch needs.
    /// </para>
    /// <para>
    /// Raising this above an authorization server's <c>PublishLeadTime</c> reintroduces exactly the
    /// failure this type exists to remove: the key rotates, this cache has not seen it, and every
    /// token signed by it is rejected with a message that reads like a bad signature.
    /// </para>
    /// </remarks>
    public TimeSpan CacheLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The shortest gap between two outbound fetches, whatever else asks for one.
    /// </summary>
    /// <remarks>
    /// A floor under <see cref="CacheLifetime"/> and under the retry below, so no combination of
    /// configuration and traffic turns a resource server into a load generator against the one
    /// component every one of its requests already depends on.
    /// </remarks>
    public TimeSpan MinimumRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long to wait after a failed fetch before trying again.
    /// </summary>
    /// <remarks>
    /// Deliberately shorter than <see cref="CacheLifetime"/>. A failure is the state where the keys
    /// held are ageing toward useless, so the interesting case is recovering quickly - bounded by
    /// <see cref="MinimumRefreshInterval"/>, which is what keeps "quickly" from meaning "per
    /// request" while the authorization server is down.
    /// </remarks>
    public TimeSpan FailureRetryInterval { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The JWKS URL, when a deployment would rather not have this make a discovery request.
    /// </summary>
    /// <remarks>
    /// Set it and no discovery document is ever fetched - the same escape
    /// <c>Boltway.Federation.Oidc</c> offers, and for the same deployments: air-gapped, or
    /// tightly egressed, or simply unwilling to have one more URL in the startup path. Unset (the
    /// default) means <c>{issuer}/.well-known/openid-configuration</c>, whose <c>issuer</c> member
    /// is checked before its <c>jwks_uri</c> is read.
    /// </remarks>
    public string JwksUri { get; set; } = string.Empty;
}

/// <summary>What a refresh did.</summary>
public enum JwksRefreshOutcome
{
    /// <summary>Keys were fetched and replaced the previous set.</summary>
    Refreshed,

    /// <summary>Nothing was fetched, because the cached set is still inside its lifetime.</summary>
    StillFresh,

    /// <summary>Nothing was fetched, because the last attempt failed too recently to retry.</summary>
    BackingOff,

    /// <summary>
    /// The fetch failed. Any previously fetched keys are still in use - see
    /// <see cref="JwksKeySource.Status"/> for how old they are.
    /// </summary>
    Failed,
}

/// <summary>A refresh outcome, with the detail a log line needs.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="KeyCount">How many signing keys are in use after this call.</param>
/// <param name="Detail">Why, when it failed. Never null on <see cref="JwksRefreshOutcome.Failed"/>.</param>
public readonly record struct JwksRefresh(JwksRefreshOutcome Outcome, int KeyCount, string? Detail);

/// <summary>What this source knows right now, for a log line or a health check.</summary>
/// <param name="KeyCount">Signing keys currently in use.</param>
/// <param name="LastSuccessAt">When keys were last fetched, or null if never.</param>
/// <param name="LastFailureAt">When a fetch last failed, or null if never.</param>
/// <param name="LastFailureDetail">Why it failed, or null.</param>
public readonly record struct JwksKeySourceStatus(
    int KeyCount,
    DateTimeOffset? LastSuccessAt,
    DateTimeOffset? LastFailureAt,
    string? LastFailureDetail);

/// <summary>
/// Keeps an authorization server's published signing keys current, for a resource server that
/// verifies its tokens offline.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it removes.</b> <c>ProtectedResourceOptions.SigningKeys</c> is a list the host fills, and
/// before this type nothing refreshed it - so a resource server stopped accepting tokens the moment
/// the authorization server rotated a key. That is not a hypothetical: <c>SigningKeyRing</c> models
/// Pending → Active → Retiring and a deployment that follows the production checklist <i>will</i>
/// rotate. The outage was scheduled; only its date was unknown.
/// </para>
/// <para>
/// <b><see cref="CurrentKeys"/> never blocks and never throws</b>, because it is called on the
/// request path - <c>AccessTokenValidator</c> reads the key set per validation. It returns the last
/// good snapshot and, if that snapshot is stale, starts <i>one</i> refresh in the background. So a
/// rotation is picked up by the request after the fetch completes rather than by the request that
/// noticed, and no request ever waits on the authorization server to answer.
/// </para>
/// <para>
/// <b>Read-driven rather than timer-driven, and that is the cheaper direction to be wrong in.</b>
/// A resource server with no traffic makes no outbound requests, and one under load refreshes
/// exactly as often as <see cref="JwksKeySourceOptions.MinimumRefreshInterval"/> permits. A timer
/// would fetch through the night to keep a cache nobody is reading warm, and would still be
/// read-driven on the first request after a restart.
/// </para>
/// <para>
/// <b>A failed fetch keeps the keys already held.</b> They are still the ones the authorization
/// server published; an authorization server that is briefly unreachable should not reject every
/// token for as long as the outage lasts. What is <i>not</i> done is pretending: <see cref="Status"/>
/// carries the failure and its age, and a host that wants an alert has the two timestamps to build
/// it from. This is the same shape as <c>IntrospectionRevocationCheck</c> failing open, and it wants
/// the same alert.
/// </para>
/// <para>
/// <b>Call <see cref="RefreshAsync"/> once at startup.</b> Before the first successful fetch this
/// source holds no keys, and a resource server holding no keys rejects everything. The sample does
/// it, and the failure is loud there rather than silent here.
/// </para>
/// </remarks>
public sealed class JwksKeySource : IDisposable
{
    private readonly IssuerString _issuer;
    private readonly IUpstreamEndpointClient _http;
    private readonly JwksKeySourceOptions _options;
    private readonly TimeProvider _time;
    private readonly AbsoluteHttpsUrl? _configuredJwksUri;
    private readonly AbsoluteHttpsUrl? _discoveryUri;

    private readonly SemaphoreSlim _gate = new(1, 1);

    // Written under _gate, read without it. A reference assignment of an already-populated array is
    // atomic, so a reader sees either the previous snapshot or the next one and never a half-built
    // list - which is the whole reason SigningKeySource exists rather than a mutable IList.
    private volatile IReadOnlyList<SecurityKey> _keys = [];

    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;
    private DateTimeOffset _lastAttemptAt = DateTimeOffset.MinValue;
    private DateTimeOffset? _lastSuccessAt;
    private DateTimeOffset? _lastFailureAt;
    private string? _lastFailureDetail;

    private int _refreshInFlight;
    private bool _disposed;

    /// <summary>Construct.</summary>
    /// <param name="issuer">
    /// The authorization server's issuer, byte-identical to the one the resource server validates
    /// <c>iss</c> against. It is compared ordinally to the discovery document's own <c>issuer</c>.
    /// </param>
    /// <param name="http">The guarded outbound client. This type makes no request of its own.</param>
    /// <param name="options">Lifetimes and the discovery escape, or the defaults.</param>
    /// <param name="time">The clock the lifetimes count on, or the system one.</param>
    /// <exception cref="ArgumentException">
    /// The issuer is unset, or <see cref="JwksKeySourceOptions.JwksUri"/> is set to something that
    /// is not an absolute https URL. Both are startup failures on purpose: the alternative is a
    /// resource server that starts, serves discovery, and rejects every token.
    /// </exception>
    public JwksKeySource(
        IssuerString issuer,
        IUpstreamEndpointClient http,
        JwksKeySourceOptions? options = null,
        TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(http);

        if (string.IsNullOrEmpty(issuer.Value))
        {
            throw new ArgumentException(
                "The issuer is unset. It is what the discovery document is checked against, so "
                + "there is no safe default for it.",
                nameof(issuer));
        }

        _issuer = issuer;
        _http = http;
        _options = options ?? new JwksKeySourceOptions();
        _time = time ?? TimeProvider.System;

        if (!string.IsNullOrEmpty(_options.JwksUri))
        {
            if (!AbsoluteHttpsUrl.TryCreate(_options.JwksUri, out var configured))
            {
                throw new ArgumentException(
                    $"JwksUri '{_options.JwksUri}' is not an absolute https URL.",
                    nameof(options));
            }

            _configuredJwksUri = configured;
        }
        else
        {
            // OIDC Discovery §4.1's append spelling. This server's own issuer is path-less by
            // validation, so the append and RFC 8414's insert spelling produce the same URL and
            // there is nothing to choose between - see AuthorizationServerOptions.ValidateIssuer for
            // why that is required rather than merely usual.
            _discoveryUri = AbsoluteHttpsUrl.TryCreate(
                _issuer.Value.TrimEnd('/') + "/.well-known/openid-configuration", out var discovery)
                ? discovery
                : throw new ArgumentException(
                    $"No discovery URL can be built from issuer '{_issuer.Value}', and JwksUri is "
                    + "unset. One of the two has to name an absolute https URL.",
                    nameof(issuer));
        }
    }

    /// <summary>What this source knows right now.</summary>
    public JwksKeySourceStatus Status =>
        new(_keys.Count, _lastSuccessAt, _lastFailureAt, _lastFailureDetail);

    /// <summary>
    /// The keys to verify with, right now. Assign this to
    /// <c>ProtectedResourceOptions.SigningKeySource</c>.
    /// </summary>
    /// <remarks>
    /// A method rather than a property so it converts to the <c>Func&lt;IReadOnlyList&lt;SecurityKey&gt;&gt;</c>
    /// that seam takes: <c>options.SigningKeySource = source.CurrentKeys;</c>. Never blocks, never
    /// throws, and starts a background refresh when the snapshot is stale.
    /// </remarks>
    /// <returns>The current snapshot, which is empty until the first successful fetch.</returns>
    public IReadOnlyList<SecurityKey> CurrentKeys()
    {
        if (!_disposed && DueForRefresh(_time.GetUtcNow()))
        {
            StartBackgroundRefresh();
        }

        return _keys;
    }

    /// <summary>
    /// Fetch now, if the intervals allow it, and wait for the answer.
    /// </summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>What happened, and how many keys are in use afterwards.</returns>
    /// <remarks>
    /// This is the startup call. It is also the one to use from a health check, because unlike
    /// <see cref="CurrentKeys"/> it reports a failure rather than absorbing it.
    /// </remarks>
    public async Task<JwksRefresh> RefreshAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            return await RefreshUnderGateAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Release the single-flight gate.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Dispose();
    }

    /// <summary>Whether the snapshot is old enough to want replacing.</summary>
    private bool SnapshotStale(DateTimeOffset now) =>
        _keys.Count == 0 || now - _fetchedAt >= _options.CacheLifetime;

    /// <summary>
    /// Whether enough time has passed since the last attempt - successful or not - to make another.
    /// </summary>
    /// <remarks>
    /// This floor applies to every trigger. Without it an empty snapshot makes every request due,
    /// and a cold start against a dead authorization server becomes one outbound attempt per inbound
    /// request.
    /// </remarks>
    private bool AttemptFloorElapsed(DateTimeOffset now) =>
        now - _lastAttemptAt >= _options.MinimumRefreshInterval;

    /// <summary>Whether the most recent attempt failed and its retry interval has not elapsed.</summary>
    /// <remarks>
    /// <b>The <c>_lastSuccessAt is null</c> arm is not redundant, and leaving it out was a defect a
    /// test caught.</b> This was written as <c>_lastFailureAt &gt; _lastSuccessAt</c>, which is a
    /// lifted comparison: with no success ever recorded the right operand is null and the whole
    /// expression is <see langword="false"/>, not true. So the backoff applied in every state except
    /// the one it was written for - a cold start against an authorization server that is down, where
    /// there is no success to be newer than.
    /// </remarks>
    private bool InFailureBackoff(DateTimeOffset now) =>
        _lastFailureAt is { } failed
        && (_lastSuccessAt is null || failed > _lastSuccessAt)
        && now - failed < _options.FailureRetryInterval;

    /// <summary>Whether a read should start a refresh.</summary>
    private bool DueForRefresh(DateTimeOffset now) =>
        AttemptFloorElapsed(now) && !InFailureBackoff(now) && SnapshotStale(now);

    /// <summary>Start at most one refresh, and never let it throw into the thread pool.</summary>
    private void StartBackgroundRefresh()
    {
        // The gate below would serialise these anyway; this stops a hundred concurrent requests
        // from each queueing a work item that will find the cache fresh and do nothing.
        if (Interlocked.CompareExchange(ref _refreshInFlight, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await RefreshAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                // Disposed while this was queued. Nothing is waiting on the answer.
            }
            finally
            {
                Volatile.Write(ref _refreshInFlight, 0);
            }
        });
    }

    /// <summary>The fetch itself. Caller holds the gate.</summary>
    private async Task<JwksRefresh> RefreshUnderGateAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();

        // Re-tested inside the gate, through the same three predicates the read path uses: without
        // this, requests that queued on a cold cache each make their own fetch as they are let
        // through one at a time.
        if (!SnapshotStale(now))
        {
            return new JwksRefresh(JwksRefreshOutcome.StillFresh, _keys.Count, null);
        }

        if (!AttemptFloorElapsed(now) || InFailureBackoff(now))
        {
            return new JwksRefresh(JwksRefreshOutcome.BackingOff, _keys.Count, _lastFailureDetail);
        }

        _lastAttemptAt = now;

        AbsoluteHttpsUrl jwksUri;

        if (_configuredJwksUri is { } configured)
        {
            jwksUri = configured;
        }
        else
        {
            var discovered = await DiscoverJwksUriAsync(cancellationToken).ConfigureAwait(false);

            if (discovered.Url is not { } found)
            {
                return Fail(now, discovered.Detail!);
            }

            jwksUri = found;
        }

        var outcome = await _http.GetAsync(
            new UpstreamDocumentRequest(jwksUri, FetchPurpose.AuthorizationServerJwks),
            cancellationToken).ConfigureAwait(false);

        if (outcome is not FetchOutcome.Ok ok)
        {
            return Fail(now, $"jwks fetch: {DescribeFetch(outcome)}");
        }

        IReadOnlyList<SecurityKey> keys;

        try
        {
            // GetSigningKeys(), not Keys: it drops anything whose `use` is not signature and
            // anything it cannot turn into a verification key, so a JWKS carrying an encryption key
            // does not put one in the signature allow-list.
            keys = [.. new JsonWebKeySet(Encoding.UTF8.GetString(ok.Body)).GetSigningKeys()];
        }
        catch (ArgumentException ex)
        {
            return Fail(now, $"jwks parse: {ex.GetType().Name}");
        }

        if (keys.Count == 0)
        {
            // Not an empty snapshot. A document that parses to no signing keys is indistinguishable
            // at this layer from one served by something that is not the authorization server, and
            // replacing good keys with none turns a fetch problem into a total outage.
            return Fail(now, "jwks document carries no signing keys");
        }

        _keys = keys;
        _fetchedAt = now;
        _lastSuccessAt = now;

        return new JwksRefresh(JwksRefreshOutcome.Refreshed, keys.Count, null);
    }

    /// <summary>Read <c>jwks_uri</c> out of the discovery document, checking the issuer first.</summary>
    private async Task<(AbsoluteHttpsUrl? Url, string? Detail)> DiscoverJwksUriAsync(
        CancellationToken cancellationToken)
    {
        var outcome = await _http.GetAsync(
            new UpstreamDocumentRequest(_discoveryUri!.Value, FetchPurpose.AuthorizationServerDiscovery),
            cancellationToken).ConfigureAwait(false);

        if (outcome is not FetchOutcome.Ok ok)
        {
            return (null, $"discovery fetch: {DescribeFetch(outcome)}");
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(ok.Body);
        }
        catch (JsonException)
        {
            return (null, "discovery document is not JSON");
        }

        using (document)
        {
            var root = document.RootElement;

            if (root.ValueKind is not JsonValueKind.Object)
            {
                return (null, "discovery document is not a JSON object");
            }

            // OIDC Discovery §4.3, checked before jwks_uri is read. The member about to be read
            // names a URL whose contents this resource server will trust to verify every token it
            // accepts, so "is this document about the issuer we asked about" settles first.
            var declared = Member(root, "issuer");

            if (!string.Equals(declared, _issuer.Value, StringComparison.Ordinal))
            {
                return (null,
                    $"discovery document declares issuer '{Trim(declared)}', configured is "
                    + $"'{_issuer.Value}'");
            }

            return AbsoluteHttpsUrl.TryCreate(Member(root, "jwks_uri"), out var jwks)
                ? (jwks, null)
                : (null, "discovery document has no jwks_uri that is an absolute https URL");
        }
    }

    /// <summary>Record a failure and keep whatever keys are already held.</summary>
    private JwksRefresh Fail(DateTimeOffset now, string detail)
    {
        _lastFailureAt = now;
        _lastFailureDetail = detail;

        return new JwksRefresh(JwksRefreshOutcome.Failed, _keys.Count, detail);
    }

    private static string? Member(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>A short, non-secret description of a failed fetch, for the log.</summary>
    /// <remarks>
    /// Nothing here comes from a response body. The one case carrying text from outside is
    /// <see cref="FetchOutcome.TransportFailed"/>, whose detail is a DNS, TCP or TLS message.
    /// </remarks>
    private static string DescribeFetch(FetchOutcome outcome) => outcome switch
    {
        FetchOutcome.Ok => "ok",
        FetchOutcome.Blocked blocked => $"blocked ({blocked.Reason})",
        FetchOutcome.Redirected redirected => $"redirected ({redirected.Status}), not followed",
        FetchOutcome.NotOk notOk => $"status {notOk.Status}",
        FetchOutcome.TooLarge tooLarge => $"body over {tooLarge.BytesRead} bytes",
        FetchOutcome.Timeout timeout => $"timed out after {timeout.Elapsed.TotalMilliseconds:F0} ms",
        FetchOutcome.TransportFailed failed => $"transport: {Trim(failed.Detail)}",
        FetchOutcome.RateLimited limited => $"outbound budget spent, retry after {limited.RetryAfter}",
        _ => "unknown outcome",
    };

    private static string Trim(string? value) =>
        value is null ? "<none>" : value.Length <= 120 ? value : value[..120];
}
