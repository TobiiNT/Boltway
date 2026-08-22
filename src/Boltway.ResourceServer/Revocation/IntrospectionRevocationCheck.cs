using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Boltway.ResourceServer.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Boltway.ResourceServer.Revocation;

/// <summary>What this resource server needs in order to introspect.</summary>
/// <remarks>
/// <para>
/// <b>A client id and secret of its own, and that is the cost of RFC 7662.</b> §2.1 requires the
/// endpoint to be authorized, and an authorization server that accepted <c>none</c> there would let
/// anybody scan for live tokens. So a resource server doing this holds a long-lived credential —
/// the thing to know about it is that the credential authenticates the <i>resource server</i> and
/// grants no access to anybody's data: what it buys is the right to ask about a token the caller
/// already handed over.
/// </para>
/// </remarks>
public sealed class IntrospectionOptions
{
    /// <summary>The authorization server's introspection endpoint, absolute.</summary>
    /// <remarks>
    /// Configured rather than derived from the issuer. RFC 8414 lets a server put it anywhere, and
    /// guessing <c>{issuer}/introspect</c> is right until it is not — at which point every request
    /// fails open silently, which is the failure this class is least able to notice.
    /// </remarks>
    /// <remarks>
    /// <b>Settable rather than <c>required</c>, and validated at registration instead.</b> Every
    /// other option in this library is filled by an <c>Action&lt;T&gt;</c>, which cannot assign an
    /// <c>init</c> member — and a type that could only be built at a construction site would make
    /// this the one registration shaped differently from its neighbours. What replaces the compiler
    /// check is <c>AddIntrospectionRevocationCheck</c>, which refuses at startup and names the
    /// property that is missing.
    /// </remarks>
    public Uri? Endpoint { get; set; }

    /// <summary>This resource server's client identifier at the authorization server.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Its secret.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// How long an answer is reused before asking again.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the revocation lag, and it is the number to argue about.</b> Zero means a round
    /// trip to the authorization server on every request, which is correct and puts that server on
    /// the critical path of every call. Thirty seconds means a session somebody ended keeps working
    /// for up to thirty more, which against a 30-minute access token is a sixtyfold improvement on
    /// asking nobody.
    /// </para>
    /// <para>
    /// Only <i>positive</i> answers are cached for this long. See the class remarks: a token found
    /// revoked is never un-cached early, and a token found live is re-checked when this elapses.
    /// </para>
    /// </remarks>
    public TimeSpan CacheLifetime { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How long to wait for the authorization server before giving up and failing open.</summary>
    /// <remarks>
    /// Short on purpose. This sits in front of every request, so a slow authorization server would
    /// otherwise turn into latency on a resource server that could have served the call.
    /// </remarks>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);
}

/// <summary>
/// Asks the authorization server, over RFC 7662, whether a token's grant still stands.
/// </summary>
/// <remarks>
/// <para>
/// <b>It fails open, and it says so every time.</b> When the authorization server cannot be reached
/// — a restart, a deploy, a network blip — this answers "not revoked" and writes a warning naming
/// the reason. The alternative was considered and rejected by the deployment this was written for:
/// the two services share a host, so an authorization server restart would take the knowledge base
/// down with it, several times per deploy, to close a window measured in seconds. The window it
/// leaves open is exactly the one that existed before this class, so failing open is never worse
/// than not having asked.
/// </para>
/// <para>
/// <b>What makes that defensible is the log line.</b> An unnoticed fail-open is how a session
/// somebody ended stays live for a week; `GitHubStore` in the connector that motivated this carries
/// the same lesson, having degraded silently for 25 commits. Every unreachable answer here is a
/// <see cref="LogLevel.Warning"/> carrying the cause, so "were we failing open, and for how long"
/// is a query rather than a guess.
/// </para>
/// <para>
/// <b>Only live answers are cached.</b> A revoked answer is not stored at all, which sounds
/// backwards and is not: the cache exists to avoid a round trip on the hot path, and the hot path
/// is tokens that work. A revoked token arrives rarely, is refused immediately, and its client
/// re-authorizes — caching that answer would optimise the case that stops happening.
/// </para>
/// <para>
/// <b>Keyed on a hash, never on the token.</b> The map outlives any one request, and a process dump
/// or a heap inspection should not hand somebody a table of live credentials.
/// </para>
/// </remarks>
public sealed class IntrospectionRevocationCheck : IAccessTokenRevocationCheck
{
    private readonly HttpClient _http;
    private readonly IntrospectionOptions _options;
    private readonly ILogger<IntrospectionRevocationCheck> _log;
    private readonly TimeProvider _clock;
    private readonly ResourceServerMetrics? _metrics;
    private readonly AuthenticationHeaderValue _credential;

    /// <summary>Token hash to the moment its "still live" answer stops being reusable.</summary>
    private readonly ConcurrentDictionary<string, DateTimeOffset> _live = new(StringComparer.Ordinal);

    /// <summary>The named client this check calls with.</summary>
    /// <remarks>
    /// Its own, never the application's. This one carries a credential on every request, and
    /// sharing a client with the handlers that call other people's APIs is how a default header
    /// ends up somewhere it was never meant to go.
    /// </remarks>
    public const string HttpClientName = "boltway-introspection";

    /// <summary>Wire one up.</summary>
    /// <param name="factory">Where the client comes from.</param>
    /// <param name="options">Where to ask and with what.</param>
    /// <param name="log">Where the fail-open warnings go.</param>
    /// <param name="clock">The clock the cache expires against.</param>
    /// <param name="metrics">
    /// Where the fail-open count goes. Optional so that constructing this by hand stays a
    /// two-argument affair, and always supplied by <c>AddIntrospectionRevocationCheck</c> — a
    /// deployment that reaches this type through DI is counted whether it asked to be or not,
    /// because the number nobody thought to ask for is the one this instrument exists to produce.
    /// </param>
    /// <remarks>
    /// <b>Takes the factory rather than the client, and that is an architecture rule rather than a
    /// preference.</b> <c>StructuralRuleTests.Only_the_guarded_fetcher_touches_system_net_http</c>
    /// bans <c>System.Net.Http</c> outside <c>Boltway.OAuth.Net</c>, and this type is the one
    /// named exception. Resolving the client in the registration extension instead would make that
    /// extension a second exception, for one line — so the call lives here, where the argument for
    /// it is already written down.
    /// </remarks>
    public IntrospectionRevocationCheck(
        IHttpClientFactory factory,
        IntrospectionOptions options,
        ILogger<IntrospectionRevocationCheck> log,
        TimeProvider? clock = null,
        ResourceServerMetrics? metrics = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Endpoint);

        _http = factory.CreateClient(HttpClientName);
        _options = options;
        _log = log;
        _clock = clock ?? TimeProvider.System;
        _metrics = metrics;

        // Built once. RFC 6749 §2.3.1 requires both halves to be form-urlencoded before they are
        // base64'd, which is the step everybody skips until a secret contains a `+`.
        _credential = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(_options.ClientId)}:{Uri.EscapeDataString(_options.ClientSecret)}")));
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsRevokedAsync(
        string token, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        var key = Fingerprint(token);
        var now = _clock.GetUtcNow();

        if (_live.TryGetValue(key, out var until) && until > now)
        {
            _metrics?.RevocationCheck.Add(1, new KeyValuePair<string, object?>("outcome", RevocationOutcome.Cached));
            return false;
        }

        // Swept here rather than on a timer: the map only grows when tokens are presented, so the
        // moment there is something to clean up is a moment this is already running. A background
        // timer would be a second thing to own for a dictionary bounded by how many distinct tokens
        // a resource server sees in one cache lifetime.
        if (!_live.IsEmpty)
        {
            foreach (var (stale, expiry) in _live)
            {
                if (expiry <= now)
                {
                    _live.TryRemove(stale, out _);
                }
            }
        }

        var active = await AskAsync(token, cancellationToken);

        if (active is null)
        {
            // Could not find out. The contract says this is `false`, and the warning above is what
            // makes that defensible rather than silent.
            return false;
        }

        if (active is true)
        {
            _live[key] = now + _options.CacheLifetime;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Ask the authorization server. True, false, or null for "could not find out".
    /// </summary>
    /// <remarks>
    /// <b>Three outcomes, not two, and collapsing them is the bug this shape prevents.</b> A
    /// reachable server saying <c>active: false</c> and an unreachable server are both "no useful
    /// answer" to a caller in a hurry, and they have opposite correct responses: one must refuse
    /// the request and the other must not. A boolean here would have to pick, and whichever it
    /// picked would be wrong half the time — either an authorization-server blip logs every user
    /// out, or a revoked session survives one because a deploy was in progress.
    /// </remarks>
    private async Task<bool?> AskAsync(string token, CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.Timeout);

            using var request = new HttpRequestMessage(HttpMethod.Post, _options.Endpoint!)
            {
                // `token_type_hint` is sent because we know: this is always an access token here.
                // The server treats it as a hint and would answer correctly without it; sending it
                // saves the lookup it would otherwise try first.
                Content = new FormUrlEncodedContent(
                [
                    new KeyValuePair<string, string>("token", token),
                    new KeyValuePair<string, string>("token_type_hint", "access_token"),
                ]),
            };

            request.Headers.Authorization = _credential;

            using var response = await _http.SendAsync(request, timeout.Token);

            var bytes = await response.Content.ReadAsByteArrayAsync(timeout.Token);

            if (!response.IsSuccessStatusCode)
            {
                var (reason, because) = Refusal(bytes, response.StatusCode);
                Warn(reason, because, started);
                return null;
            }

            using var body = JsonDocument.Parse(bytes);

            if (!body.RootElement.TryGetProperty("active", out var active)
                || active.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                // RFC 7662 §2.2 makes `active` REQUIRED. A 200 without it is a server that is not
                // speaking this protocol — a proxy's error page, or the wrong URL configured — and
                // reading a missing field as "not active" would log every user out on a typo.
                Warn(
                    FailedOpenReason.MalformedResponse,
                    "the introspection response carried no boolean `active` member",
                    started);
                return null;
            }

            var answer = active.GetBoolean();

            Record(answer ? RevocationOutcome.Live : RevocationOutcome.Revoked, started);

            return answer;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Warn(
                FailedOpenReason.Timeout,
                $"the authorization server did not answer within {_options.Timeout.TotalSeconds:0.#}s",
                started);
            return null;
        }
        catch (HttpRequestException ex)
        {
            Warn(FailedOpenReason.Unreachable, $"the authorization server could not be reached: {ex.Message}", started);
            return null;
        }
        catch (JsonException ex)
        {
            Warn(FailedOpenReason.NotJson, $"the introspection response was not JSON: {ex.Message}", started);
            return null;
        }
    }

    /// <summary>Why a refusal was refused, in the words that distinguish the two cures.</summary>
    /// <remarks>
    /// <para>
    /// <b>Read off the OAuth <c>error</c> member rather than the HTTP status.</b> RFC 6749 §5.2 puts
    /// the machine-readable reason in the body, and <c>invalid_client</c> is unambiguous where a 401
    /// is not — a proxy in front of the authorization server answers 401 too, and so does an
    /// authorization server that has simply been replaced by a login page. It is also the only form
    /// this assembly may write: an architecture rule bans a 400-599 constant outside the rejection
    /// writer, because a hand-written status is how a 4xx escapes the one place that logs it.
    /// </para>
    /// <para>
    /// <b>A body that is not JSON falls back to the status rather than to "not JSON".</b> Parsing
    /// before the status was checked made an HTML error page from a proxy report itself as a
    /// malformed introspection response, which sends whoever reads that line looking at the wrong
    /// server.
    /// </para>
    /// <para>
    /// The credential case is named separately because the two have opposite cures. A refused
    /// credential is this resource server's own configuration, it never recovers on its own, and it
    /// otherwise presents as "revocation quietly does nothing" forever.
    /// </para>
    /// </remarks>
    private static (string Reason, string Because) Refusal(byte[] body, System.Net.HttpStatusCode status)
    {
        try
        {
            using var parsed = JsonDocument.Parse(body);

            if (parsed.RootElement.ValueKind is JsonValueKind.Object
                && parsed.RootElement.TryGetProperty("error", out var error)
                && string.Equals(error.GetString(), "invalid_client", StringComparison.Ordinal))
            {
                return (
                    FailedOpenReason.CredentialRejected,
                    "the authorization server refused this resource server's own client credential");
            }
        }
        catch (JsonException)
        {
            // Not an OAuth error body. The status is all there is to report, and it is enough.
        }

        return (FailedOpenReason.Refused, $"the authorization server refused the request: {status}");
    }

    private void Warn(string reason, string because, long started)
    {
        _log.LogWarning(
            "Token revocation not checked, and the request was allowed through: {Because}. Access "
            + "granted before a session was ended stays usable until the token expires while this "
            + "persists — the same exposure as running with no revocation check at all. Endpoint "
            + "{Endpoint}, after {ElapsedMs}ms.",
            because,
            _options.Endpoint!,
            (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);

        Record(RevocationOutcome.FailedOpen, started, reason);
    }

    /// <summary>Count one decision, and time the ask that produced it.</summary>
    /// <remarks>
    /// <para>
    /// <b>Every path that leaves <see cref="AskAsync"/> passes through here exactly once</b>, which
    /// is what makes <c>live + revoked + failed_open</c> equal the number of introspection requests
    /// by construction rather than by anybody keeping two lists in step. It is the same argument
    /// <c>AuthorizationServerMetrics</c> makes for routing <c>rejection</c> through the one place
    /// that writes refusals.
    /// </para>
    /// <para>
    /// The duration is recorded for fail-opens too. A timeout is the slowest possible ask and
    /// dropping it would trim exactly the tail that the histogram exists to show.
    /// </para>
    /// </remarks>
    private void Record(string outcome, long started, string? reason = null)
    {
        if (_metrics is null)
        {
            return;
        }

        var tag = new KeyValuePair<string, object?>("outcome", outcome);

        if (reason is null)
        {
            _metrics.RevocationCheck.Add(1, tag);
        }
        else
        {
            _metrics.RevocationCheck.Add(1, tag, new KeyValuePair<string, object?>("reason", reason));
        }

        _metrics.RevocationAskDuration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds, tag);
    }

    /// <summary>A stable key for a token that is not the token.</summary>
    /// <remarks>
    /// SHA-256 and not a truncation: a prefix collides, and two tokens sharing a cache entry means
    /// one caller's revocation is answered with another's liveness.
    /// </remarks>
    private static string Fingerprint(string token) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
