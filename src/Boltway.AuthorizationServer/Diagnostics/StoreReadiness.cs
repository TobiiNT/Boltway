using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>
/// Whether the store this server keeps its users, consent and grants in can actually be reached.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is deliberately not the liveness probe, and adding it is not a reversal of the decision
/// that keeps the two apart.</b> A liveness probe is consumed by something that <i>rotates</i> -
/// Docker restarts the container, Cloud Run pulls the revision out of the load balancer - so making
/// it fail when Postgres blinks takes the whole server down for a dependency most requests never
/// touch. Discovery, JWKS and token introspection of a signed token all answer without the
/// database.
/// </para>
/// <para>
/// A monitor rotates nothing. It pages a person. So the answer it needs is the opposite one: not
/// "is the process alive" but "is the thing behind it reachable", which is the question nobody
/// could ask before this existed - an uptime check against <c>/health</c> stays green through a
/// total database outage while every sign-in fails.
/// </para>
/// <para>
/// <b>The probe is a real store call, not a new <c>SELECT 1</c> seam.</b> It asks
/// <see cref="IUserStore"/> for a subject that cannot exist. That means it travels the connection,
/// the query and the mapping a genuine request travels, so it cannot end up instrumented-but-wrong
/// - the failure mode of a health check that pings a connection the real code path does not use.
/// It also asks nothing new of anyone implementing storage: a new interface would have been a
/// breaking change for every store outside this repository, to learn something the existing
/// interface already reveals.
/// </para>
/// <para>
/// <b>The answer is cached, and that is a security property rather than an optimisation.</b> The
/// endpoint is public - it has to be, a monitor that needs a credential is a monitor that stops
/// working when the credential expires and tells you the site is down. Public plus one database
/// query per request is an amplifier: anyone who can reach it can turn cheap HTTP into database
/// load. Inside the freshness window the last answer is returned without touching the store, so the
/// load a caller can generate is bounded by the clock rather than by their patience.
/// </para>
/// <para>
/// <b>Nothing about the failure reaches the caller.</b> A store error can name a host, a database,
/// a role or a driver version, and this response is readable by anyone. The detail goes to the log
/// at warning level; the wire gets <c>unreachable</c>.
/// </para>
/// <para>
/// <b>It is not mapped automatically.</b> <c>MapBoltwayAuthorizationServer</c> maps the
/// endpoints the protocol requires; this is one a deployment chooses. A library that quietly adds a
/// public route to every consumer is a library that collides with a host which already had one, and
/// the collision surfaces as an ambiguous match at request time. Call
/// <see cref="AuthorizationServerReadinessEndpoint.MapStoreReadiness"/>.
/// </para>
/// </remarks>
public sealed partial class StoreReadiness
{
    /// <summary>
    /// The subject the probe looks up.
    /// </summary>
    /// <remarks>
    /// Subjects are minted as ULIDs - Crockford base32, twenty-six characters. This is neither, so
    /// no <see cref="ISubjectIdFactory"/> can ever produce it and the lookup is a guaranteed miss
    /// against an indexed key. Reading it in a query log should say what it is without anyone
    /// having to look it up.
    /// </remarks>
    public static readonly SubjectId ProbeSubject =
        SubjectId.FromStorage("readiness-probe-not-a-real-subject");

    private readonly IUserStore _users;
    private readonly TimeProvider _time;
    private readonly ILogger<StoreReadiness> _logger;
    private readonly TimeSpan _freshFor;
    private readonly TimeSpan _timeout;

    private readonly object _sync = new();
    private bool _known;
    private bool _probing;
    private bool _reachable;
    private DateTimeOffset _probedAt;

    /// <param name="users">The store to probe. Singleton in every storage package here.</param>
    /// <param name="time">
    /// Injected rather than <c>DateTimeOffset.UtcNow</c> so the freshness window is something a
    /// test can step across instead of sleep through.
    /// </param>
    /// <param name="logger">Where the failure detail goes, since the response cannot carry it.</param>
    /// <param name="freshFor">
    /// How long an answer is reused. Five seconds: short enough that a monitor polling once a
    /// minute always gets a fresh probe, long enough that a flood cannot outrun it.
    /// </param>
    /// <param name="timeout">
    /// How long the probe waits before calling the store unreachable. A database that hangs is
    /// down as far as anyone signing in is concerned, and without this the request hangs with it.
    /// </param>
    public StoreReadiness(
        IUserStore users,
        TimeProvider time,
        ILogger<StoreReadiness> logger,
        TimeSpan? freshFor = null,
        TimeSpan? timeout = null)
    {
        _users = users;
        _time = time;
        _logger = logger;
        _freshFor = freshFor ?? TimeSpan.FromSeconds(5);
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
    }

    /// <summary>Whether the store answered, possibly from the cached answer.</summary>
    public async Task<bool> IsReachableAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_known && _time.GetUtcNow() - _probedAt < _freshFor)
            {
                return _reachable;
            }

            // Stale, but somebody is already refreshing it. Returning the previous answer rather
            // than joining the queue is what keeps a burst from becoming a burst of queries. Before
            // the first probe completes there is no previous answer, so a cold start can run
            // several at once - bounded by process start, which nobody outside can trigger.
            if (_known && _probing)
            {
                return _reachable;
            }

            _probing = true;
        }

        bool reachable;
        try
        {
            reachable = await ProbeAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // `_probing` has to be cleared on every path out, and the only path that throws is the
            // caller cancelling - which is the one this type is careful to treat as "not the store's
            // fault". Without this, that carefulness had a much worse cost than the thing it avoided:
            // the flag stayed set for the life of the process, every later call took the
            // "somebody is already refreshing" branch, and the probe never ran again. Readiness would
            // then answer with whatever it happened to believe when a single client disconnected -
            // reporting healthy through every outage after it, which is the exact failure this
            // endpoint exists to remove.
            //
            // Nothing else is written here: a cancelled probe learned nothing, so `_known`,
            // `_reachable` and `_probedAt` must keep saying what they said before.
            lock (_sync)
            {
                _probing = false;
            }

            throw;
        }

        lock (_sync)
        {
            _probing = false;
            _known = true;
            _reachable = reachable;
            _probedAt = _time.GetUtcNow();
        }

        return reachable;
    }

    private async Task<bool> ProbeAsync(CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_timeout);

        try
        {
            _ = await _users.FindBySubjectAsync(ProbeSubject, deadline.Token).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            // Every exception means the same thing here, including the timeout: whatever a person
            // signing in is about to hit, they are about to hit it. Narrowing this to the driver's
            // exception types would let a new one through as "reachable", which is the direction
            // this must never fail in.
            StoreUnreachable(_logger, ex);
            return false;
        }
    }

    [LoggerMessage(
        EventId = 900,
        EventName = "StoreUnreachable",
        Level = LogLevel.Warning,
        Message = "Readiness probe could not reach the store. Sign-in and consent will be failing.")]
    private static partial void StoreUnreachable(ILogger logger, Exception exception);
}

/// <summary>Maps <see cref="StoreReadiness"/> onto a route.</summary>
public static class AuthorizationServerReadinessEndpoint
{
    /// <summary>The path used when none is given.</summary>
    public const string DefaultPattern = "/health/ready";

    /// <summary>
    /// Map a public readiness endpoint: <c>200</c> with <c>{"ok":true,"store":"reachable"}</c> when
    /// the store answers, <c>503</c> with <c>"unreachable"</c> when it does not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// 503 rather than 200-with-a-false-field, because the consumer is an uptime check and the
    /// thing every uptime check agrees on is the status code. A monitor configured to read a JSON
    /// field is a monitor that silently stops checking when the field is renamed.
    /// </para>
    /// <para>
    /// <b>Do not point a container healthcheck or a load balancer at this.</b> That is what
    /// <c>/health</c> is for, and the split is the whole reason this exists - see
    /// <see cref="StoreReadiness"/>.
    /// </para>
    /// </remarks>
    public static IEndpointConventionBuilder MapStoreReadiness(
        this IEndpointRouteBuilder endpoints,
        string pattern = DefaultPattern)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapGet(
            pattern,
            static async (StoreReadiness readiness, CancellationToken cancellationToken) =>
            {
                var reachable = await readiness.IsReachableAsync(cancellationToken)
                    .ConfigureAwait(false);

                return reachable
                    ? Results.Json(new { ok = true, store = "reachable" })
                    : Results.Json(
                        new { ok = false, store = "unreachable" },
                        statusCode: StatusCodes.Status503ServiceUnavailable);
            })
            .AllowAnonymous();
    }
}
