using System.Diagnostics.Metrics;

namespace Boltway.ResourceServer.Diagnostics;

/// <summary>
/// The instruments this resource server publishes, and the names they publish under.
/// </summary>
/// <remarks>
/// <para>
/// <b>This meter exists for one question: how often does revocation fail open?</b>
/// <see cref="Revocation.IntrospectionRevocationCheck"/> answers "not revoked" whenever it cannot
/// reach the authorization server, and writes a warning saying so. That was defensible on the
/// argument that the warning makes it visible - but a warning is only visible to somebody reading
/// logs, and nobody reads logs to discover a question they have not thought to ask. Until this
/// meter, "is revocation working" was <i>assumed</i>, and the deployment had chosen fail-open
/// precisely because it accepted a risk it could not then measure.
/// </para>
/// <para>
/// <b>Prefixed <c>boltway.</c> for the reason <c>AuthorizationServerMetrics</c> records
/// against measurement:</b> the meter name is a separate attribute of the stream, not part of the
/// metric's identity, and backends key the series on the name alone. A bare
/// <c>resource.revocation.check</c> would collide with anything else in the process.
/// </para>
/// <para>
/// <b>A host must name this meter or none of it is published.</b> <c>AddMeter</c> takes
/// <see cref="MeterName"/>; an unregistered meter is not an error and produces no series, which
/// looks exactly like a resource server that never fails open.
/// </para>
/// </remarks>
public sealed class ResourceServerMetrics : IDisposable
{
    /// <summary>The instrumentation scope. Register it with <c>AddMeter</c> to see any of this.</summary>
    public const string MeterName = "Boltway.ResourceServer";

    private readonly Meter _meter;

    /// <summary>Build the instruments.</summary>
    public ResourceServerMetrics()
    {
        _meter = new Meter(MeterName);

        RevocationCheck = _meter.CreateCounter<long>(
            "boltway.resource.revocation.check",
            description:
                "Revocation decisions, by outcome: cached, live, revoked, failed_open. "
                + "failed_open carries a bounded reason.");

        RevocationAskDuration = _meter.CreateHistogram<double>(
            "boltway.resource.revocation.ask.duration",
            unit: "ms",
            description:
                "How long the authorization server took to answer an introspection request, by "
                + "outcome. Cache hits are not asks and are not recorded here.");
    }

    /// <summary>
    /// Revocation decisions. Tag <c>outcome</c>, plus <c>reason</c> when the outcome is
    /// <see cref="RevocationOutcome.FailedOpen"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>cached</c> is a separate outcome from <c>live</c> on purpose, and the alert depends on
    /// it.</b> The number worth alerting on is not fail-opens over all decisions - cache hits
    /// dominate that denominator and would dilute any threshold into uselessness. It is fail-opens
    /// over the decisions where this actually asked: <c>failed_open / (live + revoked +
    /// failed_open)</c>. Folding cache hits into <c>live</c> would make that ratio unrecoverable
    /// from the series.
    /// </para>
    /// </remarks>
    public Counter<long> RevocationCheck { get; }

    /// <summary>Introspection round-trip latency. Tag <c>outcome</c>.</summary>
    /// <remarks>
    /// <b>A leading indicator, which the counter is not.</b> The check gives the authorization
    /// server a short timeout and fails open when it elapses, so a server drifting towards that
    /// timeout produces no fail-opens at all right up until it produces nothing but fail-opens.
    /// This is the series that moves first.
    /// </remarks>
    public Histogram<double> RevocationAskDuration { get; }

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();
}

/// <summary>The <c>outcome</c> tag values on <see cref="ResourceServerMetrics.RevocationCheck"/>.</summary>
/// <remarks>
/// Constants rather than literals at the call sites, because a tag value is matched ordinally by
/// whatever queries it. A dashboard filtering <c>failed_open</c> against code that emits
/// <c>failedOpen</c> is a panel that reads as a healthy system.
/// </remarks>
public static class RevocationOutcome
{
    /// <summary>A previous "still live" answer was reused; the authorization server was not asked.</summary>
    public const string Cached = "cached";

    /// <summary>The authorization server was asked and said the grant stands.</summary>
    public const string Live = "live";

    /// <summary>The authorization server was asked and said the grant is gone.</summary>
    public const string Revoked = "revoked";

    /// <summary>
    /// The authorization server could not be asked, or did not answer usefully, and the request was
    /// allowed through.
    /// </summary>
    public const string FailedOpen = "failed_open";
}

/// <summary>
/// The <c>reason</c> tag values carried alongside <see cref="RevocationOutcome.FailedOpen"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Bounded, and that is the whole design constraint.</b> The log line that accompanies every one
/// of these carries the exception message, the endpoint and the elapsed time; none of that may
/// become a tag, because metric tags multiply into series and an exception message is unbounded.
/// So the log keeps the detail and the metric keeps the category.
/// </para>
/// <para>
/// <b>The categories are split by what fixes them, not by what threw.</b>
/// <see cref="CredentialRejected"/> is separated from <see cref="Refused"/> for the reason
/// <c>IntrospectionRevocationCheck.Refusal</c> separates them in prose: a refused credential is
/// this resource server's own misconfiguration, it never recovers on its own, and it presents as
/// revocation quietly doing nothing forever. On a dashboard it is the one value that should page
/// somebody rather than wait for a trend.
/// </para>
/// </remarks>
public static class FailedOpenReason
{
    /// <summary>The authorization server could not be reached at all.</summary>
    public const string Unreachable = "unreachable";

    /// <summary>It did not answer inside the configured timeout.</summary>
    public const string Timeout = "timeout";

    /// <summary>It answered, and refused the request.</summary>
    public const string Refused = "refused";

    /// <summary>It refused this resource server's own client credential.</summary>
    public const string CredentialRejected = "credential_rejected";

    /// <summary>A 200 that carried no boolean <c>active</c> member, which RFC 7662 §2.2 requires.</summary>
    public const string MalformedResponse = "malformed_response";

    /// <summary>A 200 whose body did not parse as JSON.</summary>
    public const string NotJson = "not_json";
}
