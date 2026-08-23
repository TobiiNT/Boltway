using System.Diagnostics.Metrics;
using Boltway.OAuth.Tokens;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>
/// The instruments this server publishes, and the names they publish under.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every name is prefixed <c>boltway.</c>, and that is a measurement rather than a
/// convention.</b> The specification these come from named them <c>oauth.request.duration</c> and
/// so on, on the reasoning that the meter — <c>Boltway.Auth</c> — supplies the namespace. It
/// does not. Exported through the SDK and read back:
/// </para>
/// <code>
/// Metric Name: oauth.rejection
/// Instrumentation scope (Meter):
///     Name: Boltway.Auth
/// </code>
/// <para>
/// The meter is a separate attribute of the stream, not part of the metric's identity. Backends key
/// the series on the name and reduce the scope to a label nobody filters on, so a bare
/// <c>oauth.rejection</c> collides with any other OAuth library in the same process — and with any
/// future <c>oauth.*</c> semantic convention, which is exactly the namespace an OAuth server should
/// expect someone to standardise.
/// </para>
/// <para>
/// <b>Five of the seven specified instruments record; one is declined with a reason; one is not
/// buildable.</b> Stated plainly because a half-instrumented meter looks identical to a
/// quiet system:
/// </para>
/// <list type="table">
/// <item><term><c>rejection</c></term><description><b>Recording.</b> From
/// <c>RejectionResult.Record</c>, the one place every refusal passes through, so its total equals
/// the number of <c>Rejected</c> log lines by construction.</description></item>
/// <item><term><c>refresh.rotation</c></term><description><b>Recording.</b> All three arms of
/// <c>RefreshTokenGrant</c>'s redemption switch — <c>rotated</c>, <c>grace_replay</c>,
/// <c>reuse</c>. The last is the only signal that a refresh token leaked.</description></item>
/// <item><term><c>key.active_count</c></term><description><b>Recording.</b> Observed from the
/// ring.</description></item>
/// <item><term><c>cimd.fetch.duration</c></term><description><b>Recording.</b> Around the shared
/// flight, so the duration is the fetch every waiting caller is behind rather than one caller's
/// wait. Outcomes <c>hit</c>, <c>fetched</c>, <c>stale</c>, <c>error</c>.</description></item>
/// <item><term><c>store.duration</c></term><description><b>Recording, from a different meter.</b>
/// It lives in <c>Boltway.Storage.EntityFrameworkCore</c>, which cannot reference this
/// assembly — the dependency runs the other way, and that direction is what lets a customer
/// replace storage without taking the server with it. See <c>StorageMetrics</c>; a host must name
/// both meters.</description></item>
/// <item><term><c>request.duration</c></term><description>Declared, and deliberately not wired:
/// ASP.NET Core's own instrumentation already publishes <c>http.server.request.duration</c> by
/// route and status. A second latency metric under a name only we use would be the same numbers
/// with a worse dashboard. What it would genuinely add is <c>outcome</c> and <c>grant_type</c> as
/// dimensions, and that is worth doing on its own terms rather than as a duplicate.</description></item>
/// <item><term><c>budget.headroom</c></term><description><b>Not buildable.</b> It measures the
/// fraction of a per-endpoint latency budget consumed, and the <c>LatencyBudgetMiddleware</c> that
/// would hold those budgets does not exist. A headroom against a budget nobody set is a gauge of a
/// number this code invented.</description></item>
/// </list>
/// <para>
/// The names came from one of three competing architecture proposals, none of which was ever
/// recorded as adopted — the proposals have since been deleted (they described projects and
/// namespaces that were not built; <c>docs/DESIGN.md</c> §1 is the surviving decision record, and
/// git history has the files). So these are built because they measure things that exist, and the
/// naming is an inheritance rather than an instruction.
/// </para>
/// </remarks>
public sealed class AuthorizationServerMetrics : IDisposable
{
    /// <summary>The instrumentation scope. Register it with <c>AddMeter</c> to see any of this.</summary>
    public const string MeterName = "Boltway.Auth";

    private readonly Meter _meter;

    /// <summary>Build the instruments, and read the key ring for the gauge.</summary>
    /// <param name="keyRing">
    /// Observed rather than recorded: the count changes when a secret is rotated, not when a request
    /// arrives, so a callback reading the current ring is the only thing that cannot go stale.
    /// </param>
    public AuthorizationServerMetrics(SigningKeyRing keyRing)
    {
        ArgumentNullException.ThrowIfNull(keyRing);

        _meter = new Meter(MeterName);

        RequestDuration = _meter.CreateHistogram<double>(
            "boltway.oauth.request.duration",
            unit: "ms",
            description: "How long a protocol endpoint took, by endpoint and outcome.");

        Rejection = _meter.CreateCounter<long>(
            "boltway.oauth.rejection",
            description: "Refusals, by reason and surface. One row per rejection, from the one place that writes them.");

        CimdFetchDuration = _meter.CreateHistogram<double>(
            "boltway.oauth.cimd.fetch.duration",
            unit: "ms",
            description: "Dereferencing a client_id URL, by outcome.");

        RefreshRotation = _meter.CreateCounter<long>(
            "boltway.oauth.refresh.rotation",
            description: "Refresh redemptions by result: rotated, grace replay, or reuse detected.");

        StoreDuration = _meter.CreateHistogram<double>(
            "boltway.oauth.store.duration",
            unit: "ms",
            description: "A storage operation, by name.");

        // The one instrument that must be observable. A counter would need something to notice a
        // rotation and increment, and the thing that rotates a key is an operator editing a secret.
        _meter.CreateObservableGauge(
            "boltway.oauth.key.active_count",
            () => keyRing.ActiveKeyCount,
            description: "Signing keys currently in the Active state. Zero means no token can be minted.");
    }

    /// <summary>Endpoint latency. Tag <c>endpoint</c>, <c>outcome</c>, and <c>grant_type</c> where there is one.</summary>
    public Histogram<double> RequestDuration { get; }

    /// <summary>Refusals. Tag <c>reason</c>, <c>surface</c>, <c>status</c>.</summary>
    public Counter<long> Rejection { get; }

    /// <summary>CIMD dereference latency. Tag <c>outcome</c>.</summary>
    public Histogram<double> CimdFetchDuration { get; }

    /// <summary>Refresh redemptions. Tag <c>result</c>.</summary>
    public Counter<long> RefreshRotation { get; }

    /// <summary>Storage latency. Tag <c>operation</c>.</summary>
    public Histogram<double> StoreDuration { get; }

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();
}
