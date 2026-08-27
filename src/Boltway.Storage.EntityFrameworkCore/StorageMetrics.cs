using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Boltway.Storage.EntityFrameworkCore;

/// <summary>
/// How long each storage operation took, under its own meter.
/// </summary>
/// <remarks>
/// <para>
/// <b>A separate meter from the authorization server's, and not by preference.</b> This assembly
/// cannot reference <c>Boltway.AuthorizationServer</c> - the dependency runs the other way, and
/// that direction is what lets a customer replace storage without taking the server with it. So the
/// instrument lives where the code it measures lives, which is also what OpenTelemetry asks for: one
/// meter per instrumented library, named after the library.
/// </para>
/// <para>
/// A host that wants these has to name this meter too. That is the cost of the boundary and it is
/// the honest one - <c>AddMeter</c> takes several names.
/// </para>
/// <para>
/// The tag is the operation, spelled <c>Store.Method</c>, because the question this answers is
/// "which call is slow" and the answer has to name something a person can go and read. A tag of
/// <c>select</c> or <c>update</c> would describe SQL, which the profiler already knows and nobody
/// asked.
/// </para>
/// </remarks>
public sealed class StorageMetrics : IDisposable
{
    /// <summary>The instrumentation scope. Pass it to <c>AddMeter</c> or see nothing.</summary>
    public const string MeterName = "Boltway.Storage";

    private readonly Meter _meter;
    private readonly Histogram<double> _duration;

    /// <summary>Create the meter and its one instrument.</summary>
    public StorageMetrics()
    {
        _meter = new Meter(MeterName);

        _duration = _meter.CreateHistogram<double>(
            "boltway.oauth.store.duration",
            unit: "ms",
            description: "A storage operation, by name. Tag `operation` is Store.Method.");
    }

    /// <summary>
    /// Time one operation. Dispose to record it.
    /// </summary>
    /// <remarks>
    /// Returns a struct, and the caller holds it in a <c>using</c>. That means no allocation per
    /// call - these run on the token endpoint's path, where the budget is ten seconds for the whole
    /// request and a per-call allocation is the kind of cost that is invisible until it is the
    /// profile.
    /// </remarks>
    public Timing Track(string operation) => new(_duration, operation);

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();

    /// <summary>One timed operation, recorded when it goes out of scope.</summary>
    public readonly struct Timing : IDisposable
    {
        private readonly Histogram<double>? _histogram;
        private readonly string _operation;
        private readonly long _startedAt;

        internal Timing(Histogram<double> histogram, string operation)
        {
            _histogram = histogram;
            _operation = operation;
            _startedAt = Stopwatch.GetTimestamp();
        }

        /// <summary>Record the elapsed time. Safe on a default instance, which records nothing.</summary>
        public void Dispose() =>
            _histogram?.Record(
                Stopwatch.GetElapsedTime(_startedAt).TotalMilliseconds,
                new KeyValuePair<string, object?>("operation", _operation));
    }
}
