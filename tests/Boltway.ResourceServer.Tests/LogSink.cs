using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Boltway.ResourceServer.Tests;

/// <summary>One captured log event, with its structured properties intact.</summary>
/// <param name="Category">The logger category.</param>
/// <param name="EventId">The event id and name.</param>
/// <param name="Level">The level it was written at.</param>
/// <param name="Properties">
/// The named properties, as the message template declared them. This is the whole reason the sink
/// keeps the state object rather than the rendered string: a test that asserts on rendered text
/// passes for <c>LogWarning($"...")</c>, which is exactly the shape A-09 forbids.
/// </param>
/// <param name="Message">The rendered message, for the "no secret anywhere" sweep.</param>
/// <param name="Exception">The exception, when one rode along.</param>
internal sealed record CapturedLog(
    string Category,
    EventId EventId,
    LogLevel Level,
    IReadOnlyDictionary<string, string?> Properties,
    string Message,
    Exception? Exception)
{
    /// <summary>A property, or <see langword="null"/> when the template did not declare it.</summary>
    internal string? Property(string name) => Properties.GetValueOrDefault(name);
}

/// <summary>
/// Captures everything the server logs, at every level.
/// </summary>
/// <remarks>
/// Registered as an <see cref="ILoggerProvider"/> singleton, which is how the host's own
/// <see cref="ILoggerFactory"/> picks it up - so what these tests observe is what a deployment's
/// logging pipeline would observe, through the same interface, rather than a seam the production
/// code only has because tests wanted one.
/// </remarks>
internal sealed class LogSink : ILoggerProvider
{
    private readonly ConcurrentQueue<CapturedLog> _events = new();

    /// <summary>Everything captured so far, oldest first.</summary>
    internal IReadOnlyList<CapturedLog> Events => [.. _events];

    /// <summary>Every rejection event, identified by its event id.</summary>
    /// <remarks>
    /// The precise half of "exactly one": this counts lines the rejection writer produced, and says
    /// which reason each carried. It cannot see a <i>second</i> line about the same refusal written
    /// under a different event id - <see cref="Mentioning"/> is the half that can, and the tests use
    /// both.
    /// </remarks>
    internal IReadOnlyList<CapturedLog> Rejections =>
        [.. _events.Where(e => e.EventId.Id == 100 && string.Equals(e.EventId.Name, "Rejection", StringComparison.Ordinal))];

    /// <summary>
    /// Every captured event that names this correlation id anywhere, whatever its category.
    /// </summary>
    /// <remarks>
    /// What an operator's <c>grep</c> would return, which is the thing A-09's "exactly one" is
    /// actually about. <see cref="Rejections"/> filters on the event id and so cannot see a second
    /// line about the same refusal written under a different event - measured: adding a duplicate
    /// X-10 line back into the authorize endpoint left the event-id assertion green.
    /// </remarks>
    internal IReadOnlyList<CapturedLog> Mentioning(string correlationId) =>
        [.. _events.Where(e =>
            e.Message.Contains(correlationId, StringComparison.Ordinal)
            || e.Properties.Values.Any(v => v?.Contains(correlationId, StringComparison.Ordinal) is true))];

    public ILogger CreateLogger(string categoryName) => new SinkLogger(categoryName, _events);

    public void Dispose() { }

    private sealed class SinkLogger(string category, ConcurrentQueue<CapturedLog> events) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        // Trace, so a test cannot pass because the level filtered the line away. A rule that says
        // "nothing was logged" needs the sink to have been listening.
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var properties = new Dictionary<string, string?>(StringComparer.Ordinal);

            if (state is IReadOnlyList<KeyValuePair<string, object?>> pairs)
            {
                foreach (var (key, value) in pairs)
                {
                    properties[key] = value?.ToString();
                }
            }

            events.Enqueue(new CapturedLog(
                category, eventId, logLevel, properties, formatter(state, exception), exception));
        }
    }
}
