using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;

namespace Boltway.AuthorizationServer.Host;

/// <summary>Where the JSON lines are going, and what has to be in them to arrive whole.</summary>
public sealed class CloudLoggingOptions
{
    /// <summary>
    /// The Google Cloud project, for the trace field. Absent means the trace fields are omitted
    /// rather than guessed — a malformed <c>logging.googleapis.com/trace</c> is dropped silently by
    /// the ingestion side, which looks exactly like tracing not being on.
    /// </summary>
    public string? ProjectId { get; set; }
}

/// <summary>
/// Writes each log line as the JSON object Cloud Logging indexes, rather than as a sentence.
/// </summary>
/// <remarks>
/// <para>
/// Cloud Run captures stdout and ships it to Cloud Logging with no agent and no configuration, so
/// the logs were already arriving. What they were not was <i>queryable</i>: Google's documentation
/// draws the line at the payload's shape — a JSON object lands in <c>jsonPayload</c> where fields
/// can be indexed and searched by path, a string lands in <c>textPayload</c> where "you can search
/// the text field, but you can't index its content."
/// </para>
/// <para>
/// That mattered here more than it does in most services, because <c>RejectionResult</c> already
/// goes to the trouble of emitting every field of a refusal as a <b>named property</b> — its own
/// remarks explain that the point is for "how many <c>AccessTokenRejected</c> in the last hour, and
/// did they all name the same <c>kid</c>" to be a query instead of a grep. The console provider
/// flattened all of it back into a sentence at the last step.
/// </para>
/// <para>
/// <b>The field names are Google's and are not interchangeable.</b> The built-in
/// <c>AddJsonConsole</c> emits <c>LogLevel</c> and <c>Message</c>; Cloud Logging reads
/// <c>severity</c> and <c>message</c>. Wiring the built-in one gets structure and loses severity —
/// every line arrives at DEFAULT, so a page of errors looks like a page of chatter. The names below
/// are from Google's Cloud Run logging sample, not from memory.
/// </para>
/// <para>
/// <b>This file exists twice</b>, here and in the connector's repository, and is a copy rather than
/// a shared type on purpose: it is deployment-specific — it knows the name of a logging product —
/// and the libraries underneath it are meant not to. The same argument <c>RejectionResult</c> makes
/// about its own duplicated declaration.
/// </para>
/// </remarks>
public sealed class CloudLoggingFormatter(IOptions<CloudLoggingOptions> options)
    : ConsoleFormatter(FormatterName)
{
    /// <summary>The formatter name, for <c>AddConsole(o =&gt; o.FormatterName = …)</c>.</summary>
    public const string FormatterName = "cloud-logging";

    private readonly CloudLoggingOptions _options = options.Value;

    /// <inheritdoc />
    public override void Write<TState>(
        in LogEntry<TState> logEntry, IExternalScopeProvider? scopeProvider, TextWriter textWriter)
    {
        var message = logEntry.Formatter?.Invoke(logEntry.State, logEntry.Exception);

        // Nothing to say and nothing thrown: a line with neither is noise that still costs
        // ingestion.
        if (string.IsNullOrEmpty(message) && logEntry.Exception is null)
        {
            return;
        }

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();

            json.WriteString("severity", Severity(logEntry.LogLevel));
            json.WriteString("message", message);
            json.WriteString("logger", logEntry.Category);

            if (logEntry.EventId.Id != 0)
            {
                json.WriteNumber("eventId", logEntry.EventId.Id);
            }

            // The type and the message, never a `ToString()` of the exception object: that is the
            // stack trace, it is long, and it is the same on every occurrence. The trace belongs in
            // an error reporter rather than in every line of a log.
            if (logEntry.Exception is { } exception)
            {
                json.WriteString("exceptionType", exception.GetType().FullName);
                json.WriteString("exception", exception.Message);
            }

            // What ties a line to the request it came from, and to a trace if one is being
            // exported. Written only when the project is known — see CloudLoggingOptions.
            if (Activity.Current is { } activity && _options.ProjectId is { Length: > 0 } project)
            {
                json.WriteString(
                    "logging.googleapis.com/trace",
                    $"projects/{project}/traces/{activity.TraceId}");
                json.WriteString("logging.googleapis.com/spanId", activity.SpanId.ToString());
            }

            // The named properties the library went to the trouble of producing. Anything whose
            // name starts with '{' is the message template the formatter already rendered.
            if (logEntry.State is IReadOnlyList<KeyValuePair<string, object?>> properties)
            {
                foreach (var (key, value) in properties)
                {
                    if (key.Length == 0 || key[0] == '{' || key == "{OriginalFormat}")
                    {
                        continue;
                    }

                    json.WriteString(key, value?.ToString());
                }
            }

            json.WriteEndObject();
        }

        textWriter.WriteLine(System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    /// <summary>
    /// .NET's levels onto Cloud Logging's, which are the syslog names.
    /// </summary>
    /// <remarks>
    /// <c>LogLevel.Warning</c> is <c>WARNING</c> and <c>Critical</c> is <c>CRITICAL</c>, but
    /// <c>Trace</c> and <c>Debug</c> both collapse to <c>DEBUG</c> because Cloud Logging has no
    /// finer level and inventing one would be a string nothing filters on.
    /// </remarks>
    private static string Severity(LogLevel level) => level switch
    {
        LogLevel.Trace or LogLevel.Debug => "DEBUG",
        LogLevel.Information => "INFO",
        LogLevel.Warning => "WARNING",
        LogLevel.Error => "ERROR",
        LogLevel.Critical => "CRITICAL",
        _ => "DEFAULT",
    };
}
