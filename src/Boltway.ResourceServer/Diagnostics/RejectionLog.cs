using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.Extensions.Logging;

namespace Boltway.ResourceServer.Diagnostics;

/// <summary>
/// The one structured log message this server emits for a rejection. A-09.
/// </summary>
/// <remarks>
/// <para>
/// A copy of <c>Boltway.AuthorizationServer.Diagnostics.RejectionLog</c>, deliberately, and the
/// duplication is the smaller of two costs. The only assembly both servers reference is
/// <c>Boltway.OAuth.Primitives</c>, which is BCL-only <b>by design</b> — its project file says
/// so and gives the reason — and adding <c>Microsoft.Extensions.Logging.Abstractions</c> there to
/// share one attribute would falsify the property that assembly exists to hold. So the shared parts
/// live in Primitives, where they belong and where nothing prevents them: <see cref="Rejection"/>,
/// <see cref="ReasonCode"/>, <see cref="OAuthSurface"/>, the error table, and the
/// <c>X-Request-Id</c> spelling.
/// </para>
/// <para>
/// The event id, the event name, the template and every property name below are identical to the
/// authorization server's, so one query returns both halves of a failed connection — which is the
/// case this project is actually about: a client that got a token and then a 401 has a failure whose
/// two ends are in different processes. A test in each suite asserts the property set, so a change
/// to one that is not made to the other shows up as a red build rather than as a query that
/// quietly returns half the answer.
/// </para>
/// </remarks>
internal static partial class RejectionLog
{
    /// <summary>
    /// The logger category, fixed rather than taken from the emitting type.
    /// </summary>
    /// <remarks>
    /// Distinct from the authorization server's, because the two are separate deployables and an
    /// operator running only a resource server should not have to know the other name to configure
    /// a level. Both end in <c>.Rejection</c>, so one prefix filter still catches both in a process
    /// that hosts the pair.
    /// </remarks>
    internal const string LoggerCategory = "Boltway.ResourceServer.Rejection";

    /// <summary>The rejection event. One line, one rejection, no exceptions.</summary>
    [LoggerMessage(
        EventId = 100,
        EventName = "Rejection",
        Message = "Rejected {Surface} request {CorrelationId}: {Reason} [{RequirementId}] -> {Status} {Error}: "
            + "{Description} {Detail}")]
    internal static partial void Rejected(
        ILogger logger,
        LogLevel level,

        // Enums rather than their ToString(), so nothing is formatted when the level is disabled
        // (CA1873 is an error here) and a structured provider gets a scalar it can filter on.
        OAuthSurface surface,
        string correlationId,
        ReasonCode reason,
        string requirementId,
        int status,
        string error,

        // The public half — what the caller was told, as opposed to `detail`, which is the half
        // that never leaves the process. It arrived here because the authorization server's error
        // page stopped showing it: `/error` renders a sentence chosen for the person reading it, so
        // the exact English needs somewhere to survive. It is added on this side too because the
        // two servers declare this template separately and a property in one and not the other is
        // the drift the paired tests exist to catch.
        string description,

        string? detail,
        Exception? exception);
}
