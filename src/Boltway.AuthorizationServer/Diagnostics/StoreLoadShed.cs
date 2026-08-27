using Boltway.AuthorizationServer.Authorize;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>
/// What every endpoint answers when the store behind it could not be reached. X-43.
/// </summary>
/// <remarks>
/// <para>
/// <b>One place, because four endpoints shed and the sentence they say must not drift.</b> The
/// first version of X-43 built its rejection inline at <c>/token</c>, which was right while
/// <c>/token</c> was the only surface that shed. Three more followed a day later, and three more
/// copies of a description is how two endpoints come to describe the same outage differently - the
/// same argument <see cref="RejectionResult"/> makes about logging, one level down.
/// </para>
/// <para>
/// <b>The <i>catch</i> deliberately does not live here.</b> Each endpoint writes its own
/// <c>catch … when (TransientStoreFailure.Describes(…))</c>, because what is caught is a decision
/// about that endpoint: <c>/authorize</c> already has an exception boundary and needs its rejection
/// re-coded rather than its response replaced, and a helper that swallowed exceptions on behalf of a
/// caller would be a second response writer in everything but name. This owns the shape of the
/// answer, not the decision to give it.
/// </para>
/// </remarks>
internal static class StoreLoadShed
{
    /// <summary>
    /// How long a caller is told to wait.
    /// </summary>
    /// <remarks>
    /// A constant rather than an option, and the honest reason is that nothing here knows better.
    /// The right value is a property of how fast the dependency recovers, which is a fact about a
    /// database and a network rather than about this server - and the client re-reads the header on
    /// every attempt, so a value that is too short costs one cheap refused request and self-corrects
    /// while a value that is too long strands a working session. Five seconds is the same figure
    /// <see cref="StoreReadiness"/> uses to decide the store is gone; when there is a measurement
    /// that argues for another, it belongs in options with that measurement written beside it.
    /// </remarks>
    internal static readonly TimeSpan Wait = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The sentence on the wire, which says nothing about the store.
    /// </summary>
    /// <remarks>
    /// A driver message names the host, the database, the role and often the driver version, and
    /// every response built from this is readable by anyone who can reach the endpoint. The
    /// exception rides on the rejection to the log, where the correlation id leads.
    /// </remarks>
    internal const string Description = "The service is temporarily unable to complete this request.";

    /// <summary>The rejection, carrying the exception for the log and its type name for the detail.</summary>
    /// <param name="cause">What the endpoint caught.</param>
    /// <param name="code">
    /// The OAuth code, where the surface has one. <see cref="OAuthErrorCode.None"/> everywhere RFC
    /// 6749 registers nothing that means "come back shortly", which is every surface here except
    /// <c>/authorize</c> - see <see cref="ReasonCode.StoreUnavailable"/> for why that one is
    /// different rather than inconsistent.
    /// </param>
    internal static Rejection Because(Exception cause, OAuthErrorCode code = OAuthErrorCode.None)
    {
        ArgumentNullException.ThrowIfNull(cause);

        return Rejection.Of(
            ReasonCode.StoreUnavailable,
            code,
            Description,

            // The type name and no more. It is enough to tell a socket failure from a driver one
            // when reading the log beside the exception, and it carries no connection detail.
            $"store={cause.GetType().Name}",
            cause);
    }

    /// <summary>The 503 itself, for the surfaces that answer with a status rather than a redirect.</summary>
    /// <param name="http">The request, for its correlation id.</param>
    /// <param name="surface">Which endpoint is shedding. Recorded on the log line.</param>
    /// <param name="cause">What the endpoint caught.</param>
    internal static IResult Answer(HttpContext http, OAuthSurface surface, Exception cause)
    {
        ArgumentNullException.ThrowIfNull(http);

        return new StoreUnavailableResult(surface, Because(cause), http.TraceIdentifier, Wait);
    }

    /// <summary>
    /// The same refusal, rendered, for a surface whose caller is a person looking at a page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An empty <c>503</c> would be a real improvement over the <c>500</c> and still not the
    /// answer.</b> The status alone reaches a browser as the browser's own error page, which says
    /// nothing about coming back - and this is the surface where somebody is half way through
    /// signing in. The whole reason X-43 exists is that a temporary fault was being reported as a
    /// permanent one, to a person; answering it with a blank page repeats the shape of the mistake
    /// at a better status code.
    /// </para>
    /// <para>
    /// So it goes through <see cref="RejectionHtmlResult"/>, which renders the deployment's own
    /// error page through <c>IInteractionRenderer</c> and falls back to the built-in one if that
    /// throws. The sentence the reader gets is chosen from the reason by
    /// <c>InteractionText.ErrorSentenceFor</c>, in their language, which is the part a status can
    /// never carry.
    /// </para>
    /// <para>
    /// <b><see cref="OAuthErrorCode.None"/>, and that is what selects the row.</b> These pages are
    /// not an OAuth surface and no specification registers an <c>error</c> for them - see
    /// <see cref="OAuthSurface.Interaction"/>. Carrying no code is exactly what sends this to the
    /// untabled row rather than to a table that has none for it.
    /// </para>
    /// </remarks>
    /// <param name="http">The request, for its correlation id.</param>
    /// <param name="surface">Which surface is shedding. Recorded on the log line.</param>
    /// <param name="cause">What the endpoint caught.</param>
    internal static IResult Page(HttpContext http, OAuthSurface surface, Exception cause)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(cause);

        return new RejectionHtmlResult(
            AuthorizeHtmlError.StoreUnavailable(
                Description,
                http.TraceIdentifier,
                Wait,
                privateDetail: $"store={cause.GetType().Name}; path={http.Request.Path}",
                cause: cause,
                code: OAuthErrorCode.None),
            surface);
    }
}
