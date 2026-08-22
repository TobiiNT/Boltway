using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Http;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Boltway.AuthorizationServer.Diagnostics;

/// <summary>
/// The one place a rejection becomes a response. A-09.
/// </summary>
/// <remarks>
/// <para>
/// <b>Writing the response and emitting the log are the same act.</b> <see cref="ExecuteAsync"/> is
/// not virtual and has no branch that reaches a subclass before the log line is out, so there is no
/// ordering in which a rejection is delivered unlogged. That is a stronger claim than "every call
/// site remembers to log", and it is the difference this type exists for: the measurement that
/// started this work found sixteen authorization-server rejection classes and twenty-five in total
/// emitting zero product log lines between them, on a codebase whose design document already said
/// the obligation was structural.
/// </para>
/// <para>
/// Two further guards sit around it, because a chokepoint only helps while it is the only one:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Compile.</b> <see cref="AuthorizeHtmlError"/>, <see cref="AuthorizeRedirectError"/> and
/// <c>OAuthJsonResults.Error</c> all <i>require</i> a <see cref="Rejection"/>. There is no overload
/// that takes a bare code and description, so an error response cannot be built without the payload
/// this type logs.
/// </description></item>
/// <item><description>
/// <b>Build.</b> <c>StructuralRuleTests.Only_the_rejection_writer_produces_an_error_response</c>
/// asserts two things over compiled IL: that <see cref="OAuthErrors.Resolve"/> has exactly one
/// caller per server assembly, and that no other method in either assembly carries a constant in
/// [400, 599]. The first catches an error built through the table; the second catches one built
/// around it, since <c>StatusCodes.Status400BadRequest</c> is a <c>const</c> and reaches IL as the
/// same <c>ldc.i4</c> a literal would.
/// </description></item>
/// </list>
/// <para>
/// Two things that rule does <b>not</b> cover, stated rather than implied. A host that maps its own
/// endpoints alongside ours and returns its own 400 is outside this assembly — that is the
/// customer's surface, not the protocol surface. And two <c>404</c>s are allowlisted by name: the
/// well-known "this server publishes no document here" answers, which carry no OAuth error, no
/// description and nothing request-derived, and which RFC 9728 §3.1 probing depends on.
/// </para>
/// </remarks>
internal abstract class RejectionResult : IResult
{
    /// <summary>
    /// The logger category, fixed rather than taken from the emitting type.
    /// </summary>
    /// <remarks>
    /// An operator filters on this to see every refusal the server made, and a per-type category
    /// would spread that across <c>AuthorizeEndpoint</c>, <c>TokenEndpoint</c>,
    /// <c>InteractionEndpoints</c> and whatever is added next — so the filter that worked in
    /// staging silently stops covering a new endpoint. The surface is a property on the event
    /// instead, which is where something you want to group by belongs.
    /// </remarks>
    internal const string LoggerCategory = "Boltway.AuthorizationServer.Rejection";

    protected RejectionResult(OAuthSurface surface, Rejection rejection, string correlationId)
    {
        ArgumentNullException.ThrowIfNull(rejection);

        Surface = surface;
        Rejection = rejection;
        CorrelationId = correlationId;
    }

    /// <summary>Which endpoint is answering. Half the key into the error table.</summary>
    protected OAuthSurface Surface { get; }

    /// <summary>Why the request was refused.</summary>
    protected Rejection Rejection { get; }

    /// <summary>The id that joins this log line to the response the caller holds.</summary>
    protected string CorrelationId { get; }

    /// <summary>
    /// Log it, stamp it, write it. In that order, and not overridable.
    /// </summary>
    /// <remarks>
    /// The log comes first so that a client that disconnects mid-write still leaves a record —
    /// <c>WriteAsync</c> below can throw <see cref="OperationCanceledException"/>, and a rejection
    /// whose evidence depends on the caller staying connected is evidence about the wrong thing.
    /// </remarks>
    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        // X-31 and X-43 are the refusals with no OAuth error code — the table's `error` column for
        // both is literally (none) — so neither can be looked up in a table keyed on
        // OAuthErrorCode. Handled here rather than by a separate IResult, which is what a first
        // merge of the rate-limiting work would have produced: a second writer, outside this
        // chokepoint, and therefore a refusal that is never logged. A burst of 429s is exactly what
        // an operator most wants to see, and a burst of 503s means the database is gone — the two
        // refusals designed to arrive in bursts must not be the ones that go unrecorded.
        var spec = UntabledSpec ?? OAuthErrors.Resolve(Surface, Rejection.Error);

        var status = StatusFor(spec);

        Record(httpContext, Surface, Rejection, CorrelationId, spec.RequirementId, status, spec.Wire);

        if (RetryAfter is { } wait)
        {
            StampRetryAfter(httpContext, wait);
        }

        httpContext.Response.StatusCode = status;

        return WriteAsync(httpContext, spec);
    }

    /// <summary>
    /// Emit the line and stamp the header. The single place either obligation is discharged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Static and shared rather than inlined above, because one refusal in this server is not an
    /// OAuth error response and still has to be recorded: a rejected username and password
    /// re-renders the sign-in form at <c>200</c> (E-20), deliberately, since a redirect would need
    /// the failure in a query parameter and that is a reflected value on the one page where
    /// reflection matters. It is a rejection an operator very much wants — a burst of them is a
    /// credential-stuffing run — so it comes through here with the status it actually returned.
    /// </para>
    /// <para>
    /// Header before body, and before the caller writes anything, so the response has not started
    /// and the write cannot be silently dropped.
    /// </para>
    /// </remarks>
    internal static void Record(
        HttpContext httpContext,
        OAuthSurface surface,
        Rejection rejection,
        string correlationId,
        string requirementId,
        int status,
        string error)
    {
        var logger = httpContext.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(LoggerCategory);

        // Counted here and nowhere else, for the reason this method exists at all: it is the one
        // place every refusal in the server passes through. An instrument at each call site would
        // drift from the log the moment somebody added a rejection and forgot half of it, and the
        // whole value of `boltway.oauth.rejection` is that its total equals the number of
        // Rejected lines. GetService, not GetRequiredService — metrics are optional, and a host
        // that has not registered them should not fail on the refusal path.
        httpContext.RequestServices.GetService<AuthorizationServerMetrics>()?.Rejection.Add(
            1,
            new KeyValuePair<string, object?>("reason", rejection.Reason.ToString()),
            new KeyValuePair<string, object?>("surface", surface.ToString()),
            new KeyValuePair<string, object?>("error", error));

        RejectionLog.Rejected(
            logger,

            // Keyed on the OAuth error, not on the HTTP status, and the difference was measured
            // rather than reasoned. `server_error` is the one code that means the fault is ours, and
            // a first draft here read `status >= 500` — which is right for the HTML delivery and
            // wrong for the one that matters: once a redirect URI is validated, X-10 is delivered as
            // a `303` carrying `error=server_error`, so every crash after stage 3 logged at Warning.
            // The status describes how the answer travels; the code describes whose fault it is.
            rejection.Error is OAuthErrorCode.ServerError ? LogLevel.Error : LogLevel.Warning,
            surface,
            correlationId,
            rejection.Reason,
            requirementId,
            status,
            error,
            rejection.Description,
            rejection.PrivateDetail,
            rejection.Cause);

        httpContext.Response.Headers[DiagnosticHeaders.RequestId] = correlationId;
    }

    /// <summary>Stamp <c>Retry-After</c>, in delta-seconds.</summary>
    /// <remarks>
    /// RFC 9110 §10.2.3, and never zero: "retry immediately" is what the caller was just told not to
    /// do. Rounded up, so a client honouring it exactly does not arrive one tick early and be
    /// refused again.
    /// </remarks>
    private static void StampRetryAfter(HttpContext httpContext, TimeSpan wait) =>
        httpContext.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds))
            .ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// The status, which is the table's unless the surface has a second input.
    /// </summary>
    /// <remarks>
    /// Only <c>invalid_client</c> at <c>/token</c> overrides it: RFC 6749 §5.2 makes 401 conditional
    /// on the client having authenticated through the <c>Authorization</c> header, which is an
    /// observation about the request and not a fact the table holds.
    /// </remarks>
    protected virtual int StatusFor(OAuthErrorSpec spec) => spec.Status;

    /// <summary>
    /// How long to wait, for the one refusal that says so. X-31.
    /// </summary>
    /// <remarks>
    /// <see langword="null"/> for every rejection that has an OAuth error code, which is all of them
    /// but this one. A subclass overriding it is declaring "this response is a rate limit", and
    /// <see cref="ExecuteAsync"/> then answers 429 with a <c>Retry-After</c> instead of consulting
    /// the error table.
    /// </remarks>
    protected virtual TimeSpan? RetryAfter => null;

    /// <summary>
    /// The row to use when this surface's table has no code for the refusal, or
    /// <see langword="null"/> to look one up.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Null by default, so the table is consulted unless a subclass says otherwise.</b> It read
    /// <c>RetryAfter is null ? null : ThrottledSpec</c> for one release, which was exact while X-31
    /// was the only refusal anywhere that carried a wait — "declaring a <c>Retry-After</c> is what
    /// makes a result a throttle". X-43 broke half of that and X-11 broke the rest: both carry a
    /// wait and neither is a rate limit, and one of them has a registered <c>error</c> that must
    /// come from the table. An implicit rule that has to be re-derived every time a refusal is
    /// added is one that will eventually be re-derived wrongly, and the failure mode was silent —
    /// a 429 answered during a database outage, with X-31 on the log line an operator reads.
    /// </para>
    /// <para>
    /// So each subclass now names its own row and this default claims nothing.
    /// </para>
    /// <para>
    /// Deliberately not a way to override a row the table <i>does</i> have. Every value returned
    /// here has an empty <c>Wire</c>, which is the point: these are refusals RFC 6749 registers no
    /// <c>error</c> for, and inventing one would put a string on the wire that no client can be
    /// expected to parse. <c>OAuthErrors.Resolve</c> throwing on an unlisted pair is what keeps a
    /// real code from being smuggled onto a surface that must not emit it, and this seam does not
    /// weaken that — it has no access to a code at all.
    /// </para>
    /// </remarks>
    protected virtual OAuthErrorSpec? UntabledSpec => null;

    /// <summary>The stand-in for a table row that cannot exist.</summary>
    /// <remarks>
    /// An empty <c>Wire</c> because there is no <c>error</c> to send: RFC 6749 §5.2 defines a closed
    /// set of codes and none of them means "too many requests", so inventing one would put a value
    /// on the wire that no client can be expected to parse. The requirement id is carried so the log
    /// line still names which rule refused the request, which is what every other rejection gets
    /// from the table.
    /// </remarks>
    private protected static readonly OAuthErrorSpec ThrottledSpec =
        new(Wire: string.Empty, Status: StatusCodes.Status429TooManyRequests, ErrorDelivery.Html, "X-31");

    /// <summary>The row for a store that could not be reached. X-43.</summary>
    /// <remarks>
    /// <para>
    /// An empty <c>Wire</c> for the same reason as <see cref="ThrottledSpec"/>, and it is worth
    /// stating which near-miss it avoids: <c>temporarily_unavailable</c> means exactly this and is
    /// registered for the <i>authorization</i> endpoint by RFC 6749 §4.1.2.1. §5.2's set for
    /// <c>/token</c> does not include it, so emitting it here would be an invention on the one
    /// endpoint whose error strings clients branch on hardest. The status and the
    /// <c>Retry-After</c> carry the meaning instead, which every HTTP client already understands
    /// without being taught an OAuth code.
    /// </para>
    /// <para>
    /// <c>ErrorDelivery.Json</c> because that is the surface it answers on, even though the body is
    /// empty: the value describes where the refusal is delivered, and a 503 from <c>/token</c> is
    /// still a JSON endpoint's answer. Nothing reads it to decide whether to write a body — the
    /// result type does that.
    /// </para>
    /// </remarks>
    private protected static readonly OAuthErrorSpec StoreUnavailableSpec = new(
        Wire: string.Empty,
        Status: StatusCodes.Status503ServiceUnavailable,
        ErrorDelivery.Json,
        "X-43");

    /// <summary>The same row, for a surface whose caller is a person. X-43.</summary>
    /// <remarks>
    /// <para>
    /// The status and the requirement are identical; only the delivery differs, and it differs
    /// because an empty body is a different quality of answer depending on who is reading. A
    /// resource server branches on <c>503</c> and needs nothing else. Somebody half way through
    /// signing in gets their browser's own error page, which says nothing about coming back — and
    /// on the one surface where the whole problem is a person being told the wrong thing about
    /// their credentials, that is not good enough.
    /// </para>
    /// <para>
    /// So this one renders, through the deployment's <c>IInteractionRenderer</c> like every other
    /// page here, and the sentence a person reads is chosen by
    /// <c>InteractionText.ErrorSentenceFor</c> from the reason — which is why the reason travels
    /// rather than only the status.
    /// </para>
    /// </remarks>
    private protected static readonly OAuthErrorSpec StoreUnavailableHtmlSpec = new(
        Wire: string.Empty,
        Status: StatusCodes.Status503ServiceUnavailable,
        ErrorDelivery.Html,
        "X-43");

    /// <summary>Write the body and any delivery-specific headers.</summary>
    protected abstract Task WriteAsync(HttpContext httpContext, OAuthErrorSpec spec);
}

/// <summary>
/// An authorization failure rendered on our own origin. RFC 6749 §4.1.2.1.
/// </summary>
/// <remarks>
/// Deliberately a few hundred bytes of hand-built HTML rather than a view. It renders on a path
/// where something has already gone wrong — including, at stage 0b, "the server threw" — so anything
/// it depends on is a second thing that can fail while handling the first. Everything interpolated
/// has been through <c>ErrorText.Safe</c> and is HTML-encoded again here, because "already filtered"
/// is a property of the current call sites rather than of the type.
/// </remarks>
internal sealed class RejectionHtmlResult(AuthorizeHtmlError error, OAuthSurface surface)
    : RejectionResult(surface, error.Rejection, error.CorrelationId)
{
    /// <inheritdoc />
    protected override TimeSpan? RetryAfter => error.RetryAfter;

    /// <summary>
    /// The row for a refusal this surface has no <c>error</c> for, chosen by what it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Carrying no code is what makes a refusal untabled, and that is now the test.</b> It read
    /// <c>Reason is RateLimited</c> for a release, and before that "is a <c>Retry-After</c> set" —
    /// each exact for the refusals that existed when it was written, and each a rule that had to be
    /// widened by hand the next time one was added. <see cref="OAuthErrorCode.None"/> means
    /// literally "there is no <c>error</c> member in this response", the table is keyed on a code,
    /// and <c>The_none_code_is_not_in_the_table</c> asserts it can never hold one — so the two
    /// statements are the same statement, and asking the question this way cannot go stale.
    /// </para>
    /// <para>
    /// The reason then chooses between the untabled rows, because there are two and they mean
    /// opposite things: X-31 says the caller asked too often, X-43 says this server could not reach
    /// what it needed. A refusal that <i>does</i> carry a code goes to the table — which is what
    /// keeps X-11 at <c>/authorize</c> resolving as X-11, with <c>temporarily_unavailable</c> on the
    /// page, rather than being swallowed by the row below it.
    /// </para>
    /// </remarks>
    protected override OAuthErrorSpec? UntabledSpec => Rejection.Error is OAuthErrorCode.None
        ? Rejection.Reason is ReasonCode.StoreUnavailable ? StoreUnavailableHtmlSpec : ThrottledSpec
        : null;

    protected override async Task WriteAsync(HttpContext httpContext, OAuthErrorSpec spec)
    {
        var bytes = Encoding.UTF8.GetBytes(Render(httpContext, spec));

        httpContext.Response.ContentType = "text/html; charset=utf-8";
        httpContext.Response.ContentLength = bytes.Length;

        await httpContext.Response.Body.WriteAsync(bytes, httpContext.RequestAborted);
    }

    /// <summary>
    /// The deployment's error page, or the built-in one if producing it fails.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This page went through the renderer seam late, and the delay was the argument against
    /// it:</b> it renders where something has already gone wrong — including, at stage 0b, "the
    /// server threw" — so anything it depends on is a second thing that can fail while handling the
    /// first. That is a reason to catch, not a reason to leave two of the three pages themeable and
    /// say nothing. A customer implementing <c>IInteractionRenderer</c> restyled login and consent
    /// and found out about this one from a screenshot.
    /// </para>
    /// <para>
    /// So the seam is used and the fallback is kept. The catch is deliberately of everything: a
    /// renderer that throws here is a bug in the deployment's code, and the response it is
    /// interrupting is already an apology.
    /// </para>
    /// </remarks>
    private string Render(HttpContext httpContext, OAuthErrorSpec spec)
    {
        try
        {
            return httpContext.RequestServices
                .GetRequiredService<Interaction.IInteractionRenderer>()
                .RenderError(new Interaction.ErrorViewModel
                {
                    // Null rather than empty, and the model documents why: X-31 is the one refusal
                    // with no `error` code, and an empty <code></code> reads as a value that failed
                    // to load rather than one that was never there.
                    Code = string.IsNullOrEmpty(spec.Wire) ? null : spec.Wire,

                    // Kept, and A-12 is why: the OAuth code and a safe description must be in the
                    // body so that `curl -D-` is a sufficient debugging tool. It is also the one
                    // string on this page that cannot be translated — it is the `error_description`,
                    // and OAuth 2.1 §4.1.2.1 restricts it to %x20-21 / %x23-5B / %x5D-7E, which
                    // ErrorText.Safe enforces by dropping everything else.
                    Description = error.Description,

                    // And the sentence the person actually reads, which is a different job: what to
                    // do, in their language, chosen by what they can do about this class of refusal.
                    // A Vietnamese deployment had one English line in the middle of a translated
                    // page and no key that would change it, because the line was never written for
                    // the person in front of it.
                    Guidance = InteractionText.Plain(
                        httpContext.RequestServices.GetService<IStringLocalizer>(),
                        InteractionText.ErrorSentenceFor(error.Rejection.Reason)),

                    CorrelationId = error.CorrelationId,
                    Nonce = Endpoints.SecurityHeaders.NonceFor(httpContext),
                });
        }
        catch (Exception ex)
        {
            httpContext.RequestServices
                .GetService<ILoggerFactory>()
                ?.CreateLogger<RejectionHtmlResult>()
                .LogError(
                    ex,
                    "The registered IInteractionRenderer threw while rendering the authorization "
                    + "error page. The built-in page was served instead; the original refusal is "
                    + "logged separately under correlation id {CorrelationId}.",
                    error.CorrelationId);

            return BuiltIn(spec);
        }
    }

    /// <summary>
    /// A few hundred bytes of hand-built HTML, depending on nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The last resort, and it stays hand-built for the reason the whole type is: it is what renders
    /// when the thing that was supposed to render has failed. Everything interpolated has been
    /// through <c>ErrorText.Safe</c> and is HTML-encoded again here, because "already filtered" is a
    /// property of the current call sites rather than of the type.
    /// </para>
    /// <para>
    /// <b>English, and <c>lang="en"</c> says so.</b> It reaches for no localizer and shows the wire
    /// description rather than the reader's sentence, which is the point: it renders because
    /// resolving the renderer or the text failed, and a second attempt at the same machinery is a
    /// second chance to throw inside a response that is already an apology.
    /// </para>
    /// </remarks>
    private string BuiltIn(OAuthErrorSpec spec) =>
        new StringBuilder()
            .Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
            .Append("<title>Authorization error</title></head><body>")
            .Append("<h1>This request could not be authorized</h1>")
            .Append(string.IsNullOrEmpty(spec.Wire)
                ? string.Empty
                : "<p><code>" + WebUtility.HtmlEncode(spec.Wire) + "</code></p>")
            .Append("<p>")
            .Append(WebUtility.HtmlEncode(error.Description))
            .Append("</p><p>Reference: <code>")
            .Append(WebUtility.HtmlEncode(error.CorrelationId))
            .Append("</code></p></body></html>")
            .ToString();
}

/// <summary>
/// An authorization failure delivered by redirect to the validated URI.
/// </summary>
/// <remarks>
/// <para>
/// 303 See Other, which is what the table says for every code on the <c>Authorize</c> surface.
/// OAuth 2.1 §7.5.3 forbids 307 outright: "In HTTP, only the status code 303 unambiguously enforces
/// rewriting the HTTP POST request to an HTTP GET request. For all other status codes, including the
/// popular 302, user agents can opt not to rewrite POST to GET requests and therefore reveal the
/// user credentials to the client." Several of these arise from the consent POST.
/// </para>
/// <para>
/// The <c>Location</c> is assembled here rather than by the caller, because <c>error</c> has to be
/// the wire string from the table and the table is only read once, in the base class. It goes
/// through <c>AuthorizeResults.Build</c> — see there for the three separate things concatenation
/// breaks.
/// </para>
/// </remarks>
internal sealed class RejectionRedirectResult(AuthorizeRedirectError error)
    : RejectionResult(OAuthSurface.Authorize, error.Rejection, error.CorrelationId)
{
    protected override Task WriteAsync(HttpContext httpContext, OAuthErrorSpec spec)
    {
        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["error"] = spec.Wire,
            ["error_description"] = error.Description,

            // RFC 9207 §2 requires `iss` on every authorization response including the errors: an
            // error response is as useful to a mix-up attack as a successful one, and a client that
            // saw authorization_response_iss_parameter_supported and then a response without `iss`
            // is required to reject it — so omitting it here would break the flow rather than
            // merely weaken it.
            ["iss"] = error.Issuer.Value,
        };

        // Omitted entirely when the client sent none. `state=` is not the same as no state.
        if (error.State is not null)
        {
            parameters["state"] = error.State;
        }

        httpContext.Response.Headers[HeaderNames.Location] =
            AuthorizeResults.Build(error.Target.Value, parameters);

        return Task.CompletedTask;
    }
}

/// <summary>An OAuth JSON error body. RFC 6749 §5.2.</summary>
internal sealed class RejectionJsonResult(
    OAuthSurface surface,
    Rejection rejection,
    string correlationId,
    JsonTypeInfo<OAuthErrorBody> typeInfo,
    bool usedAuthorizationHeader,
    string challengeScheme)
    : RejectionResult(surface, rejection, correlationId)
{
    /// <inheritdoc />
    protected override int StatusFor(OAuthErrorSpec spec) =>
        Rejection.Error is OAuthErrorCode.InvalidClient
            ? OAuthErrors.StatusForClientAuthFailure(usedAuthorizationHeader)
            : spec.Status;

    protected override async Task WriteAsync(HttpContext httpContext, OAuthErrorSpec spec)
    {
        var response = httpContext.Response;

        response.ContentType = "application/json";

        // RFC 6749 §5.1, on every token response and every error: "The authorization server MUST
        // include the HTTP 'Cache-Control' response header field with a value of 'no-store'".
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";

        // §5.2: "If the client attempted to authenticate via the 'Authorization' request header
        // field, the authorization server MUST respond with an HTTP 401 … and include the
        // 'WWW-Authenticate' response header field matching the authentication scheme used by the
        // client." Expressed as the two conditions that produce the 401 rather than by comparing the
        // status against 401 — the comparison is the same answer and it would put a bare status
        // literal in this assembly, which the architecture rule reads as a second response writer.
        if (usedAuthorizationHeader && Rejection.Error is OAuthErrorCode.InvalidClient)
        {
            response.Headers[HeaderNames.WWWAuthenticate] =
                WwwAuthenticate.ClientAuthentication(challengeScheme, realm: "token");
        }

        var body = new OAuthErrorBody
        {
            Error = spec.Wire,
            ErrorDescription = ErrorText.Safe(Rejection.Description),
        };

        await JsonSerializer.SerializeAsync(response.Body, body, typeInfo, httpContext.RequestAborted);
    }
}

/// <summary>
/// A refusal because the store could not be reached. X-43.
/// </summary>
/// <remarks>
/// <para>
/// <b>No body, deliberately.</b> Every other rejection from <c>/token</c> is an OAuth JSON object
/// because a client branches on its <c>error</c> member, and this refusal has no <c>error</c> to
/// put there — see <see cref="RejectionResult.StoreUnavailableSpec"/>. <c>{"error":""}</c> is worse
/// than nothing: it is a member the RFC says must be one of a closed set, holding a value that is
/// in no set at all, and a client matching on it takes whichever branch its parser reaches first.
/// The status is the signal, <c>Retry-After</c> is the instruction, and <c>X-Request-Id</c> — which
/// the base class stamps before this runs — is what turns a report into a log line.
/// </para>
/// <para>
/// <c>no-store</c> anyway, on a response that carries nothing worth storing. It costs one header
/// and removes a class of question: a shared proxy that caches a 503 serves it to the next caller
/// after the outage ends, and RFC 9111 §4.2.2 lets a heuristically-cacheable status be reused when
/// nothing forbids it. The endpoint's whole contract is that its answers are never reused.
/// </para>
/// </remarks>
internal sealed class StoreUnavailableResult(
    OAuthSurface surface,
    Rejection rejection,
    string correlationId,
    TimeSpan retryAfter)
    : RejectionResult(surface, rejection, correlationId)
{
    /// <inheritdoc />
    protected override OAuthErrorSpec? UntabledSpec => StoreUnavailableSpec;

    /// <inheritdoc />
    /// <remarks>
    /// Never zero and never negative — <c>StampRetryAfter</c> floors the header at one second, and
    /// this floors the value it is given, so a misconfigured wait cannot become "retry immediately"
    /// against a dependency that is still down.
    /// </remarks>
    protected override TimeSpan? RetryAfter =>
        retryAfter > TimeSpan.Zero ? retryAfter : TimeSpan.FromSeconds(1);

    protected override Task WriteAsync(HttpContext httpContext, OAuthErrorSpec spec)
    {
        var response = httpContext.Response;

        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";

        // Explicit, rather than left for the server to infer from a body that never comes. A
        // response with neither Content-Length nor a body is legal and reads as a truncation to
        // anyone debugging it.
        response.ContentLength = 0;

        return Task.CompletedTask;
    }
}

/// <summary>
/// The one structured log message either server emits for a rejection.
/// </summary>
/// <remarks>
/// <para>
/// Source-generated rather than interpolated. The template is compiled once and the arguments are
/// not boxed or formatted when the level is disabled — but the reason that matters here is not
/// throughput, it is that every field below arrives at a log pipeline as a <b>named property</b>.
/// <c>LogWarning($"rejected {reason}")</c> produces a string a human can read and nothing can index,
/// so "how many <c>AccessTokenRejected</c> in the last hour, and did they all name the same
/// <c>kid</c>" is a grep instead of a query.
/// </para>
/// <para>
/// <b><c>CorrelationId</c> is an explicit property even though ASP.NET Core's hosting log scope
/// already carries the same value.</b> Three reasons it is not redundant. The scope is only emitted
/// when the host turns <c>IncludeScopes</c> on, which is off by default in every shipped provider
/// and is the host's configuration rather than this library's. Providers render it differently —
/// Serilog surfaces it as <c>RequestId</c>, the console provider flattens it into a scope string —
/// so a query that joins on it is provider-specific. And A-09 does not ask for the id in the log; it
/// asks for it in the log <i>and</i> in the response, and the response half only works if the value
/// written to the header is demonstrably the value written to the line. One property, read once,
/// used for both.
/// </para>
/// <para>
/// There is a second, identical declaration in <c>Boltway.ResourceServer</c>, and it is a
/// copy rather than a shared type. The two assemblies share only <c>Boltway.OAuth.Primitives</c>,
/// which is BCL-only by design — adding <c>Microsoft.Extensions.Logging.Abstractions</c> there to
/// save one duplicated attribute would falsify the property that assembly exists to hold. The
/// message template and every property name are kept identical so one query returns both halves of
/// a failed connection; a test in each suite asserts the property set.
/// </para>
/// </remarks>
internal static partial class RejectionLog
{
    /// <summary>The rejection event. One line, one rejection, no exceptions.</summary>
    [LoggerMessage(
        EventId = 100,
        EventName = "Rejection",
        Message = "Rejected {Surface} request {CorrelationId}: {Reason} [{RequirementId}] -> {Status} {Error}: "
            + "{Description} {Detail}")]
    internal static partial void Rejected(
        ILogger logger,
        LogLevel level,

        // The two enums are passed as enums rather than as their ToString(). It reads as a detail
        // and it is not one: formatting them at the call site runs whether or not the level is
        // enabled — CA1873, which is an error here — and a provider that captures structured values
        // gets a scalar it can filter on instead of a string it has to match.
        OAuthSurface surface,
        string correlationId,
        ReasonCode reason,
        string requirementId,
        int status,
        string error,

        // The public half of the refusal — what a client is told, and what the HTML page used to
        // show. It is here because the page stopped showing it: /error now renders a localized
        // sentence chosen by what the reader can do, so this line is where the exact English
        // survives. Without it, removing the sentence from the page would have destroyed the only
        // copy an operator could reach through the correlation id, which is A-09's whole promise.
        string description,

        string? detail,
        Exception? exception);
}
