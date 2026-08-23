using System.Globalization;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Interaction;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// E-08, the authorization endpoint.
/// </summary>
/// <remarks>
/// <para>
/// The transport shell around <see cref="AuthorizePipeline"/>. Stages 1 to 8 are the pipeline's;
/// this adds stage 0 (security headers), stage 0b (the exception boundary), and stages 9 to 12 —
/// authentication, consent, code issuance, response.
/// </para>
/// <para>
/// <b>No CORS.</b> Not a permissive policy: none at all. OAuth 2.1 §3.1 — "Cross-Origin Resource
/// Sharing MUST NOT be supported at the Authorization Endpoint as the client does not access this
/// endpoint directly, instead the client redirects the user agent to it." That is why nothing here
/// writes an <c>Access-Control-Allow-Origin</c> header and why the discovery endpoints write theirs
/// per-response rather than through a middleware a host might apply globally.
/// </para>
/// </remarks>
public static class AuthorizeEndpoint
{
    /// <summary>Map GET and POST <c>/authorize</c>.</summary>
    /// <remarks>
    /// Both methods, because OIDC Core §3.1.2.1 requires an OpenID Provider to support GET and POST
    /// while OAuth 2.1 §3.1 makes POST a MAY. This server publishes an OP metadata document, so the
    /// stricter of the two applies. A POST body is form-encoded per Appendix C.2 and lands in the
    /// same transport-neutral parameter bag as the query string, so nothing downstream can tell
    /// which arrived.
    /// </remarks>
    public static IEndpointRouteBuilder MapAuthorize(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints
            .MapMethods(AuthorizationServerPaths.Authorize, ["GET", "POST"], HandleAsync)
            .AllowAnonymous()
            .WithName("boltway-authorize");

        return endpoints;
    }

    private static async Task<IResult> HandleAsync(HttpContext http, CancellationToken cancellationToken)
    {
        var services = http.RequestServices;
        var options = services.GetRequiredService<AuthorizationServerOptions>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(AuthorizeEndpoint));

        // Registered before anything can throw, so the boundary's own error page is protected too.
        // Applying it inside the try would leave the response most in need of these headers without
        // them.
        SecurityHeaders.Apply(http);

        var correlationId = http.TraceIdentifier;
        AuthorizeContext? context = null;

        try
        {
            context = ReadRequest(http, options, services.GetRequiredService<TimeProvider>(), correlationId);

            var pipeline = services.GetRequiredService<AuthorizePipeline>();
            var outcome = await pipeline.ValidateAsync(context, cancellationToken);

            return outcome switch
            {
                AuthorizeOutcome.Html html => Refuse(logger, correlationId, html.Error),
                AuthorizeOutcome.Redirect redirect => AuthorizeResults.Redirect(redirect.Error),
                AuthorizeOutcome.Validated validated =>
                    await InteractAsync(http, services, options, validated.Context, cancellationToken),
                _ => throw new InvalidOperationException($"Unhandled outcome {outcome.GetType().Name}."),
            };
        }
        catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested)
        {
            // The user agent is gone. There is nobody to deliver a response to, and turning this
            // into a server_error redirect would log a defect that did not happen.
            AuthorizeLog.Abandoned(logger, correlationId);
            throw;
        }
        catch (Exception ex)
        {
            if (http.Response.HasStarted)
            {
                // Nothing can be written, so nothing below will log. This is the one X-10 path that
                // needs its own line: rethrowing lets the host abort the connection, which is the
                // only honest outcome — a half-written response completed with a redirect would be a
                // response the client cannot parse — and it leaves the rejection writer unreached.
                AuthorizeLog.Unhandled(logger, correlationId, ex);
                throw;
            }

            // X-11 rather than X-10 when the store is what failed, and this is the whole of the
            // difference on this endpoint: it already answered every crash with an OAuth code rather
            // than a 500, so unlike /token there was never a status to fix here — only the wrong
            // code on it. `server_error` tells a client the request cannot succeed; a client reading
            // it at the start of a flow surfaces "sign-in is broken" and stops. `temporarily_
            // unavailable` is registered for exactly this at §4.1.2.1, means "shortly", and had no
            // emitter anywhere in this server until now — the row and the requirement were both
            // written for a dependency going down, and a dependency going down produced X-10.
            var transient = TransientStoreFailure.Describes(ex);

            // The response says almost nothing either way, because the exception message may be a
            // connection string and ErrorText.Safe filters characters rather than secrets. The
            // exception itself rides on the rejection, so the writer emits one line carrying the
            // type, the message and the stack — and this endpoint no longer logs it separately,
            // which would have been two lines for one refusal.
            var detail = transient
                ? StoreLoadShed.Description
                : $"The authorization server failed to process this request. Reference: {correlationId}.";

            // The one legitimate read of context.Redirect. Every stage takes the proof as a
            // parameter; the boundary has no stage to take it from, and this is the question it
            // exists to ask — is there an address it is safe to send this to.
            //
            // For a store failure the answer is usually no, and by construction rather than by
            // luck: validating a redirect URI means reading the client, so a store that is down
            // fails before there is a validated address. That is why the pre-redirect branch is the
            // one X-11 mostly reaches, and why it needed a table row of its own.
            if (context?.Redirect is { } target)
            {
                var rejection = transient
                    ? StoreLoadShed.Because(ex, OAuthErrorCode.TemporarilyUnavailable)
                    : Rejection.Of(
                        ReasonCode.Unhandled,
                        OAuthErrorCode.ServerError,
                        detail,
                        privateDetail: $"exception={ex.GetType().FullName}",
                        cause: ex);

                // No Retry-After on this branch. The response is a 303 the browser follows at once,
                // so a header telling it to wait five seconds describes nothing it is about to do —
                // the instruction belongs to the client, and it arrives as `temporarily_unavailable`
                // in the query string where the client's own retry logic reads it.
                return AuthorizeResults.Redirect(
                    AuthorizeRedirectError.Create(
                        target, rejection, context.State, context.Issuer, correlationId));
            }

            return AuthorizeResults.Html(
                transient
                    ? AuthorizeHtmlError.StoreUnavailable(
                        detail,
                        correlationId,
                        StoreLoadShed.Wait,
                        privateDetail: $"store={ex.GetType().Name}",
                        cause: ex)
                    : new AuthorizeHtmlError(
                        Rejection.Of(
                            ReasonCode.Unhandled,
                            OAuthErrorCode.ServerError,
                            detail,
                            privateDetail: $"exception={ex.GetType().FullName}",
                            cause: ex),
                        correlationId),
                OAuthSurface.AuthorizePreRedirect);
        }
    }

    /// <summary>
    /// Render a pre-redirect refusal, logging the ones an operator has to be able to see.
    /// </summary>
    /// <remarks>
    /// Only the X-31 refusals are logged here, and only because a limiter nobody can observe is a
    /// limiter that trips on a vendor without anyone finding out. This is <b>not</b> A-09 — the
    /// ordinary 400s on this path still emit nothing, and saying otherwise would be claiming a
    /// requirement that is not met.
    /// </remarks>
    private static IResult Refuse(ILogger logger, string correlationId, AuthorizeHtmlError error)
    {
        // No log line here. The rate-limiting work added one, correctly, at a time when nothing else
        // logged a refusal on this path; the rejection writer now logs every refusal including this
        // one, and A-09 asks for exactly one line per rejection. Two lines for one event is not a
        // harmless duplicate — an operator counting 429s to size a limit would double every figure.
        //
        // Measured: with both in place, Every_rejection_emits_one_line_carrying_the_id_that_is_in_the
        // _response reported "RateLimited: 2 log lines name the correlation id, not one". Keeping the
        // writer's is the right way round, because that one is emitted by the code that writes the
        // response rather than by a call site that has to remember.
        return AuthorizeResults.Html(error);
    }

    /// <summary>Read the request into the transport-neutral parameter bag.</summary>
    private static AuthorizeContext ReadRequest(
        HttpContext http, AuthorizationServerOptions options, TimeProvider time, string correlationId)
    {
        var values = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);

        foreach (var (key, value) in http.Request.Query)
        {
            values[key] = [.. value.Where(v => v is not null).Select(v => v!)];
        }

        // A POST body is read in addition to the query string, because a client may legitimately
        // split them. A name appearing in both is left as two values, which the pipeline then
        // refuses as a repeated parameter — the alternative is choosing one, and which one it
        // chooses is exactly the question an attacker who can append to a URL is asking.
        if (HttpMethods.IsPost(http.Request.Method) && http.Request.HasFormContentType)
        {
            foreach (var (key, value) in http.Request.Form)
            {
                var incoming = value.Where(v => v is not null).Select(v => v!);
                values[key] = values.TryGetValue(key, out var existing) ? [.. existing, .. incoming] : [.. incoming];
            }
        }

        return new AuthorizeContext
        {
            Parameters = new OAuthParameters(values),
            CorrelationId = correlationId,
            Issuer = options.ValidatedIssuer,
            // The injected provider, not TimeProvider.System. Everything else in the server takes
            // the injected one, and DI registers it with TryAddSingleton — i.e. replacing it is an
            // advertised seam. Hardcoding the system clock here meant IsStale compared one clock
            // against a session timestamp written on another, so a host that injected a clock
            // silently stopped enforcing max_age. It also made the time axis untestable over HTTP,
            // which is why every time-shaped guard here was unverified.
            Now = time.GetUtcNow(),

            // The browser the consent screen will be clicked in, so a session list can say which
            // device approved. Read here and never deeper: see ApprovingDevice.
            UserAgent = ApprovingDevice.Read(http.Request),
        };
    }

    /// <summary>Stages 9 to 12.</summary>
    private static async Task<IResult> InteractAsync(
        HttpContext http,
        IServiceProvider services,
        AuthorizationServerOptions options,
        AuthorizeContext context,
        CancellationToken cancellationToken)
    {
        var redirect = context.Redirect!;
        var wantsNoInteraction = context.Prompt.Contains("none", StringComparer.Ordinal);

        // ───────── stage 9: authentication ─────────

        var session = services.GetRequiredService<IUserSession>();
        var user = await session.GetAsync(cancellationToken);

        // `select_account` asks the user to pick among sessions. This server's IUserSession
        // answers with one user or none, so there is never a selection to make — the honest
        // handling is to re-authenticate, which lets the user pick an account at the login form.
        //
        // X-14 `account_selection_required` therefore has NO emitter here, and that is a statement
        // rather than an omission. OIDC Core §3.1.2.6 defines it as the answer when the end user
        // "MAY be authenticated with different associated accounts but did not select a session" —
        // a condition that needs a *set* of sessions. `IUserSession.GetAsync` returns
        // `AuthenticatedUser?`: zero or one. The set has no representation in this codebase, so the
        // condition is unreachable at the type level. It becomes reachable the day IUserSession is
        // widened to return several sessions, and not before.
        //
        // An earlier version of this comment argued instead that stage 8 refuses `none` combined
        // with `select_account` before reaching here. True, but a non-sequitur: X-14's trigger is
        // `prompt=none` *alone* against several sessions, so refusing the combination says nothing
        // about it. The argument above is the one that holds, and it is the one that would stop
        // holding if the interface changed — which is the property a proof of unreachability needs.
        //
        // `select_account` itself is handled inside InteractionRequirements, alongside `prompt=login`
        // and `max_age`, because all three mean the same thing to this server: re-authenticate, and
        // let the user pick an account at the login form.

        // The one implementation, shared with the consent POST — see InteractionRequirements, and
        // the bypass that existed while these were two copies of which only this one was complete.
        //
        // The freshness floor inside it costs something, and the cost is worth naming because an
        // audit read it as a bug. A user whose session is 4 minutes old *from an earlier, unrelated
        // request* and who now sends `select_account` is not asked to choose; OIDC says the server
        // SHOULD ask. Answering that properly means distinguishing "authenticated in order to
        // satisfy this request" from "authenticated recently for something else", which needs the
        // request's own start time — state this server does not keep, because the authorization
        // request is carried in a URL and nothing else. Between a bounded window in which
        // `select_account` is a no-op and a redirect loop no user can escape, this takes the window.
        if (InteractionRequirements.MustReauthenticate(context, user, options.ReauthenticationFreshness))
        {
            if (wantsNoInteraction)
            {
                // OIDC Core §3.1.2.1: `none` means no authentication or consent UI may be shown.
                // `login_required` specifically, not `interaction_required` — relying parties doing
                // silent renew branch on the exact string, and many treat the latter as fatal.
                return AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
                    redirect,
                    Rejection.Of(
                        ReasonCode.LoginRequired,
                        OAuthErrorCode.LoginRequired,
                        "No authenticated session satisfies this request.",
                        user is null
                            ? "no session"
                            : $"session_age={context.Now - user.Value.AuthenticatedAt}; max_age={context.MaxAge}; prompt={string.Join(' ', context.Prompt)}"),
                    context.State,
                    context.Issuer,
                    context.CorrelationId));
            }

            return AuthorizeResults.SeeOther(LocalReturn(http, AuthorizationServerPaths.Login));
        }

        context.Subject = user!.Value.Subject;
        context.AuthTime = user.Value.AuthenticatedAt;

        // The entitlement filter, before consent so the page shows what can actually be granted, and
        // before the code is issued so nothing is minted that this account may not hold. Scope is
        // what a client may do on somebody's behalf; whether that somebody may do it is this.
        var entitled = await ScopeEntitlement.FilterAsync(
            services, context.Subject.Value, context.Scope, cancellationToken);

        if (entitled.Values.Count == 0)
        {
            // X-42. Filtering to a narrower set is an ordinary grant; filtering to nothing means the
            // client asked for nothing this account can have, which is a request that cannot be
            // answered rather than one answered with less.
            return AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
                redirect,
                Rejection.Of(
                    ReasonCode.ScopeNotAllowedForClient,
                    OAuthErrorCode.InvalidScope,
                    "This account may not be granted any of the requested scopes.",
                    $"subject={context.Subject.Value}; requested={context.Scope.ToWireString()}"),
                context.State,
                context.Issuer,
                context.CorrelationId));
        }

        context.Scope = entitled;

        // ───────── stage 10: consent ─────────

        var consentStore = services.GetRequiredService<IConsentStore>();

        // The guard is applied here rather than registered as a decorator, and that is what makes
        // it unremovable. A DI decoration depends on registration order — a customer registering
        // their own IConsentPolicy after ours silently replaces the composed one — whereas wrapping
        // at the single call site means the endpoint has no way to reach a bare policy.
        //
        // RFC 8252 §8.6: a public client cannot be authenticated, so consent is the only evidence
        // the user agreed, and anything that can reach this endpoint can claim to be that client.
        // Skipping the prompt on a repeat visit turns a guessed client_id into a silent
        // authorization.
        var configuredPolicy = services.GetRequiredService<IConsentPolicy>();
        var policy = new PublicClientReconsentGuard(configuredPolicy);

        var existing = await consentStore.FindAsync(context.Subject.Value, context.Client!.ClientId, cancellationToken);
        var resources = context.Resources.Select(r => r.Canonical).ToList();

        var decision = await policy.DecideAsync(
            new ConsentContext(context.Client, context.Subject.Value, context.Scope, resources, existing),
            cancellationToken);

        if (decision is ConsentDecision.Denied)
        {
            return AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
                redirect,
                Rejection.Of(
                    ReasonCode.ConsentPolicyDenied,
                    OAuthErrorCode.AccessDenied,
                    "The request was refused.",
                    // Named, because "the user clicked Deny" and "your IConsentPolicy said no" are
                    // the same response and completely different tickets.
                    $"policy={configuredPolicy.GetType().FullName}; client_id={context.Client!.ClientId.Value}"),
                context.State,
                context.Issuer,
                context.CorrelationId));
        }

        var mustAsk = decision is ConsentDecision.Required
            || context.Prompt.Contains("consent", StringComparer.Ordinal);

        if (mustAsk)
        {
            if (wantsNoInteraction)
            {
                return AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
                    redirect,
                    Rejection.Of(
                        ReasonCode.ConsentRequired,
                        OAuthErrorCode.ConsentRequired,
                        "This request needs consent that has not been given.",
                        $"client_id={context.Client!.ClientId.Value}; decision={decision}; prompt={string.Join(' ', context.Prompt)}; scope={context.Scope.ToWireString()}"),
                    context.State,
                    context.Issuer,
                    context.CorrelationId));
            }

            return AuthorizeResults.SeeOther(LocalReturn(http, AuthorizationServerPaths.Consent));
        }

        // ───────── stage 11: code issuance ─────────

        var issuer = services.GetRequiredService<AuthorizationCodeIssuer>();
        var issued = await issuer.IssueAsync(context, options.AuthorizationCodeLifetime, cancellationToken);

        // ───────── stage 12: response ─────────

        return AuthorizeResults.Redirect(
            AuthorizeSuccess.Create(redirect, issued.Code.Wire, context.State, context.Issuer));
    }

    /// <summary>
    /// Whether the session is too old for this request's <c>max_age</c>.
    /// </summary>
    /// <remarks>
    /// OIDC Core §3.1.2.1: "If the elapsed time is greater than this value, the OP MUST attempt to
    /// actively re-authenticate the End-User." Measured against when the user actually presented
    /// credentials, which is why <see cref="AuthenticatedUser.AuthenticatedAt"/> is stored rather
    /// than stamped per request — re-deriving it from the cookie's issuance makes every session
    /// permanently fresh and the parameter a no-op.
    /// </remarks>
    /// <remarks>
    /// Read together with the freshness floor at the call site: a session younger than
    /// <see cref="AuthorizationServerOptions.ReauthenticationFreshness"/> satisfies any
    /// <c>max_age</c>, including zero. Without that, <c>max_age=0</c> — which OIDC defines as
    /// "re-authenticate", meaning once — makes every session stale the instant it is created.
    /// </remarks>
    private static bool IsStale(AuthenticatedUser user, AuthorizeContext context) =>
        context.MaxAge is { } maxAge && context.Now - user.AuthenticatedAt > maxAge;

    /// <summary>
    /// Build a local URL that carries this authorization request forward.
    /// </summary>
    /// <remarks>
    /// The return URL is the request's own path and query, and it is built here rather than taken
    /// from a parameter. A general-purpose <c>?returnUrl=</c> on a login page is an open redirector
    /// <i>on the authorization server's origin</i> — the one origin the user has been taught to
    /// trust with a password — and the payoff is a pixel-perfect fake consent page served by the
    /// attacker, where none of this server's security headers apply. Constructing it from
    /// <see cref="HttpRequest.Path"/> means there is no caller-supplied value to validate.
    /// </remarks>
    private static string LocalReturn(HttpContext http, string page)
    {
        var self = http.Request.Path.Value + http.Request.QueryString.Value;

        var url = QueryHelpers.AddQueryString(page, "returnUrl", self);

        // Carry the language across the redirect, or it is lost here.
        //
        // `ui_locales` arrives on /authorize and the pages are /login and /consent, which are
        // separate requests. The whole of this request's query goes into `returnUrl` as one
        // percent-encoded value, so `Request.Query["ui_locales"]` on the page is empty and the
        // page renders in the default language — with `ui_locales_supported` advertised and the
        // startup check that every advertised locale is served passing. Measured: a deployment
        // serving `vi` answered `/authorize?...&ui_locales=vi` with an English login page.
        //
        // This was believed to be handled by the framework's cookie provider. Nothing writes that
        // cookie, here or anywhere, so the mechanism named in the comment on
        // `AddBoltwayInteractionLocalization` did not exist.
        //
        // What is forwarded is `CurrentUICulture`, which the localization middleware has already
        // matched against `SupportedUICultures` — a value this server chose, never the tag the
        // caller sent. The framework's own `QueryStringRequestCultureProvider` reads it back on the
        // page, so the matching stays the framework's on both hops. Each pass through /authorize
        // re-resolves from the `ui_locales` still inside `returnUrl`, which is what carries the
        // language on to /consent after sign-in.
        //
        // Only when the request actually asked. Appending a culture to every redirect would put a
        // parameter on hosts that have no localization configured, where it means nothing.
        if (!string.IsNullOrEmpty(http.Request.Query["ui_locales"].ToString()))
        {
            var resolved = CultureInfo.CurrentUICulture.Name;

            if (!string.IsNullOrEmpty(resolved))
            {
                url = QueryHelpers.AddQueryString(url, "ui-culture", resolved);
            }
        }

        return url;
    }
}

/// <summary>
/// Source-generated log messages for the authorization endpoint.
/// </summary>
/// <remarks>
/// Source-generated rather than interpolated, so the message template is compiled once and the
/// arguments are not boxed or formatted when the level is disabled. On an endpoint with a latency
/// budget the client treats as terminal, that is not a micro-optimisation — the error path is the
/// one under load when something is already wrong.
/// </remarks>
internal static partial class AuthorizeLog
{
    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "Authorization request {CorrelationId} was abandoned by the client.")]
    internal static partial void Abandoned(ILogger logger, string correlationId);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Error,
        Message = "Authorization request {CorrelationId} failed with an unhandled exception (X-10).")]
    internal static partial void Unhandled(ILogger logger, string correlationId, Exception exception);

}
