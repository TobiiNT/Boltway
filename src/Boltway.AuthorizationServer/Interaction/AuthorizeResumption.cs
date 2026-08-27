using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>The authorization request a <c>returnUrl</c> refers to, or why it could not be read.</summary>
/// <param name="Context">The re-validated request.</param>
/// <param name="Failure">What to return instead.</param>
public readonly record struct ResumedAuthorization(AuthorizeContext? Context, IResult? Failure);

/// <summary>
/// Re-enters an authorization request from a <c>returnUrl</c>, and finishes it.
/// </summary>
/// <remarks>
/// <para>
/// The consent page holds a URL, not a decision. Everything about the request is re-derived from it
/// on every hop - client resolution, exact redirect matching, PKCE, scope, <c>resource</c> - by
/// running the same <see cref="AuthorizePipeline"/> the authorization endpoint runs. So a user who
/// edits the scope in the form they are about to submit is editing a value that is then thrown away
/// and re-read from the URL, and a request whose client was disabled while the page was open is
/// refused rather than completed.
/// </para>
/// <para>
/// <see cref="CompleteAsync"/> is stages 11 and 12, shared by the authorization endpoint and the
/// consent POST. One code path, so a code issued after an explicit approval and one issued to a
/// client with standing consent are identical by construction - and so the architecture rule
/// limiting who may build a redirect response does not need a second entry.
/// </para>
/// </remarks>
public static class AuthorizeResumption
{
    /// <summary>Re-validate the authorization request a <c>returnUrl</c> names.</summary>
    public static async Task<ResumedAuthorization> ResolveAsync(
        HttpContext http, string returnUrl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);

        var services = http.RequestServices;
        var options = services.GetRequiredService<AuthorizationServerOptions>();
        var correlationId = http.TraceIdentifier;

        var queryStart = returnUrl.IndexOf('?', StringComparison.Ordinal);
        var query = queryStart < 0 ? string.Empty : returnUrl[queryStart..];

        var parsed = QueryHelpers.ParseQuery(query);
        var parameters = new OAuthParameters(
            parsed.ToDictionary(
                p => p.Key,
                p => (IReadOnlyList<string>)p.Value.Where(v => v is not null).Select(v => v!).ToArray(),
                StringComparer.Ordinal));

        var context = new AuthorizeContext
        {
            Parameters = parameters,
            CorrelationId = correlationId,
            Issuer = options.ValidatedIssuer,
            Now = services.GetRequiredService<TimeProvider>().GetUtcNow(),

            // Read again here rather than carried through the return URL. This is the request that
            // finishes the authorization - the browser is the same one, and a value round-tripped
            // through a query string is one a person could edit.
            UserAgent = ApprovingDevice.Read(http.Request),
        };

        var outcome = await services.GetRequiredService<AuthorizePipeline>()
            .ValidateAsync(context, cancellationToken);

        if (outcome is AuthorizeOutcome.Html html)
        {
            return new ResumedAuthorization(null, AuthorizeResults.Html(html.Error));
        }

        if (outcome is AuthorizeOutcome.Redirect redirect)
        {
            return new ResumedAuthorization(null, AuthorizeResults.Redirect(redirect.Error));
        }

        // ───────── stage 9: authentication ─────────
        //
        // The session is re-read here rather than trusted from the page that rendered, and it is
        // re-tested against this request's own demands. Those are two separate things, and for a
        // while only the first was done: the check was `user is null` and nothing else, under a
        // comment claiming `max_age` staleness was covered.
        //
        // What that cost, measured: a session authenticated an hour earlier, and
        // `/authorize?…&max_age=60` correctly redirecting to /login - while posting the same
        // returnUrl straight to /consent returned an authorization code stamped with the hour-old
        // auth_time. Same for `prompt=login`. Both reachable two ways: a crafted /consent link, and
        // the plain race the comment already described, where the session goes stale between the GET
        // that rendered the page and the POST that submits it.
        var user = await services.GetRequiredService<IUserSession>().GetAsync(cancellationToken);

        if (InteractionRequirements.MustReauthenticate(context, user, options.ReauthenticationFreshness))
        {
            // Back to the login page carrying this same request, rather than an error. The user is
            // mid-flow and has done nothing wrong; a session that expired while they read the
            // consent page is the ordinary case, not an attack. They sign in and land back here.
            //
            // No loop: whatever made this stale - `prompt=login`, `select_account`, an elapsed
            // `max_age` - is satisfied by the authentication that follows, and the freshness floor
            // inside MustReauthenticate is what guarantees that even for `max_age=0`.
            var login = AuthorizationServerPaths.Login
                + "?returnUrl=" + Uri.EscapeDataString(returnUrl);

            return new ResumedAuthorization(null, AuthorizeResults.SeeOther(login));
        }

        context.Subject = user!.Value.Subject;
        context.AuthTime = user.Value.AuthenticatedAt;

        // The same entitlement filter the endpoint applies, through the same helper. This path is
        // where the endpoint's checks have historically failed to be repeated - the comment below
        // records two of them - and an entitlement filter that ran only at /authorize would be a
        // third, reachable by posting the consent form for a scope the account may not hold.
        var entitled = await ScopeEntitlement.FilterAsync(
            services, context.Subject.Value, context.Scope, cancellationToken);

        if (entitled.Values.Count == 0)
        {
            return new ResumedAuthorization(null, AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
                context.Redirect!,
                Rejection.Of(
                    ReasonCode.ScopeNotAllowedForClient,
                    OAuthErrorCode.InvalidScope,
                    "This account may not be granted any of the requested scopes.",
                    $"subject={context.Subject.Value}; requested={context.Scope.ToWireString()}"),
                context.State,
                context.Issuer,
                correlationId)));
        }

        context.Scope = entitled;

        // ───────── stage 10: consent policy ─────────
        //
        // Only the refusal half. `ConsentDecision.Required` is the normal reason to be on this page
        // at all, and the user answering it is the whole point of the POST - re-deciding that here
        // would be a loop. `Denied` is different: it is the policy saying this authorization must
        // not happen, whatever the user clicks.
        //
        // This ran nowhere on the resumption path. Measured: with a policy answering `Denied`,
        // /authorize correctly redirected with `access_denied` - and GET /consent on the same
        // returnUrl rendered a full approve form, and POST approve issued a code. Any deployment
        // using this seam as an authorization control - a client blocklist, a per-tenant allowlist,
        // a risk engine - had a bypass reachable by any signed-in user typing one URL. The shipped
        // policy never returns `Denied` on its own, so the exposure was proportional to a customer
        // using the seam; the seam is documented for exactly this.
        var configuredPolicy = services.GetRequiredService<IConsentPolicy>();
        var policy = new PublicClientReconsentGuard(configuredPolicy);

        var existing = await services.GetRequiredService<IConsentStore>()
            .FindAsync(context.Subject.Value, context.Client!.ClientId, cancellationToken);

        var decision = await policy.DecideAsync(
            new ConsentContext(
                context.Client,
                context.Subject.Value,
                context.Scope,
                [.. context.Resources.Select(r => r.Canonical)],
                existing),
            cancellationToken);

        if (decision is ConsentDecision.Denied)
        {
            return new ResumedAuthorization(null, AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
                context.Redirect!,
                Rejection.Of(
                    ReasonCode.ConsentPolicyDenied,
                    OAuthErrorCode.AccessDenied,
                    "The request was refused.",
                    $"policy={configuredPolicy.GetType().FullName}; client_id={context.Client!.ClientId.Value}; resumed"),
                context.State,
                context.Issuer,
                correlationId)));
        }

        return new ResumedAuthorization(context, null);
    }

    /// <summary>
    /// The user refused. X-06.
    /// </summary>
    /// <remarks>
    /// By redirect, not HTML: the client asked a question and <c>access_denied</c> is the answer,
    /// carried with <c>state</c> verbatim and the RFC 9207 <c>iss</c> like every other authorization
    /// response. The residual is accepted deliberately - a user who clicks Deny is still sent to the
    /// client's registered address, and the only real mitigation for that is stage 3's exact match,
    /// not an interstitial that would break both vendors.
    /// </remarks>
    public static IResult Denied(AuthorizeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return AuthorizeResults.Redirect(AuthorizeRedirectError.Create(
            context.Redirect!,
            Rejection.Of(
                ReasonCode.ConsentUserDenied,
                OAuthErrorCode.AccessDenied,
                "The user refused the request.",
                $"client_id={context.Client!.ClientId.Value}; subject={context.Subject?.Value}"),
            context.State,
            context.Issuer,
            context.CorrelationId));
    }

    /// <summary>Stages 11 and 12: issue the code and redirect to the client.</summary>
    public static async Task<IResult> CompleteAsync(
        HttpContext http, AuthorizeContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(context);

        var services = http.RequestServices;
        var options = services.GetRequiredService<AuthorizationServerOptions>();

        var issued = await services.GetRequiredService<AuthorizationCodeIssuer>()
            .IssueAsync(context, options.AuthorizationCodeLifetime, cancellationToken);

        return AuthorizeResults.Redirect(
            AuthorizeSuccess.Create(context.Redirect!, issued.Code.Wire, context.State, context.Issuer));
    }
}
