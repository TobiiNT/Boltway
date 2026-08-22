using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// E-09 and E-19/E-20: the two pages a user actually sees, and the error page.
/// </summary>
/// <remarks>
/// <para>
/// <b>The consent POST completes the authorization itself.</b> It does not record consent and bounce
/// the browser back to <c>/authorize</c>, and that is forced rather than chosen:
/// <see cref="PublicClientReconsentGuard"/> turns <c>AlreadyGranted</c> into <c>Required</c>
/// unconditionally for a public client, and both vendors are public clients — so approving and
/// re-entering <c>/authorize</c> would find consent Required again and redirect to
/// <c>/consent</c> forever. Completing the flow inside the POST is what makes "the user approved
/// just now" a fact this request holds rather than one it has to re-derive.
/// </para>
/// <para>
/// It re-runs the whole authorization pipeline on the way. Nothing is inherited from the GET: the
/// client is re-resolved, the redirect URI is re-matched, PKCE, scope and <c>resource</c> are all
/// re-decided against <i>this</i> request. The <c>returnUrl</c> is therefore untrusted input that is
/// re-validated rather than a decision carried forward.
/// </para>
/// </remarks>
public static class InteractionEndpoints
{
    /// <summary>Map <c>/login</c>, <c>/consent</c>, <c>/error</c> and, when enabled, <c>/logout</c>.</summary>
    /// <remarks>
    /// <c>/logout</c> is mapped if and only if <c>EndSessionEnabled</c> is set, which is the same
    /// flag that puts <c>end_session_endpoint</c> in both discovery documents. Routed or absent,
    /// never advertised-and-404 — <c>N-06</c>. It was the second of those for the whole of this
    /// project's history: the path constant, the option and the metadata field all existed and
    /// nothing was ever mapped, so a deployment that turned the flag on published a URL that
    /// answered 404.
    /// </remarks>
    public static IEndpointRouteBuilder MapInteraction(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Every route below answers somebody looking at a page, so a store that cannot be reached
        // renders rather than returning a bare status. X-43.
        var pages = endpoints.ShedsOnStoreFailure(OAuthSurface.Interaction, rendered: true);


        pages.MapGet(AuthorizationServerPaths.Login, GetLoginAsync)
            .AllowAnonymous().WithName("boltway-login");

        pages.MapPost(AuthorizationServerPaths.Login, PostLoginAsync)
            .AllowAnonymous().WithName("boltway-login-post");

        pages.MapGet(AuthorizationServerPaths.Consent, GetConsentAsync)
            .AllowAnonymous().WithName("boltway-consent");

        pages.MapPost(AuthorizationServerPaths.Consent, PostConsentAsync)
            .AllowAnonymous().WithName("boltway-consent-post");

        pages.MapGet(AuthorizationServerPaths.Error, GetError)
            .AllowAnonymous().WithName("boltway-error");

        // Beside the consent page rather than behind a flag, because it is that page's own image
        // tag and a routed-or-absent pair is what N-06 asks for. It answers 404 for every client
        // that has no logo, which is most of them, so mapping it costs a route and nothing else.
        endpoints.ShedsOnStoreFailure(OAuthSurface.Interaction, rendered: false).MapClientLogo();

        // The issuer's own hostname, which is the other URL a person types.
        //
        // `TryUseReturnUrl`'s remarks record the measurement that produced this: after signing out,
        // `/` was a 404 and `/login` was a refusal, "so the two URLs a person would type to sign back
        // in were both dead ends". Only `/login` was fixed then. This is the other one, and the
        // reasoning is the same one word for word — somebody who has just been told their password
        // was reset types the hostname, not `/login`.
        //
        // Conditional for exactly the reason the bare-`/login` default is: with the self-service
        // pages off there is nowhere for a human to be sent, so `/` stays a 404 rather than
        // redirecting to a page that would refuse. An authorization server with no self-service
        // surface genuinely has no page for a person, and saying so with a 404 is honest.
        //
        // A redirect rather than rendering the sign-in page here, so there is one URL that draws it
        // and the address bar says which page you are on.
        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().SelfServicePagesEnabled)
        {
            pages.MapGet("/", () => Results.Redirect(AuthorizationServerPaths.Login))
                .AllowAnonymous().WithName("boltway-root");
        }

        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().EndSessionEnabled)
        {
            pages.MapGet(AuthorizationServerPaths.EndSession, GetLogoutAsync)
                .AllowAnonymous().WithName("boltway-logout");

            // Cast, because `Task<IResult>` over a lone HttpContext also fits RequestDelegate, and
            // that overload discards the result — a 200 with an empty body instead of the page.
            // ASP0016 catches it; the cast is what picks the route-handler overload.
            pages.MapPost(AuthorizationServerPaths.EndSession, (Delegate)PostLogoutAsync)
                .AllowAnonymous().WithName("boltway-logout-post");
        }

        return endpoints;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /login
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetLoginAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!TryReadReturnUrl(http, out var returnUrl))
        {
            return BadReturnUrl(http);
        }

        await AllowFormActionToClientAsync(http, returnUrl, cancellationToken);

        var renderer = http.RequestServices.GetRequiredService<IInteractionRenderer>();

        return Html(renderer.RenderLogin(
            await LoginModel(http, returnUrl, rejected: false, cancellationToken)));
    }

    /// <summary>
    /// Widen this page's <c>form-action</c> to the client, when the <c>returnUrl</c> names one that
    /// validates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The sign-in form posts here and answers 303 to a <b>local</b> <c>/authorize</c> — so nothing
    /// leaves this origin on the hop the form makes. It leaves on the next one, when
    /// <c>/authorize</c> finds standing consent and redirects to the client, and a browser applies
    /// <c>form-action</c> to that hop too. Measured in Chromium: a two-hop chain through a
    /// same-origin stop is blocked exactly like a one-hop one. So the page a returning user signs in
    /// on is the page that needs this, and the failure is silent — the code is issued and dropped.
    /// </para>
    /// <para>
    /// <b>The redirect URI is matched against the client's registrations here, and used only if it
    /// matches.</b> <see cref="AuthorizeResumption.ResolveAsync"/> cannot do it: its stage 9 finds no
    /// authenticated session — which is why we are on this page at all — and returns a result with no
    /// context. So the two trusted primitives are used directly instead of the query string being
    /// believed, because this is the page that carries the password and a crafted <c>returnUrl</c>
    /// must not be able to name where a form on it may post.
    /// </para>
    /// <para>
    /// Every failure here is silent on purpose. A <c>returnUrl</c> that names no client, an
    /// unparseable redirect URI, one that matches no registration: all leave the policy at
    /// <c>'self'</c>, and the page still renders. This decides one CSP source, not whether the
    /// request is legitimate — <c>/authorize</c> has already refused the ones that are not, and
    /// <c>PostLoginAsync</c> re-checks the <c>returnUrl</c> before acting on it.
    /// </para>
    /// </remarks>
    private static async Task AllowFormActionToClientAsync(
        HttpContext http, string returnUrl, CancellationToken cancellationToken)
    {
        var queryStart = returnUrl.IndexOf('?', StringComparison.Ordinal);

        if (queryStart < 0)
        {
            return;
        }

        // TryGetValue, not the indexer. `ParseQuery` returns a dictionary that throws on a missing
        // key rather than yielding an empty StringValues, so `?returnUrl=/authorize?client_id=x`
        // — a query string with no `redirect_uri` at all — left this method with an unhandled
        // KeyNotFoundException while every other failure around it returned quietly.
        //
        // It reached a browser as an empty 500: no body, no reason, no reference, on an anonymous
        // endpoint anyone can type a query string at. That is the shape A-09 exists to prevent, and
        // it is the one failure mode the paragraph above forgot to list — "a returnUrl that names no
        // client" was handled, "one that names no redirect URI at all" was not.
        var query = QueryHelpers.ParseQuery(returnUrl[queryStart..]);

        if (!query.TryGetValue("redirect_uri", out var values))
        {
            return;
        }

        if (!RequestedRedirectUri.TryParse(values.ToString(), out var parsed, out _))
        {
            return;
        }

        var client = await ExternalLoginEndpoints
            .ResolveClientAsync(http.RequestServices, returnUrl, cancellationToken);

        if (client is null
            || !ValidatedRedirect.From(
                RedirectUriMatcher.Match(parsed.Value, client.RedirectUris), out var validated))
        {
            return;
        }

        SecurityHeaders.AllowFormActionTo(http, validated.Value);
    }

    /// <summary>
    /// Build the sign-in page's model: what this deployment offers, and why anything is missing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every field is decided here rather than in the renderer, which is the N-14 property applied to
    /// this page. A template can fail to draw a button; it cannot enable a disabled one, invent a
    /// provider, or point a form somewhere else.
    /// </para>
    /// <para>
    /// <b>Every configured provider appears, including the unavailable ones</b> — A-11. The list is
    /// not filtered by anything before it reaches the model, and the only input to whether a control
    /// is enabled is the provider's own answer, which must carry a reason when it is no.
    /// </para>
    /// </remarks>
    private static async Task<LoginViewModel> LoginModel(
        HttpContext http, string returnUrl, bool rejected, CancellationToken cancellationToken)
    {
        var services = http.RequestServices;
        var tokens = Antiforgery(http);

        var providers = services.GetServices<Abstractions.Federation.IExternalIdentityProvider>().ToList();
        List<LoginProviderOption> options = [];

        if (providers.Count > 0)
        {
            // Resolved once for the whole list rather than per provider: it can cost an outbound
            // fetch, and every provider is being asked about the same request.
            var client = await ExternalLoginEndpoints.ResolveClientAsync(services, returnUrl, cancellationToken);
            var context = new Abstractions.Federation.ExternalProviderContext(client);

            foreach (var provider in providers)
            {
                var availability = await provider.GetAvailabilityAsync(context, cancellationToken);

                options.Add(new LoginProviderOption(
                    provider.Scheme,
                    provider.DisplayName,
                    AuthorizationServerPaths.External(provider.Scheme, "start"),
                    availability.Enabled,
                    availability.DisabledReason));

                // Without this the button is a form whose 303 the browser refuses to follow, and it
                // refuses silently — see IExternalIdentityProvider.GetChallengeOriginAsync. Widened
                // for a disabled provider too: the control is disabled in the markup, so nothing can
                // submit it, and a policy that changed with availability would be one more thing
                // differing between two renders of the same page.
                SecurityHeaders.AllowFormActionTo(
                    http, await provider.GetChallengeOriginAsync(cancellationToken));
            }
        }

        return new LoginViewModel
        {
            ReturnUrl = returnUrl,
            Rejected = rejected,
            AntiforgeryFieldName = tokens.FormFieldName,
            AntiforgeryToken = tokens.RequestToken!,

            // Local passwords exist iff something can verify one. A federation-only deployment
            // registers no hasher, and startup validation is what guarantees it has a provider
            // instead rather than nothing at all.
            LocalPasswordsEnabled = services.GetService<IPasswordHasher>() is not null,
            ExternalProviders = options,

            // Read from the same flag that decides whether /forgot is routed, so the link and the
            // page it points at cannot disagree — N-06's rule about the metadata document, applied
            // to a page. The alternative is a link that 404s for the one person least able to
            // recover from it.
            PasswordRecoveryEnabled = services
                .GetRequiredService<AuthorizationServerOptions>()
                .PasswordRecoveryEnabled,

            // Read rather than generated: SecurityHeaders minted it when Apply ran at the top of
            // this handler, and the same value goes into the header when the response commits.
            Nonce = SecurityHeaders.NonceFor(http),
        };
    }

    private static async Task<IResult> PostLoginAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await IsAntiforgeryValidAsync(http))
        {
            return AntiforgeryFailure(http);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);

        // The same reader the GET uses, so the two halves of one page agree about what an absent
        // value means. They did not: with the default below on the GET alone, a bare /login would
        // have rendered a form whose own POST answered 400 — which is the original dead end moved
        // one click later, where it costs somebody their password attempt as well.
        if (!TryUseReturnUrl(http, form["returnUrl"].ToString(), out var returnUrl))
        {
            return BadReturnUrl(http);
        }

        // Every response below that re-renders the sign-in page carries the form again, so the
        // second attempt needs the same policy the first one had. A wrong password followed by the
        // right one is the ordinary case, not an edge.
        await AllowFormActionToClientAsync(http, returnUrl, cancellationToken);

        var services = http.RequestServices;
        var users = services.GetRequiredService<IUserStore>();
        var throttle = services.GetRequiredService<LoginThrottle>();

        // GetService, not GetRequiredService, and the difference is a whole deployment shape. A
        // federation-only deployment registers no hasher; startup validation permits that as long as
        // it has an upstream provider. GetRequiredService would make this endpoint throw for such a
        // deployment, and the exception boundary would render it as `server_error` — a 500 for a
        // request that is simply not something this server does.
        if (services.GetService<IPasswordHasher>() is not { } hasher)
        {
            return AuthorizeResults.Html(new Authorize.AuthorizeHtmlError(
                Rejection.Of(
                    ReasonCode.LocalPasswordSignInUnavailable,
                    OAuthErrorCode.InvalidRequest,
                    "This server does not sign in with a password.",
                    $"path={http.Request.Path}; no IPasswordHasher is registered"),
                http.TraceIdentifier));
        }

        var username = form["username"].ToString();
        var password = form["password"].ToString();

        // X-31, and before the store is touched. Both counters are charged here rather than on the
        // way out, which is what makes them work against a burst: a limiter that counted completed
        // failures would admit all of a hundred simultaneous requests, because none of them has
        // failed yet when the last one is let in.
        //
        // It is also before FindByUsernameAsync, so the decision cannot depend on whether the
        // account exists — the counter is keyed on the submitted string. See LoginThrottle.
        var admission = throttle.Admit(username, http);

        if (!admission.Allowed)
        {
            return TooManyRequests(http, admission.Description, admission.RetryAfter);
        }

        // The 19 MiB, 95 ms hash below is the expensive thing on this endpoint, and this is the only
        // gate on how many of them run at once. Unbounded, a hundred simultaneous posts were
        // measured taking a hundred threads and 1.9 GiB of Argon2 buffers, and stalling an unrelated
        // discovery request for 4.4 s.
        using var slot = await throttle.TryEnterVerificationAsync(cancellationToken);

        if (slot is null)
        {
            return TooManyRequests(
                http,
                "The sign-in service is at capacity. Try again shortly.",
                throttle.OverloadRetryAfter);
        }

        // The configured realm, on every lookup, with one realm configured. A realm that is stored
        // and not filtered on reads as tenancy and is not — the point of filtering from day one is
        // that a second realm later is a configuration change rather than an audit of every query.
        var realm = services.GetRequiredService<AuthorizationServerOptions>().Realm;

        var account = await ResolveAccountAsync(users, realm, username, cancellationToken);

        // The hash is verified even when there is no account, against a stored dummy. Skipping it
        // returns faster for an unknown username than for a known one, and that difference is a
        // username oracle — the same one a distinct error message would be, measured in
        // milliseconds instead of words.
        var verified = account?.PasswordHash is { } stored
            ? hasher.Verify(password, stored)
            : hasher.Verify(password, DummyHash(hasher));

        if (account is null || !account.IsActive || !verified)
        {
            var renderer = services.GetRequiredService<IInteractionRenderer>();

            // 200 with the form re-rendered, not a redirect. A redirect would need the failure in a
            // query parameter, which is a reflected value on the one page where reflection matters.
            //
            // Rejected, and therefore recorded — A-09 says every path, and a failed sign-in is the
            // one an operator is most likely to be asked about. The three causes the page collapses
            // into one message are collapsed in the log too: separating them here would recreate,
            // in a file the operator can read, the username oracle the equalised hash timing above
            // exists to remove. What the log adds is the username itself, which is the field a
            // credential-stuffing run is identified by and which the page must never echo back.
            return RejectedHtml(
                renderer.RenderLogin(await LoginModel(
                    http,
                    returnUrl,
                    rejected: true,
                    cancellationToken)),
                Rejection.Of(
                    ReasonCode.PasswordRejected,
                    OAuthErrorCode.None,
                    "That username and password did not match.",
                    $"username={username}"),
                http);
        }

        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();

        // The password was correct, so the attempts that led here were this user's own. Only the
        // account counter is cleared — see LoginThrottle.RecordSuccess for why the source counter
        // is not.
        throttle.RecordSuccess(username);

        await services.GetRequiredService<IUserSignIn>()
            .SignInAsync(http, new AuthenticatedUser(account.Subject, now));

        // 303, never 302 or 307. RFC 9700 §4.12: a 307 preserves the method and the body, so the
        // browser would re-POST this form — username and password included — to wherever Location
        // points. "In HTTP, only the status code 303 unambiguously enforces rewriting the HTTP POST
        // request to an HTTP GET request."
        return AuthorizeResults.SeeOther(returnUrl);
    }

    /// <summary>
    /// A hash to verify against when no account exists.
    /// </summary>
    /// <remarks>
    /// Computed once per process from a fixed value. Its content is irrelevant — what matters is
    /// that the work happens, so the response time for an unknown username matches a known one.
    /// </remarks>
    private static string DummyHash(IPasswordHasher hasher) =>
        _dummyHash ??= hasher.Hash("boltway-timing-equaliser");

    private static string? _dummyHash;

    // ─────────────────────────────────────────────────────────────────────────
    // /consent
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetConsentAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!TryReadReturnUrl(http, out var returnUrl))
        {
            return BadReturnUrl(http);
        }

        var resolved = await AuthorizeResumption.ResolveAsync(http, returnUrl, cancellationToken);

        if (resolved.Failure is { } failure)
        {
            return failure;
        }

        var context = resolved.Context!;
        var client = context.Client!;

        // The form on this page posts back to us and we answer 303 to the client. Both browsers that
        // matter check `form-action` against that redirect, so without this the code is issued and
        // then never delivered — see SecurityHeaders.AllowFormActionTo.
        SecurityHeaders.AllowFormActionTo(http, context.Redirect!.Value);

        var options = http.RequestServices.GetRequiredService<AuthorizationServerOptions>();
        var tokens = Antiforgery(http);

        var model = new ConsentViewModel
        {
            ClientHost = ConsentModelBuilder.HostOf(client.ClientId.Value),
            RedirectHost = ConsentModelBuilder.HostOf(context.Redirect!.Value),
            RedirectsToThisDevice = client.RedirectUris.Count > 0
                && client.RedirectUris.All(u => u.Kind
                    is OAuth.Primitives.Redirects.RedirectKind.Loopback
                    or OAuth.Primitives.Redirects.RedirectKind.PrivateUseScheme),
            ClientName = ConsentModelBuilder.SafeName(client),
            ClientLogoUrl = ConsentModelBuilder.LogoUrl(client),
            Scopes = ConsentModelBuilder.Describe(context.Scope.Values, options),
            Resources = [.. context.Resources.Select(r => r.Canonical)],
            ReturnUrl = returnUrl,
            AntiforgeryFieldName = tokens.FormFieldName,
            AntiforgeryToken = tokens.RequestToken!,

            // Read rather than generated: SecurityHeaders minted it when Apply ran at the top of
            // this handler, and the same value goes into the header when the response commits.
            Nonce = SecurityHeaders.NonceFor(http),
        };

        return Html(http.RequestServices.GetRequiredService<IInteractionRenderer>().RenderConsent(model));
    }

    private static async Task<IResult> PostConsentAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await IsAntiforgeryValidAsync(http))
        {
            return AntiforgeryFailure(http);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);
        var returnUrl = form["returnUrl"].ToString();

        if (!LocalUrl.IsLocalPathTo(returnUrl, AuthorizationServerPaths.Authorize))
        {
            return BadReturnUrl(http);
        }

        var resolved = await AuthorizeResumption.ResolveAsync(http, returnUrl, cancellationToken);

        if (resolved.Failure is { } failure)
        {
            return failure;
        }

        var context = resolved.Context!;
        var approved = string.Equals(form["decision"], "approve", StringComparison.Ordinal);

        if (!approved)
        {
            return AuthorizeResumption.Denied(context);
        }

        var services = http.RequestServices;
        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();

        // Recorded before the code is issued, and widening rather than replacing — C-24. A client
        // returning for one more scope must end up with the union; replacing would silently revoke
        // authority the user granted earlier and never withdrew, and the symptom is a tool that
        // worked yesterday returning 403 today.
        await services.GetRequiredService<IConsentStore>().GrantAsync(
            context.Subject!.Value,
            context.Client!.ClientId,
            context.Scope,
            [.. context.Resources.Select(r => r.Canonical)],
            now,
            cancellationToken);

        return await AuthorizeResumption.CompleteAsync(http, context, cancellationToken);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /logout
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The confirmation, or the answer when there is nothing to confirm.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Anonymous, and it answers the same way whether or not anyone is signed in.</b> Requiring
    /// authentication would redirect a signed-out visitor to the sign-in page — asking somebody to
    /// prove who they are so they can stop being it — and it would make this endpoint a probe for
    /// whether a given browser holds a session here.
    /// </para>
    /// <para>
    /// <b>A GET never ends anything.</b> A session-ending URL is one anybody can put in an
    /// <c>&lt;img src&gt;</c>, and the result is a person signed out by a page they merely visited.
    /// OIDC RP-Initiated Logout §2 says the provider SHOULD ask; this is what asking looks like.
    /// </para>
    /// </remarks>
    private static async Task<IResult> GetLogoutAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        // IUserSession, not HttpContext.User, because that is what "signed in" means everywhere else
        // in this server. Reading the principal directly would answer differently from /authorize the
        // moment a deployment supplies its own session seam — and this page would then offer to end a
        // session the rest of the server does not believe in.
        var session = await http.RequestServices.GetRequiredService<IUserSession>().GetAsync(cancellationToken);

        return LogoutPage(http, session is null ? LogoutState.SignedOut : LogoutState.ConfirmationNeeded);
    }

    private static async Task<IResult> PostLogoutAsync(HttpContext http)
    {
        SecurityHeaders.Apply(http);

        if (!await IsAntiforgeryValidAsync(http))
        {
            return AntiforgeryFailure(http);
        }

        // Unconditional, and not guarded by "is anyone signed in". A cookie the server no longer
        // considers valid — expired ticket, rotated data-protection key — still sits in the browser
        // and still gets sent; signing out only when the principal parsed would leave exactly that
        // cookie in place, which is the case a person is most likely to be trying to fix.
        await http.RequestServices.GetRequiredService<IUserSignIn>().SignOutAsync(http);

        return LogoutPage(http, LogoutState.SignedOut);
    }

    private static IResult LogoutPage(HttpContext http, LogoutState state)
    {
        var tokens = Antiforgery(http);
        var renderer = http.RequestServices.GetRequiredService<IInteractionRenderer>();

        var html = renderer.RenderLogout(new LogoutViewModel
        {
            State = state,
            AntiforgeryFieldName = tokens.FormFieldName,
            AntiforgeryToken = tokens.RequestToken!,
            Nonce = SecurityHeaders.NonceFor(http),
            SignInUrl = SignInUrlFor(http),
        });

        return Results.Content(html, "text/html; charset=utf-8");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /error
    // ─────────────────────────────────────────────────────────────────────────

    private static IResult GetError(HttpContext http)
    {
        SecurityHeaders.Apply(http);

        return AuthorizeResults.Html(
            new Authorize.AuthorizeHtmlError(
                Rejection.Of(
                    ReasonCode.InteractionErrorPage,
                    OAuthErrorCode.ServerError,
                    "The authorization request could not be completed.",
                    // Nothing about the request, because there is nothing: this page is what a user
                    // lands on when something upstream sent them here without a request to speak for.
                    // The referrer would be the useful field and Referrer-Policy: no-referrer means
                    // there is not one, which is the right trade and worth stating rather than
                    // leaving as an empty detail somebody later "fixes".
                    $"path={http.Request.Path}"),
                http.TraceIdentifier),
            OAuthSurface.AuthorizePreRedirect);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The account the sign-in form's first field names: a username, or a verified address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two are asked in that order and the order is the rule: a username is a name this server
    /// issued and an address is a name a mail system did, so an account whose <i>username</i> is
    /// <c>a@b.example</c> wins over one whose <i>address</i> is. Anything else would let creating an
    /// account with an address-shaped username shadow somebody else's sign-in.
    /// </para>
    /// <para>
    /// <b>The address must be verified</b>, which <see cref="IUserStore.FindByVerifiedEmailAsync"/>
    /// is responsible for, and two accounts holding one verified address resolve to neither. The
    /// contrast worth keeping in mind is <c>/forgot</c>, which matches unverified addresses too:
    /// that flow <i>sends to</i> the address and so proves control, where this one would be
    /// assuming it.
    /// </para>
    /// <para>
    /// <b>S-48 is unaffected.</b> The second lookup runs only for a submission containing
    /// <c>@</c> — a property of what the caller typed, not of what exists — so the work done still
    /// does not vary with whether an account was found, and the caller learns nothing from their own
    /// input. The equalised hash below is untouched: it runs against the dummy either way.
    /// </para>
    /// <para>
    /// <b>What this does cost, stated plainly:</b> an account with an address now has two strings
    /// that reach it, and <c>LoginThrottle</c> counts per submitted string — so an attacker willing
    /// to alternate gets two budgets against one account rather than one. Keying the counter on the
    /// resolved account instead would fix that and reintroduce what the counter is deliberately
    /// blind to, since a counter that knows which account you meant can be asked whether that
    /// account exists. The per-source half of <c>X-31</c> is what bounds the run either way.
    /// </para>
    /// </remarks>
    private static async Task<UserAccount?> ResolveAccountAsync(
        IUserStore users, RealmId realm, string submitted, CancellationToken cancellationToken)
    {
        if (await users.FindByUsernameAsync(realm, submitted, cancellationToken) is { } byUsername)
        {
            return byUsername;
        }

        return submitted.Contains('@', StringComparison.Ordinal)
            ? await users.FindByVerifiedEmailAsync(realm, submitted, cancellationToken)
            : null;
    }

    private static bool TryReadReturnUrl(HttpContext http, out string returnUrl) =>
        // Read decoded, as the query collection hands it over. Checking the raw value would let
        // %2F%2Fevil.example through — the check sees one percent sign where the browser will later
        // see two slashes.
        TryUseReturnUrl(http, http.Request.Query["returnUrl"].ToString(), out returnUrl);

    /// <summary>
    /// The <c>returnUrl</c> this request should act on, or <see langword="false"/> to refuse.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Absent and invalid are different, and treating them alike was a dead end.</b> A submitted
    /// value that is not on the list is refused, unchanged: that check is what stops <c>/login</c>
    /// being an open redirector on the one origin a person has been taught to trust with a
    /// password, and an attacker chooses that value. Nobody chooses an absent one.
    /// </para>
    /// <para>
    /// So a bare <c>GET /login</c> now renders the sign-in page and lands on <c>/me</c>, where it
    /// used to answer <c>400</c> — <i>"This page was opened without a valid authorization
    /// request."</i> Measured on a running deployment: after signing out, <c>/logout</c> offered no
    /// link, <c>/</c> was <c>404</c> and <c>/login</c> was that refusal, so the two URLs a person
    /// would type to sign back in were both dead ends. Recovering an account and then being unable
    /// to reach a sign-in form is the same defect as the recovery pages' bare <c>/login</c> link,
    /// one page further on.
    /// </para>
    /// <para>
    /// <b>The default is routed-or-absent, and the validation is not.</b> Defaulting to <c>/me</c>
    /// where it is not routed would send somebody to a <c>404</c>, so the default asks; with the
    /// self-service pages off there is no standalone destination and the refusal stands. The
    /// accepted <i>list</i> stays fixed for the reason
    /// <see cref="AuthorizationServerPaths.LoginReturnTargets"/> gives — validation that differs
    /// between deployments is validation nobody can reason about.
    /// </para>
    /// </remarks>
    private static bool TryUseReturnUrl(HttpContext http, string submitted, out string returnUrl)
    {
        returnUrl = submitted;

        if (returnUrl.Length == 0)
        {
            returnUrl = http.RequestServices.GetRequiredService<AuthorizationServerOptions>()
                .SelfServicePagesEnabled
                ? AuthorizationServerPaths.Me
                : string.Empty;

            return returnUrl.Length > 0;
        }

        // A closed list rather than one path, since /login now also resumes the self-service pages.
        // Nothing else changes: a /me target carries no query string, so AllowFormActionToClientAsync
        // returns before it can widen anything, and the form's action stays 'self'.
        return LocalUrl.IsLocalPathToAny(returnUrl, AuthorizationServerPaths.LoginReturnTargets);
    }

    /// <summary>
    /// Where "go to sign in" should point, or <see langword="null"/> when nowhere does.
    /// </summary>
    /// <remarks>
    /// Shared with <c>RecoveryEndpoints</c> so the recovery pages and the sign-out page cannot come
    /// to disagree about where a person goes when they are finished — they were written a day apart
    /// and had already disagreed once, which is how <c>/logout</c> ended up offering nothing at all.
    /// </remarks>
    internal static string? SignInUrlFor(HttpContext http) =>
        http.RequestServices.GetRequiredService<AuthorizationServerOptions>().SelfServicePagesEnabled
            ? QueryHelpers.AddQueryString(
                AuthorizationServerPaths.Login, "returnUrl", AuthorizationServerPaths.Me)
            : null;

    /// <summary>The antiforgery pair for a form on one of these pages.</summary>
    /// <remarks>
    /// Internal so <see cref="MeEndpoints"/> gets the tokens the same way rather than resolving
    /// <c>IAntiforgery</c> itself. Two call sites reaching for the same service is how one of them
    /// eventually forgets to store the cookie half.
    /// </remarks>
    internal static AntiforgeryTokenSet AntiforgeryTokensFor(HttpContext http) => Antiforgery(http);

    private static AntiforgeryTokenSet Antiforgery(HttpContext http) =>
        http.RequestServices.GetRequiredService<IAntiforgery>().GetAndStoreTokens(http);

    /// <summary>
    /// Validate the antiforgery token, explicitly.
    /// </summary>
    /// <remarks>
    /// <c>app.UseAntiforgery()</c> auto-validates only endpoints whose <b>handler binds form
    /// data</b> — <c>[FromForm]</c>, <c>IFormCollection</c>, <c>IFormFile</c>. These handlers read
    /// <c>Request.Form</c> by hand, so the middleware would skip them silently and without an error.
    /// A consent POST with no antiforgery check is a state-changing form on our own origin that any
    /// page can submit: the attacker crafts an authorization request for their own client, lures the
    /// user to a page that auto-submits <c>decision=approve</c>, and the browser supplies the session
    /// cookie. <c>state</c> protects the client and does nothing here.
    /// </remarks>
    internal static async Task<bool> IsAntiforgeryValidAsync(HttpContext http)
    {
        try
        {
            await http.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(http);
            return true;
        }
        catch (AntiforgeryValidationException)
        {
            return false;
        }
    }

    /// <summary>
    /// X-31: 429 with a <c>Retry-After</c>, rendered on our own origin.
    /// </summary>
    /// <remarks>
    /// HTML rather than JSON, because the caller here is a browser that just submitted a form and
    /// every other refusal on this page answers the same way. X-31's row in the requirements gives
    /// <c>json</c> for its delivery, and that row is written for the registration endpoints
    /// (E-11..E-14) — machine surfaces, which this deployment does not route at all. Answering a
    /// form post with a JSON body would put raw JSON on the user's screen.
    /// </remarks>
    private static IResult TooManyRequests(HttpContext http, string description, TimeSpan retryAfter)
    {
        // Logged by the rejection writer, once, like every other refusal — a limiter on a sign-in
        // page that nobody can observe is one that locks a real user out silently. This used to emit
        // its own line here, which was right when nothing else logged this path and became a
        // duplicate when the writer started to; A-09 asks for exactly one line per rejection, and an
        // operator counting 429s to size a limit would otherwise double every figure.
        //
        // The username stays out of it. Putting attempted account names in the log builds the same
        // directory the login form's generic error exists to refuse.
        return AuthorizeResults.Html(
            Authorize.AuthorizeHtmlError.Throttled(description, http.TraceIdentifier, retryAfter));
    }

    internal static IResult AntiforgeryFailure(HttpContext http) =>
        AuthorizeResults.Html(new Authorize.AuthorizeHtmlError(
            Rejection.Of(
                ReasonCode.AntiforgeryTokenInvalid,
                OAuthErrorCode.InvalidRequest,
                "This form has expired. Start the authorization again.",
                // Which of the two it is decides who gets the ticket: a burst of these on one path
                // is a load balancer that lost the data-protection key ring, and a trickle spread
                // across paths is users leaving tabs open.
                $"path={http.Request.Path}; method={http.Request.Method}"),
            http.TraceIdentifier));

    /// <remarks>
    /// HTML on our own origin, never a redirect. A bad <c>returnUrl</c> means there is no
    /// authorization request to speak for, so there is no client to answer and no address it is safe
    /// to send the user to — which is the same reasoning that governs stage 3.
    /// </remarks>
    internal static IResult BadReturnUrl(HttpContext http) =>
        AuthorizeResults.Html(new Authorize.AuthorizeHtmlError(
            Rejection.Of(
                ReasonCode.ReturnUrlInvalid,
                OAuthErrorCode.InvalidRequest,
                "This page was opened without a valid authorization request.",
                // The rejected value goes to the log and nowhere near the page. This is the guard
                // that stops /login and /consent being open redirectors on the one origin the user
                // has been taught to trust with a password, so "what did they send" is the entire
                // content of an abuse report — and reflecting it would be the vulnerability.
                $"path={http.Request.Path}; returnUrl={Submitted(http)}"),
            http.TraceIdentifier));

    /// <summary>The <c>returnUrl</c> as submitted, from wherever this request carried it.</summary>
    /// <remarks>
    /// Read for the log only, and never re-rendered. The form body is only read when the request
    /// already has one buffered — <c>ReadFormAsync</c> has run by the time a POST reaches
    /// <c>BadReturnUrl</c> — so this cannot itself throw on a body that does not parse.
    /// </remarks>
    private static string Submitted(HttpContext http) =>
        http.Request.HasFormContentType && http.Request.Form.ContainsKey("returnUrl")
            ? http.Request.Form["returnUrl"].ToString()
            : http.Request.Query["returnUrl"].ToString();

    private static InteractionHtmlResult Html(string markup) => new(markup, null, null);

    /// <summary>An interactive page that is also a refusal.</summary>
    private static InteractionHtmlResult RejectedHtml(string markup, Rejection rejection, HttpContext http) =>
        new(markup, rejection, http.TraceIdentifier);
}

/// <summary>
/// An interactive page.
/// </summary>
/// <remarks>
/// Carries an optional <see cref="Rejection"/> because one of these pages is a refusal at
/// <c>200</c>: the sign-in form re-rendered after a bad password. When it is present it is recorded
/// on the way out, by the same method every OAuth error response goes through, so the failed
/// sign-in appears in the same query as everything else and carries the same <c>X-Request-Id</c>.
/// </remarks>
internal sealed class InteractionHtmlResult(string markup, Rejection? rejection, string? correlationId) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        if (rejection is not null)
        {
            RejectionResult.Record(
                httpContext,
                OAuthSurface.AuthorizePreRedirect,
                rejection,
                correlationId!,
                requirementId: "E-20",
                status: StatusCodes.Status200OK,

                // No `error` member reaches the wire here, and the log says so rather than naming a
                // code the response does not carry. OAuthErrorCode.None exists for exactly this
                // distinction — "no error code in the response", not "we forgot one".
                error: "none");
        }

        httpContext.Response.StatusCode = StatusCodes.Status200OK;
        httpContext.Response.ContentType = "text/html; charset=utf-8";

        await httpContext.Response.WriteAsync(markup, httpContext.RequestAborted);
    }
}
