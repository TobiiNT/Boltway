using System.Globalization;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>The self-service pages. E-46.</summary>
/// <remarks>
/// <para>
/// <b>Cookie-authenticated, with antiforgery, and they refuse a bearer token — the mirror image of
/// <see cref="AccountEndpoints"/>.</b> Read literally, <c>N-17</c> would cover <c>/account/*</c> as
/// well and mean a user changing their own password has to run an OAuth client. That is absurd,
/// and the way out is a third prefix rather than a softened rule: <c>/admin/</c> and
/// <c>/account/</c> refuse cookies, <c>/me/</c> refuses bearers, and the prefixes are disjoint so an
/// architecture test decides both without judgement.
/// </para>
/// <para>
/// <b>Why the different rule is sound.</b> <c>N-17</c> exists because an XSS on the sign-in page
/// would otherwise reach <c>users:write</c>, and <c>users:write</c> is everyone. These pages reach
/// exactly one account — the one already signed in — and <c>S-49</c> makes a password change require
/// the current password, which an XSS does not have. Different blast radius, different rule.
/// </para>
/// <para>
/// <b>They call <see cref="UserAdministration"/> in process</b> (§1.13) rather than calling
/// <c>/account/*</c> over HTTP. A page that called its own API would need a token to call it with,
/// which is the thing this surface exists to avoid needing.
/// </para>
/// <para>
/// <b>Every page is drawn through <see cref="IInteractionRenderer"/>,</b> so a deployment that has
/// replaced the look of <c>/login</c> and <c>/consent</c> gets these in the same look — and every
/// one of those methods is a default interface member, so one that has not gets the library's pages
/// and still compiles (§7.4).
/// </para>
/// </remarks>
public static class MeEndpoints
{
    /// <summary>Map the self-service pages.</summary>
    /// <param name="endpoints">The route builder.</param>
    public static IEndpointRouteBuilder MapSelfServicePages(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Every route below answers somebody looking at a page, so a store that cannot be reached
        // renders rather than returning a bare status. X-43.
        var pages = endpoints.ShedsOnStoreFailure(OAuthSurface.Interaction, rendered: true);


        // `AllowAnonymous` and no scheme, the same as every other interaction page: the session is
        // read through IUserSession rather than through an authorization policy, so that "signed in"
        // means here what it means at /authorize even when a deployment supplies its own seam.
        pages.MapGet(AuthorizationServerPaths.Me, GetAccountAsync)
            .AllowAnonymous().WithName("boltway-me");

        pages.MapGet(AuthorizationServerPaths.MePassword, GetPasswordAsync)
            .AllowAnonymous().WithName("boltway-me-password");

        pages.MapPost(AuthorizationServerPaths.MePassword, (Delegate)PostPasswordAsync)
            .AllowAnonymous().WithName("boltway-me-password-post");

        pages.MapGet(AuthorizationServerPaths.MeSessions, GetSessionsAsync)
            .AllowAnonymous().WithName("boltway-me-sessions");

        pages.MapPost(AuthorizationServerPaths.MeSessions, (Delegate)PostSessionsAsync)
            .AllowAnonymous().WithName("boltway-me-sessions-post");

        pages.MapGet(AuthorizationServerPaths.MeConsents, GetConsentsAsync)
            .AllowAnonymous().WithName("boltway-me-consents");

        pages.MapPost(AuthorizationServerPaths.MeConsents, (Delegate)PostConsentsAsync)
            .AllowAnonymous().WithName("boltway-me-consents-post");

        pages.MapPost(AuthorizationServerPaths.MeEmailVerify, (Delegate)PostVerifyEmailAsync)
            .AllowAnonymous().WithName("boltway-me-email-verify-post");

        return endpoints;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /me
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetAccountAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.Me);
        }

        // The link forms are the reason this page carries antiforgery tokens at all. POST
        // /external/{scheme}/link is state-changing and refuses without a session, so it is exactly
        // the shape a page on another origin would like to submit on a signed-in user's behalf.
        var tokens = InteractionEndpoints.AntiforgeryTokensFor(http);

        List<AccountProviderLink> providers = [];

        var configured = http.RequestServices
            .GetServices<Abstractions.Federation.IExternalIdentityProvider>()
            .ToList();

        // Read once for the page rather than once per provider: one account holds a handful of
        // links and the answer for every button is in the same list.
        var linked = configured.Count == 0
            ? []
            : await http.RequestServices.GetRequiredService<IUserStore>()
                .ListExternalLoginsAsync(account.Subject, cancellationToken);

        foreach (var provider in configured)
        {
            providers.Add(new AccountProviderLink(
                provider.Scheme,
                provider.DisplayName,
                AuthorizationServerPaths.External(provider.Scheme, "link"),
                linked.Any(link => string.Equals(
                    link.UpstreamIssuer, provider.Issuer, StringComparison.Ordinal))));

            // The sign-in page needs this for the same reason and says why there. This page needed
            // it first in practice: linking is the step a user reaches before they have ever
            // signed in with the provider, so it is the button that gets pressed first.
            SecurityHeaders.AllowFormActionTo(
                http, await provider.GetChallengeOriginAsync(cancellationToken));
        }

        // Read from the same option that decides whether /logout is routed at all, so the link and
        // the endpoint can never disagree. Computing it here rather than in the renderer keeps the
        // renderer a function of its model, which is what lets a themed one be tested without a
        // server.
        var signOutUrl =
            http.RequestServices.GetRequiredService<AuthorizationServerOptions>().EndSessionEnabled
                ? AuthorizationServerPaths.EndSession
                : null;

        return Page(http, r => r.RenderAccount(new AccountPageModel(
            account.Username,
            account.Email,
            account.EmailVerified,
            account.Roles,
            account.PasswordHash is not null,
            SecurityHeaders.NonceFor(http),
            providers,
            tokens.FormFieldName,
            tokens.RequestToken!,
            signOutUrl,
            VerifyEmailUrl: CanVerifyEmail(http, account) ? AuthorizationServerPaths.MeEmailVerify : null,
            VerificationNotice: http.Request.Query[VerificationFlag].ToString() switch
            {
                "sent" => EmailVerificationNotice.Sent,
                "too-soon" => EmailVerificationNotice.TooSoon,

                // Anything else, including nothing and including a value somebody typed into the
                // address bar, says nothing. A page does not owe a stranger's query string a reply.
                _ => EmailVerificationNotice.None,
            })));
    }

    /// <summary>The query flag the redirect after a press carries back.</summary>
    /// <remarks>
    /// A redirect rather than rendering the page from the POST, so a refresh does not re-send. The
    /// flag says what happened to the press — not that the address is confirmed, which stays false
    /// until somebody opens the link, and which the model carries separately for that reason.
    /// </remarks>
    private const string VerificationFlag = "verification";

    /// <summary>Whether this account has an address worth offering to confirm, on a server that can.</summary>
    /// <remarks>
    /// <para>
    /// Three conditions, and each removes a way for the button to be a lie. No address, nothing to
    /// send to. Already verified, nothing to prove. No <c>PasswordRecoveryEnabled</c>, and the
    /// deployment has no <c>INotificationSender</c> at all — that flag is refused at startup without
    /// one, so it is the server's own answer to "can this process send mail", not a second guess at
    /// it.
    /// </para>
    /// <para>
    /// Answered here rather than in the renderer, like <c>SignOutUrl</c> beside it: a themed
    /// renderer is then a function of its model and can be tested without a server.
    /// </para>
    /// </remarks>
    private static bool CanVerifyEmail(HttpContext http, Abstractions.Users.UserAccount account) =>
        account.Email is { Length: > 0 }
        && !account.EmailVerified
        && http.RequestServices.GetRequiredService<AuthorizationServerOptions>().PasswordRecoveryEnabled;

    /// <summary>
    /// Send this account's own address a confirmation link. <c>E-41</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The half of <c>E-41</c> that never existed.</b>
    /// <c>AccountRecovery.RequestEmailVerificationAsync</c> minted the token and composed the mail,
    /// <c>/verify-email</c> redeemed it, and nothing called the first one — its only callers were
    /// three tests, so no deployment could produce the link that page receives.
    /// </para>
    /// <para>
    /// <b>Throttled, and the account being signed in is not a reason to skip it.</b> §3.1: this
    /// sends mail to an address the server chooses, so it cannot be used to reach a stranger — but a
    /// held session is still a button that mails somebody on every press, and the counter is what
    /// keeps a stuck client or a bored operator from filling their own inbox. Keyed on the subject,
    /// which is the honest key here: unlike <c>/forgot</c> there is no oracle to protect, so the
    /// limit can name exactly who it is limiting.
    /// </para>
    /// <para>
    /// <b>The same redirect whether or not anything was sent.</b> The three conditions in
    /// <see cref="CanVerifyEmail"/> are re-checked, because a button drawn by a page is not a
    /// promise about the request that follows it — an address can be verified, or removed, between
    /// the render and the press. There is nothing to report in that case: the page it lands on shows
    /// the current state, which is the answer.
    /// </para>
    /// </remarks>
    private static async Task<IResult> PostVerifyEmailAsync(
        HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.Me);
        }

        if (!CanVerifyEmail(http, account))
        {
            return Results.Redirect(AuthorizationServerPaths.Me);
        }

        var admission = http.RequestServices.GetRequiredService<RecoveryThrottle>()
            .Admit(account.Subject.Value, http);

        if (!admission.Allowed)
        {
            // A redirect carrying a sentence, not the 429 the API surface answers with. This is a
            // form post from a browser, and RecoveryEndpoints.TooManyRequests writes a JSON problem
            // document — which on a page is §7.3's complaint exactly: a line of JSON where a
            // sentence should be. The header still goes out for anything reading it.
            http.Response.Headers.RetryAfter =
                ((int)Math.Ceiling(admission.RetryAfter.TotalSeconds))
                    .ToString(CultureInfo.InvariantCulture);

            return Results.Redirect(AuthorizationServerPaths.Me + "?" + VerificationFlag + "=too-soon");
        }

        await http.RequestServices.GetRequiredService<AccountRecovery>()
            .RequestEmailVerificationAsync(account.Subject, cancellationToken);

        return Results.Redirect(AuthorizationServerPaths.Me + "?" + VerificationFlag + "=sent");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /me/password
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetPasswordAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.MePassword);
        }

        return PasswordPage(
            http,
            account.PasswordHash is null ? ChangePasswordProblem.NoPassword : ChangePasswordProblem.None);
    }

    /// <summary>
    /// Change the signed-in person's password.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The subject comes from the session and from nowhere else.</b> There is no field in this
    /// form naming an account, so the handler has no value it could be made to act on but the
    /// caller's own — the same property <c>/account/*</c> has, arrived at the same way.
    /// </para>
    /// <para>
    /// <b>The confirmation field is checked here rather than in the browser.</b> A mistyped new
    /// password is a lockout, these pages ship no JavaScript, and a check that only exists in a
    /// <c>pattern</c> attribute is one a form post can skip.
    /// </para>
    /// </remarks>
    private static async Task<IResult> PostPasswordAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.MePassword);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);
        var current = form["current"].ToString();
        var replacement = form["new"].ToString();

        if (!string.Equals(replacement, form["confirm"].ToString(), StringComparison.Ordinal))
        {
            return PasswordPage(http, ChangePasswordProblem.Mismatch);
        }

        if (string.IsNullOrWhiteSpace(replacement))
        {
            return PasswordPage(http, ChangePasswordProblem.Blank);
        }

        // A checkbox, so absent means unchecked means no. §1.10: the server cannot tell a routine
        // change from a response to a compromise, so the person says.
        var revoke = string.Equals(form["revoke"].ToString(), "true", StringComparison.Ordinal);

        var result = await http.RequestServices.GetRequiredService<UserAdministration>().ChangePasswordAsync(
            new Actor(ActorKind.Client, account.Subject) { CorrelationId = http.TraceIdentifier },
            account.Subject,
            current,
            replacement,
            revoke,
            cancellationToken);

        // Signed out on the way out, when they asked to be. Revoking grants does not touch this
        // browser's cookie — a grant and a session are different things — so leaving the cookie
        // would answer "sign me out everywhere, including here" with everywhere but here.
        if (result.Status is AdministrationStatus.Ok && revoke)
        {
            await http.RequestServices.GetRequiredService<IUserSignIn>().SignOutAsync(http);
        }

        return result.Status switch
        {
            AdministrationStatus.Ok => PasswordPage(http, ChangePasswordProblem.None, result.Revoked),
            AdministrationStatus.WrongPassword => PasswordPage(http, ChangePasswordProblem.WrongPassword),
            AdministrationStatus.NoPassword => PasswordPage(http, ChangePasswordProblem.NoPassword),

            // The account went away between the session read and the write. Sending them to sign in
            // again is the honest next step: whatever they were is not in the directory now.
            _ => SignInFirst(AuthorizationServerPaths.MePassword),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /me/sessions
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetSessionsAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.MeSessions);
        }

        return await SessionsPageAsync(http, account.Subject, ended: false, cancellationToken);
    }

    /// <summary>
    /// End one session.
    /// </summary>
    /// <remarks>
    /// <b>The grant is loaded and its subject checked before anything is revoked</b>, for the reason
    /// <see cref="AccountEndpoints"/> spells out: the id arrives from a form field, and
    /// <c>IGrantStore.RevokeAsync</c> takes an id and no subject. Without the check this page would
    /// end any session in the deployment for anyone who can sign in. A grant that is not the
    /// caller's is treated as absent — the page redraws with nothing said, which is what a stale
    /// form should do and is also not an oracle.
    /// </remarks>
    private static async Task<IResult> PostSessionsAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.MeSessions);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);
        var grantId = form["grant"].ToString();

        var grants = http.RequestServices.GetRequiredService<IGrantStore>();
        var ended = false;

        // "None of this was me". Two posts: the first asks, the second acts. The question is not
        // ceremony — every other control on this page ends one grant, which the reader can undo by
        // approving again, and this one ends the application they are reading the page in.
        // One field, two values, carried by whichever button was pressed. `ask` draws the question
        // and `confirm` answers it; anything else is neither and falls through to the single-grant
        // path below, which is the safe direction for a value nobody here wrote.
        if (form["all"] is { Count: > 0 } all)
        {
            if (all != "confirm")
            {
                return await SessionsPageAsync(
                    http, account.Subject, ended: false, cancellationToken, confirming: true);
            }

            var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();

            // The set operation, not a loop over the listing. IGrantStore says why: the moment this
            // is called is the moment somebody is responding to a compromise, and enumerate-then-
            // revoke leaves a window in which a grant created in between survives. That window is
            // exactly what an attacker holding a live session would land in.
            var count = await grants.RevokeAllForSubjectAsync(account.Subject, now, cancellationToken);

            // And the browser sessions, which the grant store knows nothing about. Without this the
            // control cuts what the applications hold and leaves whoever granted it signed in, free
            // to grant it again — the gap SessionRevalidation exists to close, and the reason this
            // page's next sentence can now say the password is the second step rather than the only
            // one that does anything.
            //
            // The reader's own session goes too. That is not collateral damage: they are being asked
            // "was this you", and a control that spares the browser it was pressed in would spare an
            // attacker's if they were the one pressing it.
            await http.RequestServices
                .GetRequiredService<IUserStore>()
                .StampSessionsAsync(account.Subject, now, cancellationToken);

            return await SessionsPageAsync(
                http, account.Subject, ended: false, cancellationToken, endedAll: count);
        }

        if (!string.IsNullOrEmpty(grantId)
            && await grants.FindAsync(grantId, cancellationToken) is { } grant
            && grant.Subject == account.Subject)
        {
            var clock = http.RequestServices.GetRequiredService<TimeProvider>();

            ended = await grants.RevokeAsync(grantId, clock.GetUtcNow(), cancellationToken);
        }

        return await SessionsPageAsync(http, account.Subject, ended, cancellationToken);
    }

    /// <summary>
    /// Draw the sessions, in the same words the approvals page uses.
    /// </summary>
    /// <remarks>
    /// <b>Through <see cref="ConsentModelBuilder.Describe"/>, like <see cref="ConsentsPageAsync"/>
    /// and like the consent page.</b> This method used to pass <c>g.Scope.ToWireString()</c>, and
    /// what that produced on a deployment with descriptions configured was a page reading
    /// <c>email docs:read docs:write</c> one click away from a page reading them as sentences. Somebody
    /// deciding whether to end a session is making the same judgement they made when they approved
    /// it, so they get the same words.
    /// </remarks>
    private static async Task<IResult> SessionsPageAsync(
        HttpContext http,
        SubjectId subject,
        bool ended,
        CancellationToken cancellationToken,
        bool confirming = false,
        int? endedAll = null)
    {
        var grants = await http.RequestServices
            .GetRequiredService<IGrantStore>()
            .ListForSubjectAsync(subject, cancellationToken);

        // One call for the whole page rather than one per row. The list is already in hand, and a
        // query per session is the shape that is invisible with three of them and is the page with
        // thirty — which is whoever has the most, not whoever tested it.
        var refreshed = await http.RequestServices
            .GetRequiredService<IRefreshTokenStore>()
            .LastIssuedForGrantsAsync([.. grants.Select(g => g.GrantId)], cancellationToken);

        var options = http.RequestServices.GetRequiredService<AuthorizationServerOptions>();
        var tokens = InteractionEndpoints.AntiforgeryTokensFor(http);

        return Page(http, r => r.RenderSessions(new SessionsPageModel(
            [.. grants.Select(g => new SessionLine(
                g.GrantId,
                g.ClientId.Value,
                ConsentModelBuilder.HostOf(g.ClientId.Value),
                ConsentModelBuilder.Describe(g.Scope.Values, options),
                g.Resources,
                g.CreatedAt,

                // Absent for a grant that has never rotated, which is every session younger than
                // one access-token lifetime. TryGetValue rather than a default, so "never" stays
                // distinguishable from a moment at the epoch.
                refreshed.TryGetValue(g.GrantId, out var last) ? last : null,

                // Described here, not in the renderer, for the reason SessionsPageModel gives.
                ApprovingDevice.Describe(g.UserAgent)))],
            ended,
            tokens.FormFieldName,
            tokens.RequestToken!,
            SecurityHeaders.NonceFor(http),

            // The page says how long an application that never re-checks keeps access after this
            // list is emptied, and this is the number it says. Read from the options rather than
            // written into the sentence, because the sentence outlived the option's default once
            // already.
            options.AccessTokenLifetime,
            confirming,
            endedAll)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // /me/consents
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetConsentsAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.MeConsents);
        }

        return await ConsentsPageAsync(http, account.Subject, withdrawn: false, cancellationToken);
    }

    /// <summary>
    /// Withdraw one approval.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The client id comes from a form field and the subject does not</b>, which is what makes
    /// the pair safe: <c>IConsentStore.RevokeAsync</c> is keyed on <c>(subject, client)</c> and the
    /// subject is the session's, so however the id is spelled it can only ever reach a record of the
    /// caller's own. That is a stronger property than <c>/me/sessions</c> has — a grant id is a
    /// global key, so that handler has to load and compare — and it is why there is no ownership
    /// check here rather than one that was forgotten.
    /// </para>
    /// <para>
    /// <b>The id is parsed rather than passed through.</b> The same
    /// <c>ClientIdentifier.TryParseFromRequest</c> the authorization endpoint runs, for the same
    /// reason: it arrives from a browser, it reaches a store key and a log line, and it settles the
    /// kind as <c>Unknown</c> so that whoever sent it does not get to declare what sort of client
    /// they are. A malformed one redraws the page having done nothing, like a stale grant id does.
    /// </para>
    /// <para>
    /// <b>This does not end the sessions</b>, and the page says so — <c>E-38</c>. Revoking grants
    /// from here would make "ask me again next time" also mean "sign me out", and only one of those
    /// is what the button said.
    /// </para>
    /// </remarks>
    private static async Task<IResult> PostConsentsAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        if (await SignedInAccountAsync(http, cancellationToken) is not { } account)
        {
            return SignInFirst(AuthorizationServerPaths.MeConsents);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);
        var withdrawn = false;

        if (ClientIdentifier.TryParseFromRequest(form["client"].ToString(), out var client))
        {
            withdrawn = await http.RequestServices
                .GetRequiredService<IConsentStore>()
                .RevokeAsync(account.Subject, client, cancellationToken);
        }

        return await ConsentsPageAsync(http, account.Subject, withdrawn, cancellationToken);
    }

    /// <summary>
    /// Draw the approvals, described the way they were described when they were given.
    /// </summary>
    /// <remarks>
    /// <b>The scope descriptions come from <see cref="ConsentModelBuilder.Describe"/>, which is the
    /// same function the consent page and <see cref="SessionsPageAsync"/> use.</b> A person agreed
    /// to "Read every account"; a page that showed them <c>users:read</c> would be asking them to
    /// recognise a decision from a string nobody promised was legible. A-14 is decided in that
    /// function rather than here, so a fourth page describing scopes cannot get it wrong on its own.
    /// </remarks>
    private static async Task<IResult> ConsentsPageAsync(
        HttpContext http, SubjectId subject, bool withdrawn, CancellationToken cancellationToken)
    {
        var consents = await http.RequestServices
            .GetRequiredService<IConsentStore>()
            .ListAsync(subject, cancellationToken);

        var options = http.RequestServices.GetRequiredService<AuthorizationServerOptions>();
        var tokens = InteractionEndpoints.AntiforgeryTokensFor(http);

        return Page(http, r => r.RenderConsents(new ConsentsPageModel(
            [.. consents.Select(c => new ConsentLine(
                c.ClientId.Value,
                ConsentModelBuilder.HostOf(c.ClientId.Value),
                ConsentModelBuilder.Describe(c.Scope.Values, options),
                c.Resources,
                c.GrantedAt))],
            withdrawn,
            tokens.FormFieldName,
            tokens.RequestToken!,
            SecurityHeaders.NonceFor(http))));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The signed-in person's account, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><see cref="IUserSession"/>, not <c>HttpContext.User</c>.</b> That is what "signed in"
    /// means everywhere else in this server, and reading the principal directly would answer
    /// differently from <c>/authorize</c> the moment a deployment supplies its own seam.
    /// </para>
    /// <para>
    /// <b>And then the directory, not the session.</b> The session carries a subject and the time it
    /// was proven; everything these pages display — the handle, the address, whether a password
    /// exists — is read now. A cookie can outlive the account it names.
    /// </para>
    /// </remarks>
    private static async Task<UserAccount?> SignedInAccountAsync(
        HttpContext http, CancellationToken cancellationToken)
    {
        var session = await http.RequestServices
            .GetRequiredService<IUserSession>()
            .GetAsync(cancellationToken);

        if (session is not { } user)
        {
            return null;
        }

        return await http.RequestServices
            .GetRequiredService<IUserStore>()
            .FindBySubjectAsync(user.Subject, cancellationToken);
    }

    /// <summary>
    /// Send an unauthenticated visitor to sign in, and back here afterwards.
    /// </summary>
    /// <remarks>
    /// 303, like every other redirect this server emits (E-20), and the <c>returnUrl</c> is a
    /// constant from <see cref="AuthorizationServerPaths"/> rather than anything off the request —
    /// so this cannot become a way to make the sign-in page redirect somewhere chosen by a caller.
    /// <c>/login</c> validates it again anyway, against a closed list that these three paths are on.
    /// </remarks>
    private static IResult SignInFirst(string page) =>
        AuthorizeResults.SeeOther(
            AuthorizationServerPaths.Login + "?returnUrl=" + Uri.EscapeDataString(page));

    private static IResult PasswordPage(
        HttpContext http, ChangePasswordProblem problem, int revoked = -1)
    {
        var tokens = InteractionEndpoints.AntiforgeryTokensFor(http);

        return Page(http, r => r.RenderChangePassword(new ChangePasswordPageModel(
            problem,
            revoked >= 0,
            revoked < 0 ? 0 : revoked,
            tokens.FormFieldName,
            tokens.RequestToken!,
            SecurityHeaders.NonceFor(http))));
    }

    private static IResult Page(HttpContext http, Func<IInteractionRenderer, string> render)
    {
        var renderer = http.RequestServices.GetRequiredService<IInteractionRenderer>();

        return Results.Content(render(renderer), "text/html; charset=utf-8");
    }
}
