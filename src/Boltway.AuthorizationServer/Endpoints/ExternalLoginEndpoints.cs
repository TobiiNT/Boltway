using System.Security.Cryptography;
using System.Text;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Federation;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// Federated sign-in: the two endpoints an upstream round trip needs, and the link endpoint that is
/// the safe alternative to matching accounts by email.
/// </summary>
/// <remarks>
/// <para>
/// <b>The callback is a new redirect surface on this server's own origin</b>, which is the shape
/// <c>LocalUrl</c> and the <c>returnUrl</c> gating exist to protect. Everything that decides where a
/// user ends up is written into an encrypted cookie at the start and re-gated when it is read back.
/// The upstream controls <c>code</c>, <c>state</c> and <c>error</c>, and none of those is or becomes
/// a URL. There is no parameter on the callback that a redirect target can be derived from.
/// </para>
/// <para>
/// <b>Account resolution is by <c>(upstream issuer, upstream subject)</c> and by nothing else.</b>
/// Not by email address, not by email address plus <c>email_verified</c>. The attack that rule is
/// about is concrete: an attacker registers the victim's address at an upstream that does not verify
/// it, signs in here, and the server hands them the victim's local account. Requiring
/// <c>email_verified</c> does not fix it - that is a claim made by the upstream, about a check this
/// server did not perform and cannot audit, and the entire reason to have a provider abstraction is
/// that a future deployment will add an upstream whose verification nobody here has reviewed.
/// </para>
/// <para>
/// The structural half of that argument is worth more than the reasoning, and it has changed shape
/// once, which is worth more than either. It used to be that <c>IUserStore</c> exposed
/// <c>FindBySubjectAsync</c>, <c>FindByUsernameAsync</c> and <c>FindByExternalLoginAsync</c> and no
/// method finding an account by email address at all - an absent method cannot be called from here
/// or anywhere. That held until signing in with a verified address shipped, because the sign-in
/// form needs precisely the lookup federation must not have.
/// </para>
/// <para>
/// <b>So the guard is now the call site rather than the absence.</b>
/// <c>StructuralRuleTests.Only_the_sign_in_form_resolves_an_account_by_address</c> reads the IL for
/// callers of <c>FindByVerifiedEmailAsync</c> and fails on any that is not the sign-in form; this
/// file is not on that allowlist and adding it turns the suite red. It is a narrower claim than the
/// one it replaces and a stronger one to keep - the old rule would have passed a callback here that
/// resolved by username, and this one names who may resolve by anything a stranger asserts.
/// </para>
/// <para>
/// So an upstream identity reaches an existing account exactly one way: <c>POST
/// /external/{scheme}/link</c>, submitted from a page the account is already signed in to, with an
/// antiforgery token, where the session that finishes the round trip must be the same subject that
/// started it. The sufficient condition is that the person operating the browser has <i>already</i>
/// authenticated as the local account - so linking adds an upstream credential to an account its
/// owner is holding, rather than admitting an upstream credential to an account on the strength of a
/// claim about it.
/// </para>
/// </remarks>
public static class ExternalLoginEndpoints
{
    /// <summary>Map the three federation routes.</summary>
    public static IEndpointRouteBuilder MapExternalLogin(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Every route below answers somebody looking at a page, so a store that cannot be reached
        // renders rather than returning a bare status. X-43.
        var pages = endpoints.ShedsOnStoreFailure(OAuthSurface.Interaction, rendered: true);


        endpoints.MapPost(AuthorizationServerPaths.ExternalStart, StartAsync)
            .AllowAnonymous().WithName("boltway-external-start");

        endpoints.MapPost(AuthorizationServerPaths.ExternalLink, LinkAsync)
            .AllowAnonymous().WithName("boltway-external-link");

        pages.MapGet(AuthorizationServerPaths.ExternalCallback, CallbackAsync)
            .AllowAnonymous().WithName("boltway-external-callback");

        return endpoints;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // start / link
    // ─────────────────────────────────────────────────────────────────────────

    private static Task<IResult> StartAsync(HttpContext http, string scheme, CancellationToken cancellationToken) =>
        BeginAsync(http, scheme, ExternalLoginIntent.SignIn, cancellationToken);

    private static Task<IResult> LinkAsync(HttpContext http, string scheme, CancellationToken cancellationToken) =>
        BeginAsync(http, scheme, ExternalLoginIntent.Link, cancellationToken);

    private static async Task<IResult> BeginAsync(
        HttpContext http, string scheme, ExternalLoginIntent intent, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        var services = http.RequestServices;
        var form = await http.Request.ReadFormAsync(cancellationToken);
        var returnUrl = form["returnUrl"].ToString();

        // Two different gates, and the difference is what each flow resumes.
        //
        // A sign-in lands where POST /login lands, and it is the *same list* rather than a rule
        // that resembles it. This said "may only ever land back on /authorize - the same rule POST
        // /login follows", and that stopped being true when /login learned to resume the
        // self-service pages: the two drifted, and the comment claiming they agreed is what kept
        // anybody from noticing. Measured, on the running deployment, once a bare GET /login began
        // defaulting its returnUrl to /me - the sign-in page rendered a provider button whose own
        // endpoint answered 400, so "sign in with Google" from a hand-typed /login was an error
        // page. The list, not a second opinion about it.
        //
        // A link is started from wherever a customer put the button in their own application, so it
        // may land on any local path; "local" is still the whole of the protection, and it is what
        // stops this endpoint being a redirector on the one origin the user types a password into.
        var gated = intent is ExternalLoginIntent.SignIn
            ? LocalUrl.IsLocalPathToAny(returnUrl, AuthorizationServerPaths.LoginReturnTargets)
            : LocalUrl.IsLocal(returnUrl);

        if (!gated)
        {
            return InteractionEndpoints.BadReturnUrl(http);
        }

        var provider = Find(services, scheme);

        if (provider is null)
        {
            return Refuse(
                http,
                ReasonCode.ExternalProviderUnknown,
                "That sign-in method is not available.",
                $"scheme={Echo(scheme)}");
        }

        string? linkSubject = null;

        if (intent is ExternalLoginIntent.Link)
        {
            // Checked here as well as on the way back. Doing it only on the way back would send a
            // signed-out user all the way to the upstream, have them authenticate, and refuse them
            // on return - which teaches people to click through an upstream consent screen for
            // nothing.
            var user = await services.GetRequiredService<IUserSession>().GetAsync(cancellationToken);

            if (user is null)
            {
                return Refuse(
                    http,
                    ReasonCode.ExternalLinkRequiresSession,
                    "Sign in before connecting another sign-in method.",
                    $"scheme={Echo(scheme)}; phase=start");
            }

            linkSubject = user.Value.Subject.Value;
        }

        var availability = await provider.GetAvailabilityAsync(
            new ExternalProviderContext(await ResolveClientAsync(services, returnUrl, cancellationToken)),
            cancellationToken);

        if (!availability.Enabled)
        {
            // The reason reaches the user, because A-11 says a configured-but-unavailable method
            // states why. It is the provider's own string and it is HTML-encoded by the error page,
            // like everything else that is rendered.
            return Refuse(
                http,
                ReasonCode.ExternalProviderUnavailable,
                availability.DisabledReason!,
                $"scheme={Echo(scheme)}; phase=start");
        }

        var pending = services.GetRequiredService<ExternalLoginStateStore>()
            .Create(provider.Scheme, returnUrl, intent, linkSubject);

        ExternalChallenge challenge;

        try
        {
            challenge = await provider.BeginAsync(
                new ExternalLoginContext(
                    CallbackUrl(services, provider.Scheme),
                    pending.State,
                    pending.Nonce,
                    S256(pending.CodeVerifier)),
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A provider that cannot reach its own discovery document throws here, because
            // ExternalChallenge has no failure case - it is a validated redirect target. Caught and
            // turned into a logged rejection rather than left to the exception boundary, so it
            // carries a reason an operator can filter on instead of arriving as `server_error`.
            //
            // The exception's message goes to the log and never to the page: it names an upstream
            // host and possibly a TLS failure, which is this deployment's business.
            return Refuse(
                http,
                ReasonCode.ExternalProviderUnavailable,
                "That sign-in method is temporarily unavailable.",
                $"scheme={Echo(scheme)}; phase=start; {ex.GetType().Name}: {Echo(ex.Message)}");
        }

        // Written only once the challenge exists. Writing it first would leave a browser holding a
        // pending request for a round trip that never started, and the next genuine attempt would
        // overwrite it anyway - but the ordering also means a failure here leaves no state at all,
        // which is the easier thing to reason about.
        services.GetRequiredService<ExternalLoginStateStore>().Write(http, pending);

        return AuthorizeResults.SeeOther(challenge.Location);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // callback
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> CallbackAsync(
        HttpContext http, string scheme, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        var services = http.RequestServices;

        // Read and delete in one act, before anything else. A replayed callback finds no pending
        // request, so a captured `state` is worth exactly one attempt.
        var pending = services.GetRequiredService<ExternalLoginStateStore>().TakeAndClear(http);

        if (pending is null)
        {
            return Refuse(
                http,
                ReasonCode.ExternalPendingRequestMissing,
                "This sign-in has expired. Start again.",
                $"scheme={Echo(scheme)}");
        }

        // The scheme in the path must be the one the round trip started with. Without this, a
        // pending request minted for provider A could be completed by pointing the browser at
        // provider B's callback - and provider B would validate an ID token from B against a nonce
        // A issued, which succeeds. Two upstreams is exactly when that becomes reachable, which is
        // why it is here now rather than when the second provider ships.
        if (!string.Equals(pending.Scheme, scheme, StringComparison.Ordinal))
        {
            return Refuse(
                http,
                ReasonCode.ExternalStateMismatch,
                "This sign-in has expired. Start again.",
                $"scheme={Echo(scheme)}; pending={Echo(pending.Scheme)}");
        }

        if (!ExternalLoginStateStore.StateMatches(pending.State, http.Request.Query["state"].ToString()))
        {
            return Refuse(
                http,
                ReasonCode.ExternalStateMismatch,
                "This sign-in could not be completed. Start again.",
                $"scheme={Echo(scheme)}; state_present={!string.IsNullOrEmpty(http.Request.Query["state"].ToString())}");
        }

        // Only after `state` has matched. An `error` on an unbound callback is anybody's error, and
        // acting on it - even to render a page - would let a stranger drive this endpoint's output.
        if (http.Request.Query["error"].ToString() is { Length: > 0 } upstreamError)
        {
            return Refuse(
                http,
                ReasonCode.ExternalAuthorizationDenied,
                "The sign-in was not completed.",
                $"scheme={Echo(scheme)}; error={Echo(upstreamError)}; "
                + $"description={Echo(http.Request.Query["error_description"].ToString())}");
        }

        var code = http.Request.Query["code"].ToString();

        if (string.IsNullOrEmpty(code))
        {
            return Refuse(
                http,
                ReasonCode.ExternalAuthorizationDenied,
                "The sign-in was not completed.",
                $"scheme={Echo(scheme)}; neither code nor error was returned");
        }

        var provider = Find(services, scheme);

        if (provider is null)
        {
            // Reachable when a provider is removed from configuration while a round trip is in
            // flight, which is an ordinary deploy.
            return Refuse(
                http,
                ReasonCode.ExternalProviderUnknown,
                "That sign-in method is not available.",
                $"scheme={Echo(scheme)}; phase=callback");
        }

        var result = await provider.CompleteAsync(
            new ExternalCallbackContext(
                code,
                CallbackUrl(services, provider.Scheme),
                pending.CodeVerifier,
                http.Request.Query.ToDictionary(q => q.Key, q => q.Value.ToString(), StringComparer.Ordinal)),
            cancellationToken);

        if (result is ExternalLoginResult.Failed failed)
        {
            var (reason, message) = Map(failed.Kind);

            return Refuse(http, reason, message, $"scheme={Echo(scheme)}; {Echo(failed.Detail)}");
        }

        var principal = ((ExternalLoginResult.Authenticated)result).Principal;

        // OIDC Core §3.1.3.7 rule 11. Done here rather than inside the provider so it happens once,
        // identically, for every provider that will ever be added - the value it must equal is in
        // the cookie, which a provider cannot see by design.
        if (!ExternalLoginStateStore.NonceMatches(pending.Nonce, principal.Nonce))
        {
            return Refuse(
                http,
                ReasonCode.ExternalNonceMismatch,
                "This sign-in could not be completed. Start again.",
                $"scheme={Echo(scheme)}; nonce_present={!string.IsNullOrEmpty(principal.Nonce)}");
        }

        return pending.Intent is ExternalLoginIntent.Link
            ? await CompleteLinkAsync(http, pending, principal, cancellationToken)
            : await CompleteSignInAsync(http, pending, principal, cancellationToken);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // account resolution
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> CompleteSignInAsync(
        HttpContext http,
        PendingExternalLogin pending,
        ExternalPrincipal principal,
        CancellationToken cancellationToken)
    {
        var services = http.RequestServices;
        var users = services.GetRequiredService<IUserStore>();

        // The one lookup. (issuer, subject), ordinal on both halves, and there is no fallback below
        // it - no email, no username, no "close enough".
        var realm = services.GetRequiredService<AuthorizationServerOptions>().Realm;

        var account = await users.FindByExternalLoginAsync(
            realm, principal.Issuer, principal.Subject, cancellationToken);

        if (account is null)
        {
            var options = services.GetRequiredService<ExternalLoginOptions>();

            if (options.UnknownIdentity is not UnknownExternalIdentityPolicy.Provision)
            {
                return Refuse(
                    http,
                    ReasonCode.ExternalIdentityUnlinked,
                    "This account is not connected to a sign-in here. Sign in first, then connect it.",
                    $"scheme={Echo(pending.Scheme)}; iss={Echo(principal.Issuer)}; "
                    + "policy=Refuse; set ExternalLoginOptions.UnknownIdentity to Provision to create "
                    + "accounts on first sign-in");
            }

            account = await ProvisionAsync(services, principal, options, cancellationToken);

            // Recorded here rather than inside ProvisionAsync, which takes a service provider and
            // knows nothing about this request. An account came into existence because an upstream
            // said so, which is at least as worth recording as a link onto one that already existed.
            if (account is not null)
            {
                // The deployment's defaults, because a provisioned account is the "creator named no
                // role" case every time - there is no creator. Without this, a deployment that
                // turned provisioning on had every sign-up land on the floor while its DEFAULT_ROLES
                // said otherwise, and the two surfaces disagreed about what "by default" means.
                var defaulted = await AssignDefaultRolesAsync(services, account.Subject, cancellationToken);

                await RecordAsync(
                    http,
                    "user.external.provision",
                    account.Subject,
                    realm,
                    $"scheme={pending.Scheme}; iss={principal.Issuer}; sub={principal.Subject}"
                        + (defaulted is null ? string.Empty : $"; role={defaulted} (defaulted)"),
                    cancellationToken);
            }

            if (account is null)
            {
                return Refuse(
                    http,
                    ReasonCode.ExternalIdentityUnlinked,
                    "This sign-in could not be completed.",
                    $"scheme={Echo(pending.Scheme)}; provisioning failed, most likely a racing "
                    + "sign-in created the same link first");
            }
        }

        if (!account.IsActive)
        {
            return Refuse(
                http,
                ReasonCode.ExternalAccountDisabled,
                "This account cannot sign in.",
                $"scheme={Echo(pending.Scheme)}; subject={Echo(account.Subject.Value)}");
        }

        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();

        await services.GetRequiredService<IUserSignIn>()
            .SignInAsync(http, new AuthenticatedUser(account.Subject, now));

        // The same list POST /login returns to, not /authorize alone - the gate at the *start* of
        // this round trip was widened to it and this one was left behind, so a sign-in begun from a
        // hand-typed /login was allowed to leave, authenticated at Google, came back, signed the
        // user in, and was refused on the last line. Measured on the running deployment: the cookie
        // was set and the browser landed on "this page was opened without a valid authorization
        // request", which is the worst shape a refusal can have - the side effect happened and the
        // page says nothing did.
        return Resume(http, pending, AuthorizationServerPaths.LoginReturnTargets);
    }

    /// <summary>
    /// Create a brand-new local account for an upstream identity nothing is linked to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>New, always.</b> Nothing here searches for an existing account to attach to, and the store
    /// offers no way to search by the one field that would tempt someone - the email address. An
    /// upstream identity whose email matches an existing local account gets its own separate
    /// account, which is the correct answer: the two are the same person only if that person says
    /// so, from inside the account, through the link endpoint.
    /// </para>
    /// <para>
    /// The username is the minted subject. It is never typed by anyone - a federated account has no
    /// password form to type it into - and every other candidate is worse: the email address is the
    /// value this whole design refuses to key on, and <c>{scheme}:{subject}</c> would collide with a
    /// local username somebody could choose. A ULID cannot collide with an account this server
    /// minted, and if a local account somehow holds that exact string, the store refuses the
    /// insertion and this returns <see langword="null"/> rather than overwriting anything.
    /// </para>
    /// </remarks>
    private static async Task<UserAccount?> ProvisionAsync(
        IServiceProvider services,
        ExternalPrincipal principal,
        ExternalLoginOptions options,
        CancellationToken cancellationToken)
    {
        var users = services.GetRequiredService<IUserStore>();
        var subject = services.GetRequiredService<ISubjectIdFactory>().Mint();
        var realm = services.GetRequiredService<AuthorizationServerOptions>().Realm;

        var email = options.CopyEmailOnProvision ? Claim(principal, "email") : null;

        var account = new UserAccount(
            subject,
            subject.Value,
            email,

            // The upstream's assertion, carried through as an assertion. Nothing in this server
            // reads it to decide which account anything is; it reaches the `email_verified` claim of
            // an ID token, where OIDC Core already describes it as the provider's statement rather
            // than a fact.
            EmailVerified: email is not null
                && string.Equals(Claim(principal, "email_verified"), "true", StringComparison.Ordinal),

            // No password. A federation-only account cannot be signed into with one, and POST /login
            // still pays for a hash against a stored dummy so the absence is not observable.
            PasswordHash: null)
        {
            Realm = realm,
        };

        try
        {
            await users.StoreAsync(account, cancellationToken);

            await users.LinkExternalLoginAsync(
                new ExternalLogin(principal.Issuer, principal.Subject, subject) { Realm = realm },
                cancellationToken);
        }
        catch (InvalidOperationException)
        {
            // The stores are add-only and refuse a duplicate subject, a duplicate username, or an
            // upstream identity already linked elsewhere. All three mean somebody else got there
            // first - two tabs, a double-click, two instances - and the honest answer is to refuse
            // this attempt rather than to guess which existing row was meant.
            return null;
        }

        return account;
    }

    /// <summary>
    /// Give a provisioned account the deployment's default roles, when it declares any.
    /// </summary>
    /// <returns>The ids assigned, space-joined for the audit detail - or null when none were.</returns>
    /// <remarks>
    /// <para>
    /// The same <see cref="AccountDefaults"/> that <c>UserAdministration.CreateAsync</c> applies,
    /// and the same fill-an-absence semantics; a provisioned account simply hits the absence every
    /// time, because nobody was there to name a role. Unregistered means what it means everywhere:
    /// the account holds nothing it was not given.
    /// </para>
    /// <para>
    /// <b>A default naming a role the realm does not define costs the account the assignment, not
    /// the person their sign-in.</b> The store refuses such an assignment on purpose, but here the
    /// caller is a stranger mid-OAuth who can fix nothing, so the refusal is logged at error -
    /// naming the role - and the sign-in proceeds with the account holding nothing. The floor is
    /// the direction this tree already fails in: <c>AdminRoleScopePolicy</c> narrows rather than
    /// refusing, and <c>IRoleStore</c> drops what it cannot resolve at claims time. The host's
    /// <c>migrate</c> verb checks DEFAULT_ROLES against the definitions on every deploy, so
    /// reaching this branch takes deleting a role out from under a live configuration.
    /// </para>
    /// </remarks>
    private static async Task<string?> AssignDefaultRolesAsync(
        IServiceProvider services, SubjectId subject, CancellationToken cancellationToken)
    {
        if (services.GetService<AccountDefaults>() is not { } defaults)
        {
            return null;
        }

        try
        {
            await services.GetRequiredService<IUserStore>()
                .SetRolesAsync(subject, defaults.Roles, cancellationToken);
        }
        catch (InvalidOperationException undefined)
        {
            services.GetService<ILoggerFactory>()
                ?.CreateLogger("Boltway.AuthorizationServer.ExternalLogin")
                .LogError(
                    new EventId(103, "ProvisionedDefaultRolesUndefined"),
                    "A provisioned account was signed in holding no roles, because the default "
                    + "assignment was refused: {Reason} Fix AccountDefaults or define the role; "
                    + "`migrate` validates the pair on every deploy.",
                    undefined.Message);

            return null;
        }

        return string.Join(' ', defaults.Roles);
    }

    private static async Task<IResult> CompleteLinkAsync(
        HttpContext http,
        PendingExternalLogin pending,
        ExternalPrincipal principal,
        CancellationToken cancellationToken)
    {
        var services = http.RequestServices;
        var user = await services.GetRequiredService<IUserSession>().GetAsync(cancellationToken);

        // The same subject that started it, not merely some subject. A session that changed between
        // the two legs - a signed-out-and-in, or a shared browser - must not attach an upstream
        // identity to whoever happens to be signed in now.
        if (user is null || !string.Equals(user.Value.Subject.Value, pending.LinkSubject, StringComparison.Ordinal))
        {
            return Refuse(
                http,
                ReasonCode.ExternalLinkRequiresSession,
                "Sign in before connecting another sign-in method.",
                $"scheme={Echo(pending.Scheme)}; phase=callback; session_present={user is not null}");
        }

        var users = services.GetRequiredService<IUserStore>();

        var realm = services.GetRequiredService<AuthorizationServerOptions>().Realm;

        var existing = await users.FindByExternalLoginAsync(
            realm, principal.Issuer, principal.Subject, cancellationToken);

        if (existing is not null
            && !string.Equals(existing.Subject.Value, user.Value.Subject.Value, StringComparison.Ordinal))
        {
            // Refused, never re-pointed. Moving a link is how whoever controls an upstream subject
            // lands the next federated sign-in inside somebody else's data.
            return Refuse(
                http,
                ReasonCode.ExternalIdentityLinkedElsewhere,
                "That account is already connected to a different sign-in here.",
                $"scheme={Echo(pending.Scheme)}; iss={Echo(principal.Issuer)}");
        }

        if (existing is null)
        {
            try
            {
                await users.LinkExternalLoginAsync(
                    new ExternalLogin(principal.Issuer, principal.Subject, user.Value.Subject) { Realm = realm },
                    cancellationToken);

                await RecordAsync(
                    http,
                    "user.external.link",
                    user.Value.Subject,
                    realm,
                    $"scheme={pending.Scheme}; iss={principal.Issuer}; sub={principal.Subject}",
                    cancellationToken);
            }
            catch (InvalidOperationException)
            {
                return Refuse(
                    http,
                    ReasonCode.ExternalIdentityLinkedElsewhere,
                    "That account is already connected to a different sign-in here.",
                    $"scheme={Echo(pending.Scheme)}; iss={Echo(principal.Issuer)}; raced");
            }
        }

        // Already linked to this same account is a success, not an error: clicking "connect" twice
        // must not be a failure.
        return Resume(http, pending, expectedPaths: null);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Send the browser to the URL the pending request was created with, re-gated.
    /// </summary>
    /// <remarks>
    /// The gate runs again here even though the value was gated before it was written. It cost one
    /// line and it removes the need to reason about whether the cookie could have been tampered with
    /// - which it could not, being authenticated - and about whether some future change writes a
    /// pending request from a path that did not gate. "Validated when it was written" is a claim
    /// about a request that is over.
    /// </remarks>
    private static IResult Resume(
        HttpContext http, PendingExternalLogin pending, IReadOnlyList<string>? expectedPaths)
    {
        var acceptable = expectedPaths is null
            ? LocalUrl.IsLocal(pending.ReturnUrl)
            : LocalUrl.IsLocalPathToAny(pending.ReturnUrl, expectedPaths);

        return acceptable
            ? AuthorizeResults.SeeOther(pending.ReturnUrl)
            : InteractionEndpoints.BadReturnUrl(http);
    }

    /// <summary>
    /// Record that an upstream identity was attached to an account.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Linking adds a way into an account and left no trace.</b> Changing a password is recorded,
    /// asking for a reset link is recorded, verifying an address is recorded - and granting a second
    /// credential that signs in forever was not. Noticed when a user linked Google, the page said
    /// nothing, and there was nowhere to look to find out whether it had happened. "Who attached
    /// this, and when" is exactly the question an audit trail exists for, and it could not be
    /// answered.
    /// </para>
    /// <para>
    /// <b>The upstream issuer and subject go in the detail, and neither is a credential.</b> A
    /// subject is an opaque identifier the upstream asserts; holding it authenticates nothing,
    /// because reaching this code at all requires the upstream to have signed a token for it. It is
    /// also the field that answers the question people actually ask - <i>which</i> Google account -
    /// which an operator otherwise cannot tell from a second one linked a minute later. Well inside
    /// the 256 characters the column holds.
    /// </para>
    /// <para>
    /// Optional, like every other caller treats it: a deployment that registered no audit store gets
    /// no record rather than a failed sign-in.
    /// </para>
    /// </remarks>
    private static Task RecordAsync(
        HttpContext http,
        string action,
        SubjectId subject,
        RealmId realm,
        string detail,
        CancellationToken cancellationToken)
    {
        var audit = http.RequestServices.GetService<IAdminAuditStore>();

        if (audit is null)
        {
            return Task.CompletedTask;
        }

        return audit.RecordAsync(
            new AdminAuditEntry(
                http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow(),

                // The person holding the browser, not an operator and not a client. `self` is what
                // the account's own actions are, and this is one: the link endpoint refuses without
                // a session, so the actor is the account being changed.
                "self",
                subject,
                ActorClient: null,
                action,
                realm,
                subject,
                TargetHandle: null,
                AdminAuditOutcome.Succeeded,
                http.TraceIdentifier)
            {
                Detail = detail,
            },
            cancellationToken);
    }

    private static IExternalIdentityProvider? Find(IServiceProvider services, string scheme) =>
        services.GetServices<IExternalIdentityProvider>()
            .FirstOrDefault(p => string.Equals(p.Scheme, scheme, StringComparison.Ordinal));

    /// <summary>
    /// The absolute callback URL, from the configured issuer.
    /// </summary>
    /// <remarks>
    /// N-13: never from <c>Request.Host</c> or <c>Request.Scheme</c>, which an architecture rule
    /// enforces over IL across the whole solution. Behind a reverse proxy the scheme would be
    /// <c>http</c>, and with host-header injection the host is the attacker's - and this value is
    /// sent to the upstream as <c>redirect_uri</c>, where a wrong one either fails the exact-match
    /// check the upstream performs or, if the upstream is lax, delivers the code somewhere else.
    /// The issuer is path-less by configuration validation, so this concatenation cannot produce a
    /// double slash or land under a path.
    /// </remarks>
    private static string CallbackUrl(IServiceProvider services, string scheme) =>
        services.GetRequiredService<AuthorizationServerOptions>().ValidatedIssuer.Value.TrimEnd('/')
        + AuthorizationServerPaths.External(scheme, "callback");

    /// <summary>The PKCE challenge for a verifier. RFC 7636 §4.2.</summary>
    private static string S256(string verifier) =>
        Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    /// <summary>Read one surfaced claim, or nothing.</summary>
    private static string? Claim(ExternalPrincipal principal, string name) =>
        principal.Claims.TryGetValue(name, out var value) && value.Length > 0 ? value : null;

    /// <summary>One provider failure, as a reason for the log and a sentence for the user.</summary>
    /// <remarks>
    /// Exhaustive over <see cref="ExternalFailureKind"/> with no default arm, so adding a member to
    /// that enum is a compile error here rather than a failure that silently renders as something
    /// else. <see cref="ExternalFailureKind.None"/> is the unset value and a provider returning it
    /// is a provider bug - it maps to the same refusal as a rejected token, which fails closed.
    /// </remarks>
    private static (ReasonCode Reason, string Message) Map(ExternalFailureKind kind) => kind switch
    {
        ExternalFailureKind.TokenExchangeFailed => (
            ReasonCode.ExternalTokenExchangeFailed, "The sign-in could not be completed. Try again."),
        ExternalFailureKind.IdentityTokenMissing => (
            ReasonCode.ExternalIdentityTokenMissing, "The sign-in could not be completed."),
        ExternalFailureKind.ProviderUnavailable => (
            ReasonCode.ExternalProviderUnavailable, "That sign-in method is temporarily unavailable."),
        _ => (ReasonCode.ExternalIdentityTokenRejected, "The sign-in could not be completed."),
    };

    /// <summary>
    /// The client the pending authorization request names, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A-11 is a per-client requirement - "disable a connection for a client ⇒ the login page states
    /// why" - so an availability decision has to be able to see the client. It is resolved through
    /// the same <c>IClientResolver</c> chain the authorize pipeline uses, so a CIMD client resolves
    /// to the same record here as there, out of the same cache.
    /// </para>
    /// <para>
    /// Failure is not an error: this returns <see langword="null"/> and the provider decides. The
    /// browser arrived here from <c>/authorize</c>, which already resolved this client successfully,
    /// so a failure means something changed in between - an evicted cache entry plus an unreachable
    /// origin, or a spent outbound budget. Refusing the sign-in page for that would turn a transient
    /// upstream problem into "you cannot log in".
    /// </para>
    /// </remarks>
    internal static async Task<Abstractions.Clients.ClientRecord?> ResolveClientAsync(
        IServiceProvider services, string returnUrl, CancellationToken cancellationToken)
    {
        var queryStart = returnUrl.IndexOf('?', StringComparison.Ordinal);

        if (queryStart < 0)
        {
            return null;
        }

        var parsed = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(returnUrl[queryStart..]);

        if (!parsed.TryGetValue("client_id", out var raw)
            || !ClientIdentifier.TryParseFromRequest(raw.ToString(), out var clientId))
        {
            return null;
        }

        foreach (var resolver in services.GetServices<Abstractions.Clients.IClientResolver>())
        {
            if (!resolver.CanResolve(clientId))
            {
                continue;
            }

            var resolution = await resolver.ResolveAsync(clientId, cancellationToken);

            if (resolution.Client is { } client)
            {
                return client;
            }
        }

        return null;
    }

    /// <summary>An HTML refusal on our own origin, logged once by the rejection writer.</summary>
    /// <remarks>
    /// <para>
    /// HTML rather than a redirect, and never a redirect to the client. At every point this method
    /// is called from, either there is no validated redirect URI at all or the failure is about this
    /// server's own sign-in rather than about the client's request - and the one thing a federation
    /// failure must not do is hand a stranger a way to bounce a browser off this origin.
    /// </para>
    /// <para>
    /// <b>The <c>RequirementId</c> on the log line will read <c>X-02</c>, and that is the error
    /// table's row rather than a claim about federation.</b> These refusals are pre-redirect
    /// <c>invalid_request</c> answers at 400, which is the pair <c>OAuthErrors</c> holds under that
    /// id, and no federation-specific row was added - a new <c>OAuthSurface</c> for it would be a
    /// change to a table two servers share. The field an operator filters federation refusals on is
    /// <c>Reason</c>, which is specific to each of them.
    /// </para>
    /// </remarks>
    private static IResult Refuse(HttpContext http, ReasonCode reason, string description, string detail) =>
        AuthorizeResults.Html(
            new Authorize.AuthorizeHtmlError(
                Rejection.Of(reason, OAuthErrorCode.InvalidRequest, description, detail),
                http.TraceIdentifier));

    /// <summary>Bound a value before it goes in a log line. The rejection factory also caps and strips.</summary>
    private static string Echo(string? value) =>
        value is null ? "<none>" : value.Length <= 160 ? value : value[..160];
}
