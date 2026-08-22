using Boltway.AuthorizationServer.Abstractions.Clients;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>One scope, as the consent page must present it.</summary>
/// <param name="Name">The scope value.</param>
/// <param name="Description">
/// The configured human description, <b>verbatim</b>.
/// </param>
/// <param name="HasDescription">
/// Whether a description was configured. When it is <see langword="false"/> the page shows the raw
/// scope and a configuration warning — A-14 requires exactly that rather than a guess.
/// </param>
/// <remarks>
/// A-14: consent renders each scope's configured description verbatim and <b>never derives consent
/// text by parsing the scope name</b>. The field failure that rule comes from is a screen that
/// assumed <c>action:resource</c> and rendered "read: story your read" — nonsense presented to a
/// user as the thing they are agreeing to.
/// </remarks>
public sealed record ConsentScope(string Name, string Description, bool HasDescription);

/// <summary>
/// Everything the consent page must show. Computed by the server, never by a template.
/// </summary>
/// <remarks>
/// N-14's fields are produced here so that a customer's template can only fail to <i>display</i>
/// them — it cannot compute them wrongly. That is the difference between a security requirement and
/// a styling suggestion.
/// </remarks>
public sealed record ConsentViewModel
{
    /// <summary>
    /// The host of the <c>client_id</c> URL. <b>The relying party's real identity.</b>
    /// </summary>
    /// <remarks>
    /// The whole mitigation for a self-asserted client name. Anyone can publish
    /// <c>{"client_name": "Claude"}</c> at their own URL; nobody else can publish it at
    /// <c>claude.ai</c>. MCP makes displaying this a MUST, and specifically says to display it
    /// rather than <c>client_name</c>.
    /// </remarks>
    public required string ClientHost { get; init; }

    /// <summary>
    /// The host of the <b>requested</b> redirect URI.
    /// </summary>
    /// <remarks>
    /// Defeats the attack CIMD structurally cannot: an attacker presents the legitimate client's
    /// metadata URL, binds any loopback port, and harvests the code — the server sees a genuine
    /// client document and the user sees a genuine client name. The only thing that differs, and the
    /// only thing that can be shown, is where the code is about to be sent.
    /// </remarks>
    public required string RedirectHost { get; init; }

    /// <summary>Whether every registered redirect URI delivers the code to the user's own device.</summary>
    /// <remarks>
    /// <para>
    /// N-14 requires an explicit warning for this shape, because such a client's callback is
    /// something a process on the user's machine could have claimed rather than something a domain
    /// owner proved. Claude Code is the live loopback case.
    /// </para>
    /// <para>
    /// This was <c>LoopbackOnly</c> and tested only <c>RedirectKind.Loopback</c>, so a
    /// native app using a private-use scheme (RFC 8252 §7.1, <c>com.example.app:/oauth</c>) got no
    /// warning — and, because <c>Uri.Host</c> is empty for those, no destination either. A review
    /// measured a consent page telling that user the code would be sent to nowhere in particular.
    /// Both kinds carry the same risk and RFC 8252 §8.4 says so explicitly of private-use schemes:
    /// another application can register the same scheme, and the operating system does not
    /// adjudicate. The name changed with the predicate rather than after it, because a flag called
    /// <c>LoopbackOnly</c> that is true for a non-loopback client is the kind of quiet lie this
    /// codebase keeps finding.
    /// </para>
    /// </remarks>
    public required bool RedirectsToThisDevice { get; init; }

    /// <summary>
    /// The client's self-asserted name, capped. <b>Plain text; the renderer encodes.</b> Secondary
    /// text, never the identity.
    /// </summary>
    public required string? ClientName { get; init; }

    /// <summary>
    /// Where this server re-serves the client's logo, or <see langword="null"/> for no logo.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A path on this origin, never the client's own URL.</b> It points at
    /// <see cref="Configuration.AuthorizationServerPaths.ClientLogo"/>, which fetches
    /// <c>logo_uri</c> server-side and re-serves the bytes. Hotlinking would tell whoever hosts the
    /// image who is looking at a consent page for which application and when, and the page's
    /// <c>default-src 'self'</c> refuses it anyway.
    /// </para>
    /// <para>
    /// <b>It is a claim, exactly like <see cref="ClientName"/>, and it is set only when that one
    /// is.</b> Anyone can publish a logo at their own URL — that is the same sentence as
    /// <c>{"client_name":"Claude"}</c>, in a form that is much harder to be sceptical of, because a
    /// familiar mark reads as proof in a way a familiar word does not. So it never appears without
    /// the name it belongs to, which is what carries
    /// <see cref="InteractionText.ConsentNameUnverified"/>: a logo outside that sentence is an
    /// unverified assertion with nothing next to it saying so.
    /// </para>
    /// <para>
    /// <b>Non-null here is not "there is a logo".</b> It is "there was a <c>logo_uri</c>, and this
    /// is where to ask". The endpoint answers 404 for a host that is down, a body that is not an
    /// image, and an image type this server will not re-serve — so the page must read correctly with
    /// the image missing, which is why the <c>alt</c> is empty and nothing is laid out around it.
    /// </para>
    /// </remarks>
    public required string? ClientLogoUrl { get; init; }

    /// <summary>What is being asked for.</summary>
    public required IReadOnlyList<ConsentScope> Scopes { get; init; }

    /// <summary>Which resources the tokens will be valid at. RFC 8707 §2.1.</summary>
    public required IReadOnlyList<string> Resources { get; init; }

    /// <summary>The gated, local URL that resumes the authorization request.</summary>
    public required string ReturnUrl { get; init; }

    /// <summary>The antiforgery field name and token to render as a hidden input.</summary>
    public required string AntiforgeryFieldName { get; init; }

    /// <summary>The antiforgery token value.</summary>
    public required string AntiforgeryToken { get; init; }

    /// <inheritdoc cref="LoginViewModel.Nonce"/>
    public required string? Nonce { get; init; }
}

/// <summary>
/// One upstream sign-in method, as the login page must present it.
/// </summary>
/// <param name="Scheme">The provider's route segment. Already constrained to <c>[a-z0-9-]</c>.</param>
/// <param name="DisplayName">What the button says. Plain text; the renderer encodes.</param>
/// <param name="StartUrl">
/// The local path a form posts to in order to begin. Computed by the server from
/// <see cref="Configuration.AuthorizationServerPaths.External"/>, never assembled by a template.
/// </param>
/// <param name="Enabled">Whether the control is usable.</param>
/// <param name="DisabledReason">
/// Why it is not, when it is not. <see langword="null"/> iff <paramref name="Enabled"/>.
/// </param>
/// <remarks>
/// A-11 is the reason <paramref name="DisabledReason"/> is on the model at all: a configured method
/// that is unavailable renders as a <b>disabled control with a stated reason</b>, and never silently
/// vanishes. A renderer that drops the reason is failing to display something the server computed,
/// which is the same class of mistake as dropping the client hostname from the consent page — and
/// the same mitigation applies, which is that it is not a decision the template gets to make.
/// </remarks>
public sealed record LoginProviderOption(
    string Scheme, string DisplayName, string StartUrl, bool Enabled, string? DisabledReason);

/// <summary>What the login page must show.</summary>
/// <remarks>
/// The N-14 property, applied to this page: every field here is computed server-side, so a
/// customer's renderer can fail to <i>display</i> a sign-in method and cannot invent one, cannot
/// enable a disabled one, and cannot point its form somewhere else. The three fields added for
/// federated sign-in are <c>required</c> for that reason — a renderer built against the older shape
/// does not silently lose the buttons, it fails to compile.
/// </remarks>
public sealed record LoginViewModel
{
    /// <summary>The gated, local URL that resumes the authorization request.</summary>
    public required string ReturnUrl { get; init; }

    /// <summary>Whether the previous attempt was refused. False on first render.</summary>
    /// <remarks>
    /// <para>
    /// <b>A bool, and the type is the rule.</b> A message distinguishing "no such user" from "wrong
    /// password" turns the login form into a username oracle, and so does a response time that
    /// distinguishes them — the password hasher runs either way for that reason. A richer type here
    /// would be somewhere to put the distinction; a bool cannot express one.
    /// </para>
    /// <para>
    /// It carried the sentence itself until a Vietnamese deployment rendered
    /// <i>"That username and password did not match."</i> under a heading reading "Đăng nhập" —
    /// measured on a running server. An endpoint that hands a renderer prose has decided the
    /// wording on the renderer's behalf, so no <see cref="IInteractionRenderer"/> could translate
    /// it and no translation file had a key for it. The renderer owns the words here as it does
    /// everywhere else on these pages; the endpoint reports what happened.
    /// </para>
    /// </remarks>
    public required bool Rejected { get; init; }

    /// <summary>The antiforgery field name.</summary>
    public required string AntiforgeryFieldName { get; init; }

    /// <summary>The antiforgery token value.</summary>
    public required string AntiforgeryToken { get; init; }

    /// <summary>
    /// Whether this deployment verifies local passwords at all.
    /// </summary>
    /// <remarks>
    /// <see langword="false"/> for a federation-only deployment, which registers no
    /// <c>IPasswordHasher</c>. The username and password fields must not be rendered in that case:
    /// a form that cannot succeed is worse than no form, because the user assumes they have
    /// forgotten a password they never had.
    /// </remarks>
    public required bool LocalPasswordsEnabled { get; init; }

    /// <summary>
    /// Every configured upstream sign-in method, available or not. A-10 and A-11.
    /// </summary>
    /// <remarks>
    /// Every one, in registration order, including the ones that are disabled — that is A-11, and it
    /// is why this list is not filtered before it reaches the model. A-10 is the other half: nothing
    /// here consults a per-client allow-list before deciding what to put in the list, so a
    /// configured provider is offered to every client unless a provider itself says otherwise, with
    /// a reason.
    /// </remarks>
    public required IReadOnlyList<LoginProviderOption> ExternalProviders { get; init; }

    /// <summary>
    /// Whether this deployment can send somebody a reset link, and therefore whether the page
    /// should offer one. <c>E-39</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Routed-or-absent, the same rule <c>N-06</c> applies to the metadata document.</b> It is
    /// false when <c>PasswordRecoveryEnabled</c> is off, and <c>/forgot</c> is not routed in that
    /// case — so a page drawing the link unconditionally would send somebody who has forgotten their
    /// password to a 404, which is the worst moment available to hand a person a dead end.
    /// </para>
    /// <para>
    /// <b><c>required</c>, like the three federation fields and for the reason given there.</b> A
    /// renderer built against the older shape does not quietly lose the link — it fails to compile,
    /// once, which is when the author can do something about it. This library has now shipped five
    /// capabilities that existed and could not be reached from a deployment; the cost of finding out
    /// is the whole argument for spending a compile error here.
    /// </para>
    /// </remarks>
    public required bool PasswordRecoveryEnabled { get; init; }

    /// <summary>
    /// This response's CSP nonce, or <see langword="null"/> when the deployment configured none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Put it on an inline <c>&lt;script&gt;</c> or <c>&lt;style&gt;</c> as
    /// <c>nonce="…"</c> and the browser runs it; leave it off and the browser refuses, whatever the
    /// element says. <see langword="null"/> means <c>InteractionOptions.UseContentSecurityPolicyNonce</c>
    /// is off and the page must have no inline content at all — the policy then has no
    /// <c>script-src</c>, so <c>default-src 'self'</c> governs and nothing inline runs.
    /// </para>
    /// <para>
    /// <b>Fresh for every response, and never to be cached, logged or reused.</b> A nonce that
    /// appears twice is a nonce an attacker can predict, which is the whole value gone. The pages
    /// send <c>Cache-Control: no-store</c>, which is what makes the per-response guarantee hold as
    /// far as the browser.
    /// </para>
    /// <para>
    /// <b>Required rather than optional, though most renderers will ignore it.</b> The failure it
    /// prevents is not a missing security field — it is a renderer author writing an inline script,
    /// watching the browser refuse it, and having nothing to point at. A compile error puts the
    /// property in front of them once, which is exactly when it is useful.
    /// </para>
    /// </remarks>
    public required string? Nonce { get; init; }
}

/// <summary>
/// Renders the two interactive pages.
/// </summary>
/// <remarks>
/// <para>
/// The one seam for the UI, and it takes a view model rather than a request: the model is the
/// server's, only the HTML is the customer's. A seam that handed over the request would let a
/// template decide what the user is told they are approving.
/// </para>
/// <para>
/// The shipped implementation is hand-written HTML with no Razor and no separate UI package. What
/// it must respect is the CSP this server sends — <c>default-src 'self'</c> with no
/// <c>style-src</c> or <c>script-src</c>, so both fall back to <c>'self'</c> and inline styles,
/// inline scripts and <c>data:</c> images are all blocked. A template that looks fine in isolation
/// and renders unstyled behind these headers is the predictable first surprise.
/// </para>
/// </remarks>
public interface IInteractionRenderer
{
    /// <summary>Render the consent page.</summary>
    string RenderConsent(ConsentViewModel model);

    /// <summary>Render the login page.</summary>
    string RenderLogin(LoginViewModel model);

    /// <summary>Render the sign-out page.</summary>
    /// <param name="model">Which of the two states to draw, and the form's fields.</param>
    /// <remarks>
    /// <para>
    /// <b>A default implementation, so adding a page to this interface does not break every
    /// deployment that has implemented it.</b> That is the whole reason it is a default member: a
    /// required one would turn every future page into a compile error in customer projects, and the
    /// choice between "never add a page" and "break everyone" is not one worth having.
    /// </para>
    /// <para>
    /// The default draws the library's page with the library's <i>unthemed</i> shell, because a
    /// default member has no dependency injection and therefore cannot reach the layout this
    /// deployment registered. That is a visible difference, on purpose: an implementation that has
    /// not written this page gets one that plainly does not match the others, which is the signal to
    /// write it. A deployment that replaced only <see cref="IInteractionLayout"/> never lands here —
    /// it is still using <see cref="DefaultInteractionRenderer"/>, which overrides this and wraps
    /// with the registered layout.
    /// </para>
    /// </remarks>
    string RenderLogout(LogoutViewModel model) => DefaultInteractionRenderer.Unthemed.RenderLogout(model);

    /// <summary>Render the authorization-error page.</summary>
    /// <param name="model">What went wrong, in the form a user may be shown.</param>
    /// <remarks>
    /// <para>
    /// A default member, for the reason <see cref="RenderLogout"/> gives.
    /// </para>
    /// <para>
    /// <b>This page is allowed to fail, and the caller expects it to.</b> It renders where something
    /// has already gone wrong — including "the server threw" — so the endpoint calls this inside a
    /// <c>try</c> and writes a built-in document if it throws. An implementation does not need to be
    /// defensive on its own account; it needs to know that being the second failure in a row is a
    /// state the server plans for rather than one it will crash in.
    /// </para>
    /// </remarks>
    string RenderError(ErrorViewModel model) => DefaultInteractionRenderer.Unthemed.RenderError(model);

    /// <summary>Render the self-service front page, <c>/me</c>.</summary>
    /// <param name="model">The account as the directory currently holds it.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderAccount(AccountPageModel model) => DefaultInteractionRenderer.Unthemed.RenderAccount(model);

    /// <summary>Render the self-service password page, <c>/me/password</c>.</summary>
    /// <param name="model">The form, and whatever the last attempt was refused for.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderChangePassword(ChangePasswordPageModel model) =>
        DefaultInteractionRenderer.Unthemed.RenderChangePassword(model);

    /// <summary>Render the self-service session list, <c>/me/sessions</c>.</summary>
    /// <param name="model">The sessions, each with the form that ends it.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderSessions(SessionsPageModel model) => DefaultInteractionRenderer.Unthemed.RenderSessions(model);

    /// <summary>Render the self-service list of approvals, <c>/me/consents</c>.</summary>
    /// <param name="model">The approvals, each with the form that withdraws it.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderConsents(ConsentsPageModel model) => DefaultInteractionRenderer.Unthemed.RenderConsents(model);

    /// <summary>Render the page a password-reset link lands on. <c>E-42</c>, <c>E-43</c>.</summary>
    /// <param name="model">The form, or what to say instead of one.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderResetPassword(ResetPasswordPageModel model) =>
        DefaultInteractionRenderer.Unthemed.RenderResetPassword(model);

    /// <summary>Render the page a verification link lands on. <c>E-44</c>.</summary>
    /// <param name="model">Whether it worked.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderVerifyEmail(VerifyEmailPageModel model) =>
        DefaultInteractionRenderer.Unthemed.RenderVerifyEmail(model);

    /// <summary>Render the page that asks for a reset link, <c>/forgot</c>. <c>E-39</c>.</summary>
    /// <param name="model">The form, or what to say instead of one.</param>
    /// <remarks>A default member, for the reason <see cref="RenderLogout"/> gives.</remarks>
    string RenderForgotPassword(ForgotPasswordPageModel model) =>
        DefaultInteractionRenderer.Unthemed.RenderForgotPassword(model);
}

/// <summary>What the forgot-password page is showing.</summary>
public enum ForgotPasswordState
{
    /// <summary>The form, waiting for a handle or an address.</summary>
    Form = 0,

    /// <summary>
    /// The request was accepted.
    /// </summary>
    /// <remarks>
    /// <b>Reached whether or not an account matched, and the sentence says so.</b> <c>S-48</c>: a
    /// page that answered differently for an unknown address would be a way to test which addresses
    /// are registered, at whatever rate the throttle allows. There is no <c>NotFound</c> state to
    /// render because the handler is never told.
    /// </remarks>
    Sent,

    /// <summary>
    /// Too many requests. §3.1.
    /// </summary>
    /// <remarks>
    /// Distinguished from <see cref="Sent"/> rather than folded into it, because the alternative is
    /// telling somebody mail is on its way when the server has decided not to send it — and that
    /// person then waits for something that will not arrive instead of trying again later. It is the
    /// same answer <c>E-39</c> gives a programmatic caller, which is where the trade was weighed:
    /// the counter is keyed on the submitted string precisely so it cannot separate a real
    /// identifier from an invented one.
    /// </remarks>
    Throttled,
}

/// <summary>
/// The page that asks for a reset link.
/// </summary>
/// <param name="State">Which of the three things to draw.</param>
/// <param name="AntiforgeryFieldName">The antiforgery field name for the form.</param>
/// <param name="AntiforgeryToken">The antiforgery token for the form.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <param name="SignInUrl">
/// Where "go to sign in" should point, or <see langword="null"/> when there is nowhere to send
/// them and the link should not be drawn at all.
/// </param>
/// <remarks>
/// <b>The submitted identifier is not carried back into the page.</b> Not for secrecy — the person
/// typed it — but because the field is an email address on a page that may be reached from a shared
/// machine, and because redrawing it would tempt a renderer into showing "we looked for X", which is
/// one sentence away from saying whether X was found.
/// </remarks>
public sealed record ForgotPasswordPageModel(
    ForgotPasswordState State,
    string AntiforgeryFieldName,
    string AntiforgeryToken,
    string? Nonce,
    string? SignInUrl);

/// <summary>What the reset page is showing.</summary>
public enum ResetPasswordState
{
    /// <summary>The form, waiting for a new password.</summary>
    Form = 0,

    /// <summary>The two copies did not match.</summary>
    Mismatch,

    /// <summary>The new password was blank.</summary>
    Blank,

    /// <summary>
    /// The link is expired, already used, or was never issued.
    /// </summary>
    /// <remarks>
    /// One state for all three, said plainly. §7.3: that is <b>not</b> the oracle <c>S-48</c> is
    /// about — a token is 256 bits of CSPRNG output, so there is nothing to enumerate — and a person
    /// who is not told their link has expired clicks it again rather than asking for a new one.
    /// </remarks>
    Expired,

    /// <summary>It worked.</summary>
    Done,
}

/// <summary>The page a password-reset link lands on.</summary>
/// <param name="State">Which of the five things to draw.</param>
/// <param name="Token">
/// The value out of the link, to be carried through the form as a hidden field.
/// </param>
/// <param name="SessionsRevoked">How many sessions ended. Read only when done.</param>
/// <param name="AntiforgeryFieldName">The antiforgery field name for the form.</param>
/// <param name="AntiforgeryToken">The antiforgery token for the form.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <param name="SignInUrl">
/// Where "go to sign in" should point after a successful reset, or <see langword="null"/> when
/// there is nowhere to send them and the link should not be drawn at all.
/// </param>
/// <remarks>
/// <b>The token travels in a hidden field rather than in the form's action.</b> A query string is
/// written to access logs, kept in browser history and sent in <c>Referer</c> to anything the page
/// loads — and this one is a live credential for the account. It arrives in the URL because a link
/// in an email has nowhere else to put it; it does not have to stay there.
/// </remarks>
public sealed record ResetPasswordPageModel(
    ResetPasswordState State,
    string Token,
    int SessionsRevoked,
    string AntiforgeryFieldName,
    string AntiforgeryToken,
    string? Nonce,
    string? SignInUrl);

/// <summary>The page a verification link lands on.</summary>
/// <param name="Verified">Whether the address is now recorded as proven.</param>
/// <param name="Email">Which address, when one was verified.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <remarks>
/// <b>No form and no button: the link itself is the action.</b> A confirmation step would be the
/// right shape for something destructive, and this is the opposite — the worst outcome of following
/// a verification link is that an address somebody already controls is marked as theirs.
/// </remarks>
public sealed record VerifyEmailPageModel(bool Verified, string? Email, string? Nonce);

/// <summary>
/// The self-service front page.
/// </summary>
/// <remarks>
/// <b>No password hash and no session count.</b> The first for the reason no surface here carries
/// one; the second because a number that is wrong by the time it renders invites a reader to trust
/// it — <c>/me/sessions</c> is one click away and is the page that knows.
/// </remarks>
/// <summary>
/// One upstream provider this account may be linked to, as <c>/me</c> must present it.
/// </summary>
/// <param name="Scheme">The provider's route segment.</param>
/// <param name="DisplayName">What the button says. Plain text; the renderer encodes.</param>
/// <param name="LinkUrl">The local path the form posts to, computed by the server.</param>
/// <param name="Linked">Whether this account already holds an identity from this provider.</param>
/// <remarks>
/// <para>
/// <b><paramref name="Linked"/> shipped as an absence first, and the absence was the defect.</b>
/// The page could offer to connect a provider and could not say whether connecting had already
/// happened, so a founder pressed the button, the round trip succeeded, the page came back
/// identical, and nothing anywhere told them it had worked. Closing it needed
/// <c>IUserStore.ListExternalLoginsAsync</c> — a method every implementation has to grow, which is
/// why it was a limitation for a day rather than a line.
/// </para>
/// <para>
/// Matched on the provider's issuer and not on its scheme: a link is stored as
/// <c>(issuer, upstream subject)</c>, and a scheme is this server's routing name, which could be
/// renamed under a directory that would then quietly report every account as unlinked.
/// </para>
/// </remarks>
public sealed record AccountProviderLink(string Scheme, string DisplayName, string LinkUrl, bool Linked);

/// <param name="Handle">What they type at the sign-in page.</param>
/// <param name="Email">Their address, if the directory has one.</param>
/// <param name="EmailVerified">Whether it has been proven.</param>
/// <param name="Roles">What their tokens claim, if anything. Every one the account holds, in id order.</param>
/// <param name="HasPassword">Whether a password exists here at all — not what it is.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <param name="Providers">
/// The upstream providers configured here, or empty when there are none. Empty is the ordinary case
/// for a deployment with no federation, and the section is absent rather than empty.
/// </param>
/// <param name="AntiforgeryFieldName">The antiforgery field name for the link forms.</param>
/// <param name="AntiforgeryToken">The antiforgery token value.</param>
/// <param name="SignOutUrl">
/// Where "sign out" points, and <see langword="null"/> for a deployment that has not enabled the
/// end-session page. Nullable rather than a constant path for the reason the whole page is built
/// on: <c>/logout</c> is only routed when <c>EndSessionEnabled</c> is set, so a renderer that
/// always drew the link would send anyone who trusted it to a 404 — on the one page whose job is
/// to tell a person what they can do about their own account.
/// </param>
/// <param name="VerifyEmailUrl">
/// Where "send me a confirmation link" posts, and <see langword="null"/> when there is nothing to
/// offer. Nullable for the same reason as <paramref name="SignOutUrl"/> and then some: the endpoint
/// is only routed when the deployment has a mail sender, and the button is only worth drawing when
/// there is an address that is not already proven. The endpoint decides all three and hands the
/// answer down, so the renderer stays a function of its model.
/// </param>
/// <param name="VerificationNotice">
/// What to say about the last press of that button, if there was one. Distinct from
/// <paramref name="EmailVerified"/>, which stays false until somebody opens the link — the two
/// together are what let the page say "check your mail" rather than repeating the offer.
/// </param>
public sealed record AccountPageModel(
    string Handle,
    string? Email,
    bool EmailVerified,
    IReadOnlyList<string> Roles,
    bool HasPassword,
    string? Nonce,
    IReadOnlyList<AccountProviderLink> Providers,
    string AntiforgeryFieldName,
    string AntiforgeryToken,
    string? SignOutUrl,
    string? VerifyEmailUrl = null,
    EmailVerificationNotice VerificationNotice = EmailVerificationNotice.None);

/// <summary>What the account page says about the last request for a confirmation link.</summary>
/// <remarks>
/// An enum rather than two booleans, the same shape <see cref="ChangePasswordProblem"/> uses and for the
/// same reason: the states are mutually exclusive, and a pair of flags is a way to write a page that
/// says two contradictory things at once.
/// </remarks>
public enum EmailVerificationNotice
{
    /// <summary>Nothing was asked for, so nothing is said.</summary>
    None = 0,

    /// <summary>A link is on its way. Not "the address is confirmed" — nobody has opened it yet.</summary>
    Sent,

    /// <summary>
    /// Asked too often. Said rather than swallowed.
    /// </summary>
    /// <remarks>
    /// A page that ignores a press looks broken, and the person's next move is to press it again —
    /// which is the thing the throttle is there to stop.
    /// </remarks>
    TooSoon,
}

/// <summary>Why a password change was refused, for the page to say so.</summary>
public enum ChangePasswordProblem
{
    /// <summary>It was not refused. Either nothing has been submitted yet, or it worked.</summary>
    None = 0,

    /// <summary>The current password did not verify. <c>S-49</c>.</summary>
    WrongPassword,

    /// <summary>The two copies of the new password did not match.</summary>
    Mismatch,

    /// <summary>The new password was blank.</summary>
    Blank,

    /// <summary>
    /// The account signs in through an upstream provider and has no password here.
    /// </summary>
    NoPassword,
}

/// <summary>
/// The self-service password page.
/// </summary>
/// <param name="Problem">What to say about the last attempt, if there was one.</param>
/// <param name="Changed">Whether the password was just changed. Mutually exclusive with a problem.</param>
/// <param name="SessionsRevoked">
/// How many sessions ended on the way, when the person asked for that. Read only when
/// <paramref name="Changed"/>.
/// </param>
/// <param name="AntiforgeryFieldName">The antiforgery field name for the form.</param>
/// <param name="AntiforgeryToken">The antiforgery token for the form.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <remarks>
/// <b>The form is redrawn on every refusal, and it is always empty.</b> Repopulating a password
/// field means the value is in the HTML of a page that a proxy may cache and a browser will keep in
/// history — and the person retyping it is the only cost of not doing so.
/// </remarks>
public sealed record ChangePasswordPageModel(
    ChangePasswordProblem Problem,
    bool Changed,
    int SessionsRevoked,
    string AntiforgeryFieldName,
    string AntiforgeryToken,
    string? Nonce);

/// <summary>
/// One session, as the page draws it.
/// </summary>
/// <param name="Id">The grant id, which the end-this-one form posts back.</param>
/// <param name="ClientId">Which client holds it. Plain text; the renderer encodes.</param>
/// <param name="ClientHost">
/// The host of <paramref name="ClientId"/> when it is a URL, and the id itself when it is not.
/// </param>
/// <param name="Scopes">What it may do, <b>described the way it was described when approved</b>.</param>
/// <param name="Resources">Which resources it may reach.</param>
/// <param name="CreatedAt">When it was authorized.</param>
/// <remarks>
/// <b>Deliberately the same shape as <see cref="ConsentLine"/>, minus the id.</b> This carried a
/// wire scope string for a release, and the result was measured on a Vietnamese deployment: the
/// approvals page read "Đọc cơ sở tri thức của công ty" and the sessions page read
/// <c>email kb:read kb:write offline_access openid</c> — the same permissions, to the same person,
/// on two pages one click apart. The person deciding whether to end a session is making the same
/// judgement they made on the consent page, so they need the same words, and
/// <see cref="ConsentModelBuilder.Describe"/> is now the single place either page gets them.
/// </remarks>
/// <param name="LastRefreshedAt">
/// When this session last renewed its access, or <see langword="null"/> if it never has.
/// </param>
/// <param name="Device">
/// The browser this session was approved from, already described, or <see langword="null"/>.
/// </param>
/// <remarks>
/// <para>
/// <b><paramref name="LastRefreshedAt"/> is the last time the grant minted a refresh token, and it
/// is not "last active".</b> Access tokens are signed rather than looked up, so a request made with
/// one this server already issued never reaches this process: somebody can work for half an hour
/// without moving this value, and the value can move with nobody at the keyboard, because renewal
/// is a timer inside the client. It is the strongest liveness signal available here, and the page
/// has to say which of the two it is showing.
/// </para>
/// <para>
/// <b>Null renders as nothing rather than as "never".</b> A grant authorized minutes ago has not
/// refreshed yet and is perfectly healthy, so a row reading "never renewed" would report ordinary
/// freshness as an anomaly on the page people come to when they are already suspicious.
/// </para>
/// <para>
/// <b><paramref name="Device"/> is described here rather than in the renderer</b>, like
/// <paramref name="ClientHost"/> beside it and for the same reason: a themed renderer is then a
/// function of its model and can be tested without a server. <c>ApprovingDevice.Describe</c> does
/// the describing, and it falls back to the raw header rather than inventing a name. Null on every
/// grant older than the column, and on any browser that sent no header — rendered as nothing,
/// because a row reading "unknown device" says less than a row that does not mention one.
/// </para>
/// </remarks>
public sealed record SessionLine(
    string Id,
    string ClientId,
    string ClientHost,
    IReadOnlyList<ConsentScope> Scopes,
    IReadOnlyList<string> Resources,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastRefreshedAt = null,
    string? Device = null);

/// <summary>
/// The self-service session list.
/// </summary>
/// <param name="Sessions">Every live session, newest first. Empty is an ordinary state.</param>
/// <param name="Ended">Whether one was just ended, so the page can say so.</param>
/// <param name="AntiforgeryFieldName">The antiforgery field name for the forms.</param>
/// <param name="AntiforgeryToken">The antiforgery token for the forms.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <param name="AccessTokenLifetime">
/// How long an access token this server issues stays valid, which is the ceiling on how long an
/// application that never re-checks keeps access after its session is ended.
/// </param>
/// <param name="Confirming">
/// Whether the reader has asked to end everything and is being asked whether they meant it.
/// </param>
/// <param name="EndedAll">
/// How many were ended by the control that ends them all, or <see langword="null"/> when it has
/// not just run. Zero is a real answer and is not <see langword="null"/>: somebody who pressed it
/// on an account with nothing to cut has still had their question answered.
/// </param>
/// <remarks>
/// <para>
/// <b>The list does not mark which one the reader is using.</b> Working that out means matching the
/// browser's cookie session against a grant, and the two are different things — a person signed in
/// here may hold no grant at all. Guessing would put "this device" against the wrong row, which is
/// worse than not saying.
/// </para>
/// <para>
/// <b>Ending everything is two round trips, and the second one is not a formality.</b> Every other
/// control on this page ends one session, which a reader can undo by approving again; this one ends
/// all of them, including the application they are reading the page in. The confirmation is drawn
/// on this page rather than on one of its own so that the list of what is about to be cut is still
/// in front of them while they answer — a separate page would ask the question with the evidence
/// out of sight.
/// </para>
/// <para>
/// <b><paramref name="AccessTokenLifetime"/> is on the model rather than read by the renderer</b>,
/// for the reason every other value here is: the renderer is a seam a deployment replaces, and a
/// replacement that had to fetch the options itself to say a true sentence is one that will say a
/// false one instead. It is the configured value, not a constant — see
/// <see cref="InteractionText.SessionsTokens"/> for what a constant cost.
/// </para>
/// </remarks>
public sealed record SessionsPageModel(
    IReadOnlyList<SessionLine> Sessions,
    bool Ended,
    string AntiforgeryFieldName,
    string AntiforgeryToken,
    string? Nonce,
    TimeSpan AccessTokenLifetime,
    bool Confirming = false,
    int? EndedAll = null);

/// <summary>One standing approval, as the page draws it.</summary>
/// <param name="ClientId">Who was approved. Plain text; the renderer encodes.</param>
/// <param name="ClientHost">
/// The host of <paramref name="ClientId"/> when it is a URL, and the id itself when it is not.
/// </param>
/// <param name="Scopes">
/// What was approved, <b>described the way the consent page described it</b>. Built by
/// <see cref="ConsentModelBuilder.Describe"/>, which is also what <see cref="SessionLine"/> uses.
/// </param>
/// <param name="Resources">Which resources it covers.</param>
/// <param name="GrantedAt">When it was last approved.</param>
/// <remarks>
/// <para>
/// <b>The scopes are <see cref="ConsentScope"/>s, not a wire string, and that is the point of the
/// page.</b> A person agreed to "Read every account"; showing them <c>users:read</c> here asks them
/// to re-derive what they agreed to from a token nobody promised was readable. A-14 applies for the
/// same reason it applies on the consent page — the description is configured or it is absent, and
/// an absent one renders as the raw scope with a warning rather than as a guess.
/// </para>
/// <para>
/// <b><paramref name="ClientHost"/> is computed here rather than left to the renderer</b>, the same
/// way <c>ConsentViewModel.ClientHost</c> is: it is the client's real identity, an IDN A-label, and
/// a template deriving it with <c>new Uri(id).Host</c> would render the Unicode form — which is the
/// homograph N-14's display requirement exists to defeat.
/// </para>
/// </remarks>
public sealed record ConsentLine(
    string ClientId,
    string ClientHost,
    IReadOnlyList<ConsentScope> Scopes,
    IReadOnlyList<string> Resources,
    DateTimeOffset GrantedAt);

/// <summary>
/// The self-service list of standing approvals.
/// </summary>
/// <param name="Consents">Every approval on record. Empty is an ordinary state.</param>
/// <param name="Withdrawn">Whether one was just withdrawn, so the page can say so.</param>
/// <param name="AntiforgeryFieldName">The antiforgery field name for the forms.</param>
/// <param name="AntiforgeryToken">The antiforgery token for the forms.</param>
/// <param name="Nonce">The CSP nonce for this response, when the deployment has them on.</param>
/// <remarks>
/// <b>Withdrawing an approval is not ending a session, and the page must say which one it did.</b>
/// <c>E-38</c> settles the behaviour — the approval is forgotten so the next authorization asks
/// again, and access already granted keeps working — and a page that performed that silently would
/// leave a person believing they had cut something off. The list and <c>/me/sessions</c> are two
/// different questions about the same client, and the honest answer here links to the other.
/// </remarks>
public sealed record ConsentsPageModel(
    IReadOnlyList<ConsentLine> Consents,
    bool Withdrawn,
    string AntiforgeryFieldName,
    string AntiforgeryToken,
    string? Nonce);

/// <summary>
/// The authorization-error page.
/// </summary>
/// <remarks>
/// Every field here has already been through <c>ErrorText.Safe</c>, and a renderer must encode it
/// anyway: "already filtered" is a property of the current call sites rather than of the type, and
/// this is the page most likely to be reached by input nobody predicted.
/// </remarks>
public sealed record ErrorViewModel
{
    /// <summary>
    /// The OAuth error code, or <see langword="null"/> when the refusal has none.
    /// </summary>
    /// <remarks>
    /// Null rather than empty, and a renderer should omit the element rather than draw an empty one.
    /// <c>X-31</c> is the one refusal with no code, and a blank <c>&lt;code&gt;&lt;/code&gt;</c>
    /// reads as a value that failed to load rather than one that was never there.
    /// </remarks>
    public required string? Code { get; init; }

    /// <summary>
    /// What went wrong, in the words the client was given. <b>English, and <c>A-12</c> requires it
    /// on the page.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Not localizable, and the reason is a spec rule rather than an omission.</b> This is the
    /// <c>error_description</c>, and OAuth 2.1 §4.1.2.1 restricts it to
    /// <c>%x20-21 / %x23-5B / %x5D-7E</c> — <c>ErrorText.Safe</c> drops everything else, so a
    /// Vietnamese sentence put here would arrive as its ASCII fragments. It is written for whoever
    /// is integrating a client, and <c>A-12</c> says it must be in the body so that <c>curl -D-</c>
    /// is a sufficient debugging tool.
    /// </para>
    /// <para>
    /// <b>Which is why it is not the sentence a user reads.</b> That is <see cref="Guidance"/>. A
    /// renderer shows both: the guidance first and prominently, this subordinate to it and marked as
    /// the developer's half — see <see cref="InteractionText.ErrorDeveloperDetail"/>.
    /// </para>
    /// </remarks>
    public required string Description { get; init; }

    /// <summary>
    /// What the person reading this page can do about it. <b>Localized.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// Chosen by <see cref="InteractionText.ErrorSentenceFor"/> from the refusal's reason code, and
    /// already resolved through the deployment's localizer — so a renderer displays it and does not
    /// have to know the mapping exists.
    /// </para>
    /// <para>
    /// <b>Grouped by remedy, not by cause.</b> Twenty-six reason codes reach this page and there are
    /// five things a reader can do about any of them. That is a deliberate loss of precision on the
    /// page and no loss anywhere else: the exact reason, its requirement id, this description and
    /// the private detail are all on the log line the correlation id joins to.
    /// </para>
    /// <para>
    /// <b><c>required</c>, like <c>LoginViewModel</c>'s fields and for the same reason.</b> A
    /// renderer written against the older shape does not quietly show a page whose only sentence is
    /// in a language its readers do not use — it fails to compile, once.
    /// </para>
    /// </remarks>
    public required string Guidance { get; init; }

    /// <summary>The correlation id, which is what a support conversation is keyed on.</summary>
    public required string CorrelationId { get; init; }

    /// <summary>The CSP nonce for this response, when the deployment has them on.</summary>
    public required string? Nonce { get; init; }
}

/// <summary>Which half of the sign-out page to draw.</summary>
public enum LogoutState
{
    /// <summary>There is a session, and the user has not yet said to end it.</summary>
    ConfirmationNeeded,

    /// <summary>There is no session — either it has just been ended, or there never was one.</summary>
    SignedOut,
}

/// <summary>
/// The sign-out page.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two states, one page, and the confirmation is not politeness.</b> A <c>GET</c> that ends a
/// session is a session-ending link anybody can put in an <c>&lt;img&gt;</c> tag — logout CSRF,
/// which is a denial of service against a person rather than against a server, and the reason OIDC
/// RP-Initiated Logout says the provider SHOULD ask. So the <c>GET</c> draws a form and the
/// <c>POST</c> carries an antiforgery token like the other two on this origin.
/// </para>
/// <para>
/// <b>There is no return URL and no <c>post_logout_redirect_uri</c>.</b> A redirect target supplied
/// by the caller is an open redirector on the issuer's own hostname unless it is matched against
/// something registered, and nothing here registers one yet. The specification permits refusing to
/// redirect — it is a MUST NOT unless the URI has been validated — so the page ends the session and
/// says so, rather than sending the browser somewhere it was told to.
/// </para>
/// </remarks>
public sealed record LogoutViewModel
{
    /// <summary>Whether to draw the confirmation or the answer.</summary>
    public required LogoutState State { get; init; }

    /// <summary>The antiforgery field name for the confirmation form.</summary>
    public required string AntiforgeryFieldName { get; init; }

    /// <summary>The antiforgery token for the confirmation form.</summary>
    public required string AntiforgeryToken { get; init; }

    /// <summary>The CSP nonce for this response, when the deployment has them on.</summary>
    public required string? Nonce { get; init; }

    /// <summary>
    /// Where "go to sign in" points once the session is over, or <see langword="null"/> for no link.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured on a running deployment: this page had no link of any kind, <c>/</c> answered
    /// <c>404</c> and <c>/login</c> answered <c>400</c>, so signing out was a one-way door — the
    /// two URLs a person would then type were both dead ends, on the server that holds their
    /// account.
    /// </para>
    /// <para>
    /// <c>required</c>, so the change reached every construction site rather than defaulting the
    /// two that already existed back to the behaviour being fixed. Null when the self-service pages
    /// are not routed: <c>/authorize</c> needs a request in flight, so with them off there is
    /// genuinely nowhere for a standalone arrival to go, and a link onto an error page is worse
    /// than no link.
    /// </para>
    /// </remarks>
    public required string? SignInUrl { get; init; }
}

/// <summary>Builds a <see cref="ConsentViewModel"/> from a resolved client and request.</summary>
internal static class ConsentModelBuilder
{
    /// <summary>
    /// The scopes, in the words the deployment configured for them.
    /// </summary>
    /// <param name="scopes">The scope values, in the order they should be read.</param>
    /// <param name="options">Where the descriptions come from.</param>
    /// <remarks>
    /// <para>
    /// <b>One function, because three pages describe scopes and they must not describe them
    /// differently.</b> The consent page asks for a decision, <c>/me/consents</c> shows the decision
    /// that was made, and <c>/me/sessions</c> shows what it is currently granting — the same
    /// permissions three times, to the same person. This existed as three copies for exactly as
    /// long as it took to notice that one of them was rendering the wire scope.
    /// </para>
    /// <para>
    /// <b>A-14 lives here now.</b> A scope with no configured description keeps its raw value and is
    /// flagged, never given text derived from its name, and that is decided once rather than by
    /// each caller remembering. The flag matters more away from the consent page: a description can
    /// be removed from configuration <i>after</i> an approval that used it, so the pages showing
    /// history can be asked to describe an agreement whose words no longer exist.
    /// </para>
    /// </remarks>
    internal static IReadOnlyList<ConsentScope> Describe(
        IEnumerable<string> scopes, Configuration.AuthorizationServerOptions options) =>
        [.. scopes.Select(s => new ConsentScope(
            s,
            options.ScopeDescriptions.TryGetValue(s, out var description) ? description : s,
            options.ScopeDescriptions.ContainsKey(s)))];

    /// <summary>How much of a self-asserted name is rendered.</summary>
    /// <remarks>
    /// Capped because it is attacker-chosen text on a page whose whole job is to be read carefully.
    /// A name long enough to push the hostname off the screen defeats the display requirement
    /// without breaking any rule about the characters in it.
    /// </remarks>
    internal const int MaxClientNameLength = 64;

    /// <summary>
    /// What to show the user as "where this goes".
    /// </summary>
    /// <remarks>
    /// <para>
    /// A private-use-scheme redirect (RFC 8252 §7.1, <c>com.example.app:/oauth2redirect</c>) has no
    /// authority component, so <c>Uri.Host</c> is the empty string. That rendered as
    /// <c>the code will be sent to &lt;strong&gt;&lt;/strong&gt;</c> — measured — and since
    /// <c>LoopbackOnly</c> is false for that kind, the client class got no destination and no
    /// warning at all. This field is described as "the only thing that can be shown" against an
    /// attack CIMD structurally cannot prevent, and for native apps it was showing nothing.
    /// </para>
    /// <para>
    /// The scheme is the right answer there, because for a private-use scheme the scheme <i>is</i>
    /// the identity: §7.1 requires it to be a reverse-DNS name the app controls, and it is what the
    /// operating system dispatches on.
    /// </para>
    /// </remarks>
    internal static string HostOf(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed))
        {
            // Not parseable, so show it whole rather than silently showing nothing. Registered
            // redirect URIs have already been through RegisteredRedirectUri, so reaching here means
            // something upstream changed and a visibly odd line is better than a blank one.
            return url;
        }

        // IdnHost, not Host. `Uri.Host` returns the Unicode form, and a review reproduced the
        // consequence end to end: the client_id line rendered `xn--80ak6aa92e.com` while the
        // redirect line rendered `аррӏе.com` — one origin, two alphabets, the second reading as
        // apple.com to any human. `ClientIdentifier.TryParseFromRequest` bans everything outside
        // %x20-7E so the client_id side is always an A-label, and U-17's same-origin check compares
        // `IdnHost`, so the two spellings are the same origin and that guard never fires.
        //
        // A-labels for everything is the only self-consistent choice here. N-14 names this display
        // as the mitigation for a self-asserted client name, and a mitigation rendered in a script
        // the attacker chose is not one — browsers show punycode in the address bar for this exact
        // reason.
        return string.IsNullOrEmpty(parsed.IdnHost) ? parsed.Scheme : parsed.IdnHost;
    }

    /// <summary>
    /// The self-asserted name, capped. <b>Plain text — the renderer encodes.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// This used to HTML-encode, on the reasoning that a customer's renderer could then not forget
    /// to. The shipped renderer encodes every value it writes, so the name was encoded twice, and a
    /// review measured the result: <c>Acme &amp; "Claude" &lt;b&gt;Inc&lt;/b&gt;</c> displayed
    /// literally as <c>Acme &amp;amp; &amp;quot;Claude&amp;quot; …</c>, and <c>Café</c> as
    /// <c>Caf&amp;#233;</c> — mojibake on the one page whose entire job is to be read carefully.
    /// </para>
    /// <para>
    /// It also broke the cap. <see cref="MaxClientNameLength"/> is applied to the raw name, but
    /// double-encoding expands each <c>&lt;</c> to six rendered characters, so a 64-character name
    /// of angle brackets displayed as ~256 — roughly four times what the cap intends, against a
    /// rationale that is specifically about a name long enough to push the hostname off the screen.
    /// </para>
    /// <para>
    /// Pre-encoding one field was the worse trade in the end: it made the model inconsistent, so a
    /// custom renderer doing the obviously correct thing — encode everything — corrupts exactly this
    /// field and nothing else. Every string on the model is now plain text, uniformly, which is a
    /// contract a renderer can follow without knowing which fields are special.
    /// </para>
    /// </remarks>
    internal static string? SafeName(ClientRecord client)
    {
        if (string.IsNullOrWhiteSpace(client.ClientName))
        {
            return null;
        }

        return client.ClientName.Length <= MaxClientNameLength
            ? client.ClientName
            : client.ClientName[..(MaxClientNameLength - 1)] + "…";
    }

    /// <summary>
    /// Where the consent page asks this server for the client's logo, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Null unless the client published both a logo and a name</b>, and the name is the reason.
    /// The logo is a self-assertion, and the only sentence on the page that says so is the one
    /// attached to the name — so a logo without a name would be the strongest claim on the page
    /// with no caveat anywhere near it. Refusing to draw it is cheaper than inventing a second
    /// caveat for a case almost no client is in.
    /// </para>
    /// <para>
    /// The <c>client_id</c> is escaped as a query value here rather than at the renderer, because
    /// every other string on the model is plain text that the renderer encodes for HTML — and a URL
    /// needs percent-encoding, which is a different operation. Doing both is how <c>&amp;</c> in a
    /// CIMD identifier becomes <c>&amp;amp;</c> in a query string and the endpoint sees a different
    /// client. This one value is therefore URL-ready and HTML-unsafe, the same as any other
    /// attribute value the renderer encodes on its way out.
    /// </para>
    /// </remarks>
    internal static string? LogoUrl(ClientRecord client)
    {
        if (string.IsNullOrWhiteSpace(client.LogoUri) || string.IsNullOrWhiteSpace(client.ClientName))
        {
            return null;
        }

        return Configuration.AuthorizationServerPaths.ClientLogo
            + "?client_id=" + Uri.EscapeDataString(client.ClientId.Value);
    }
}
