using System.Net;
using Boltway.OAuth.Primitives.Diagnostics;
using Microsoft.Extensions.Localization;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// Every sentence the shipped pages say, and how a deployment replaces one.
/// </summary>
/// <remarks>
/// <para>
/// <b>Constants rather than a <c>.resx</c>, and the difference is the fallback.</b> The design asked
/// for a neutral resource file, and measured against .NET 10 that would work — a key missing from
/// <c>vi</c> resolves to the neutral value, not to the key. What it also brings is satellite
/// assemblies, which belong to the assembly owning the resx, so a customer still cannot add a
/// language to <i>ours</i>. Since the override route is a registered
/// <see cref="IStringLocalizerFactory"/> either way, the resx would have bought a packaging story
/// and no capability. English lives here, and a missing translation falls back to it explicitly
/// rather than through a resource chain.
/// </para>
/// <para>
/// <b>A translation can never introduce markup.</b> <see cref="Format"/> HTML-encodes the string it
/// gets back from the localizer and then splices already-safe HTML into the <c>{0}</c> placeholders.
/// So a deployment supplies sentences, this file supplies structure, and a translation containing
/// <c>&lt;script&gt;</c> renders as the text somebody typed. Braces survive encoding, which is what
/// makes the order work.
/// </para>
/// <para>
/// <b>Whole sentences, not fragments.</b> "The application at {0} is asking to access your account"
/// is one key rather than three, because word order is not a property every language shares — a page
/// assembled from translated fragments in English order reads as machine output in most of them.
/// </para>
/// </remarks>
public static class InteractionText
{
    /// <summary>The consent page's title.</summary>
    public const string ConsentTitle = nameof(ConsentTitle);

    /// <summary>Who is asking. <c>{0}</c> is the client's hostname.</summary>
    public const string ConsentClientAsking = nameof(ConsentClientAsking);

    /// <summary>The client's self-asserted name. <c>{0}</c> is the name.</summary>
    public const string ConsentNameClaim = nameof(ConsentNameClaim);

    /// <summary>The qualification N-14 requires beside a self-asserted name.</summary>
    public const string ConsentNameUnverified = nameof(ConsentNameUnverified);

    /// <summary>Where the code goes. <c>{0}</c> is the redirect hostname.</summary>
    public const string ConsentCodeGoesTo = nameof(ConsentCodeGoesTo);

    /// <summary>The loopback warning's emphasised half.</summary>
    public const string ConsentDeviceWarning = nameof(ConsentDeviceWarning);

    /// <summary>The loopback warning's instruction.</summary>
    public const string ConsentDeviceWarningAdvice = nameof(ConsentDeviceWarningAdvice);

    /// <summary>The heading above the scope list.</summary>
    public const string ConsentScopesHeading = nameof(ConsentScopesHeading);

    /// <summary>A-14's warning beside a scope nobody described.</summary>
    public const string ConsentScopeUndescribed = nameof(ConsentScopeUndescribed);

    /// <summary>The heading above the resource list.</summary>
    public const string ConsentResourcesHeading = nameof(ConsentResourcesHeading);

    /// <summary>The approve control.</summary>
    public const string ConsentApprove = nameof(ConsentApprove);

    /// <summary>The deny control.</summary>
    public const string ConsentDeny = nameof(ConsentDeny);

    /// <summary>The sign-in page's title and heading.</summary>
    public const string LoginTitle = nameof(LoginTitle);

    /// <summary>
    /// The first field's label: a handle, or an address the account has proved it controls.
    /// </summary>
    /// <remarks>
    /// The key keeps its name while the sentence changed, and that is deliberate: the constant's
    /// value <i>is</i> the lookup key, so renaming it would silently drop every deployment's
    /// translation of this line to the English fallback — a page that goes half-English on upgrade,
    /// which is the failure a translated deployment is least able to see.
    /// <para>
    /// A deployment whose accounts have no addresses should translate this back to "Username". The
    /// label describes what the form accepts, and what it accepts is a property of the data.
    /// </para>
    /// </remarks>
    public const string LoginUsername = nameof(LoginUsername);

    /// <summary>The password field's label.</summary>
    public const string LoginPassword = nameof(LoginPassword);

    /// <summary>Heading for the section that links an upstream account.</summary>
    public const string AccountLinkHeading = nameof(AccountLinkHeading);

    /// <summary>The link button. <c>{0}</c> is the provider's display name.</summary>
    public const string AccountLinkProvider = nameof(AccountLinkProvider);

    /// <summary>
    /// Said beside a provider this account already holds. <c>{0}</c> is the display name.
    /// </summary>
    /// <remarks>
    /// A statement and not a button, because there is nothing to press: unlinking is a separate
    /// decision this page does not offer, and a control that looks like one and is not would be
    /// worse than the sentence.
    /// </remarks>
    public const string AccountLinked = nameof(AccountLinked);

    /// <summary>
    /// What linking is for, said once above the buttons.
    /// </summary>
    /// <remarks>
    /// Worth a sentence because the button alone reads as "sign in with Google" — which is what the
    /// other page's button does, and this one does something different to an account that already
    /// exists.
    /// </remarks>
    public const string AccountLinkExplanation = nameof(AccountLinkExplanation);

    /// <summary>
    /// The one thing a refused sign-in says, whatever was wrong with it.
    /// </summary>
    /// <remarks>
    /// One key because there is one sentence, and there is one sentence because two would say
    /// whether the account exists. A translation must keep that: rendering "sai mật khẩu" here
    /// would turn the form into a directory of who has an account, in a language the reviewer of
    /// the English text cannot read.
    /// </remarks>
    public const string LoginRejected = nameof(LoginRejected);

    /// <summary>The submit control.</summary>
    public const string LoginSubmit = nameof(LoginSubmit);

    /// <summary>A federated provider's button. <c>{0}</c> is the provider's display name.</summary>
    public const string LoginWithProvider = nameof(LoginWithProvider);

    /// <summary>What the page says when a deployment configured no way in at all.</summary>
    public const string LoginNoMethod = nameof(LoginNoMethod);

    /// <summary>The sign-out confirmation's title and heading.</summary>
    public const string LogoutTitle = nameof(LogoutTitle);

    /// <summary>The question the confirmation asks.</summary>
    public const string LogoutQuestion = nameof(LogoutQuestion);

    /// <summary>The confirmation's submit control.</summary>
    public const string LogoutSubmit = nameof(LogoutSubmit);

    /// <summary>The signed-out page's title and heading.</summary>
    public const string LogoutDoneTitle = nameof(LogoutDoneTitle);

    /// <summary>What the signed-out page says happened.</summary>
    public const string LogoutDoneBody = nameof(LogoutDoneBody);

    /// <summary>That signing out here revokes no token already issued.</summary>
    public const string LogoutDoneTokens = nameof(LogoutDoneTokens);

    /// <summary>The self-service front page's title and heading.</summary>
    public const string AccountTitle = nameof(AccountTitle);

    /// <summary>The label beside the handle.</summary>
    public const string AccountHandle = nameof(AccountHandle);

    /// <summary>The label beside the email address.</summary>
    public const string AccountEmail = nameof(AccountEmail);

    /// <summary>What is shown where an address would be, when there is none.</summary>
    public const string AccountEmailNone = nameof(AccountEmailNone);

    /// <summary>The qualification beside an address nobody has proven.</summary>
    public const string AccountEmailUnverified = nameof(AccountEmailUnverified);

    /// <summary>The button that asks for a confirmation link.</summary>
    public const string AccountVerifyEmail = nameof(AccountVerifyEmail);

    /// <summary>
    /// What is said after one has been sent.
    /// </summary>
    /// <remarks>
    /// Deliberately about the mail rather than about the address: nothing is proven until somebody
    /// opens the link, and a sentence saying the address is confirmed would be wrong for as long as
    /// it takes to walk to the inbox.
    /// </remarks>
    public const string AccountVerifyEmailSent = nameof(AccountVerifyEmailSent);

    /// <summary>What is said when the link was asked for too often.</summary>
    public const string AccountVerifyEmailTooSoon = nameof(AccountVerifyEmailTooSoon);

    /// <summary>The label beside the role.</summary>
    public const string AccountRole = nameof(AccountRole);

    /// <summary>The link to the password page.</summary>
    public const string AccountChangePassword = nameof(AccountChangePassword);

    /// <summary>The link to the session list.</summary>
    public const string AccountSessions = nameof(AccountSessions);

    /// <summary>What the front page says instead of offering a password change.</summary>
    public const string AccountNoPassword = nameof(AccountNoPassword);

    /// <summary>The password page's title and heading.</summary>
    public const string PasswordTitle = nameof(PasswordTitle);

    /// <summary>The current-password field's label.</summary>
    public const string PasswordCurrent = nameof(PasswordCurrent);

    /// <summary>The new-password field's label.</summary>
    public const string PasswordNew = nameof(PasswordNew);

    /// <summary>The confirm-password field's label.</summary>
    public const string PasswordConfirm = nameof(PasswordConfirm);

    /// <summary>The label on the option that ends every other session.</summary>
    public const string PasswordRevokeSessions = nameof(PasswordRevokeSessions);

    /// <summary>The submit control.</summary>
    public const string PasswordSubmit = nameof(PasswordSubmit);

    /// <summary>What the page says when the change worked.</summary>
    public const string PasswordChanged = nameof(PasswordChanged);

    /// <summary>What it adds when sessions were ended too. <c>{0}</c> is the count.</summary>
    public const string PasswordChangedRevoked = nameof(PasswordChangedRevoked);

    /// <summary>S-49's refusal.</summary>
    public const string PasswordWrong = nameof(PasswordWrong);

    /// <summary>The two copies did not match.</summary>
    public const string PasswordMismatch = nameof(PasswordMismatch);

    /// <summary>The new password was blank.</summary>
    public const string PasswordBlank = nameof(PasswordBlank);

    /// <summary>There is no local password to change.</summary>
    public const string PasswordNone = nameof(PasswordNone);

    /// <summary>The session page's title and heading.</summary>
    public const string SessionsTitle = nameof(SessionsTitle);

    /// <summary>What the page says when there are none.</summary>
    public const string SessionsNone = nameof(SessionsNone);

    /// <summary>The label beside when a session started. <c>{0}</c> is the timestamp.</summary>
    public const string SessionsStarted = nameof(SessionsStarted);

    /// <summary>
    /// The label beside the browser a session was approved from. <c>{0}</c> is the description.
    /// </summary>
    /// <remarks>
    /// <b>"Approved from", not "used on".</b> The value is stamped once, when the consent screen was
    /// clicked, and no refresh touches it — so a session approved on a laptop and used from a phone
    /// still says laptop, and the wording has to be the one that stays true. It is also the question
    /// somebody is actually asking when they open this page: which of these did I agree to.
    /// </remarks>
    public const string SessionsDevice = nameof(SessionsDevice);

    /// <summary>
    /// The label beside when a session last renewed its access. <c>{0}</c> is the timestamp.
    /// </summary>
    /// <remarks>
    /// <b>"Renewed", never "active", and the difference is not a shade of wording.</b> What this
    /// server can see is the moment the grant last minted a refresh token. Access tokens are signed
    /// rather than looked up, so a request made with one already in hand never reaches this process
    /// — a person can work for half an hour without moving this number, and the number can move
    /// with nobody at the keyboard, because renewal is a timer in the client. Calling it "last
    /// active" would describe activity this server does not observe.
    /// </remarks>
    public const string SessionsRefreshed = nameof(SessionsRefreshed);

    /// <summary>
    /// That renewal is the application's timer rather than evidence of somebody using it.
    /// </summary>
    /// <remarks>
    /// The caveat that stops <see cref="SessionsRefreshed"/> being read as "somebody was here". A
    /// reader deciding whether a session belongs to them is asking a security question, and the
    /// honest answer is that a recent renewal shows the application still holds access, not that a
    /// person did anything.
    /// </remarks>
    public const string SessionsRefreshedNote = nameof(SessionsRefreshedNote);

    /// <summary>The control that ends one session.</summary>
    public const string SessionsEnd = nameof(SessionsEnd);

    /// <summary>What the page says after one was ended.</summary>
    public const string SessionsEnded = nameof(SessionsEnded);

    /// <summary>
    /// What ending a session does to access an application already holds. <c>{0}</c> is this
    /// deployment's access-token lifetime, in whole minutes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The number is interpolated because a literal one goes stale in silence.</b> This sentence
    /// read "up to an hour" while
    /// <see cref="Configuration.AuthorizationServerOptions.AccessTokenLifetime"/> defaulted to
    /// thirty minutes, so every deployment that took the default was told a figure twice the real
    /// one. No literal could have been right either: the option's legal range runs from five
    /// minutes to twenty-four hours, and nothing about editing it prompts anybody to edit a string
    /// table. A sentence that names a configured value has to be handed that value.
    /// </para>
    /// <para>
    /// <b>It is conditional because this server does not know the answer.</b> Since
    /// <c>/introspect</c> shipped, ending a session can cut access already granted — but only for a
    /// resource server that asks, and whether any asks is a decision taken in a different process
    /// that this one never hears from. Stating either outcome flatly would be an assumption written
    /// down as a measurement, on the page somebody opens precisely to find out whether they are
    /// still exposed. So both branches are given, along with what decides between them.
    /// </para>
    /// </remarks>
    public const string SessionsTokens = nameof(SessionsTokens);

    /// <summary>The control that ends every session at once, for a reader who did not do this.</summary>
    public const string SessionsEndAll = nameof(SessionsEndAll);

    /// <summary>What the page asks before ending them all.</summary>
    public const string SessionsEndAllQuestion = nameof(SessionsEndAllQuestion);

    /// <summary>The control that confirms it.</summary>
    public const string SessionsEndAllConfirm = nameof(SessionsEndAllConfirm);

    /// <summary>The way out of the confirmation without ending anything.</summary>
    public const string SessionsEndAllCancel = nameof(SessionsEndAllCancel);

    /// <summary>What the page says afterwards. <c>{0}</c> is how many were ended.</summary>
    public const string SessionsEndedAll = nameof(SessionsEndedAll);

    /// <summary>
    /// What to do next, once access is cut. The half a revocation cannot do.
    /// </summary>
    /// <remarks>
    /// Revoking every grant answers "who has access" and says nothing about "who can sign in". A
    /// reader who stops here has removed the consequence and left the cause, and is the more
    /// dangerous for believing they have finished.
    /// </remarks>
    public const string SessionsEndedAllNext = nameof(SessionsEndedAllNext);

    /// <summary>The link back to the front page.</summary>
    public const string AccountBack = nameof(AccountBack);

    /// <summary>The link to the list of approvals.</summary>
    public const string AccountConsents = nameof(AccountConsents);

    /// <summary>The link that starts signing out.</summary>
    /// <remarks>
    /// Its own key rather than a second use of <see cref="LogoutSubmit"/>. This one is a link to a
    /// page that asks; that one is the button on that page which does it. Several languages
    /// distinguish the two, and a deployment that translated the button would have silently
    /// retitled the link.
    /// </remarks>
    public const string AccountSignOut = nameof(AccountSignOut);

    /// <summary>The approvals page's title and heading.</summary>
    public const string ConsentsTitle = nameof(ConsentsTitle);

    /// <summary>What the page says when there are none.</summary>
    public const string ConsentsNone = nameof(ConsentsNone);

    /// <summary>The label beside when an approval was given. <c>{0}</c> is the timestamp.</summary>
    public const string ConsentsGranted = nameof(ConsentsGranted);

    /// <summary>The control that withdraws one approval.</summary>
    public const string ConsentsWithdraw = nameof(ConsentsWithdraw);

    /// <summary>What the page says after one was withdrawn.</summary>
    public const string ConsentsWithdrawn = nameof(ConsentsWithdrawn);

    /// <summary>
    /// That withdrawing an approval does not end the access already granted. <c>E-38</c>.
    /// </summary>
    public const string ConsentsNotSessions = nameof(ConsentsNotSessions);

    /// <summary>The link to the session list, where the access itself is ended.</summary>
    public const string ConsentsSeeSessions = nameof(ConsentsSeeSessions);

    /// <summary>The link on the sign-in page for somebody who cannot sign in. <c>E-39</c>.</summary>
    public const string LoginForgotPassword = nameof(LoginForgotPassword);

    /// <summary>
    /// What separates the providers from the password form when the providers come first.
    /// </summary>
    /// <remarks>
    /// Only rendered with <c>InteractionOptions.ProvidersFirst</c> on <b>and</b> both methods
    /// configured — a page with one way in has nothing to separate. It is a sentence rather than a
    /// bare "or" because the thing below it is a specific alternative, and a divider that says which
    /// alternative saves the reader working it out from the fields.
    /// </remarks>
    public const string LoginOrPassword = nameof(LoginOrPassword);

    /// <summary>The forgot-password page's title and heading.</summary>
    public const string ForgotTitle = nameof(ForgotTitle);

    /// <summary>What the page asks for.</summary>
    public const string ForgotInstruction = nameof(ForgotInstruction);

    /// <summary>The identifier field's label.</summary>
    public const string ForgotAccount = nameof(ForgotAccount);

    /// <summary>The submit control.</summary>
    public const string ForgotSubmit = nameof(ForgotSubmit);

    /// <summary>The one answer the page gives. <c>S-48</c> — it does not depend on what was found.</summary>
    public const string ForgotSent = nameof(ForgotSent);

    /// <summary>What it says when the request was refused for rate. §3.1.</summary>
    public const string ForgotThrottled = nameof(ForgotThrottled);

    /// <summary>The reset page's title and heading.</summary>
    public const string ResetTitle = nameof(ResetTitle);

    /// <summary>What the reset page asks for.</summary>
    public const string ResetInstruction = nameof(ResetInstruction);

    /// <summary>The submit control.</summary>
    public const string ResetSubmit = nameof(ResetSubmit);

    /// <summary>What the page says when the link no longer works.</summary>
    public const string ResetExpired = nameof(ResetExpired);

    /// <summary>How to get another one.</summary>
    public const string ResetExpiredAdvice = nameof(ResetExpiredAdvice);

    /// <summary>What the page says when it worked.</summary>
    public const string ResetDone = nameof(ResetDone);

    /// <summary>That every session ended with it. <c>{0}</c> is the count.</summary>
    public const string ResetDoneRevoked = nameof(ResetDoneRevoked);

    /// <summary>The link to the sign-in page.</summary>
    public const string ResetSignIn = nameof(ResetSignIn);

    /// <summary>The verification page's title and heading.</summary>
    public const string VerifyTitle = nameof(VerifyTitle);

    /// <summary>What it says when the address is now proven. <c>{0}</c> is the address.</summary>
    public const string VerifyDone = nameof(VerifyDone);

    /// <summary>What it says when the link no longer works.</summary>
    public const string VerifyExpired = nameof(VerifyExpired);

    /// <summary>The error page's title.</summary>
    public const string ErrorTitle = nameof(ErrorTitle);

    /// <summary>
    /// Something about this attempt went stale. Start again.
    /// </summary>
    /// <remarks>
    /// One of five sentences the error page chooses between. See <see cref="ErrorSentenceFor"/> for
    /// why they are grouped by what the reader can do rather than by what went wrong.
    /// </remarks>
    public const string ErrorStartAgain = nameof(ErrorStartAgain);

    /// <summary>Too many attempts. <c>X-31</c>.</summary>
    public const string ErrorTooMany = nameof(ErrorTooMany);

    /// <summary>The application sent something this server does not accept. Not the reader's fault.</summary>
    public const string ErrorApplication = nameof(ErrorApplication);

    /// <summary>This account cannot sign in here.</summary>
    public const string ErrorAccount = nameof(ErrorAccount);

    /// <summary>The reader declined at the upstream provider.</summary>
    public const string ErrorDeclined = nameof(ErrorDeclined);

    /// <summary>
    /// The label above the English half of the error page. <c>A-12</c>.
    /// </summary>
    /// <remarks>
    /// The label is translated and what it labels is not, on purpose: the <c>error_description</c>
    /// under it is restricted to ASCII by OAuth 2.1 §4.1.2.1 and is written for whoever is
    /// integrating the client. Without the label it reads as a string somebody forgot to translate.
    /// </remarks>
    public const string ErrorDeveloperDetail = nameof(ErrorDeveloperDetail);

    /// <summary>The error page's heading.</summary>
    public const string ErrorHeading = nameof(ErrorHeading);

    /// <summary>The correlation id line. <c>{0}</c> is the id.</summary>
    public const string ErrorReference = nameof(ErrorReference);

    /// <summary>
    /// The line under the wordmark in <see cref="DefaultInteractionLayout"/>'s brand panel.
    /// </summary>
    /// <remarks>
    /// <b>Empty by default and omitted when empty</b>, which is what makes it a shell setting rather
    /// than a sentence the library says. There is nothing general to write here — a tagline is a
    /// deployment's own claim about itself — so the shipped pages carry none, and a deployment that
    /// wants one writes it in the file it already keeps its other sentences in. It is on the panel
    /// and never near the body, so nothing here can compete with the client hostname for N-14's
    /// most-prominent slot.
    /// </remarks>
    public const string ShellTagline = nameof(ShellTagline);

    /// <summary>
    /// Which server this is, printed in the brand panel under <see cref="ShellTagline"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The deployment's own host, and nothing a request carried.</b> A person deciding whether to
    /// approve is deciding partly on where they are, and the address bar is the only thing that
    /// tells them — which is not visible in an app's embedded browser and is the first thing a
    /// phishing page imitates. Saying it on the page is a second copy of a fact the server knows.
    /// </para>
    /// <para>
    /// Empty by default and omitted when empty, like the tagline. It sits in the same table because
    /// it is text on the page and the rule here is that page text lives in one file; a deployment
    /// writes the same value into each of its languages, which is the cost of that rule and a small
    /// one for one line.
    /// </para>
    /// </remarks>
    public const string ShellDomain = nameof(ShellDomain);

    private static readonly Dictionary<string, string> English = new(StringComparer.Ordinal)
    {
        // The two shell strings, empty on purpose: see their remarks. Present in the table rather
        // than absent from it because Default throws for a key it does not know, and Keys is what a
        // deployment's translation file is checked against — a key missing here is one a deployment
        // cannot set.
        [ShellTagline] = "",
        [ShellDomain] = "",

        [ConsentTitle] = "Authorize access",
        [ConsentClientAsking] = "The application at {0} is asking to access your account.",
        [ConsentNameClaim] = "It calls itself “{0}”.",
        [ConsentNameUnverified] = "That name is chosen by the application and is not verified.",
        [ConsentCodeGoesTo] = "If you approve, the authorization code will be sent to {0}.",
        [ConsentDeviceWarning] = "This application receives the code on your own device.",
        [ConsentDeviceWarningAdvice] =
            "Approve only if you started this from an application on this device that you trust.",
        [ConsentScopesHeading] = "It is asking for",
        [ConsentScopeUndescribed] = "(no description configured for this scope)",
        [ConsentResourcesHeading] = "At",
        [ConsentApprove] = "Approve",
        [ConsentDeny] = "Deny",

        [LoginTitle] = "Sign in",
        [LoginUsername] = "Username or email",
        [LoginPassword] = "Password",
        [AccountLinkHeading] = "Other ways to sign in",
        [AccountLinkProvider] = "Link {0}",
        [AccountLinked] = "{0} is connected to this account.",
        [AccountLinkExplanation] =
            "Linking lets you sign in to this account with that provider, as well as with your password.",
        [LoginRejected] = "That username and password did not match.",
        [LoginSubmit] = "Sign in",
        [LoginWithProvider] = "Sign in with {0}",
        [LoginNoMethod] = "This server has no sign-in method configured.",
        [LoginForgotPassword] = "I have forgotten my password",
        [LoginOrPassword] = "or use a password",

        [LogoutTitle] = "Sign out",
        [LogoutQuestion] = "End your session on this server?",
        [LogoutSubmit] = "Sign out",
        [LogoutDoneTitle] = "Signed out",
        [LogoutDoneBody] = "Your session on this server has ended.",
        [LogoutDoneTokens] =
            "Applications you have already authorized may still have access tokens. "
            + "Signing out here does not revoke them.",

        [AccountTitle] = "Your account",
        [AccountHandle] = "Username",
        [AccountEmail] = "Email",
        [AccountEmailNone] = "None recorded",
        [AccountEmailUnverified] = "not verified",
        [AccountVerifyEmail] = "Send me a confirmation link",
        [AccountVerifyEmailSent] =
            "A confirmation link is on its way to that address. It expires, and can only be used "
            + "once.",
        [AccountVerifyEmailTooSoon] =
            "A link was already sent. Check that address, and wait a few minutes before asking for "
            + "another one.",
        [AccountRole] = "Role",
        [AccountChangePassword] = "Change your password",
        [AccountSessions] = "See where you are signed in",
        [AccountNoPassword] =
            "You sign in through another provider, so there is no password here to change.",
        [AccountBack] = "Back to your account",

        [PasswordTitle] = "Change your password",
        [PasswordCurrent] = "Current password",
        [PasswordNew] = "New password",
        [PasswordConfirm] = "New password again",
        [PasswordRevokeSessions] = "Sign me out everywhere, including here",
        [PasswordSubmit] = "Change password",
        [PasswordChanged] = "Your password has been changed.",
        [PasswordChangedRevoked] = "{0} session(s) were ended.",
        [PasswordWrong] = "That is not your current password.",
        [PasswordMismatch] = "The two new passwords do not match.",
        [PasswordBlank] = "The new password is blank.",
        [PasswordNone] =
            "You sign in through another provider, so there is no password here to change.",

        [SessionsTitle] = "Where you are signed in",
        [SessionsNone] = "No application currently has access to your account.",
        [SessionsStarted] = "Authorized {0}",
        [SessionsDevice] = "Approved from {0}",
        [SessionsRefreshed] = "Access last renewed {0}",
        [SessionsRefreshedNote] =
            "Applications renew their access on a timer of their own, so a recent renewal means the "
            + "application still has access rather than that somebody was using it.",
        [SessionsEnd] = "End this session",
        [SessionsEnded] = "That session has ended.",
        [SessionsEndAll] = "None of this was me",
        [SessionsEndAllQuestion] =
            "End every session above? Every application listed loses access, including the one you "
            + "are reading this in, and each will have to be approved again. You will be signed out "
            + "here as well, on every browser including this one.",
        [SessionsEndAllConfirm] = "End all of them",
        [SessionsEndAllCancel] = "Leave them alone",
        [SessionsEndedAll] = "{0} session(s) were ended.",
        [SessionsEndedAllNext] =
            "Now change your password. Everyone signed in to this account has been signed out, "
            + "including whoever you are worried about — but they got in once, and nothing here "
            + "has changed how.",
        [SessionsTokens] =
            "Ending a session stops new access tokens being issued for it. If the application's own "
            + "server checks with this one, it loses access at that next check; if it does not, the "
            + "application keeps working until its current token expires, which is at most "
            + "{0} minutes.",

        [AccountConsents] = "See what you have approved",
        [AccountSignOut] = "Sign out",
        [ConsentsTitle] = "What you have approved",
        [ConsentsNone] = "You have not approved any application.",
        [ConsentsGranted] = "Approved {0}",
        [ConsentsWithdraw] = "Withdraw this approval",
        [ConsentsWithdrawn] = "That approval has been withdrawn.",
        [ConsentsNotSessions] =
            "Withdrawing an approval means the application has to ask you again next time. It does "
            + "not end access it already has.",
        [ConsentsSeeSessions] = "End its access as well",

        [ResetTitle] = "Choose a new password",
        [ResetInstruction] = "Enter a new password for your account.",
        [ResetSubmit] = "Set password",
        [ResetExpired] = "This link no longer works.",
        [ResetExpiredAdvice] =
            "A reset link can only be used once, and it expires. Ask for a new one to try again.",
        [ResetDone] = "Your password has been set. You can sign in with it now.",
        [ResetDoneRevoked] =
            "{0} session(s) were ended, so anything already signed in to your account has been "
            + "signed out.",
        [ResetSignIn] = "Go to sign in",

        [ForgotTitle] = "Reset your password",
        [ForgotInstruction] = "Enter your username or your email address.",
        [ForgotAccount] = "Username or email",
        [ForgotSubmit] = "Send me a link",

        // S-48: the same sentence whether or not an account matched, and it is about what will
        // happen rather than about what was found.
        [ForgotSent] =
            "If an account matches, a link to reset its password is on its way. The link expires, "
            + "and can only be used once.",
        [ForgotThrottled] =
            "Too many requests have been made recently. Wait a few minutes and try again — a link "
            + "you have already been sent still works.",

        [VerifyTitle] = "Email address",
        [VerifyDone] = "{0} is confirmed as your address.",
        [VerifyExpired] =
            "This link no longer works. A confirmation link can only be used once, and it expires.",

        [ErrorTitle] = "Authorization error",
        [ErrorHeading] = "This request could not be authorized",
        [ErrorReference] = "Reference: {0}",

        [ErrorStartAgain] =
            "This request is no longer valid — it may have expired, or this page may have been "
            + "opened on its own. Start again from the application you are connecting.",
        [ErrorTooMany] =
            "There have been too many attempts recently. Wait a few minutes and try again.",
        [ErrorApplication] =
            "The application sent a request this server does not accept. This is not something you "
            + "can fix — give the reference below to whoever runs that application.",
        [ErrorAccount] =
            "This account cannot sign in here. Ask whoever administers this server, and give them "
            + "the reference below.",
        [ErrorDeclined] = "You declined at the sign-in provider, so nothing was authorized.",
        [ErrorDeveloperDetail] = "Technical detail, for whoever runs the application:",
    };

    /// <summary>
    /// Which sentence the error page shows for a refusal.
    /// </summary>
    /// <param name="reason">Why the request was refused.</param>
    /// <returns>One of the constants on this type.</returns>
    /// <remarks>
    /// <para>
    /// <b>Grouped by what the reader can do, not by what went wrong,</b> and the difference is the
    /// whole design. Twenty-six reason codes reach the error page and a person can take exactly five
    /// actions in response to them: start again, wait, tell whoever runs the application, ask an
    /// administrator, or nothing because they declined on purpose. Twenty-six sentences would be
    /// twenty-six translations of "a redirect URI registration is unusable" — accurate, and useless
    /// to the founder reading it.
    /// </para>
    /// <para>
    /// <b>The precise cause is not lost, it moves to where it is useful.</b> Every refusal is logged
    /// with its <c>Reason</c>, its requirement id, its description and the private detail the page
    /// never carries — <c>A-09</c> — and the page shows the correlation id that joins the two. That
    /// is what the reference is for, and it was already on the page. An operator gets more than the
    /// page ever showed them; the person gets a sentence they can act on.
    /// </para>
    /// <para>
    /// <b>An unmapped reason is <see cref="ErrorApplication"/>,</b> which is a decision rather than a
    /// default. Every refusal reaching this page except <c>ExternalAuthorizationDenied</c> is
    /// something the reader did not cause, so guessing "not your fault, here is the reference" is
    /// both the likeliest truth and the one guess that cannot blame somebody for a bug. A new reason
    /// code still gets a sentence and a reference on the first request rather than falling back to
    /// English prose on an otherwise translated page.
    /// </para>
    /// </remarks>
    internal static string ErrorSentenceFor(ReasonCode reason) =>
        reason switch
        {
            // The reader's own session or tab went stale. Starting again works.
            ReasonCode.AntiforgeryTokenInvalid
                or ReasonCode.ReturnUrlInvalid
                or ReasonCode.InteractionErrorPage
                or ReasonCode.ExternalStateMismatch
                or ReasonCode.ExternalNonceMismatch
                or ReasonCode.ExternalPendingRequestMissing
                or ReasonCode.ExternalLinkRequiresSession => ErrorStartAgain,

            ReasonCode.RateLimited => ErrorTooMany,

            // The account exists and is not allowed to sign in — an administrator's decision or an
            // unlinked identity. Distinct from the one below because the person to ask is different.
            ReasonCode.ExternalAccountDisabled
                or ReasonCode.ExternalIdentityUnlinked
                or ReasonCode.ExternalIdentityLinkedElsewhere => ErrorAccount,

            // The one refusal on this page the reader caused on purpose. Saying "the application
            // sent something wrong" here would be telling somebody their own decision was a bug.
            ReasonCode.ExternalAuthorizationDenied => ErrorDeclined,

            _ => ErrorApplication,
        };

    /// <summary>Every key, for a deployment building a translation and for the tests.</summary>
    /// <remarks>
    /// Exposed so that "did we translate all of them" is a question with a mechanical answer. A
    /// deployment can assert its own dictionary covers this set; the library asserts every key it
    /// renders is in it.
    /// </remarks>
    public static IReadOnlyCollection<string> Keys => English.Keys;

    /// <summary>The English text for a key.</summary>
    /// <param name="key">One of the constants on this type.</param>
    /// <exception cref="ArgumentOutOfRangeException">No such key.</exception>
    public static string Default(string key) =>
        English.TryGetValue(key, out var text)
            ? text
            : throw new ArgumentOutOfRangeException(nameof(key), key, "No such interaction string.");

    /// <summary>
    /// The text for a key, as encoded HTML, with safe markup spliced into its placeholders.
    /// </summary>
    /// <param name="localizer">The deployment's, or <see langword="null"/> for English.</param>
    /// <param name="key">One of the constants on this type.</param>
    /// <param name="safeHtml">
    /// Values for <c>{0}</c>, <c>{1}</c>… <b>Already-encoded HTML</b>, because the caller is this
    /// assembly and the values it splices are things like <c>&lt;strong&gt;host&lt;/strong&gt;</c>.
    /// </param>
    /// <returns>Markup, ready to append.</returns>
    public static string Format(IStringLocalizer? localizer, string key, params string[] safeHtml)
    {
        ArgumentNullException.ThrowIfNull(safeHtml);

        var text = Localized(localizer, key);

        // The translation is encoded and the arguments are not — that order is the whole safety
        // property. Doing it the other way, or using string.Format on the raw text, would let a
        // translation supply markup, and a translation is data a deployment edits rather than code
        // it reviews.
        var encoded = WebUtility.HtmlEncode(text);

        for (var i = 0; i < safeHtml.Length; i++)
        {
            encoded = encoded.Replace(
                "{" + i.ToString(System.Globalization.CultureInfo.InvariantCulture) + "}",
                safeHtml[i],
                StringComparison.Ordinal);
        }

        return encoded;
    }

    /// <summary>The text for a key, as plain text, for a place that encodes its own.</summary>
    /// <param name="localizer">The deployment's, or <see langword="null"/> for English.</param>
    /// <param name="key">One of the constants on this type.</param>
    public static string Plain(IStringLocalizer? localizer, string key) => Localized(localizer, key);

    /// <summary>
    /// The deployment's text, or English.
    /// </summary>
    /// <remarks>
    /// <c>ResourceNotFound</c> is the signal, and it is why the fallback is explicit rather than
    /// implied: a localizer that has no entry for a key returns the key itself, so trusting the value
    /// unconditionally is how a page comes to read <c>ConsentApprove</c> in production.
    /// </remarks>
    private static string Localized(IStringLocalizer? localizer, string key)
    {
        if (localizer is null)
        {
            return Default(key);
        }

        var localized = localizer[key];

        return localized.ResourceNotFound ? Default(key) : localized.Value;
    }
}
