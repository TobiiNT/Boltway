namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// Every path this server serves. Constants, not configuration.
/// </summary>
/// <remarks>
/// <para>
/// Not settable, on purpose. A configurable path has to be validated (leading slash? trailing
/// slash? percent-encoded?), has to be threaded into the metadata document, and buys nothing: the
/// only party that reads these is a client, and a client reads them out of the metadata document
/// rather than guessing. Making them constants means the document and the routing table cannot
/// disagree, because there is one source for both.
/// </para>
/// <para>
/// The well-known paths are the exception to "one path per endpoint": RFC 8414 §3 inserts the
/// well-known segment <i>before</i> the issuer path, OIDC Discovery §4.1 appends it after, and MCP
/// clients probe several spellings in order. All six are served, and all six return the same bytes.
/// </para>
/// </remarks>
public static class AuthorizationServerPaths
{
    /// <summary>RFC 8414 §3. E-01.</summary>
    public const string OAuthAuthorizationServerMetadata = "/.well-known/oauth-authorization-server";

    /// <summary>OIDC Discovery §4. E-02.</summary>
    public const string OpenIdConfiguration = "/.well-known/openid-configuration";

    /// <summary>RFC 8414 §2 <c>jwks_uri</c>. E-07.</summary>
    public const string Jwks = "/.well-known/jwks.json";

    /// <summary>E-08.</summary>
    public const string Authorize = "/authorize";

    /// <summary>E-09.</summary>
    public const string Consent = "/consent";

    /// <summary>E-10.</summary>
    public const string Token = "/token";

    /// <summary>E-11..E-14. Routed only in the dynamic-registration profile.</summary>
    public const string Register = "/register";

    /// <summary>E-15.</summary>
    public const string Introspect = "/introspect";

    /// <summary>E-16.</summary>
    public const string Revoke = "/revoke";

    /// <summary>E-17.</summary>
    public const string UserInfo = "/userinfo";

    /// <summary>E-18.</summary>
    public const string EndSession = "/logout";

    /// <summary>E-19.</summary>
    public const string Login = "/login";

    /// <summary>E-19.</summary>
    public const string Error = "/error";

    /// <summary>
    /// A client's <c>logo_uri</c>, re-served from this origin. Takes <c>?client_id=</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A proxy, because hotlinking is a disclosure.</b> A client's <c>logo_uri</c> is a URL the
    /// client chose, and ChatGPT's live metadata points at a third-party CDN — so an
    /// <c>&lt;img src&gt;</c> straight at it would tell that host who is looking at a consent page
    /// for which application, and when. The consent page's own <c>default-src 'self'</c> refuses it
    /// anyway, which is the second half of the same decision rather than a separate one.
    /// </para>
    /// <para>
    /// The <c>client_id</c> rides in the query rather than in the path because a CIMD one is a URL,
    /// and a URL in a path segment is a double-encoding argument nobody wins. It is not a secret:
    /// it is already in the <c>/authorize</c> request that produced the page this image is on.
    /// </para>
    /// </remarks>
    public const string ClientLogo = "/client-logo";

    /// <summary>The administrative collection. E-27.</summary>
    /// <remarks>
    /// <b>The prefix is load-bearing.</b> <c>N-17</c>'s architecture test asserts that nothing routed
    /// under <c>/admin/</c> carries a cookie authentication scheme, so the rule is enforced by the
    /// path rather than by every handler remembering. A route added here inherits it; a route added
    /// elsewhere does not, which is why these are constants rather than strings at the call site.
    /// </remarks>
    public const string AdminUsers = "/admin/users";

    /// <summary>One account, by the handle a person types. E-26, E-28.</summary>
    /// <remarks>
    /// By handle rather than by subject, because both callers start from what somebody typed and the
    /// subject is a ULID nobody has to hand. The realm comes from configuration, not from the URL.
    /// </remarks>
    public const string AdminUser = "/admin/users/{handle}";

    /// <summary>Reset one account's password. E-29.</summary>
    public const string AdminUserPassword = "/admin/users/{handle}/password";

    /// <summary>One account's sessions. E-30.</summary>
    /// <remarks>
    /// A collection under the account, deleted as a whole, because that is what the operation is:
    /// <c>DELETE</c> on the set rather than a <c>POST /revoke-sessions</c> verb. Individual sessions
    /// are <c>E-36</c>, on the self-service surface, and they are the reason this reads as a
    /// collection rather than a flag on the account.
    /// </remarks>
    public const string AdminUserSessions = "/admin/users/{handle}/sessions";

    /// <summary>Anonymise one account. E-31.</summary>
    /// <remarks>
    /// <c>POST</c> and not <c>DELETE</c>, and the difference is the whole design: the row stays.
    /// A <c>DELETE /admin/users/{handle}</c> would promise erasure, and erasure with outstanding
    /// grants leaves dangling references and empties the audit trail on request of the audited.
    /// </remarks>
    public const string AdminUserAnonymise = "/admin/users/{handle}/anonymise";

    /// <summary>The administrative audit log. E-32.</summary>
    /// <summary>
    /// The service account acting as one person. E-33.
    /// </summary>
    /// <remarks>
    /// Singular and under the account, because that is what it is: a property of a person rather
    /// than a member of a client collection. One account holds at most one, so there is no id in
    /// the path and no list to page through — <c>POST</c> creates or rotates, <c>PATCH</c> turns it
    /// off, <c>DELETE</c> removes it.
    /// </remarks>
    public const string AdminUserServiceAccount = "/admin/users/{handle}/service-account";

    /// <summary>The roles a realm defines.</summary>
    public const string AdminRoles = "/admin/roles";

    /// <summary>One role, by its immutable id.</summary>
    public const string AdminRole = "/admin/roles/{id}";

    /// <summary>The administrative audit trail.</summary>
    public const string AdminAudit = "/admin/audit";

    /// <summary>The prefix every administrative route shares.</summary>
    /// <remarks>What the <c>N-17</c> architecture test scans for.</remarks>
    public const string AdminPrefix = "/admin/";

    /// <summary>The caller's own account. E-33.</summary>
    /// <remarks>
    /// <b>No identifier in the path, and that is the design rather than a shorthand.</b> Every
    /// <c>/admin</c> route names whose account it is; none of these do. A handler that cannot be
    /// told which account to act on has no code path that reaches another one — §1.6, two surfaces
    /// rather than one with a guard, and the guard is the thing that gets a special case added to it
    /// eighteen months later.
    /// </remarks>
    public const string Account = "/account";

    /// <summary>Change your own password. E-34.</summary>
    public const string AccountPassword = "/account/password";

    /// <summary>Your own sessions. E-35.</summary>
    public const string AccountSessions = "/account/sessions";

    /// <summary>End one of your own sessions. E-36.</summary>
    /// <remarks>
    /// The grant id, which is what <c>E-35</c> returns and what an access token carries. The design
    /// table calls this <c>{family}</c>; a refresh family is descended from a grant and revoking the
    /// grant ends every family under it, so the grant is the thing a person means by "this session"
    /// and the thing they can actually see.
    /// </remarks>
    public const string AccountSession = "/account/sessions/{grant}";

    /// <summary>What you have approved. E-37.</summary>
    public const string AccountConsents = "/account/consents";

    /// <summary>Withdraw one approval. E-38.</summary>
    /// <remarks>
    /// <b>A catch-all segment, because a client id is often a URL.</b> This server supports client
    /// ID metadata documents, where the id <i>is</i> <c>https://claude.ai/oauth/…</c> — several path
    /// segments and a scheme. <c>{clientId}</c> would match none of it, and telling callers to
    /// percent-encode the slashes moves the problem into whether the proxy in front normalises
    /// <c>%2F</c>, which is not a thing this repository can promise about somebody else's
    /// deployment.
    /// </remarks>
    public const string AccountConsent = "/account/consents/{**clientId}";

    /// <summary>Where a reset link lands. E-42, E-43.</summary>
    /// <remarks>
    /// <b>Not under <c>/account/</c> or <c>/me/</c>, and it is neither of those things.</b> It is
    /// reached by somebody who cannot sign in, holding a token instead of a session — so it carries
    /// no cookie requirement and no bearer requirement, and putting it under either prefix would
    /// make one of the two N-17 architecture tests wrong about it.
    /// </remarks>
    public const string Reset = "/reset";

    /// <summary>Where a verification link lands. E-44.</summary>
    public const string VerifyEmail = "/verify-email";

    /// <summary>
    /// Where somebody who cannot sign in asks for a reset link, in a browser. E-39.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A page, because <see cref="AccountPasswordForgot"/> answers JSON.</b> That endpoint is for
    /// a caller driving the flow programmatically, and it already accepts a form post — but it
    /// answers <c>202</c> with a JSON body, so a browser posting to it directly is shown a line of
    /// JSON where a sentence should be. §7.3 made this call once already for <c>E-40</c> and
    /// <c>E-41</c>: an endpoint with no page is a design that mails somebody a URL answering 405.
    /// The link on the sign-in page is the half that was missing, and it needs somewhere to go.
    /// </para>
    /// <para>
    /// Top-level, beside <see cref="Reset"/> and for the same reason: it is reached by somebody
    /// holding neither a session nor a token, so it belongs to neither N-17 prefix.
    /// </para>
    /// </remarks>
    public const string Forgot = "/forgot";

    /// <summary>Ask for a reset link. E-39. Public.</summary>
    public const string AccountPasswordForgot = "/account/password/forgot";

    /// <summary>Redeem a reset link. E-40. Public.</summary>
    public const string AccountPasswordReset = "/account/password/reset";

    /// <summary>Redeem a verification link. E-41. Public.</summary>
    public const string AccountEmailVerify = "/account/email/verify";

    /// <summary>The self-service pages' front page. E-46.</summary>
    /// <remarks>
    /// <b>A third prefix, and the reason there are three rather than two.</b> Read literally,
    /// <c>N-17</c> would mean a founder changing their own password has to run an OAuth client,
    /// which is absurd — and the way out is not to soften the rule. <c>/admin/</c> and
    /// <c>/account/</c> are bearer-only and refuse a cookie; these are the opposite and refuse a
    /// bearer. Disjoint prefixes make both halves mechanical: an architecture test reads the routing
    /// table and needs no judgement about which page meant what.
    /// </remarks>
    public const string Me = "/me";

    /// <summary>Change your own password, in a browser. E-46.</summary>
    public const string MePassword = "/me/password";

    /// <summary>See and end your own sessions, in a browser. E-46.</summary>
    public const string MeSessions = "/me/sessions";

    /// <summary>
    /// See and withdraw what you have approved, in a browser. E-46.
    /// </summary>
    /// <remarks>
    /// <b>No client id in the path, unlike <see cref="AccountConsent"/>.</b> That route needs a
    /// catch-all because a CIMD client id is a URL and the API has nowhere else to put it; a page has
    /// a form, so the id rides in a field and the routing table stays free of a segment that matches
    /// everything under <c>/me/</c>. Which matters more than tidiness: <c>{**clientId}</c> here would
    /// swallow any <c>/me/</c> page added later.
    /// </remarks>
    public const string MeConsents = "/me/consents";

    /// <summary>
    /// Ask for a link confirming your own address, in a browser. <c>E-41</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>POST only, and it is the half of <c>E-41</c> that was missing.</b>
    /// <c>AccountRecovery.RequestEmailVerificationAsync</c> minted the token and composed the mail,
    /// <see cref="VerifyEmail"/> redeemed it, and the <c>EmailVerification</c> token purpose existed
    /// — with nothing anywhere calling the first one. Its only callers were three tests, so a real
    /// deployment could never produce the link that page exists to receive. §7.3 made this call
    /// once for <c>E-40</c>: an endpoint with no page mails somebody a URL that answers 405; this is
    /// the same defect facing the other way, a page nothing can send you to.
    /// </para>
    /// <para>
    /// <b>Here rather than beside <see cref="Forgot"/>, because the caller is signed in.</b> The
    /// method's own remarks say it is "not an oracle and does not need <c>S-48</c>'s treatment" —
    /// the caller already holds a session for this subject, so "does this account exist" is not a
    /// secret being kept from them. Putting it on the public surface would mean inventing that
    /// treatment for a question nobody was asking.
    /// </para>
    /// <para>
    /// Not in <see cref="LoginReturnTargets"/>, and correctly so: nothing can GET it, so no login
    /// can return to it. <c>MeSurfaceTests</c> scans GET routes only.
    /// </para>
    /// </remarks>
    public const string MeEmailVerify = "/me/email/verify";

    /// <summary>The prefix every self-service page shares.</summary>
    /// <remarks>What the <c>N-17</c> architecture test scans for, along with <see cref="Me"/>.</remarks>
    public const string MePrefix = "/me/";

    /// <summary>
    /// Every page <c>/login</c> will resume to, and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>/login</c> used to resume exactly one thing, and its <c>returnUrl</c> check took one path.
    /// A person who lands on <c>/me</c> without a session has to be sent somewhere to get one, and
    /// coming back afterwards is the whole point — so the check now takes this list.
    /// </para>
    /// <para>
    /// <b>It is a constant, closed at compile time.</b> Relaxing the check to "any local path" would
    /// be the easy version and would hand the sign-in page's redirect to whatever page exists next,
    /// including ones nobody considered as a landing target.
    /// </para>
    /// <para>
    /// The <c>/me</c> entries stay listed whether or not a deployment serves them. A
    /// <c>returnUrl</c> naming a page that is not routed lands on this server's own 404, which is a
    /// worse experience and not a security property — and making the list depend on configuration
    /// would mean the sign-in page's validation differed between deployments.
    /// </para>
    /// <para>
    /// <b>Every page under <see cref="MePrefix"/> belongs here, and adding one means adding it
    /// here.</b> A page reachable while signed in but missing from this list works perfectly until
    /// the session expires, and then answers a refusal at <c>/login</c> — which is the worst time to
    /// find out, and is what happened to <c>/me</c> itself before this became a list. The routing
    /// table is read back and compared against this list in <c>MeSurfaceTests</c>, so the two cannot
    /// drift without a test saying which page was forgotten.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> LoginReturnTargets { get; } =
        [Authorize, Me, MePassword, MeSessions, MeConsents];

    /// <summary>The prefix the programmatic self-service API shares.</summary>
    /// <remarks>
    /// What the <c>N-17</c> architecture test scans for, along with <see cref="Account"/> itself —
    /// which has no trailing slash and so matches no prefix, and would have been the one route on
    /// this surface the test never looked at.
    /// </remarks>
    public const string AccountPrefix = "/account/";

    /// <summary>
    /// Where a federated sign-in begins: <c>POST /external/{scheme}/start</c>.
    /// </summary>
    /// <remarks>
    /// A POST, not a GET, and the reason is what the request does rather than what it looks like: it
    /// writes a cookie that binds this browser to a <c>state</c>, a <c>nonce</c> and a PKCE verifier
    /// for the next ten minutes. A GET would let any page on the internet plant that cookie in a
    /// visitor's browser, which is not by itself an account takeover — the callback still has to
    /// match a <c>state</c> the attacker cannot read — but it is a state-changing request on this
    /// origin, and this server's other two of those are antiforgery-protected form posts. Being
    /// consistent costs one form element on the sign-in page.
    /// </remarks>
    public const string ExternalStart = "/external/{scheme}/start";

    /// <summary>Where the upstream sends the browser back: <c>GET /external/{scheme}/callback</c>.</summary>
    public const string ExternalCallback = "/external/{scheme}/callback";

    /// <summary>
    /// Where an already-signed-in user links an upstream identity: <c>POST /external/{scheme}/link</c>.
    /// </summary>
    /// <remarks>
    /// The explicit, authenticated alternative to matching accounts by email address. See
    /// <c>ExternalLoginEndpoints</c> for why that alternative has to exist.
    /// </remarks>
    public const string ExternalLink = "/external/{scheme}/link";

    /// <summary>The concrete path for one scheme, with no route template in it.</summary>
    /// <param name="scheme">A validated provider scheme.</param>
    /// <param name="leaf">One of <c>start</c>, <c>callback</c>, <c>link</c>.</param>
    /// <remarks>
    /// Built by substitution rather than by string interpolation at each call site, so the three
    /// route templates above and the URLs that are emitted cannot drift apart. The scheme is
    /// constrained to <c>[a-z0-9-]</c> at startup, so nothing here needs escaping — and that is a
    /// property of the validation, not of this method, which is why the validation is a startup
    /// failure rather than a filter.
    /// </remarks>
    public static string External(string scheme, string leaf) => "/external/" + scheme + "/" + leaf;
}
