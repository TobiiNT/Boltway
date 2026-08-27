using Boltway.OAuth.Primitives.Errors;

namespace Boltway.OAuth.Primitives.Diagnostics;

/// <summary>
/// Which check refused a request. A closed set, one member per distinguishable cause.
/// </summary>
/// <remarks>
/// <para>
/// The reason an operator needs is almost never the reason the client is told. Several of the
/// members below share one <c>error</c> and one <c>error_description</c> on purpose - every
/// <c>AuthorizationCode*</c> member answers the client with <c>invalid_grant</c> and the words
/// "The authorization code is invalid", because distinguishing them on the wire is an oracle. The
/// distinction still has to exist somewhere, and this enum is where.
/// </para>
/// <para>
/// An enum rather than a string, for the same reason <see cref="OAuthErrorCode"/> is: a string
/// invites a plausible-looking invention at the call site, and a log field nobody can enumerate
/// cannot be alerted on. A test asserts every member below is reachable, so a member that stops
/// being emitted is a red build rather than a category that quietly empties out.
/// </para>
/// </remarks>
public enum ReasonCode
{
    /// <summary>Unset. Never emitted; present so <c>default</c> is not a real reason.</summary>
    None = 0,

    // ── any surface ─────────────────────────────────────────────────────────

    /// <summary>A parameter appeared more than once. Which one is in the detail.</summary>
    RepeatedParameter,

    // ── /authorize, before a redirect URI is trusted ─────────────────────────

    /// <summary><c>client_id</c> is absent or does not parse.</summary>
    ClientIdMalformed,

    /// <summary>No resolver in the chain claims this identifier.</summary>
    ClientUnknown,

    /// <summary>The client resolved and is switched off.</summary>
    ClientDisabled,

    /// <summary>
    /// A resolver recognised the identifier and could not turn it into a client. The CIMD case.
    /// </summary>
    ClientMetadataUnusable,

    /// <summary><c>redirect_uri</c> was omitted and the client has other than one registered.</summary>
    RedirectUriAmbiguous,

    /// <summary>The single registered redirect URI does not itself parse.</summary>
    RedirectUriRegistrationUnusable,

    /// <summary><c>redirect_uri</c> is present and empty, which is malformed rather than omitted.</summary>
    RedirectUriEmpty,

    /// <summary><c>redirect_uri</c> does not parse.</summary>
    RedirectUriMalformed,

    /// <summary><c>redirect_uri</c> parses and matches none of the client's registrations.</summary>
    RedirectUriMismatch,

    // ── /authorize, once redirecting is permitted ────────────────────────────

    /// <summary><c>response_type</c> is absent.</summary>
    ResponseTypeMissing,

    /// <summary><c>response_type</c> is present and is not <c>code</c>.</summary>
    ResponseTypeUnsupported,

    /// <summary>The client's registered <c>grant_types</c> do not include the one being used.</summary>
    ClientNotRegisteredForGrantType,

    /// <summary>The client's registered <c>response_types</c> do not include <c>code</c>.</summary>
    ClientNotRegisteredForResponseType,

    /// <summary><c>code_challenge</c> is absent. N-02.</summary>
    PkceChallengeMissing,

    /// <summary><c>code_challenge_method</c> is absent or is not <c>S256</c>.</summary>
    PkceMethodUnsupported,

    /// <summary><c>code_challenge</c> is not 43 characters of unpadded base64url.</summary>
    PkceChallengeMalformed,

    /// <summary><c>scope</c> contains a token outside RFC 6749 §3.3's grammar.</summary>
    ScopeMalformed,

    /// <summary>A requested scope is not one this server offers.</summary>
    ScopeUnsupported,

    /// <summary>A requested scope is offered but not to this client.</summary>
    ScopeNotAllowedForClient,

    /// <summary><c>resource</c> was omitted and this server has no unambiguous default. A-02.</summary>
    ResourceDefaultUnavailable,

    /// <summary>More <c>resource</c> values than the endpoint's budget allows.</summary>
    ResourceTooMany,

    /// <summary>A <c>resource</c> value is not an absolute URI without a fragment.</summary>
    ResourceMalformed,

    /// <summary>
    /// A <c>resource</c> value is unknown or not permitted. Deliberately one reason for both - the
    /// registry returns the same answer, and this enum must not become the oracle the response is not.
    /// </summary>
    ResourceUnavailable,

    /// <summary>A parameter this server publishes that it does not support was used. X-16.</summary>
    ParameterNotSupported,

    /// <summary><c>prompt=none</c> was combined with another prompt value.</summary>
    PromptCombinationInvalid,

    /// <summary><c>max_age</c> is not a non-negative number of seconds within range.</summary>
    MaxAgeInvalid,

    // ── /authorize, the interaction stages ──────────────────────────────────

    /// <summary><c>prompt=none</c> and no session satisfies the request. X-12.</summary>
    LoginRequired,

    /// <summary><c>prompt=none</c> and consent has not been given. X-13.</summary>
    ConsentRequired,

    /// <summary>The consent policy refused, whatever the user would have clicked. X-06.</summary>
    ConsentPolicyDenied,

    /// <summary>The user clicked Deny. X-06.</summary>
    ConsentUserDenied,

    /// <summary>The endpoint threw. X-10.</summary>
    Unhandled,

    // ── /login, /consent, /error ────────────────────────────────────────────

    /// <summary>The page was opened without a <c>returnUrl</c> naming a local authorization request.</summary>
    ReturnUrlInvalid,

    /// <summary>The antiforgery token is missing, stale or does not validate.</summary>
    AntiforgeryTokenInvalid,

    /// <summary>
    /// The username and password did not match, or the account is inactive. One reason for all
    /// three causes, because the page gives one answer and the timing is equalised to match.
    /// </summary>
    PasswordRejected,

    /// <summary>The standalone error page was rendered.</summary>
    InteractionErrorPage,

    /// <summary>
    /// A password was submitted to a deployment that has no local password verification configured.
    /// </summary>
    /// <remarks>
    /// A federation-only deployment registers no <c>IPasswordHasher</c>, so the sign-in page renders
    /// no password form. This is the refusal for a POST that arrives anyway - a stale tab, a
    /// bookmarked form, or someone probing. It is deliberately distinguishable from
    /// <see cref="PasswordRejected"/> in the log: one means a credential was wrong, the other means
    /// this deployment does not do passwords, and an operator chasing "nobody can sign in" needs
    /// them to be different lines.
    /// </remarks>
    LocalPasswordSignInUnavailable,

    // ── federated sign-in ───────────────────────────────────────────────────

    /// <summary>No upstream identity provider is registered under that scheme.</summary>
    ExternalProviderUnknown,

    /// <summary>
    /// The provider is registered and answered <c>Disabled</c>, or cannot run at all - no endpoints,
    /// no keys, a discovery document that does not name the configured issuer.
    /// </summary>
    ExternalProviderUnavailable,

    /// <summary>
    /// The callback arrived with no readable pending-request cookie: never started, already used,
    /// expired, or issued by a different instance with different data-protection keys.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="ExternalStateMismatch"/> on purpose. This one is almost always
    /// benign - a user who left the tab open, or a bookmarked callback URL - while a mismatch means
    /// two values that both exist disagree, which is the shape of an injected authorization
    /// response.
    /// </remarks>
    ExternalPendingRequestMissing,

    /// <summary>
    /// <c>state</c> is absent from the callback, or does not equal the one bound to this browser.
    /// </summary>
    ExternalStateMismatch,

    /// <summary>The upstream answered the authorization request with an <c>error</c>.</summary>
    /// <remarks>
    /// Includes the ordinary case of a user clicking "cancel" at the upstream, which is
    /// <c>access_denied</c> and is not a fault. Logged all the same: a burst of them is a
    /// misconfigured client registration at the upstream, which looks exactly like users changing
    /// their minds until somebody counts.
    /// </remarks>
    ExternalAuthorizationDenied,

    /// <summary>The upstream token endpoint could not be reached, refused, or answered unusably.</summary>
    ExternalTokenExchangeFailed,

    /// <summary>The exchange succeeded and carried no <c>id_token</c>.</summary>
    ExternalIdentityTokenMissing,

    /// <summary>
    /// The ID token did not validate: signature, <c>alg</c>, <c>iss</c>, <c>aud</c>, <c>exp</c>,
    /// <c>iat</c>, a missing <c>sub</c>, or an RFC 9207 <c>iss</c> mismatch on the response itself.
    /// </summary>
    /// <remarks>
    /// One reason for all of them, exactly as <see cref="AccessTokenRejected"/> is on the resource
    /// server: which check failed is in the detail, for the log, and the user is told the same thing
    /// either way.
    /// </remarks>
    ExternalIdentityTokenRejected,

    /// <summary>The ID token's <c>nonce</c> is absent, or is not the one this browser was issued.</summary>
    ExternalNonceMismatch,

    /// <summary>
    /// The upstream identity is genuine and no local account is linked to it.
    /// </summary>
    /// <remarks>
    /// The default answer for a first-time federated sign-in, because provisioning is opt-in. It is
    /// <b>not</b> a fallback to matching on email: this server has no code path that finds an account
    /// by email address, which is what makes the classic federated account takeover unreachable
    /// rather than merely avoided.
    /// </remarks>
    ExternalIdentityUnlinked,

    /// <summary>The linked local account exists and is disabled.</summary>
    ExternalAccountDisabled,

    /// <summary>
    /// A link was requested and this upstream identity is already linked to a different local
    /// account.
    /// </summary>
    /// <remarks>
    /// Refused rather than re-pointed. Moving a link is how whoever controls an upstream subject -
    /// or anyone who can replay a link request - lands the next federated sign-in inside somebody
    /// else's data.
    /// </remarks>
    ExternalIdentityLinkedElsewhere,

    /// <summary>
    /// A link was requested and the browser is not signed in as the account it started from.
    /// </summary>
    /// <remarks>
    /// Covers both "no session" and "a different session than the one that began the link", which
    /// are the same refusal: linking is an act by an authenticated account on itself.
    /// </remarks>
    ExternalLinkRequiresSession,

    // ── /token, request shape ───────────────────────────────────────────────

    /// <summary>The request was not <c>application/x-www-form-urlencoded</c>.</summary>
    MediaTypeUnsupported,

    /// <summary>The body is form-encoded by declaration and does not parse.</summary>
    RequestBodyUnreadable,

    /// <summary><c>grant_type</c> is absent.</summary>
    GrantTypeMissing,

    /// <summary><c>grant_type</c> is not one this server offers.</summary>
    GrantTypeUnsupported,

    /// <summary>
    /// The grant is offered and has no handler. A wiring error, not a client error - options
    /// validation is supposed to make it unreachable.
    /// </summary>
    GrantTypeHasNoHandler,

    // ── /token, client authentication ───────────────────────────────────────

    /// <summary>More than one client authentication mechanism was presented. OAuth 2.1 §2.4.</summary>
    ClientAuthenticationMethodsCombined,

    /// <summary>An <c>Authorization</c> header was sent and is not a well-formed Basic credential.</summary>
    ClientAuthorizationHeaderMalformed,

    /// <summary>The header and the body name different clients.</summary>
    ClientIdentifierMismatch,

    /// <summary>The client is registered for a method this server does not offer.</summary>
    ClientAuthMethodNotOffered,

    /// <summary>The method is offered and has no implementation. A wiring error.</summary>
    ClientAuthMethodNotImplemented,

    /// <summary>A client registered as public presented a credential.</summary>
    ClientCredentialsUnexpected,

    /// <summary>A client registered as confidential presented none.</summary>
    ClientCredentialsMissing,

    /// <summary>The presented client secret does not match the stored hash.</summary>
    ClientCredentialsInvalid,

    // ── /token, the authorization_code grant ────────────────────────────────

    /// <summary><c>code</c> is absent.</summary>
    AuthorizationCodeMissing,

    /// <summary><c>code</c> is not a well-formed authorization code of ours.</summary>
    AuthorizationCodeMalformed,

    /// <summary>No stored code has that hash.</summary>
    AuthorizationCodeUnknown,

    /// <summary>The code was issued to a different client.</summary>
    AuthorizationCodeWrongClient,

    /// <summary><c>redirect_uri</c> was sent and differs from the one the authorization used.</summary>
    AuthorizationCodeRedirectUriMismatch,

    /// <summary>The code is past its expiry.</summary>
    AuthorizationCodeExpired,

    /// <summary>The grant behind the code is missing or revoked.</summary>
    AuthorizationCodeGrantInactive,

    /// <summary>
    /// A second presentation inside the retry window. Refused, and deliberately <b>not</b> treated
    /// as a replay: a lost response and a double-click both land here.
    /// </summary>
    AuthorizationCodeReplayedWithinRetryWindow,

    /// <summary>A fully valid second presentation outside the retry window. The grant is revoked.</summary>
    AuthorizationCodeReplayed,

    /// <summary><c>code_verifier</c> is present without a stored challenge, or absent with one.</summary>
    PkceVerifierPresenceMismatch,

    /// <summary><c>code_verifier</c> is outside RFC 7636's grammar.</summary>
    PkceVerifierMalformed,

    /// <summary>The stored challenge does not re-parse. A corrupted record.</summary>
    PkceStoredChallengeUnusable,

    /// <summary>The verifier does not match the stored challenge.</summary>
    PkceVerifierMismatch,

    // ── /introspect ─────────────────────────────────────────────────────────

    /// <summary><c>token</c> is absent. The only thing this endpoint requires of a caller.</summary>
    /// <remarks>
    /// Raised only after client authentication has passed. RFC 7662 §2.1 requires authorization on
    /// this endpoint to stop token scanning, and telling an unauthenticated caller which parameter
    /// they left out confirms the endpoint is live and takes it.
    /// </remarks>
    TokenParameterMissing,

    // ── /token, the refresh_token grant ─────────────────────────────────────

    /// <summary><c>refresh_token</c> is absent.</summary>
    RefreshTokenMissing,

    /// <summary><c>refresh_token</c> is not a well-formed refresh token of ours.</summary>
    RefreshTokenMalformed,

    /// <summary>No stored refresh token has that hash.</summary>
    RefreshTokenUnknown,

    /// <summary>The grant behind the refresh token is missing or revoked.</summary>
    RefreshTokenGrantInactive,

    /// <summary>The refresh token belongs to a different client.</summary>
    RefreshTokenWrongClient,

    /// <summary>The requested <c>scope</c> does not parse.</summary>
    RefreshTokenScopeMalformed,

    /// <summary>The requested <c>scope</c> exceeds the grant. Never <c>invalid_grant</c>.</summary>
    RefreshTokenScopeWidened,

    /// <summary>A consumed token was presented outside the grace window. The family is revoked.</summary>
    RefreshTokenReuseDetected,

    /// <summary>
    /// A racing redemption landed in the grace window and the successor could not be reconstructed.
    /// The one that means "this deployment's derivation key is wrong", not "this client is wrong".
    /// </summary>
    RefreshTokenSuccessorUnrecoverable,

    // ── the resource server ─────────────────────────────────────────────────

    /// <summary>No Bearer credential was presented. X-32.</summary>
    BearerCredentialAbsent,

    /// <summary>A Bearer credential was presented in a way that does not parse. X-35.</summary>
    BearerCredentialMalformed,

    /// <summary><c>exp</c> is in the past beyond the configured skew. X-33.</summary>
    AccessTokenExpired,

    /// <summary><c>aud</c> does not name this resource. N-01's second leg. X-33.</summary>
    AccessTokenWrongAudience,

    /// <summary>
    /// Anything else the validator refused: signature, <c>kid</c>, <c>alg</c>, <c>typ</c>,
    /// <c>iss</c>, unparseable. The detail carries which - the response cannot. X-33.
    /// </summary>
    AccessTokenRejected,

    /// <summary>
    /// The token verified, and the grant behind it has been revoked. X-33.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="AccessTokenRejected"/> because the cause and the cure are different
    /// and only one of them is the caller's. A rejected token failed a check on the token itself; a
    /// revoked one is a perfectly good token whose session somebody ended, which is the one 401 a
    /// deployment should expect to see on purpose. Rolled into the same response - the client is
    /// told <c>invalid_token</c> either way, per RFC 6750 - and separated in the log, where "how
    /// often does ending a session actually cut something" is a question with an answer.
    /// </remarks>
    AccessTokenRevoked,

    /// <summary>A valid token without a scope the endpoint requires. X-34.</summary>
    InsufficientScope,

    // ── rate limits ─────────────────────────────────────────────────────────

    /// <summary>
    /// A rate limit, a quota or a circuit breaker refused the request. X-31.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One of the two reasons whose response carries no OAuth <c>error</c> code - X-31's row in the
    /// requirements has <i>(none)</i> in that column, because being over a limit is a transport
    /// condition and RFC 6749 §4.1.2.1 registers nothing that means it. <see cref="StoreUnavailable"/>
    /// is the other, for the same reason on a different surface. The detail says which limit,
    /// which is the part an operator needs and the part a caller must not be told: "the breaker for
    /// this client_id is open" and "the per-host outbound budget is spent" are different facts about
    /// the server's state.
    /// </para>
    /// <para>
    /// One reason rather than one per limiter, deliberately. A caller distinguishing "I hit the
    /// per-client budget" from "I hit the per-host budget" learns which other clients share a host
    /// with them, which is exactly the inference the CIMD fetch limits exist to make expensive.
    /// </para>
    /// </remarks>
    RateLimited,

    // ── the store behind the endpoint ───────────────────────────────────────

    /// <summary>
    /// The store could not be reached, so the request was shed rather than answered. X-43.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is not <see cref="OAuthErrorCode.ServerError"/> and the difference is the whole
    /// point.</b> <c>server_error</c> means the request cannot succeed and says nothing about when
    /// it might; a client reading one at <c>/token</c> has no instruction but to give up, and the
    /// person holding it is told their credentials are the problem. A dependency that is briefly
    /// unreachable is the opposite situation: nothing about the request was wrong, and the same
    /// request a minute later succeeds. Answering both the same way spends a re-authorization on an
    /// outage that lasted forty seconds.
    /// </para>
    /// <para>
    /// <b>Measured, not hypothesised.</b> 2026-08-22 03:43:16 UTC: DNS for the database host failed
    /// with <c>EAI_AGAIN</c>, <c>/token</c> raised the driver exception through the endpoint, and
    /// ASP.NET Core turned it into a bare <c>500</c> after five seconds. The client stopped
    /// refreshing, replayed its expired access token, then sent none at all, and the user was shown
    /// "authorization failed, check your credentials and permissions". The store answered normally
    /// seventy seconds later. Nothing was wrong with the credentials, the grant or the client.
    /// </para>
    /// <para>
    /// <b>The code on the wire depends on the surface, and that is the specification rather than an
    /// inconsistency.</b> At <c>/token</c>, <c>/introspect</c> and <c>/userinfo</c> the response
    /// carries no OAuth <c>error</c> at all, like <see cref="RateLimited"/>: RFC 6749 §5.2 defines a
    /// closed set for the token endpoint - which RFC 7662 §2.3 adopts - and none of its members
    /// means "come back shortly", while RFC 6750 registers nothing for it either. The status and the
    /// <c>Retry-After</c> carry the meaning instead. At <c>/authorize</c> the code
    /// <c>temporarily_unavailable</c> <i>is</i> registered, by §4.1.2.1, and means exactly this - so
    /// there the honest answer is to use it rather than to imitate the other surfaces' silence.
    /// <c>OAuthErrors</c> refusing to resolve that pair anywhere else is what keeps the two apart.
    /// </para>
    /// <para>
    /// <b>Every surface that reads a store sheds, and each for its own reason.</b> <c>/token</c>
    /// because <c>DESIGN.md</c> §1.2 says it load-sheds rather than queuing, and because a client
    /// hits it unattended. <c>/introspect</c> because neither <c>active</c> is available when the
    /// revocation lookup failed - <c>true</c> is failing open on the denylist the endpoint exists to
    /// consult, and <c>false</c> is a definite answer built from no information. <c>/userinfo</c>
    /// because the nearest code a caller might otherwise be given, <c>invalid_token</c>, makes every
    /// conforming client discard a credential that is perfectly good. <c>/authorize</c> because
    /// <c>server_error</c> tells a client to give up at the start of a flow.
    /// </para>
    /// <para>
    /// The detail names the exception type and nothing else. A driver message can carry the host,
    /// the database, the role and the driver version, and this response is readable by anyone who
    /// can reach the endpoint - the exception itself goes to the log, where the correlation id
    /// leads.
    /// </para>
    /// </remarks>
    StoreUnavailable,

    // ── client_credentials ──────────────────────────────────────────────────

    /// <summary>
    /// A <c>client_credentials</c> request came from a client that names no owner account.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Refused rather than served with the client as its own subject. A token whose <c>sub</c> is a
    /// client id looks exactly like one a person got, and every consumer downstream - role checks,
    /// audit trails, anything that attributes a write - would resolve it against an account table
    /// it is not in. The failure would surface as "this account has no roles", far from here.
    /// </para>
    /// <para>
    /// So the owner is not optional and its absence is a configuration error, said plainly. See
    /// <c>ClientRecord.Owner</c> for why binding to an account is the design rather than inventing a
    /// second kind of identity.
    /// </para>
    /// </remarks>
    ClientHasNoOwner,

    /// <summary>
    /// A client names an owner account that does not exist, or that is disabled.
    /// </summary>
    /// <remarks>
    /// One reason for both, because the distinction is exactly the one that must not reach the
    /// caller: "that account was deleted" and "that account is suspended" are facts about a person,
    /// and the client presenting a secret is not necessarily entitled to either. The detail carries
    /// which it was, and the detail is server-side.
    /// </remarks>
    ClientOwnerUnusable,

    /// <summary>
    /// The standing grant behind a service account has been revoked.
    /// </summary>
    /// <remarks>
    /// Its own reason rather than <see cref="RefreshTokenGrantInactive"/>, which names the same
    /// state reached down a different path. Nothing was refreshed here and no refresh token exists
    /// to be inactive; what happened is that somebody revoked this client's standing authorization
    /// and it stayed revoked, which is the design - the grant id is derived from the client and its
    /// owner, so the next request finds the same revoked row rather than minting a new one.
    /// </remarks>
    ClientCredentialsGrantRevoked,

    // ── /token, private_key_jwt (RFC 7523) ──────────────────────────────────

    /// <summary>
    /// <c>client_assertion_type</c> is absent, repeated, or not the jwt-bearer URN.
    /// </summary>
    /// <remarks>
    /// Its own code rather than folding into <see cref="ClientCredentialsMissing"/>, because the two
    /// point an operator at different things: a missing assertion is a client that did not
    /// authenticate, and a wrong type is a client that authenticated by a mechanism this endpoint
    /// does not implement - RFC 7521 §4.2 registers the URN, and a different one means SAML or
    /// something nobody here has built.
    /// </remarks>
    ClientAssertionTypeUnsupported,

    /// <summary>The assertion did not verify: signature, issuer, audience, expiry or algorithm.</summary>
    /// <remarks>
    /// One code for all of them on purpose, matching how the secret paths report a bad secret. Which
    /// check failed goes in the private detail; the client is told only that authentication failed,
    /// because the difference between "wrong audience" and "bad signature" is a map of this server's
    /// validation to anyone willing to send assertions until the message changes.
    /// </remarks>
    ClientAssertionInvalid,

    /// <summary>The assertion has no usable <c>jti</c>, so replay could not be prevented.</summary>
    /// <remarks>
    /// Refused rather than accepted-without-the-check. RFC 7523 §3 makes <c>jti</c> optional and the
    /// replay check a MAY, so this is stricter than the letter - and the alternative is a credential
    /// whose reuse this server cannot detect, silently, on the one endpoint where reuse matters.
    /// </remarks>
    ClientAssertionIdentifierUnusable,

    /// <summary>This assertion has been presented before.</summary>
    ClientAssertionReplayed,

    /// <summary>The client's key set could not be fetched or parsed.</summary>
    /// <remarks>
    /// Distinct from <see cref="ClientAssertionInvalid"/> because the fault is not the assertion's:
    /// the client may have signed correctly and its own origin be unreachable. The client is still
    /// told only that authentication failed - it cannot fix this server's view of its keys - but an
    /// operator reading the log needs to know they are looking at somebody else's outage.
    /// </remarks>
    ClientAssertionKeysUnavailable,
}

/// <summary>
/// Why a request was refused, in the form an operator needs rather than the form the client gets.
/// </summary>
/// <remarks>
/// <para>
/// A-09. This is the <b>diagnostic payload</b> and not a response: it carries no status, no wire
/// string and no delivery. Those come from <see cref="OAuthErrors"/> keyed on the surface, and the
/// separation is deliberate - <c>DESIGN.md</c> §1.3 flaw 5 records what happens when the diagnostic
/// type and the delivery type are merged. An error delivered by redirect still requires a validated
/// redirect URI to construct, and folding the log obligation into that type would have made the
/// obligation reachable without one.
/// </para>
/// <para>
/// <b><see cref="PrivateDetail"/> never reaches the wire, and <see cref="Description"/> always
/// does.</b> That is the whole point of there being two fields. The sharpest case is a resource
/// server: an unparseable JWT, a wrong signing key, an <c>iss</c> mismatch and a wrong <c>typ</c>
/// are one <c>invalid_token</c> to the client and four different mornings for whoever is on call.
/// </para>
/// </remarks>
public sealed record Rejection
{
    private Rejection(ReasonCode reason, OAuthErrorCode error, string description, string? privateDetail, Exception? cause)
    {
        Reason = reason;
        Error = error;
        Description = description;
        PrivateDetail = privateDetail;
        Cause = cause;
    }

    /// <summary>Which check refused this request.</summary>
    public ReasonCode Reason { get; }

    /// <summary>The OAuth error the client is told.</summary>
    public OAuthErrorCode Error { get; }

    /// <summary>
    /// The description the client is told. Filtered again by the delivery type before it is written.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Detail for the log only. <see langword="null"/> when the reason says everything.
    /// </summary>
    /// <remarks>
    /// Control characters are stripped and the value is capped in <see cref="Of"/> - several call
    /// sites put a caller-supplied URL or header value here, and a CR/LF pair in a log line is a
    /// forged second line. Filtering in the factory rather than at each call site is the same
    /// argument <c>ErrorText.Safe</c> makes about the wire: a call site is a place to forget.
    /// </remarks>
    public string? PrivateDetail { get; }

    /// <summary>
    /// The exception behind this rejection, for the log only. Set for X-10 and nothing else.
    /// </summary>
    public Exception? Cause { get; }

    /// <summary>The only factory.</summary>
    /// <param name="reason">Which check refused the request.</param>
    /// <param name="error">The OAuth error the client is told.</param>
    /// <param name="description">The description the client is told.</param>
    /// <param name="privateDetail">Detail for the log. Never written to a response.</param>
    /// <param name="cause">The exception behind the rejection, if there was one.</param>
    public static Rejection Of(
        ReasonCode reason,
        OAuthErrorCode error,
        string description,
        string? privateDetail = null,
        Exception? cause = null)
    {
        ArgumentNullException.ThrowIfNull(description);

        if (reason is ReasonCode.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                reason,
                "A rejection needs a real reason: ReasonCode.None is the unset value, and a log field "
                + "full of 'None' is a field nobody can alert on.");
        }

        return new Rejection(reason, error, description, LogText.Safe(privateDetail), cause);
    }
}

/// <summary>
/// Makes a value safe to put in a log line.
/// </summary>
/// <remarks>
/// Narrower than <c>ErrorText.Safe</c>, which filters to OAuth 2.1 §4.1.2.1's response character
/// set. A log line is not a redirect query string: <c>"</c> and non-ASCII are fine there and are
/// often the whole content of a diagnosis. What is not fine is a control character, because CR and
/// LF turn one attacker-influenced field into two log lines, and the second one can say anything.
/// </remarks>
internal static class LogText
{
    /// <summary>
    /// The cap.
    /// </summary>
    /// <remarks>
    /// Longer than the wire cap, because this text is read by one person on one occasion rather
    /// than echoed to every client. Still bounded: a CIMD <c>client_id</c> is a caller-chosen URL,
    /// and an unbounded field is a way to push the rest of the line out of a log viewer.
    /// </remarks>
    internal const int MaxLength = 512;

    /// <summary>Strip control characters and truncate.</summary>
    internal static string? Safe(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        var builder = new System.Text.StringBuilder(Math.Min(value.Length, MaxLength));

        foreach (var c in value)
        {
            if (builder.Length == MaxLength)
            {
                builder.Length = MaxLength - 1;
                builder.Append('~');
                break;
            }

            // Dropped rather than replaced, for the reason ErrorText gives: a replacement character
            // is still a character whose position the caller chose.
            if (!char.IsControl(c))
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }
}

/// <summary>Response headers this project defines.</summary>
public static class DiagnosticHeaders
{
    /// <summary>
    /// The correlation id, on every rejection either server writes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A-09 accepts the id in <c>error_description</c> or in a header, and this is the header -
    /// chosen because it is the only channel that works on all four delivery shapes this project
    /// emits. A redirect error carries its description in the <c>Location</c> query of a 303 the
    /// browser immediately follows away from; a challenge carries it inside a quoted
    /// <c>WWW-Authenticate</c> parameter that competes with <c>resource_metadata</c> for the same
    /// line; and <c>error_description</c> is filtered to OAuth 2.1 §4.1.2.1's set and capped at 240
    /// characters, so an id appended to a long description is an id that gets truncated. A header
    /// is one place, on the response the caller actually received, and <c>curl -D-</c> shows it -
    /// which is what A-12 asks of every failure.
    /// </para>
    /// <para>
    /// It also stays out of the client's hands in the one case that matters: an authorization error
    /// delivered by redirect goes to the client's own address, so anything in
    /// <c>error_description</c> is handed to a third party by design. The header stays on our hop.
    /// </para>
    /// <para>
    /// Defined here rather than in either server, because the authorization server and the resource
    /// server must spell it the same way for one grep to find both halves of a failed connection.
    /// </para>
    /// </remarks>
    public const string RequestId = "X-Request-Id";
}
