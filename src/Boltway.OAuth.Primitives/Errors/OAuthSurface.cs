namespace Boltway.OAuth.Primitives.Errors;

/// <summary>
/// Which endpoint is answering. Half of the key into the error table.
/// </summary>
/// <remarks>
/// The surface is part of the key because the same code means different things — and gets a
/// different status and a different delivery — depending on where it is emitted. It is also how the
/// table refuses combinations that are legal-looking but wrong: <c>access_denied</c> is a real code
/// that must never come out of <c>/token</c>, and <c>unsupported_grant_type</c> must never come out
/// of <c>/authorize</c>.
/// </remarks>
public enum OAuthSurface
{
    /// <summary>
    /// <c>/authorize</c>, <b>before</b> a redirect URI has been validated. RFC 6749 §4.1.2.1.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A separate surface from <see cref="Authorize"/> because the two halves of that endpoint obey
    /// opposite rules, and the difference is not expressible in the error code alone. RFC 6749
    /// §4.1.2.1: "If the request fails due to a missing, invalid, or mismatching redirect URI … the
    /// authorization server MUST NOT redirect the user agent to the invalid redirect URI."
    /// </para>
    /// <para>
    /// The reason it needs its own surface: <c>invalid_request</c> is the correct code for a
    /// mismatched <c>redirect_uri</c> <i>and</i> for a malformed <c>code_challenge</c>, but the
    /// first must be rendered as HTML on our own origin and the second must be redirected. Keyed
    /// only on (endpoint, code) the two collapse together, and the collapse resolves the
    /// never-redirect case to a redirect — turning the authorization endpoint into an open
    /// redirector that also leaks <c>state</c>.
    /// </para>
    /// <para>
    /// The boundary is exactly the point where the request pipeline mints a validated redirect, so
    /// which surface applies is a question the code already has to answer.
    /// </para>
    /// </remarks>
    AuthorizePreRedirect,

    /// <summary>
    /// <c>/authorize</c>, after the redirect URI is validated and redirecting is permitted.
    /// </summary>
    Authorize,

    /// <summary><c>/token</c>. RFC 6749 §5.2.</summary>
    Token,

    /// <summary><c>/register</c>. RFC 7591 §3.2.2.</summary>
    Registration,

    /// <summary><c>/register/{id}</c>. RFC 7592 §2.</summary>
    RegistrationManagement,

    /// <summary>A protected resource, and <c>/userinfo</c>. RFC 6750 §3.</summary>
    ResourceServer,

    /// <summary><c>/introspect</c>. RFC 7662 §2.3.</summary>
    Introspection,

    /// <summary><c>/revoke</c>. RFC 7009 §2.2.</summary>
    Revocation,

    /// <summary>
    /// The pages a person is looking at: sign-in, consent, password recovery, self-service.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Not an OAuth surface, and it has no rows in <see cref="OAuthErrors"/> on purpose.</b>
    /// Every other value here names an endpoint some specification defines an <c>error</c> set for.
    /// These have none — a sign-in form is not a protocol surface, and the refusals it produces
    /// (a rejected password, a rate limit, a store that cannot be reached) are answered with a
    /// status and a rendered page rather than a code a client parses.
    /// </para>
    /// <para>
    /// It exists so the rejection log can say <i>which</i> of the two halves of this server failed.
    /// An operator woken by a burst of refusals needs to know whether token issuance is affected or
    /// whether people simply cannot reach the sign-in page, and those are different pages to open.
    /// Before this, a refusal from a login page had to borrow a surface that named a different
    /// endpoint, which put the wrong answer in the one field an operator groups by.
    /// </para>
    /// </remarks>
    Interaction,

    /// <summary>
    /// The management APIs behind the admin and self-service UIs: <c>/admin/*</c>, <c>/account/*</c>.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="Interaction"/> because the caller is different in the way that
    /// decides the answer: a script in a page rather than the page. A refusal here is JSON or a
    /// bare status the UI branches on, where the same condition on <see cref="Interaction"/> has to
    /// render something a person can read. Like it, this surface has no rows in the error table.
    /// </remarks>
    Administration,
}

/// <summary>How an error reaches the caller.</summary>
public enum ErrorDelivery
{
    /// <summary>
    /// Query parameters on a redirect to the <b>validated</b> <c>redirect_uri</c>.
    /// </summary>
    /// <remarks>
    /// Only reachable once a redirect URI has been matched against the client's registrations.
    /// Before that point the server must not redirect at all — an unvalidated <c>redirect_uri</c>
    /// plus an error response is an open redirector that also leaks <c>state</c>.
    /// </remarks>
    Redirect,

    /// <summary>An OAuth JSON body: <c>error</c>, <c>error_description</c>.</summary>
    Json,

    /// <summary>
    /// An OAuth JSON body <b>and</b> a <c>WWW-Authenticate</c> header.
    /// </summary>
    /// <remarks>
    /// Its own value rather than a flag, because RFC 6749 §5.2 makes the header mandatory rather
    /// than advisory for a client-authentication failure: "MUST … include the 'WWW-Authenticate'
    /// response header field matching the authentication scheme used by the client." A delivery
    /// mode that could not express "both" would have made the omission unrepresentable, and
    /// therefore silent.
    /// </remarks>
    JsonWithChallenge,

    /// <summary>
    /// An HTML page on the authorization server's own origin, for failures that must not redirect.
    /// </summary>
    Html,

    /// <summary>A <c>WWW-Authenticate</c> challenge header.</summary>
    Header,
}
