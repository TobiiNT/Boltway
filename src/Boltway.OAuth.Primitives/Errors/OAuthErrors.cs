using System.Collections.Frozen;

namespace Boltway.OAuth.Primitives.Errors;

/// <summary>
/// One error, fully specified: its wire string, its HTTP status, and how it is delivered.
/// </summary>
/// <param name="Wire">The exact <c>error</c> value. Clients branch on this string.</param>
/// <param name="Status">The HTTP status. Part of the protocol signal, not a formality.</param>
/// <param name="Delivery">How the error reaches the caller.</param>
/// <param name="RequirementId">The <c>X-nn</c> row this implements, so a log line is traceable.</param>
public sealed record OAuthErrorSpec(string Wire, int Status, ErrorDelivery Delivery, string RequirementId);

/// <summary>
/// The single table mapping (surface, code) to its wire form, status and delivery.
/// </summary>
/// <remarks>
/// <para>
/// One table, used by the production code <i>and</i> by the conformance tests, so a wrong wire
/// string is one failure rather than forty-one places to get right independently.
/// </para>
/// <para>
/// <see cref="Resolve"/> <b>throws</b> on a pair that is not listed. That is the point of the type:
/// it turns "<c>access_denied</c> is never emitted from <c>/token</c>" from a sentence in a
/// specification into something the process cannot do. A call site that tries it does not produce a
/// subtly wrong response for a client to misinterpret — it fails loudly, in a test, at the moment
/// someone writes it.
/// </para>
/// </remarks>
public static class OAuthErrors
{
    private static readonly FrozenDictionary<(OAuthSurface, OAuthErrorCode), OAuthErrorSpec> Table =
        new Dictionary<(OAuthSurface, OAuthErrorCode), OAuthErrorSpec>
        {
            // ── /authorize, before a redirect URI is validated ───────────────────
            //
            // X-01, X-02 and X-03: HTML at 400, never a redirect. RFC 6749 §4.1.2.1 — with an
            // unknown client or a redirect URI that does not match, there is no address it is safe
            // to send the user to, and redirecting anyway makes the authorization endpoint an open
            // redirector that also leaks `state`.
            //
            // X-02 needs this separate surface rather than a separate code: `invalid_request` is
            // correct BOTH for a mismatched redirect_uri (never redirect) and for a malformed
            // code_challenge (must redirect). Keyed on (endpoint, code) alone the two collapse, and
            // the collapse resolves the never-redirect case to a redirect.
            [(OAuthSurface.AuthorizePreRedirect, OAuthErrorCode.InvalidClient)] =
                new("invalid_client", 400, ErrorDelivery.Html, "X-01/X-03"),
            [(OAuthSurface.AuthorizePreRedirect, OAuthErrorCode.InvalidRequest)] =
                new("invalid_request", 400, ErrorDelivery.Html, "X-02"),

            // A crash before the redirect URI is trusted. 500, not 400.
            //
            // The design note for the exception boundary said HTML 400 here, and 400 is the wrong
            // answer to a server fault: it tells the caller their request was malformed when the
            // server broke, which sends whoever is debugging it to the client. There is no redirect
            // available on this surface — that is what the surface means — so the status is the only
            // channel left to say which side failed.
            //
            // Without this row Resolve() throws, which would turn every pre-redirect crash into a
            // second crash inside the handler for the first.
            [(OAuthSurface.AuthorizePreRedirect, OAuthErrorCode.ServerError)] =
                new("server_error", 500, ErrorDelivery.Html, "X-10"),

            // 503 rather than 500, and it is the same distinction X-43 draws at /token: server_error
            // says the request cannot succeed, temporarily_unavailable says it can, shortly. This is
            // the half of that pair the person sees — the store failed before a redirect URI could be
            // validated, so there is nowhere safe to send them and the answer renders here.
            //
            // The row is new; the requirement is not. X-11 has been in the table for the redirect
            // half since before there was anything to emit it, and A_pre_redirect_status_says_which
            // _side_failed has been asserting that this exact pair must be 5xx — against a row that
            // did not exist. Adding it is what gives that assertion something to hold.
            [(OAuthSurface.AuthorizePreRedirect, OAuthErrorCode.TemporarilyUnavailable)] =
                new("temporarily_unavailable", 503, ErrorDelivery.Html, "X-11"),

            // ── /authorize, once redirecting is permitted ────────────────────────
            //
            // 303 throughout, not 302. OAuth 2.1 §7.5.3 and RFC 9700 §4.12: an authorization server
            // redirecting a request that may carry user credentials MUST NOT use 307 and SHOULD use
            // 303. Several of these arise from the consent POST — access_denied is by definition
            // the answer to one — so a uniform 303 satisfies N-12 without asking each call site to
            // know whether it got here by GET or POST. 303 is legal on the GET paths too.
            [(OAuthSurface.Authorize, OAuthErrorCode.InvalidRequest)] =
                new("invalid_request", 303, ErrorDelivery.Redirect, "X-04"),
            [(OAuthSurface.Authorize, OAuthErrorCode.UnauthorizedClient)] =
                new("unauthorized_client", 303, ErrorDelivery.Redirect, "X-05"),
            [(OAuthSurface.Authorize, OAuthErrorCode.AccessDenied)] =
                new("access_denied", 303, ErrorDelivery.Redirect, "X-06"),
            [(OAuthSurface.Authorize, OAuthErrorCode.UnsupportedResponseType)] =
                new("unsupported_response_type", 303, ErrorDelivery.Redirect, "X-07"),
            [(OAuthSurface.Authorize, OAuthErrorCode.InvalidScope)] =
                new("invalid_scope", 303, ErrorDelivery.Redirect, "X-08"),
            [(OAuthSurface.Authorize, OAuthErrorCode.InvalidTarget)] =
                new("invalid_target", 303, ErrorDelivery.Redirect, "X-09"),
            // X-10 exists precisely because a 500 cannot be delivered through a redirect. Any
            // unhandled exception after the redirect URI is trusted becomes this.
            [(OAuthSurface.Authorize, OAuthErrorCode.ServerError)] =
                new("server_error", 303, ErrorDelivery.Redirect, "X-10"),
            [(OAuthSurface.Authorize, OAuthErrorCode.TemporarilyUnavailable)] =
                new("temporarily_unavailable", 303, ErrorDelivery.Redirect, "X-11"),
            [(OAuthSurface.Authorize, OAuthErrorCode.LoginRequired)] =
                new("login_required", 303, ErrorDelivery.Redirect, "X-12"),
            [(OAuthSurface.Authorize, OAuthErrorCode.ConsentRequired)] =
                new("consent_required", 303, ErrorDelivery.Redirect, "X-13"),
            [(OAuthSurface.Authorize, OAuthErrorCode.AccountSelectionRequired)] =
                new("account_selection_required", 303, ErrorDelivery.Redirect, "X-14"),
            [(OAuthSurface.Authorize, OAuthErrorCode.InteractionRequired)] =
                new("interaction_required", 303, ErrorDelivery.Redirect, "X-15"),
            [(OAuthSurface.Authorize, OAuthErrorCode.RequestNotSupported)] =
                new("request_not_supported", 303, ErrorDelivery.Redirect, "X-16"),
            [(OAuthSurface.Authorize, OAuthErrorCode.RequestUriNotSupported)] =
                new("request_uri_not_supported", 303, ErrorDelivery.Redirect, "X-16"),
            [(OAuthSurface.Authorize, OAuthErrorCode.RegistrationNotSupported)] =
                new("registration_not_supported", 303, ErrorDelivery.Redirect, "X-16"),

            // ── /token ──────────────────────────────────────────────────────────
            //
            // Deliberately ABSENT from this surface: access_denied, unsupported_response_type,
            // server_error, temporarily_unavailable, invalid_token, insufficient_scope. Each is a
            // real code that belongs somewhere else, and Resolve throwing is what keeps them there.
            [(OAuthSurface.Token, OAuthErrorCode.InvalidRequest)] =
                new("invalid_request", 400, ErrorDelivery.Json, "X-17"),
            // 400 by default, NOT a blanket 401. OAuth 2.1 §3.2.4: the token endpoint "responds
            // with an HTTP 400 (Bad Request) status code (unless specified otherwise)", and for
            // this code specifically "MAY return an HTTP 401 … If the client attempted to
            // authenticate via the Authorization request header field, the authorization server
            // MUST respond with an HTTP 401." So 401 is conditional on evidence the table does not
            // have — see StatusForClientAuthFailure, which the endpoint calls with what it observed.
            [(OAuthSurface.Token, OAuthErrorCode.InvalidClient)] =
                new("invalid_client", 400, ErrorDelivery.JsonWithChallenge, "X-18"),
            [(OAuthSurface.Token, OAuthErrorCode.InvalidGrant)] =
                new("invalid_grant", 400, ErrorDelivery.Json, "X-19"),
            [(OAuthSurface.Token, OAuthErrorCode.UnauthorizedClient)] =
                new("unauthorized_client", 400, ErrorDelivery.Json, "X-20"),
            // Not invalid_request: OAuth 2.1 §3.2.4 excludes grant type from that code explicitly.
            [(OAuthSurface.Token, OAuthErrorCode.UnsupportedGrantType)] =
                new("unsupported_grant_type", 400, ErrorDelivery.Json, "X-21"),
            [(OAuthSurface.Token, OAuthErrorCode.InvalidScope)] =
                new("invalid_scope", 400, ErrorDelivery.Json, "X-22"),
            [(OAuthSurface.Token, OAuthErrorCode.InvalidTarget)] =
                new("invalid_target", 400, ErrorDelivery.Json, "X-23"),

            // ── /register ───────────────────────────────────────────────────────
            //
            // RFC 7591 defines no invalid_request at this endpoint. Note also that ASP.NET Core's
            // default ProblemDetails body has no `error` member at all, so letting it through here
            // produces a response neither vendor's parser can read.
            [(OAuthSurface.Registration, OAuthErrorCode.InvalidRedirectUri)] =
                new("invalid_redirect_uri", 400, ErrorDelivery.Json, "X-24"),
            [(OAuthSurface.Registration, OAuthErrorCode.InvalidClientMetadata)] =
                new("invalid_client_metadata", 400, ErrorDelivery.Json, "X-25"),
            [(OAuthSurface.Registration, OAuthErrorCode.InvalidSoftwareStatement)] =
                new("invalid_software_statement", 400, ErrorDelivery.Json, "X-26"),
            [(OAuthSurface.Registration, OAuthErrorCode.UnapprovedSoftwareStatement)] =
                new("unapproved_software_statement", 400, ErrorDelivery.Json, "X-27"),

            // ── /register/{id} ──────────────────────────────────────────────────
            //
            // 401 and never 404, even for a client that does not exist. A 404 here would make the
            // endpoint a client-id enumeration oracle.
            [(OAuthSurface.RegistrationManagement, OAuthErrorCode.InvalidToken)] =
                new("invalid_token", 401, ErrorDelivery.Header, "X-28"),
            // RFC 7592 §2.2: "If the client attempts to set an invalid metadata field and the
            // authorization server does not set a default value, the authorization server responds
            // with an error as described in [RFC7591]." So a PUT carrying bad metadata rejects with
            // the RFC 7591 codes — without these rows Resolve would throw on a legitimate rejection.
            [(OAuthSurface.RegistrationManagement, OAuthErrorCode.InvalidRedirectUri)] =
                new("invalid_redirect_uri", 400, ErrorDelivery.Json, "X-24"),
            [(OAuthSurface.RegistrationManagement, OAuthErrorCode.InvalidClientMetadata)] =
                new("invalid_client_metadata", 400, ErrorDelivery.Json, "X-25"),

            // ── resource server and /userinfo ───────────────────────────────────
            [(OAuthSurface.ResourceServer, OAuthErrorCode.InvalidToken)] =
                new("invalid_token", 401, ErrorDelivery.Header, "X-32/X-33"),
            // 403, and it MUST carry error="insufficient_scope" plus the scopes that would work.
            // A bare 403 is terminal for Claude: it produces no re-authentication prompt at all.
            [(OAuthSurface.ResourceServer, OAuthErrorCode.InsufficientScope)] =
                new("insufficient_scope", 403, ErrorDelivery.Header, "X-34"),
            // 400, not 401. Getting this backwards makes a client retry-loop forever: it reads 401
            // as "refresh and try again", refreshes successfully, and sends the same malformed
            // header.
            [(OAuthSurface.ResourceServer, OAuthErrorCode.InvalidRequest)] =
                new("invalid_request", 400, ErrorDelivery.Header, "X-35"),

            // ── /introspect ─────────────────────────────────────────────────────
            //
            // An inactive token is NOT an error here and so has no row at all. RFC 7662 §2.3: "a
            // properly formed and authorized query for an inactive or otherwise invalid token …
            // is not considered an error response by this specification." It is answered 200 with
            // {"active":false} by the endpoint's success path. Returning 401 instead makes a
            // conformant resource server conclude its own credentials are broken and stop asking.
            //
            // §2.3 also defines a 401 for a caller authenticating with a BEARER token that lacks
            // privileges — note 401, not 403. There is no row for it because this server accepts
            // only client credentials at this endpoint; if bearer-authenticated introspection is
            // ever added, that row is required.
            [(OAuthSurface.Introspection, OAuthErrorCode.InvalidRequest)] =
                new("invalid_request", 400, ErrorDelivery.Json, "X-37"),
            [(OAuthSurface.Introspection, OAuthErrorCode.InvalidClient)] =
                new("invalid_client", 401, ErrorDelivery.JsonWithChallenge, "X-38"),

            // ── /revoke ─────────────────────────────────────────────────────────
            //
            // RFC 7009 §2.2: an unknown, invalid or already-revoked token is a SUCCESS. The client
            // asked for the token to not work, and it does not.
            [(OAuthSurface.Revocation, OAuthErrorCode.InvalidRequest)] =
                new("invalid_request", 400, ErrorDelivery.Json, "X-37"),
            [(OAuthSurface.Revocation, OAuthErrorCode.InvalidClient)] =
                new("invalid_client", 401, ErrorDelivery.JsonWithChallenge, "X-38"),
            [(OAuthSurface.Revocation, OAuthErrorCode.UnsupportedTokenType)] =
                new("unsupported_token_type", 400, ErrorDelivery.Json, "X-40"),

            // ── deliberately absent: X-31, the rate limit ────────────────────────
            //
            // There is no row for it anywhere in this table, and there cannot be one. X-31 is the
            // only requirement whose `error` column is literally *(none)*: being over a limit is a
            // transport condition and no registered OAuth code means it. This table is keyed on an
            // OAuthErrorCode, and the one member that could stand for "no code" —
            // OAuthErrorCode.None — is excluded by Resolve's contract and by a test that walks every
            // surface asserting it, because None describes a response rather than naming an error.
            //
            // So a 429 is built where it is emitted, not looked up here: AuthorizeHtmlError.Throttled
            // and AuthorizeResults.Html. What it carries is the status and a Retry-After, which is
            // exactly what X-31 specifies, plus a description for whoever is reading.
            //
            // Borrowing temporarily_unavailable was considered and is wrong: it is the server saying
            // the fault is its own, and 429 says the fault is the caller's. The two contradict, and
            // A_pre_redirect_status_says_which_side_failed already pins that code to 5xx.
        }.ToFrozenDictionary();

    /// <summary>
    /// Look up an error, or throw if this surface may not emit this code.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The pair is not in the table. This is a programming error, not a runtime condition: it means
    /// a call site is trying to emit a code the specification does not permit at that endpoint.
    /// </exception>
    public static OAuthErrorSpec Resolve(OAuthSurface surface, OAuthErrorCode code)
    {
        if (Table.TryGetValue((surface, code), out var spec))
        {
            return spec;
        }

        throw new InvalidOperationException(
            $"'{code}' is not an error the {surface} endpoint may emit. This pair is absent from " +
            "the table deliberately — see OAuthErrors for which surface owns this code. Emitting " +
            "it anyway would produce a response the client cannot act on.");
    }

    /// <summary>Whether a surface may emit a code. For tests and for lint.</summary>
    public static bool CanEmit(OAuthSurface surface, OAuthErrorCode code) => Table.ContainsKey((surface, code));

    /// <summary>
    /// The status for a client-authentication failure, which depends on how the client tried.
    /// </summary>
    /// <param name="usedAuthorizationHeader">
    /// Whether the client presented credentials in the <c>Authorization</c> header, as observed by
    /// the endpoint. Not inferable from the error code, which is why this is a separate call.
    /// </param>
    /// <remarks>
    /// OAuth 2.1 §3.2.4 and RFC 6749 §5.2: the token endpoint answers 400 in general, and for
    /// <c>invalid_client</c> "MAY return an HTTP 401 … If the client attempted to authenticate via
    /// the Authorization request header field, the authorization server MUST respond with an HTTP
    /// 401 … and include the 'WWW-Authenticate' response header field matching the authentication
    /// scheme used by the client."
    /// <para>
    /// A blanket 401 is a real interop problem rather than a pedantic one: a client that
    /// authenticated in the request body and receives 401 with a <c>Basic</c> challenge may switch
    /// authentication schemes on retry, or treat the response as a transport-level auth failure
    /// rather than an OAuth one.
    /// </para>
    /// </remarks>
    public static int StatusForClientAuthFailure(bool usedAuthorizationHeader) =>
        usedAuthorizationHeader ? 401 : 400;

    /// <summary>Every (surface, code) pair, for table-driven conformance tests.</summary>
    public static IReadOnlyCollection<KeyValuePair<(OAuthSurface Surface, OAuthErrorCode Code), OAuthErrorSpec>>
        All => Table;
}
