namespace Boltway.OAuth.Primitives.Errors;

/// <summary>
/// Every OAuth / OIDC error code this server can emit. A closed set.
/// </summary>
/// <remarks>
/// <para>
/// Closed on purpose. A <see cref="string"/> error code invites a plausible-looking invention at
/// the call site, and clients branch on these exactly: RFC 6749 §5.2 and the connector
/// documentation both say a refresh failure must be <c>invalid_grant</c> and "not
/// <c>invalid_request</c> or a custom code", because the client's recovery path is selected by the
/// string. An invented code is not a cosmetic problem — it is a client that never recovers.
/// </para>
/// <para>
/// The wire spelling lives in <see cref="OAuthErrors"/>, not here, so the enum member and the string
/// cannot drift apart at a call site that builds a response by hand.
/// </para>
/// </remarks>
public enum OAuthErrorCode
{
    /// <summary>No error code in the response. Distinct from "not set" — see RFC 6750 §3.1.</summary>
    None = 0,

    // ── RFC 6749 §4.1.2.1, the authorization endpoint ───────────────────────────
    /// <summary>Malformed, missing or repeated parameter.</summary>
    InvalidRequest,

    /// <summary>The client is known but not permitted this grant or response type.</summary>
    UnauthorizedClient,

    /// <summary>The resource owner or the policy refused.</summary>
    AccessDenied,

    /// <summary><c>response_type</c> is not <c>code</c>.</summary>
    UnsupportedResponseType,

    /// <summary>Unknown scope, or a scope this client may not request.</summary>
    InvalidScope,

    /// <summary>An unhandled failure. Exists so a 500 is never delivered by redirect.</summary>
    ServerError,

    /// <summary>A dependency is down, or load is being shed. The client may retry.</summary>
    TemporarilyUnavailable,

    // ── RFC 6749 §5.2, the token endpoint ───────────────────────────────────────
    /// <summary>Client authentication failed, or the client could not be identified.</summary>
    InvalidClient,

    /// <summary>
    /// The grant is unknown, expired, revoked, already used, or was issued to another client.
    /// </summary>
    InvalidGrant,

    /// <summary>The grant type is not one this server implements.</summary>
    UnsupportedGrantType,

    // ── RFC 8707 §2 ─────────────────────────────────────────────────────────────
    /// <summary>
    /// The requested <c>resource</c> is malformed, unknown, or outside this grant's resource set.
    /// </summary>
    /// <remarks>
    /// Never substitute <see cref="InvalidGrant"/> for this. A client reads
    /// <c>invalid_grant</c> as "the refresh token is dead" and discards it, turning a recoverable
    /// mistake about which resource was asked for into a full re-consent loop.
    /// </remarks>
    InvalidTarget,

    // ── OIDC Core §3.1.2.6 ──────────────────────────────────────────────────────
    /// <summary><c>prompt=none</c> but no authenticated session, or <c>max_age</c> was exceeded.</summary>
    LoginRequired,

    /// <summary><c>prompt=none</c> but the requested scopes have not been consented to.</summary>
    ConsentRequired,

    /// <summary><c>prompt=none</c>, several sessions, and the server cannot choose.</summary>
    AccountSelectionRequired,

    /// <summary><c>prompt=none</c> but some other interaction is required.</summary>
    InteractionRequired,

    /// <summary>The <c>request</c> parameter (JAR) was used; we publish that we do not support it.</summary>
    RequestNotSupported,

    /// <summary>The <c>request_uri</c> parameter was used.</summary>
    RequestUriNotSupported,

    /// <summary>The <c>registration</c> parameter was used.</summary>
    RegistrationNotSupported,

    // ── RFC 6750 §3.1, the resource server ──────────────────────────────────────
    /// <summary>The access token is missing, malformed, expired, revoked or for another audience.</summary>
    InvalidToken,

    /// <summary>The token is valid but lacks the scope this operation needs.</summary>
    InsufficientScope,

    // ── RFC 7591 §3.2.2, dynamic client registration ────────────────────────────
    /// <summary>One or more redirect URIs in the registration are invalid.</summary>
    InvalidRedirectUri,

    /// <summary>The submitted client metadata is invalid or self-inconsistent.</summary>
    InvalidClientMetadata,

    /// <summary>The software statement is not a valid, verifiable assertion.</summary>
    InvalidSoftwareStatement,

    /// <summary>The software statement verifies, but policy declines this software.</summary>
    UnapprovedSoftwareStatement,

    // ── RFC 7009 §2.2.1, revocation ─────────────────────────────────────────────
    /// <summary>This server does not revoke tokens of the presented type.</summary>
    UnsupportedTokenType,
}
