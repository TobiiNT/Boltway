# Token Formats & Lifecycle — Implementer Reference

Target: from-scratch OAuth 2.1 + OIDC Authorization Server in C# / ASP.NET Core 9, trusted by
Claude.ai MCP connectors and ChatGPT connectors. Auth0 replacement.

Primary sources fetched and quoted below:

| Spec | What it governs here |
|---|---|
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens (`at+jwt`) |
| RFC 7662 | Token Introspection |
| RFC 7009 | Token Revocation |
| RFC 7519 | JWT — registered claims, validation |
| RFC 7515 | JWS — JOSE header params, signature validation |
| RFC 7517 | JWK / JWK Set — `kid`, `use`, key rotation |
| RFC 7518 | JWA — `alg` registry, key-size MUSTs |
| RFC 6750 | Bearer token usage — RS error codes + `WWW-Authenticate` |
| RFC 8693 | `scope` and `client_id` JWT claim definitions |
| RFC 8414 | AS metadata field names (`jwks_uri`, `introspection_endpoint`, …) |
| RFC 9700 | OAuth 2.0 Security BCP — refresh token rotation & replay detection |
| OIDC Core 1.0 | `auth_time`, `acr`, `amr`, `azp`, `at_hash` |

Provenance note: every quote below was pulled from the RFC text during this research pass, except
the RFC 9700 §4.14.2 bullets, which the fetcher truncated on `rfc-editor.org`; those are quoted from
the identical text in `draft-ietf-oauth-security-topics-16` §4.13.2 (renumbered to §4.14.2 in the
published RFC) and cross-checked against a search hit on the published RFC. They are flagged inline.

---

## 1. RFC 9068 — JWT Access Tokens

### 1.1 JOSE header

| Param | Requirement | Value | Notes |
|---|---|---|---|
| `alg` | REQUIRED (RFC 7515 §4.1.1) | `RS256` / `ES256` / `PS256` | `none` forbidden |
| `typ` | REQUIRED (RFC 9068 §2.1) | `at+jwt` | RS must also accept `application/at+jwt` |
| `kid` | REQUIRED in practice | key id from JWKS | Not spec-REQUIRED, but omit it and rotation breaks |

Normative:

> "JWT access tokens MUST be signed." — RFC 9068 §2.1

> "JWT access tokens MUST NOT use `none` as the signing algorithm." — RFC 9068 §2.1

> "Authorization servers and resource servers conforming to this specification MUST include RS256
> (as defined in [RFC7518]) among their supported signature algorithms." — RFC 9068 §2.1

> "JWT access tokens MUST include this media type in the `typ` header parameter to explicitly declare
> that the JWT represents an access token complying with this profile." — RFC 9068 §2.1

> "…the `typ` value used SHOULD be `at+jwt`." — RFC 9068 §2.1

> "The resource server MUST verify that the `typ` header value is `at+jwt` or `application/at+jwt`
> and reject tokens carrying any other value." — RFC 9068 §4

RFC 7515 §4.1.9 explains why both spellings exist:

> "it is RECOMMENDED that producers omit an `application/` prefix … A recipient using the media type
> value MUST treat it as if `application/` were prepended"

**Implementation: emit `at+jwt`, accept `{at+jwt, application/at+jwt}` case-insensitively.**

### 1.2 Claims

| Claim | Status | Type | Definition source | Value in this AS |
|---|---|---|---|---|
| `iss` | **REQUIRED** | StringOrURI | RFC 7519 §4.1.1 | AS issuer URL, exactly matching `issuer` metadata |
| `exp` | **REQUIRED** | NumericDate | RFC 7519 §4.1.4 | `iat + access_token_ttl` |
| `aud` | **REQUIRED** | StringOrURI \| array | RFC 7519 §4.1.3 | resource indicator (RFC 8707) of the RS |
| `sub` | **REQUIRED** | StringOrURI | RFC 7519 §4.1.2 | user id, or client id for `client_credentials` |
| `client_id` | **REQUIRED** | string | RFC 8693 §4.3 | the requesting client's id |
| `iat` | **REQUIRED** | NumericDate | RFC 7519 §4.1.6 | issue time |
| `jti` | **REQUIRED** | string | RFC 7519 §4.1.7 | unique, ≥128 bits entropy |
| `scope` | SHOULD | space-delimited string | RFC 8693 §4.2 | granted scopes |
| `auth_time` | OPTIONAL | NumericDate | OIDC Core §2 | when the user actually authenticated |
| `acr` | OPTIONAL | string | OIDC Core §2 | authn context class |
| `amr` | OPTIONAL | array of strings | OIDC Core §2 | authn methods, case-sensitive strings |
| `groups` / `roles` / `entitlements` | SHOULD (if used) | per RFC 7643 §4.1.2 | RFC 9068 §2.2.3.1 | authorization attributes |

> "`iat` … This claim identifies the time at which the JWT access token was issued." — RFC 9068 §2.2

> "the value of `sub` SHOULD correspond to the subject identifier of the resource owner." (resource
> owner grants) / "the value of `sub` SHOULD correspond to an identifier the authorization server
> uses to indicate the client application." (client-only grants) — RFC 9068 §2.2

> "If an authorization request includes a scope parameter, the corresponding issued JWT access token
> SHOULD include a `scope` claim as defined in Section 4.2 of [RFC8693]." — RFC 9068 §2.2.3

> "All the individual scope strings in the `scope` claim MUST have meaning for the resources
> indicated in the `aud` claim." — RFC 9068 §2.2.3

`scope` wire format, from RFC 8693 §4.2:

> "The value of the `scope` claim is a JSON string containing a space-separated list of scopes
> associated with the token, in the format described in Section 3.3 of [RFC6749]."

**It is a single space-delimited string, NOT a JSON array.** `"scope": "read write"` — not
`["read","write"]`. Auth0 and Keycloak both emit the string; some homegrown servers emit an array
and break every conformant RS. (Note the asymmetry: OIDC `amr` *is* an array.)

`client_id`, from RFC 8693 §4.3:

> "The `client_id` claim carries the client identifier of the OAuth 2.0 [RFC6749] client that
> requested the token."

### 1.3 Wire example

```
eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6IjIwMjYtMDgtYS1yc2EifQ...
```

Decoded header:

```json
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "2026-08-a-rsa"
}
```

Decoded payload:

```json
{
  "iss": "https://auth.example.com",
  "aud": "https://mcp.example.com",
  "sub": "usr_01J8ZQ3K9V2M",
  "client_id": "cid_claude_ai",
  "iat": 1754179200,
  "exp": 1754182800,
  "jti": "at_7f3c1e9a4b2d8065",
  "scope": "stories:read stories:write",
  "auth_time": 1754179150,
  "acr": "urn:mace:incommon:iap:silver",
  "amr": ["pwd", "otp"]
}
```

### 1.4 Resource-server validation algorithm (RFC 9068 §4, in order)

| # | Check | Normative text | On failure |
|---|---|---|---|
| 1 | `typ` header | "The resource server MUST verify that the `typ` header value is `at+jwt` or `application/at+jwt` and reject tokens carrying any other value." | `401` + `error="invalid_token"` |
| 2 | Decrypt if JWE | "If encryption was negotiated … and the incoming JWT access token is not encrypted, the resource server SHOULD reject it." | `401` `invalid_token` |
| 3 | Issuer | "The issuer identifier for the authorization server … MUST exactly match the value of the `iss` claim." | `401` `invalid_token` |
| 4 | Audience | "The resource server MUST validate that the `aud` claim contains a resource indicator value corresponding to an identifier the resource server expects for itself. The JWT access token MUST be rejected if `aud` does not contain a resource indicator of the current resource server as a valid audience." | `401` `invalid_token` |
| 5 | Signature | "The resource server MUST validate the signature of all incoming JWT access tokens according to [RFC7515] using the algorithm specified in the JWT `alg` Header Parameter. The resource server MUST reject any JWT in which the value of `alg` is `none`. The resource server MUST use the keys provided by the authorization server." | `401` `invalid_token` |
| 6 | Expiry | "The current time MUST be before the time represented by the `exp` claim. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew." | `401` `invalid_token` |
| 7 | Authorization claims | "the resource server SHOULD use them in combination with any other contextual information available to determine whether the current call should be authorized or rejected." | `403` `insufficient_scope` |

> "The resource server MUST handle errors as described in Section 3.1 of [RFC6750]. In particular,
> in case of any failure in the validation checks listed above, the authorization server response
> MUST include the error code `invalid_token`." — RFC 9068 §4

RFC 7519 §4.1.3 restates the audience rule generically:

> "If the principal processing the claim does not identify itself with a value in the `aud` claim
> when this claim is present, then the JWT MUST be rejected."

RFC 7519 §7.2 closing note — the reason you must pin algorithms:

> "it is an application decision which algorithms may be used in a given context. Even if a JWT can
> be successfully validated, unless the algorithms used in the JWT are acceptable to the
> application, it SHOULD reject the JWT."

### 1.5 Security requirements from RFC 9068 §5

> "To prevent cross-JWT confusion, authorization servers MUST use a distinct identifier as an `aud`
> claim value to uniquely identify access tokens issued by the same issuer for distinct resources."

> "Authorization servers cannot rely on the use of different keys for signing OpenID Connect ID
> Tokens and JWT tokens as a method to safeguard against the consequences of leaking specific keys."

> "The authorization server MUST NOT issue a JWT access token if the authorization granted by the
> token would be ambiguous."

> "if the authorization server elects to use the client_id as the `sub` value for access tokens
> issued using the client credentials grant, the authorization server should prevent clients from
> registering an arbitrary client_id value."

### 1.6 ASP.NET Core 9 notes

Issuing (`Microsoft.IdentityModel.JsonWebTokens`):

```csharp
var descriptor = new SecurityTokenDescriptor
{
    Issuer   = issuer,                       // -> iss
    Audience = resourceIndicator,            // -> aud (use Claims for multi-valued aud)
    IssuedAt = now, NotBefore = now, Expires = now.AddMinutes(10),
    TokenType = "at+jwt",                    // -> typ header. NOT a claim.
    SigningCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256),
    Claims = new Dictionary<string, object>
    {
        ["sub"]       = subject,
        ["client_id"] = clientId,
        ["jti"]       = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)),
        ["scope"]     = string.Join(' ', grantedScopes),   // space-delimited STRING
    }
};
```

`SecurityTokenDescriptor.TokenType` is what sets the `typ` header. `rsaKey.KeyId` sets `kid`.

Validating (`Microsoft.AspNetCore.Authentication.JwtBearer`):

```csharp
options.MapInboundClaims = false;            // keep "sub", do not remap to ClaimTypes.NameIdentifier
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidTypes           = ["at+jwt", "application/at+jwt"],  // enforces RFC 9068 §4 step 1
    ValidAlgorithms      = ["RS256", "ES256"],                // pin; blocks alg confusion
    ValidateIssuer       = true,  ValidIssuer   = issuer,
    ValidateAudience     = true,  ValidAudiences = [resourceIndicator],
    ValidateLifetime     = true,
    ClockSkew            = TimeSpan.FromSeconds(60),          // default is 5 minutes
    NameClaimType        = "sub",
};
```

**Traps in the Microsoft stack specifically:**

| Trap | Consequence | Fix |
|---|---|---|
| `MapInboundClaims` defaults to `true` | `sub` silently becomes `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`; tenant lookup on `"sub"` returns null | `MapInboundClaims = false` |
| `ClockSkew` defaults to 5 minutes | Expired tokens accepted for 5 extra minutes; exceeds RFC 9068's "no more than a few minutes" | set explicitly, 30–120 s |
| `ValidTypes` unset | ID tokens accepted as access tokens (cross-JWT confusion, RFC 9068 §5) | set `ValidTypes` |
| `ValidAlgorithms` unset | handler trusts the token's own `alg` header | pin the list |
| `ValidateAudience` disabled "for now" | any RS's token works at every RS | never disable |

---

## 2. RFC 6750 — resource server error surface

| Error code | HTTP status | RFC 6750 §3.1 definition |
|---|---|---|
| *(none — no credentials sent)* | `401` | bare `WWW-Authenticate: Bearer realm="…"` |
| `invalid_request` | `400` | "Request is missing required parameter, includes unsupported parameter, repeats parameters, or uses multiple token methods" |
| `invalid_token` | `401` | "Access token provided is expired, revoked, malformed, or invalid for other reasons" |
| `insufficient_scope` | `403` | "Request requires higher privileges than provided by access token" |

Bearer syntax (RFC 6750 §2.1):

```
b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
credentials = "Bearer" 1*SP b64token
```

Exact failure response:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  error="invalid_token",
                  error_description="The access token expired"
```

`WWW-Authenticate` auth-params allowed at most once each: `realm`, `scope`, `error`,
`error_description`, `error_uri`.

**Trap:** for an MCP server, the `401` challenge is also where RFC 9728 `resource_metadata` is
advertised. Claude.ai and ChatGPT both bootstrap discovery from this header — a `401` with an empty
or missing `WWW-Authenticate` dead-ends the connector.

---

## 3. RFC 7662 — Token Introspection

### 3.1 Request

`POST {introspection_endpoint}`, `Content-Type: application/x-www-form-urlencoded`.

> "The protected resource calls the introspection endpoint using an HTTP POST [RFC7231] request with
> parameters sent as `application/x-www-form-urlencoded` data." — RFC 7662 §2.1

| Form parameter | Status | Value |
|---|---|---|
| `token` | **REQUIRED** | "The string value of the token." |
| `token_type_hint` | OPTIONAL | "A hint about the type of the token submitted for introspection." — `access_token` or `refresh_token` |

Endpoint authentication is mandatory:

> "To prevent token scanning attacks, the endpoint MUST also require some form of authorization to
> access this endpoint, such as client authentication as described in OAuth 2.0 [RFC6749] or a
> separate OAuth 2.0 access token." — RFC 7662 §2.1

> "The authorization server MUST require authentication of protected resources that need to access
> the introspection endpoint and SHOULD require protected resources to be specifically authorized to
> call the introspection endpoint." — RFC 7662 §4

```http
POST /oauth/introspect HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=mF_9.B5f-4.1JqM&token_type_hint=access_token
```

### 3.2 Response

`200 OK`, `Content-Type: application/json`.

> "The server responds with a JSON object [RFC7159] in `application/json` format." — RFC 7662 §2.2

| JSON field | Status | Type | Definition (RFC 7662 §2.2) |
|---|---|---|---|
| `active` | **REQUIRED** | boolean | "Boolean indicator of whether or not the presented token is currently active." |
| `scope` | OPTIONAL | string | "A JSON string containing a space-separated list of scopes associated with this token" |
| `client_id` | OPTIONAL | string | "Client identifier for the OAuth 2.0 client that requested this token" |
| `username` | OPTIONAL | string | "Human-readable identifier for the resource owner who authorized this token" |
| `token_type` | OPTIONAL | string | "Type of the token as defined in Section 5.1 of OAuth 2.0" — i.e. `Bearer` |
| `exp` | OPTIONAL | integer | "Integer timestamp … indicating when this token will expire" |
| `iat` | OPTIONAL | integer | "Integer timestamp … indicating when this token was originally issued" |
| `nbf` | OPTIONAL | integer | "Integer timestamp … indicating when this token is not to be used before" |
| `sub` | OPTIONAL | string | "Subject of the token … Usually a machine-readable identifier of the resource owner" |
| `aud` | OPTIONAL | string \| array | "Service-specific string identifier or list representing the intended audience" |
| `iss` | OPTIONAL | string | "String representing the issuer of this token" |
| `jti` | OPTIONAL | string | "String identifier for the token" |

That list is exactly the initial contents of the IANA **OAuth Token Introspection Response** registry
(RFC 7662 §3.1); new members require Specification Required review.

Active response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "active": true,
  "client_id": "cid_claude_ai",
  "username": "ada",
  "scope": "stories:read stories:write",
  "sub": "usr_01J8ZQ3K9V2M",
  "aud": "https://mcp.example.com",
  "iss": "https://auth.example.com",
  "exp": 1754182800,
  "iat": 1754179200,
  "nbf": 1754179200,
  "jti": "at_7f3c1e9a4b2d8065",
  "token_type": "Bearer"
}
```

Inactive response — **`200`, not `401`, not `404`**:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"active":false}
```

> "If the introspection call is properly authorized but the token is not active … the authorization
> server MUST return an introspection response with the `active` field set to `false`." — RFC 7662 §2.2

> "A properly formed and authorized query for an inactive or otherwise invalid token … is not
> considered an error response. In these cases, the authorization server MUST instead respond with an
> introspection response with the `active` field set to `false`." — RFC 7662 §2.3

> "To avoid disclosing too much of the authorization server's state to a third party, the
> authorization server SHOULD NOT include any additional information about an inactive token."
> — RFC 7662 §2.2

### 3.3 Error responses

| Condition | Status | Body |
|---|---|---|
| Token unknown / expired / revoked, caller authenticated | **`200`** | `{"active":false}` |
| Missing `token` parameter | `400` | `{"error":"invalid_request"}` |
| Bad/absent client credentials | **`401`** | `{"error":"invalid_client"}` + `WWW-Authenticate` |
| Authenticated caller not authorized to introspect | `403` | `{"error":"access_denied"}` (deployment choice; RFC 7662 §4 mandates the check, not the code) |

> "If the protected resource uses OAuth 2.0 client credentials to authenticate to the introspection
> endpoint and its credentials are invalid, the authorization server responds with an HTTP 401
> (Unauthorized)." — RFC 7662 §2.3

### 3.4 What the AS must actually check before saying `active: true`

> "The authorization server MUST perform all applicable checks against a token's state" — RFC 7662 §4

Concretely: not expired, past `nbf`, not revoked, signature valid, issued to a client still enabled,
and — critically — **the token was actually issued for the resource server doing the asking.**

### 3.5 Caching

> "If the response contains the `exp` parameter (expiration), the response MUST NOT be cached beyond
> the time indicated therein." — RFC 7662 §4

> "The server MUST support Transport Layer Security (TLS) 1.2 … the client or protected resource MUST
> perform a TLS/SSL server certificate check." — RFC 7662 §4

### 3.6 Interop traps

| Trap | Why it bites |
|---|---|
| Returning `401` for an expired token | Every conformant RS treats `401` as *"my introspection credentials are wrong"* and may drop its own client registration. `{"active":false}` + `200` is the only correct answer. |
| Leaking `sub`/`scope` alongside `"active": false` | Turns the endpoint into an oracle; violates §2.2 SHOULD NOT. Return the two-field body literally. |
| `GET` support "for debugging" | §2.1 says POST. Tokens end up in access logs, Referer headers, and proxy caches. |
| Unauthenticated endpoint | Direct violation of §2.1 and §4 MUST; enables token-scanning. |
| Omitting `aud` from the response | An RS cannot tell that a token minted for a *different* RS is being replayed at it. Always include `aud` and `iss`. |
| No rate limit | §4's token-fishing concern. Rate-limit per authenticated caller, not per IP. |
| Caching `active:true` past `exp` | Revocation becomes unobservable. Bound cache TTL by `min(exp - now, small constant)`. |

---

## 4. RFC 7009 — Token Revocation

### 4.1 Request

`POST {revocation_endpoint}`, `application/x-www-form-urlencoded`, client-authenticated.

> "The client constructs the request by including the following parameters using the
> `application/x-www-form-urlencoded` format in the HTTP request entity-body." — RFC 7009 §2.1

| Form parameter | Status | Definition |
|---|---|---|
| `token` | **REQUIRED** | "The token that the client wants to get revoked" |
| `token_type_hint` | OPTIONAL | "A hint about the type of the token submitted for revocation" |

**`token_type_hint` registry (RFC 7009 §4.1.2) — the complete set of values:**

| Value | Meaning |
|---|---|
| `access_token` | An access token as defined in RFC 6749 §1.4 |
| `refresh_token` | A refresh token as defined in RFC 6749 §1.5 |

> "An authorization server MAY ignore this parameter, particularly if it is able to detect the token
> type automatically." — RFC 7009 §2.1

> "An invalid token type hint value is ignored by the authorization server and does not influence the
> revocation response." — RFC 7009 §2.1

```http
POST /oauth/revoke HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token
```

### 4.2 Response — always `200`

> "The authorization server responds with HTTP status code 200 if the token has been revoked
> successfully **or if the client submitted an invalid token**." — RFC 7009 §2.2

> "Invalid tokens do not cause an error response since the client cannot handle such an error in a
> reasonable way." — RFC 7009 §2.2

> "The content of the response body is ignored by the client as all necessary information is conveyed
> in the response code." — RFC 7009 §2.2

```http
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Length: 0
```

Return an empty body. Do not return `{"revoked":true}` — it is ignored and it leaks whether the token
existed if you ever vary it.

### 4.3 Cascade rules

> "If the particular token is a refresh token and the authorization server supports the revocation of
> access tokens, then the authorization server SHOULD also invalidate all access tokens based on the
> same authorization grant." — RFC 7009 §2.1

> "If the token passed to the request is an access token, the server MAY revoke the respective
> refresh token as well." — RFC 7009 §2.1

| Token revoked | Cascade | Strength |
|---|---|---|
| refresh token | → all access tokens from the same grant | **SHOULD** |
| access token | → the refresh token of that grant | MAY |

For self-contained JWT access tokens the cascade is only enforceable with a `jti`/grant-id denylist
consulted at introspection time (or short TTLs). Store the denylist keyed by `grant_id`, entries
expiring at `max(exp)` of the grant's access tokens — bounded growth, no unbounded table.

### 4.4 Error responses

| Condition | Status | `error` |
|---|---|---|
| Success, **or unknown/invalid/already-revoked token** | **`200`** | *(no body)* |
| Missing `token` parameter | `400` | `invalid_request` |
| Bad/absent client credentials | `401` | `invalid_client` |
| Token of a type this AS refuses to revoke | `400` | **`unsupported_token_type`** |
| Overload | `503` + `Retry-After` | — |

> `unsupported_token_type`: "The authorization server does not support the revocation of the presented
> token type." — RFC 7009 §2.2.1

> "If the server responds with HTTP status code 503, the client must assume the token still exists and
> may retry after a reasonable delay." — RFC 7009 §2.2

### 4.5 Security

> "Appropriate countermeasures, which should be in place for the token endpoint as well, MUST be
> applied to the revocation endpoint." — RFC 7009 §5

> "Clients MUST authenticate the revocation endpoint (certificate validation, etc.)" — RFC 7009 §5

### 4.6 Interop traps

| Trap | Why it bites |
|---|---|
| `404` / `400` for an unknown token | Explicit MUST violation and a presence oracle. Return `200` unconditionally. |
| Revoking a token belonging to another client | The AS MUST verify the token was issued to the authenticated client. Otherwise any client can log out any other client's users. RFC 7009 §2.1 note: an AS may return `200` here too rather than confess. |
| Skipping the refresh→access cascade | The SHOULD in §2.1. "Sign out everywhere" silently leaves live access tokens for the full TTL. |
| Constant-time gap between "revoked" and "unknown" | Timing oracle. Do the same amount of work either way. |
| No CORS on the endpoint | Browser-based clients (and some connector UIs) call revoke via `fetch`. |

---

## 5. JWT / JWS / JWK primitives

### 5.1 JOSE header parameters that matter (RFC 7515 §4.1)

| Param | Requirement | Note |
|---|---|---|
| `alg` | "This Header Parameter MUST be present and MUST be understood and processed by implementations." (§4.1.1) | Reject unsupported values |
| `kid` | OPTIONAL. "When used with a JWK, the `kid` value is used to match a JWK `kid` parameter value." (§4.1.4) | Required in practice for rotation |
| `typ` | OPTIONAL in JWS; REQUIRED by RFC 9068 (§4.1.9) | `at+jwt` |
| `crit` | "If any of the listed extension Header Parameters are not understood and supported by the recipient, then the JWS is invalid." (§4.1.11) | Must appear only in the protected header |

> "If none of the validations in step 9 succeeded, then the JWS MUST be considered invalid."
> — RFC 7515 §5.2

Algorithm-substitution defense (RFC 7515 §10.7) — one of:

> "Require that the `alg` Header Parameter be carried in the JWS Protected Header"

…combined with a **verifier-side allow-list**. Relying on the token's own `alg` alone is the classic
RS256→HS256 confusion bug: attacker flips `alg` to `HS256` and signs with the RSA *public* key as the
HMAC secret. Pinning `ValidAlgorithms` and binding `kid`→key-type kills it.

### 5.2 `alg` registry with implementation requirements (RFC 7518 §3.1)

| `alg` | Algorithm | RFC 7518 requirement | Use here |
|---|---|---|---|
| `HS256` | HMAC using SHA-256 | Required | ✗ symmetric — never for tokens an RS validates |
| `HS384` / `HS512` | HMAC SHA-384/512 | Optional | ✗ |
| **`RS256`** | RSASSA-PKCS1-v1_5 + SHA-256 | Recommended | **✓ default — RFC 9068 §2.1 MUST support** |
| `RS384` / `RS512` | RSASSA-PKCS1-v1_5 | Optional | — |
| **`ES256`** | ECDSA P-256 + SHA-256 | **Recommended+** | ✓ preferred where clients support it |
| `ES384` / `ES512` | ECDSA P-384/P-521 | Optional | — |
| `PS256` | RSASSA-PSS + SHA-256, MGF1-SHA-256 | Optional | ✓ acceptable modern RSA |
| `PS384` / `PS512` | RSASSA-PSS | Optional | — |
| `none` | No signature | Optional | ✗ **MUST NOT** (RFC 9068 §2.1) |

Key sizes:

> "A key of the same size as the hash output (for instance, 256 bits for `HS256`) or larger MUST be
> used with this algorithm." — RFC 7518 §3.2

> "A key of size 2048 bits or larger MUST be used with these algorithms." — RFC 7518 §3.3 (RS*)

> "A key of size 2048 bits or larger MUST be used with this algorithm." — RFC 7518 §3.5 (PS*)

**RS256 vs ES256 — the decision:**

| | RS256 | ES256 |
|---|---|---|
| RFC 7518 status | Recommended | **Recommended+** (i.e. likely to be promoted) |
| RFC 9068 §2.1 | **MUST be among supported algorithms** | — |
| Signature size | 256 bytes (2048-bit key) | 64 bytes |
| Sign speed | slow | fast |
| Verify speed | **very fast** | slower than RSA verify |
| Client/RS support | universal | near-universal, some old libraries lag |
| Determinism | deterministic | ECDSA is randomized — needs a good RNG; nonce reuse leaks the private key |

**Recommendation:** publish both. Sign with `RS256` by default (RFC 9068 makes RS256 support
mandatory anyway, so it is the one algorithm every counterparty is guaranteed to handle), keep an
`ES256` key in the JWKS and switch the default per-client once you have telemetry. Advertise both in
`id_token_signing_alg_values_supported`. Do **not** ship ES256-only against Claude.ai / ChatGPT
connectors — RS256 is the interoperability floor.

### 5.3 JWK members (RFC 7517 §4)

| Member | Status | Values |
|---|---|---|
| `kty` | **REQUIRED** — "This member MUST be present in a JWK." (§4.1) | `RSA`, `EC`, `oct`, `OKP` |
| `use` | OPTIONAL (§4.2) | **`sig`**, **`enc`** (complete initial registry, §8.2) |
| `key_ops` | OPTIONAL (§4.3) | `sign`, `verify`, `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, `deriveKey`, `deriveBits` |
| `alg` | OPTIONAL (§4.4) | e.g. `RS256` |
| `kid` | OPTIONAL (§4.5) | opaque string |
| `x5c`, `x5t`, `x5t#S256`, `x5u` | OPTIONAL | X.509 |

> "The `use` and `key_ops` JWK members SHOULD NOT be used together; however, if both are used, the
> information they convey MUST be consistent." — RFC 7517 §4.3

> "Different keys within the JWK Set SHOULD use distinct `kid` values." — RFC 7517 §4.5

JWK Set (RFC 7517 §5):

> "The JSON object MUST have a `keys` member, with its value being an array of JWKs."

> "Implementations SHOULD ignore JWKs within a JWK Set that use `kty` values that are not understood
> by them, that are missing required members, or for which values are out of the supported ranges."

Key-material member names:

| `kty` | Public members | Private members |
|---|---|---|
| `RSA` (§6.3) | `n`, `e` | `d`, and optionally `p`, `q`, `dp`, `dq`, `qi`, `oth` |
| `EC` (§6.2) | `crv`, `x`, `y` | `d` |

`crv` for ES256 is `P-256`. All values are base64url, no padding.

---

## 6. JWKS publication and rotation

### 6.1 The endpoint

Advertised as `jwks_uri` in AS metadata (RFC 8414 §2):

> "URL of the authorization server's JWK Set document. The referenced document contains the signing
> key(s) the client uses to validate signatures from the authorization server. This URL MUST use the
> `https` scheme."

```http
GET /.well-known/jwks.json HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=300
ETag: "jwks-2026-08-03-a"
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "2026-08-a-rsa",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nnd...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "2026-08-a-ec",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }
  ]
}
```

**Publish public parameters only.** Never `d`, `p`, `q`, `dp`, `dq`, `qi`. A JWK serializer that
round-trips a private key is the single most damaging bug possible here — write a unit test that
asserts the JWKS response body contains none of those member names.

### 6.2 Rotation with overlapping keys

The invariant: **a verifier must never encounter a `kid` it has not had the opportunity to fetch, and
must never lose a key while tokens signed by it are still alive.**

| Phase | Duration | JWKS contains | Signing with | Why |
|---|---|---|---|---|
| 1. Pre-publish | ≥ 2 × JWKS `max-age` (and ≥ longest RS cache), min 24 h | old + **new** | old | Every RS caches the new key *before* it can see a token using it |
| 2. Cut over | instant | old + new | **new** | Verifiers already hold the new key |
| 3. Overlap / drain | ≥ max access-token TTL + skew | **old** + new | new | Tokens signed by the old key are still valid |
| 4. Retire | — | new (+ next pre-published key) | new | Old key removed from JWKS and destroyed |

Total rotation window = pre-publish + drain. With 10-minute access tokens and a 5-minute JWKS
cache, a 24 h / 1 h schedule is comfortable. Never do 1→4 in one deploy.

**`kid` scheme.** Make it opaque but sortable and collision-free: `{yyyy-MM}-{seq}-{kty}` or the
RFC 7638 JWK thumbprint. Never reuse a `kid` for different key material — a verifier that cached
`kid=k1` will happily verify against the stale key and either fail every token or, worse, accept
tokens after you intended to retire the key.

### 6.3 JWKS traps

| Trap | Consequence |
|---|---|
| Sign with a key not yet in the JWKS | Global outage for the RS cache TTL. This is the #1 rotation incident. |
| Remove the old key at cutover | All in-flight tokens instantly fail with `invalid_token`. |
| Reuse a `kid` for new material | Cached-key verifiers silently diverge; unfalsifiable failures. |
| Omit `kid` from the JWT header | RS must trial-verify against every key — works until two keys share `kty`, then it is a timing sink and a rotation hazard. |
| `Cache-Control: no-store` on JWKS | Every token validation becomes an outbound HTTP call; JWKS endpoint becomes the availability bottleneck for the whole system. |
| Unbounded refetch on unknown `kid` | Attacker sends tokens with random `kid`s → JWKS-endpoint DoS. Rate-limit refetch (e.g. at most 1 per 5 min per unknown kid, with a negative cache). |
| Mixing signing and encryption keys without `use` | Verifier may pick an `enc` key. Always set `"use": "sig"` on signing keys. |
| Rotating during a deploy freeze / cert renewal | Pre-publish decouples the two; keep rotation out of the deploy path entirely. |

---

## 7. Refresh token rotation & reuse detection (RFC 9700)

### 7.1 Normative requirements

> "Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation as
> described in Section 4.14. [RFC6749] already mandates that refresh tokens for confidential clients
> can only be used by the client for which they were issued." — RFC 9700 §2.2.2

RFC 9700 §4.14.2 (text below quoted from the identical passage in
`draft-ietf-oauth-security-topics-16` §4.13.2 — the `rfc-editor.org` render truncated before §4.14):

> "Authorization servers MUST utilize one of these methods to detect refresh token replay by
> malicious actors for public clients:
>
> * **Sender-constrained refresh tokens:** the authorization server cryptographically binds the
>   refresh token to a certain client instance by utilizing [RFC8705] or [I-D.ietf-oauth-token-binding].
> * **Refresh token rotation:** the authorization server issues a new refresh token with every access
>   token refresh response. The previous refresh token is invalidated but information about the
>   relationship is retained by the authorization server."

The published RFC 9700 §4.14.2 continues (this sentence verified against the published RFC):

> "If a refresh token is compromised and subsequently used by both the attacker and the legitimate
> client, one of them will present an invalidated refresh token, which will inform the authorization
> server of the breach. The authorization server cannot determine which party submitted the invalid
> refresh token, **but it will revoke the active refresh token.** This stops the attack at the cost of
> forcing the legitimate client to obtain a fresh authorization grant."

Supporting requirements:

> "If refresh tokens are issued, those refresh tokens MUST be bound to the scope and resource servers
> as consented by the resource owner." — RFC 9700 §4.14.2

> "Refresh tokens SHOULD expire if the client has been inactive for some time, i.e., the refresh token
> has not been used to obtain fresh access tokens for some time." — RFC 9700 §4.14.2

> Authorization servers "MAY revoke refresh tokens automatically in case of a security event, such as:
> password change" and "logout at the authorization server." — RFC 9700 §4.14.2

The analogous rule for authorization codes:

> "[RFC6749] further recommends that, when an attempt is made to redeem a code twice, the authorization
> server SHOULD revoke all tokens issued previously based on that code." — RFC 9700 §4.2.4

Related access-token requirements:

> "Access tokens SHOULD be restricted to certain resources and actions" — RFC 9700 §2.3

> "Access tokens SHOULD be audience-restricted to a specific resource server or … to a small set of
> resource servers" — RFC 9700 §2.3

> "Authorization and resource servers SHOULD use mechanisms for sender-constraining access tokens,
> such as mutual TLS for OAuth 2.0 [RFC8705] or OAuth 2.0 Demonstrating Proof of Possession (DPoP)
> [RFC9449]" — RFC 9700 §2.2.1

### 7.2 Data model — the token family

The spec's phrase *"information about the relationship is retained"* is the whole design. Model it as
a **grant** (the family) with an append-only chain of refresh tokens:

```
grants
  grant_id            PK
  client_id
  subject
  scope               -- consented scope, immutable
  resources           -- consented resource indicators (aud values), immutable
  auth_time
  status              -- active | revoked
  revoked_reason      -- null | reuse_detected | user_logout | password_change | admin | expired
  created_at
  last_used_at        -- drives inactivity expiry
  absolute_expires_at

refresh_tokens
  token_hash          PK   -- SHA-256 of the token; never store the token itself
  grant_id            FK
  generation          int  -- 0,1,2,… monotonic within the family
  predecessor_hash    -- the "relationship" RFC 9700 requires you to retain
  issued_at
  expires_at
  consumed_at         -- null = current/active; non-null = rotated out
```

`refresh_tokens` rows are **never deleted** while the grant is alive — a deleted row is
indistinguishable from a forged token, and reuse detection dies with it. Prune only after
`grant.absolute_expires_at`.

### 7.3 Redemption algorithm

```
POST /oauth/token
grant_type=refresh_token&refresh_token=<rt>&scope=<optional narrower>
```

1. Authenticate the client (or verify PKCE-era public-client binding).
2. `h = SHA256(rt)`. Look up `refresh_tokens` by `h`.
3. **Not found** → `400 invalid_grant`. (Do not distinguish forged from expired.)
4. Found, but `grant.status = revoked` → `400 invalid_grant`.
5. **Found and `consumed_at IS NOT NULL` → REUSE DETECTED.**
   - Set `grant.status = revoked`, `revoked_reason = reuse_detected`.
   - Invalidate **every** refresh token in the family, including the currently-active one.
   - Cascade per RFC 7009 §2.1: add `grant_id` to the access-token denylist so outstanding JWT access
     tokens from this grant stop introspecting `active:true`.
   - Emit a high-severity audit event (`grant_id`, `client_id`, `subject`, both IPs, both UAs).
   - Respond `400 invalid_grant`.
6. `refresh_tokens.token_hash != grant`'s client → `400 invalid_grant` (RFC 6749: refresh tokens are
   bound to the issuing client).
7. Requested `scope` not a subset of `grant.scope` → `400 invalid_scope`.
8. Happy path, **in one transaction**:
   - `UPDATE refresh_tokens SET consumed_at = now() WHERE token_hash = h AND consumed_at IS NULL`
     — if this affects 0 rows, another request won the race; go to step 5's logic or the grace-window
     rule in §7.4.
   - Insert the successor row (`generation + 1`, `predecessor_hash = h`).
   - Mint the new access token.
   - `grant.last_used_at = now()`.

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCI...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "rt_9f2b8c1d0e4a6537",
  "scope": "stories:read stories:write"
}
```

Failure — the only correct code:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_grant","error_description":"Refresh token is invalid or has been revoked."}
```

**`invalid_grant`, `400`.** Not `401`, not `invalid_token` (that is a *resource server* code from
RFC 6750, not a token-endpoint code), not `invalid_request`. OAuth 2.1 §3.2.4 defines `invalid_grant`
as covering a grant that "…or was issued to another client."

Token-endpoint error registry (OAuth 2.1 §3.2.4 / RFC 6749 §5.2), all `400` except where noted:

| `error` | When |
|---|---|
| `invalid_request` | missing/repeated/malformed parameter |
| `invalid_client` | client authentication failed — **MAY be `401`**; "If the client attempted to authenticate via the `Authorization` request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the `WWW-Authenticate` response header field matching the authentication scheme used by the client." |
| `invalid_grant` | bad/expired/revoked/reused refresh token or code; wrong client |
| `unauthorized_client` | client not allowed this grant type |
| `unsupported_grant_type` | unknown `grant_type` |
| `invalid_scope` | requested scope exceeds the grant |

### 7.4 The concurrency trap (this is the one that ships broken)

Real clients — including MCP connectors that fan out parallel tool calls — fire two refreshes with the
*same* refresh token within milliseconds when an access token expires mid-burst. A naive reuse
detector nukes the user's session on every such burst, and users experience "random logouts."

There is a documented CVE class here: an OAuth provider whose concurrent redemption **forked the token
family** instead of serializing, producing two live branches from one parent
(GHSA-392p-2q2v-4372, `@better-auth/oauth-provider`). Both failure directions are real: over-eager
revocation (denial of service) and forking (defeats detection entirely).

Correct handling:

| Situation | Response |
|---|---|
| `consumed_at` set **within the grace window** (30–60 s) **and** the successor has not itself been consumed | Replay the *same* successor tokens (idempotent). Do **not** revoke. |
| `consumed_at` set outside the grace window | Reuse detected → revoke the family. |
| `consumed_at` set within the window but the successor is already consumed too | Reuse detected → revoke. The chain moved on; this is a genuine replay. |
| Two concurrent redemptions of the same token | The conditional `UPDATE … WHERE consumed_at IS NULL` makes exactly one win. The loser reads the winner's successor and returns it. **Never** create two successors. |

The idempotency window must be bounded and short, and the AS must never issue two *different*
successors for one parent. Use the DB's atomicity (the conditional UPDATE, or `SELECT … FOR UPDATE`),
not an application-level lock — the AS will be multi-instance.

### 7.5 Lifetime policy

| Knob | Suggested default | Basis |
|---|---|---|
| Access token TTL | 5–15 min | short TTL is the practical revocation mechanism for self-contained JWTs |
| Refresh token TTL (per-token) | ≥ access TTL, e.g. 30 days | must outlive the access token |
| Grant inactivity expiry | 14–30 days | RFC 9700 §4.14.2 SHOULD |
| Grant absolute expiry | 90–365 days | forces periodic re-consent |
| Rotation | **every redemption** | RFC 9700 §4.14.2 |
| Reuse window | 30–60 s | see §7.4 |

Additional automatic revocation triggers (RFC 9700 §4.14.2 MAY, treat as SHOULD): password change,
MFA enrollment change, user logout at the AS, account disable, client secret rotation, admin action.

---

## 8. AS metadata to publish (RFC 8414)

Served at `/.well-known/oauth-authorization-server`.

> "issuer: The authorization server's issuer identifier, which is a URL that uses the `https` scheme
> and has no query or fragment components." — RFC 8414 §2 (REQUIRED)

Path-construction rule (RFC 8414 §3) — **insert the well-known segment between host and path**, do not
append it:

```
issuer   https://example.com/issuer1
metadata GET /.well-known/oauth-authorization-server/issuer1  Host: example.com
```

(Not `https://example.com/issuer1/.well-known/…`. Many clients try both; OIDC Discovery historically
appends. Serve both paths.)

| Field | RFC 8414 status | Ship it? |
|---|---|---|
| `issuer` | REQUIRED | yes |
| `authorization_endpoint` | REQUIRED (unless no such grants) | yes |
| `token_endpoint` | REQUIRED (unless implicit-only) | yes |
| `response_types_supported` | REQUIRED | `["code"]` |
| `jwks_uri` | OPTIONAL | **yes — non-negotiable for `at+jwt`** |
| `scopes_supported` | RECOMMENDED | yes |
| `grant_types_supported` | OPTIONAL | `["authorization_code","refresh_token","client_credentials"]` |
| `token_endpoint_auth_methods_supported` | OPTIONAL | yes |
| `token_endpoint_auth_signing_alg_values_supported` | OPTIONAL | if `private_key_jwt` |
| `introspection_endpoint` | OPTIONAL | yes |
| `introspection_endpoint_auth_methods_supported` | OPTIONAL | yes |
| `revocation_endpoint` | OPTIONAL | yes |
| `revocation_endpoint_auth_methods_supported` | OPTIONAL | yes |
| `code_challenge_methods_supported` | OPTIONAL | **`["S256"]` — OAuth 2.1 requires PKCE** |
| `registration_endpoint` | OPTIONAL | only if DCR is enabled |
| `signed_metadata` | OPTIONAL | no |
| `service_documentation`, `op_policy_uri`, `op_tos_uri`, `ui_locales_supported`, `response_modes_supported` | OPTIONAL | as needed |

RFC 9068 §4 on discovery:

> "Authorization servers SHOULD use OAuth 2.0 Authorization Server Metadata [RFC8414] to advertise to
> resource servers their signing keys via `jwks_uri` and what `iss` claim value to expect via the
> `issuer` metadata value."

---

## 9. Master error-code table

| Endpoint | Condition | HTTP | `error` |
|---|---|---|---|
| Token | missing/malformed param | 400 | `invalid_request` |
| Token | client auth failed (Authorization header used) | **401** + `WWW-Authenticate` | `invalid_client` |
| Token | client auth failed (body creds) | 400 or 401 | `invalid_client` |
| Token | bad/expired/revoked/**reused** refresh token, wrong client | 400 | **`invalid_grant`** |
| Token | code already redeemed | 400 | `invalid_grant` (+ revoke all tokens from that code) |
| Token | scope exceeds grant | 400 | `invalid_scope` |
| Token | grant type not allowed for client | 400 | `unauthorized_client` |
| Token | unknown grant type | 400 | `unsupported_grant_type` |
| Introspection | token unknown/expired/revoked | **200** | *(none)* `{"active":false}` |
| Introspection | missing `token` | 400 | `invalid_request` |
| Introspection | caller auth failed | 401 | `invalid_client` |
| Revocation | success **or unknown token** | **200**, empty body | *(none)* |
| Revocation | missing `token` | 400 | `invalid_request` |
| Revocation | caller auth failed | 401 | `invalid_client` |
| Revocation | token type not revocable | 400 | **`unsupported_token_type`** |
| Revocation | overloaded | 503 + `Retry-After` | — |
| Resource server | no credentials | 401 | *(bare challenge)* |
| Resource server | any RFC 9068 §4 validation failure | 401 | **`invalid_token`** |
| Resource server | malformed request | 400 | `invalid_request` |
| Resource server | scope insufficient | 403 | `insufficient_scope` |

---

## 10. Implementation checklist

**Access token issuance**

- [ ] `typ: at+jwt` header on every access token; `kid` present
- [ ] `alg` ∈ {RS256, ES256, PS256}; RS256 supported unconditionally (RFC 9068 §2.1 MUST)
- [ ] All seven REQUIRED claims present: `iss` `exp` `aud` `sub` `client_id` `iat` `jti`
- [ ] `scope` is a space-delimited **string**
- [ ] `aud` is a distinct resource indicator per RS (RFC 9068 §5 cross-JWT confusion)
- [ ] `jti` ≥ 128 bits of CSPRNG entropy
- [ ] ID tokens use `typ: JWT`, access tokens `typ: at+jwt` — never interchangeable

**Introspection**

- [ ] POST only, form-encoded, TLS 1.2+
- [ ] Endpoint authenticated **and** caller authorized (RFC 7662 §2.1 + §4 MUSTs)
- [ ] Inactive → `200 {"active":false}` with nothing else
- [ ] Response includes `aud` and `iss` so the RS can reject cross-audience replay
- [ ] `Cache-Control: no-store`; no caching past `exp`
- [ ] Rate-limited per authenticated caller

**Revocation**

- [ ] POST, form-encoded, client-authenticated
- [ ] `200` for unknown/invalid tokens, always, empty body
- [ ] `token_type_hint` accepted, invalid values ignored
- [ ] Token ownership verified against the authenticated client
- [ ] Refresh-token revocation cascades to access tokens of the same grant (RFC 7009 §2.1 SHOULD)

**JWKS**

- [ ] Public parameters only — automated test asserting no `d`/`p`/`q`/`dp`/`dq`/`qi` in the body
- [ ] `kid` unique and never reused; `use: "sig"` set
- [ ] `Cache-Control` with a finite `max-age`; `ETag`
- [ ] Rotation runbook: pre-publish → cut over → drain → retire, four separate steps
- [ ] Unknown-`kid` refetch rate-limited with a negative cache

**Refresh tokens**

- [ ] Rotation on every redemption; predecessor invalidated but retained
- [ ] Stored as SHA-256 hashes, never plaintext
- [ ] Reuse of a consumed token revokes the **entire family** + cascades to access tokens
- [ ] Bounded idempotency window (30–60 s) for concurrent redemption; exactly one successor per parent
- [ ] Bound to client, scope, and resource indicators
- [ ] Inactivity expiry + absolute expiry
- [ ] High-severity audit event on reuse detection

**Cross-cutting**

- [ ] Algorithm allow-list pinned at every verification point
- [ ] `MapInboundClaims = false` wherever Microsoft's handler is used
- [ ] `ClockSkew` set explicitly (default 5 min is too generous)
- [ ] `Cache-Control: no-store` on every token-bearing response
