# OpenID Connect Core 1.0 — Implementer's Distillation (Authorization Code Flow OP)

Source: OpenID Connect Core 1.0 incorporating errata set 2 (2023-12-15),
<https://openid.net/specs/openid-connect-core-1_0.html>.
Supporting: OIDC Discovery 1.0 §3, OIDC RP-Initiated Logout 1.0, OIDC Session Management 1.0,
RFC 6750 §2–3, RFC 6749 §4.1.2.1/§5.2, RFC 9700 §2.1.1 / §4.2.4 / §4.14.2.

Scope of this doc: **only** what an AS must implement to be a conformant OP for
`response_type=code`. Implicit and hybrid are called out only where they change a rule you
would otherwise get wrong. Target: C# / ASP.NET Core 10 (`net10.0`).

---

## 0. TL;DR — the ten things that break interop

| # | Rule | Where |
|---|---|---|
| 1 | `scope` MUST contain `openid`, else "behavior is entirely unspecified" — treat as *not* an OIDC request; do not issue an `id_token` | §3.1.2.1 |
| 2 | ID Token `aud` MUST contain the **`client_id`** — never the API/resource URL | §2, §3.1.3.7 |
| 3 | If `nonce` was in the request, the ID Token MUST carry it verbatim. If it was not, do **not** invent one | §2 |
| 4 | PKCE and `nonce` are **complementary**, not alternatives — support both | RFC 9700 §2.1.1 |
| 5 | `max_age` present ⇒ `auth_time` REQUIRED in ID Token, and re-auth if stale | §3.1.2.1, §2 |
| 6 | `prompt=none` ⇒ never render UI; return `login_required` / `consent_required` / `account_selection_required` **via redirect**, not as an HTML page | §3.1.2.1, §3.1.2.6 |
| 7 | `prompt` containing `none` **together with** any other value is an error | §3.1.2.1 |
| 8 | UserInfo `sub` MUST equal ID Token `sub`; response `Content-Type: application/json` | §5.3.2 |
| 9 | Discovery `issuer` MUST be byte-identical to ID Token `iss` **and** to the `/.well-known/openid-configuration` prefix | Discovery §4.3 |
| 10 | RS256 MUST be supported and MUST appear in `id_token_signing_alg_values_supported` | §15.1, Discovery §3 |

---

## 1. The `openid` scope

> "REQUIRED. OpenID Connect requests MUST contain the `openid` scope value. If the `openid`
> scope value is not present, the behavior is entirely unspecified." — §3.1.2.1

**Concrete (ASP.NET Core):** in the authorize endpoint, parse `scope` as a space-delimited,
case-sensitive set.

```csharp
var scopes = (Request.Query["scope"].ToString() ?? "")
    .Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
bool isOidc = scopes.Contains("openid");
```

| Condition | Behavior |
|---|---|
| `openid` present | OIDC request. Token response MUST include `id_token`. UserInfo callable. |
| `openid` absent | Plain OAuth 2.0. MUST NOT return `id_token`. UserInfo SHOULD return `403 insufficient_scope`. |
| `openid` absent but `nonce`/`prompt`/`max_age` present | Still not OIDC. Do not silently upgrade. Safest: reject with `invalid_scope` if you want strictness, else ignore the OIDC params. |

**Trap:** MCP clients (Claude connectors) frequently request only resource scopes and **no**
`openid`. An AS that hard-requires `openid` on every authorize request will break them.
Make OIDC conditional on the scope, not mandatory.

**Trap 2:** §3.1.2.2 says the AS MUST "Verify that a `scope` parameter is present and contains
the `openid` scope value" — but that validation step only applies *once you have decided the
request is an OIDC request*. Do not apply it to non-OIDC OAuth requests.

**Trap 3:** unknown scope values. RFC 6749 lets you either error with `invalid_scope` or
narrow silently. Narrowing silently is the interoperable choice; if you narrow, the token
response MUST include a `scope` member listing what was actually granted.

---

## 2. The ID Token — claim by claim

ID Token = a JWT, signed with JWS (§2). For the code flow the ID Token is delivered **only**
from the token endpoint, in the `id_token` member of the token response.

### 2.1 Claims table

| Claim | Status | Value / format | When exactly |
|---|---|---|---|
| `iss` | **REQUIRED** | `https` URL, **no query or fragment**. Case-sensitive. | Always. MUST equal Discovery `issuer` byte-for-byte. |
| `sub` | **REQUIRED** | String, ≤ **255 ASCII** chars. "locally unique and never reassigned identifier within the Issuer for the End-User". Case-sensitive. | Always. |
| `aud` | **REQUIRED** | String **or** array of strings. "MUST contain the OAuth 2.0 `client_id` of the Relying Party as an audience value." | Always. |
| `exp` | **REQUIRED** | NumericDate (seconds since epoch, JSON number). | Always. |
| `iat` | **REQUIRED** | NumericDate. | Always. |
| `auth_time` | **Conditional** | NumericDate — "Time when the End-User authentication occurred." | "When a `max_age` request is made or when `auth_time` is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL." (§2) |
| `nonce` | **Conditional** | String, passed through **unmodified**. | "If present in the Authentication Request, Authorization Servers MUST include a `nonce` Claim in the ID Token with the Claim Value being the `nonce` value sent in the Authentication Request." (§2) |
| `acr` | OPTIONAL | String. | If you assert an authentication context class. |
| `amr` | OPTIONAL | Array of strings. | Never required. |
| `azp` | OPTIONAL | String = a `client_id`. "If present, it MUST contain the OAuth 2.0 Client ID of this party." | "only needed when the ID Token has a single audience value and that audience is different than the authorized party". Errata 2 adds that in practice it only occurs with extensions beyond this spec. |
| `at_hash` | **Conditional** | base64url string | See §2.3. **OPTIONAL** in the code flow. |
| `c_hash` | **Conditional** | base64url string | See §2.3. **Not applicable** to pure code flow. |

### 2.2 Exact wire shape

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "2026-08-a"
}
.
{
  "iss": "https://auth.example.com",
  "sub": "8f4c1e2a9b6d47f0a1c3",
  "aud": "cid_2Xq7...",
  "exp": 1754236800,
  "iat": 1754233200,
  "auth_time": 1754233190,
  "nonce": "n-0S6_WzA2Mj",
  "azp": "cid_2Xq7..."
}
```

**Trap — the `aud` mistake that will bite this exact project.** With RFC 8707 resource
indicators / RFC 9728 protected-resource metadata, the **access token**'s `aud` is the
*resource* (e.g. `https://mcp.example.com/mcp`), while the **ID Token**'s `aud` is the
*`client_id`*. They are different values and must not be unified. Putting the resource URL in
the ID Token `aud` makes every conformant OIDC client reject the token at validation rule 3.

**Trap — `aud` scalar vs array.** "in the common special case when there is one audience, the
`aud` value MAY be a single case-sensitive string." Real-world validators are split; some
libraries mis-handle a one-element array. Emitting a **single string** when there is one
audience is the most interoperable choice. (`System.IdentityModel.Tokens.Jwt` and
`Microsoft.IdentityModel.JsonWebTokens` both handle either.)

**Trap — `azp`.** Emit `azp` only when `aud` has more than one value, or omit it entirely.
Some RPs (historically Spring Security, Jetty, several JS libs) have shipped bugs where they
*require* `azp` whenever `aud` is an array. Keeping `aud` a single string and `azp` absent
sidesteps the whole class. If you do emit it: `azp == client_id`.

**Trap — never invent `nonce`.** If the RP omitted `nonce`, an ID Token containing one is
harmless per spec but signals to some strict RPs that state got crossed. More importantly:
never *substitute* a server-generated nonce, and never normalize/trim the RP's value.
Pass-through is byte-exact.

**Trap — `alg: none`.** §15.1 permits `none` for ID Tokens delivered **only** from the token
endpoint over TLS in the code flow, when the client registered
`id_token_signed_response_alg=none`. Do **not** implement it. An `alg=none` code path is the
classic JWT vulnerability; there is no upside for an Auth0 replacement.

**Trap — `typ`.** Do not stamp ID Tokens with `typ: at+jwt` (that is RFC 9068, for *access*
tokens). `typ: JWT` or omitted. Conversely, if your access tokens are JWTs, they SHOULD be
`typ: at+jwt` so a resource server can refuse an ID Token presented as an access token.

### 2.3 `at_hash` and `c_hash` — exact algorithm

Algorithm (§3.1.3.6, §3.3.2.11), identical for both:

1. Take the ASCII octets of the token's string value (`access_token` for `at_hash`,
   `code` for `c_hash`).
2. Hash with the hash function implied by the JWS `alg` header:
   `RS256`/`ES256`/`PS256`/`HS256` → SHA-256; `*384` → SHA-384; `*512` → SHA-512;
   `EdDSA` → per the curve (Ed25519 → SHA-512).
3. Take the **left-most half** of the hash octets (SHA-256 → first 16 bytes).
4. base64url-encode, **no padding**.

```csharp
static string LeftHalfHash(string value, HashAlgorithmName alg)
{
    byte[] digest = alg.Name switch
    {
        "SHA256" => SHA256.HashData(Encoding.ASCII.GetBytes(value)),
        "SHA384" => SHA384.HashData(Encoding.ASCII.GetBytes(value)),
        _        => SHA512.HashData(Encoding.ASCII.GetBytes(value)),
    };
    return Base64UrlEncoder.Encode(digest.AsSpan(0, digest.Length / 2).ToArray());
}
```

| Flow | `at_hash` | `c_hash` |
|---|---|---|
| `response_type=code` (ID Token from token endpoint) | **OPTIONAL** | Not applicable — no ID Token is issued from the authorization endpoint |
| `response_type=id_token` | MUST NOT (no access token) | OPTIONAL |
| `response_type=id_token token` | **REQUIRED** | OPTIONAL |
| `response_type=code id_token` | OPTIONAL | **REQUIRED** |
| `response_type=code id_token token` | **REQUIRED** | **REQUIRED** |

> c_hash: "If the ID Token is issued from the Authorization Endpoint with a `code`, which is the
> case for the `response_type` values `code id_token` and `code id_token token`, this is
> REQUIRED; otherwise, its inclusion is OPTIONAL." — §3.3.2.11

**Recommendation:** emit `at_hash` even in the code flow. It is OPTIONAL in OIDC Core but
**REQUIRED** by FAPI 2.0 and by several conformance profiles, and no RP breaks on its
presence. Cost is one hash. Emitting it wrong, however, *does* break RPs — the two errors
implementers make are (a) hashing the base64url-decoded bytes instead of the ASCII characters
of the token string, and (b) using the full digest instead of the left half.

**Trap:** `at_hash` must be computed over the access token **actually returned in that same
token response**. If you rotate/re-mint the access token after signing the ID Token, the hash
is stale and conformant RPs reject it.

---

## 3. `nonce` and PKCE — both, not either

These defend **different legs** of the flow. This is the single most commonly conflated point.

| | PKCE (RFC 7636) | `nonce` (OIDC Core §3.1.2.1, §2) |
|---|---|---|
| Binds | the authorization **code** to the client instance that started the flow | the **ID Token** to the client's authentication session |
| Checked by | the **AS**, at the token endpoint | the **RP**, at ID Token validation |
| Carried in | `code_challenge` + `code_challenge_method` → `code_verifier` | `nonce` request param → `nonce` ID Token claim |
| Defeats | code interception / code injection into the token request | ID Token replay and injection at the client |
| Failure mode if missing | attacker redeems a stolen code | attacker splices a valid-but-different ID Token into the RP's session |

Normative, RFC 9700 §2.1.1:

> "Authorization servers MUST support PKCE [RFC7636]."
>
> "Public clients MUST use PKCE [RFC7636] to this end." … "For confidential clients, the use of
> PKCE [RFC7636] is RECOMMENDED." … "With additional precautions … confidential OpenID Connect
> clients MAY use the `nonce` parameter."
>
> "Authorization servers MUST provide a way to detect their support for PKCE." (⇒ advertise
> `code_challenge_methods_supported: ["S256"]` in discovery metadata.)
>
> "…MUST mitigate PKCE downgrade attacks by ensuring that a token request containing a
> `code_verifier` parameter is accepted only if a `code_challenge` parameter was present in the
> authorization request."

So the "or" in RFC 9700 is an **RP-side** choice for *confidential* clients only. From the
**AS side** there is no or: you support PKCE unconditionally and you honor `nonce`
unconditionally.

### AS obligations checklist

| Obligation | Error when violated |
|---|---|
| Accept `code_challenge` + `code_challenge_method` at `/authorize`; store bound to the code | — |
| Advertise `code_challenge_methods_supported: ["S256"]` | — |
| Reject `code_challenge_method=plain` (do not advertise it) | `invalid_request` at authorize |
| `code_challenge` present but `code_verifier` missing at token endpoint | `invalid_grant` |
| `code_verifier` present but no `code_challenge` was stored → **downgrade attack** | `invalid_grant` |
| `code_verifier` mismatch | `invalid_grant` |
| Require PKCE for **all** clients (recommended posture for OAuth 2.1) | `invalid_request` at authorize when `code_challenge` absent |
| Echo `nonce` into ID Token, unmodified | (RP rejects) |
| Do not require `nonce` in the code flow — it is OPTIONAL there | `invalid_request` would be non-conformant |

**S256 verification:** `BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge`, compared
with a **fixed-time** comparison (`CryptographicOperations.FixedTimeEquals`). `code_verifier`
is 43–128 chars from `[A-Za-z0-9-._~]`.

**Trap:** MCP clients from both Anthropic and OpenAI send PKCE `S256` and typically **do not**
send `nonce` (they often do not request `openid` at all). Do not make `nonce` mandatory.
Equally, do not skip `nonce` support — a browser SPA or a .NET RP using
`Microsoft.AspNetCore.Authentication.OpenIdConnect` **always** sends `nonce` and **always**
validates it.

**Trap:** authorization codes MUST be single-use — RFC 9700 §4.2.4: "Authorization codes MUST
be invalidated by the authorization server after their first use at the token endpoint."
On detected reuse, revoke every token derived from that code and return `invalid_grant`.

---

## 4. `prompt`

> "Space-delimited, case-sensitive list of ASCII string values … If this parameter contains
> `none` with any other value, an error is returned." — §3.1.2.1

| Value | Semantics (§3.1.2.1) | AS behavior |
|---|---|---|
| `none` | "The Authorization Server MUST NOT display any authentication or consent user interface pages." | Fully silent. Any need for interaction ⇒ error redirect. |
| `login` | "The Authorization Server SHOULD prompt the End-User for reauthentication." | Force fresh authentication even if a session exists. Update `auth_time`. If it cannot reauthenticate ⇒ `login_required`. |
| `consent` | "The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client." | Show the consent screen even if consent was previously stored. Cannot ⇒ `consent_required`. |
| `select_account` | "The Authorization Server SHOULD prompt the End-User to select a user account." | Show account chooser. Cannot ⇒ `account_selection_required`. |

Combinations other than `none` may be combined freely (`login consent` is legal and common).

### `prompt=none` error mapping

| Situation under `prompt=none` | `error` string | HTTP |
|---|---|---|
| No authenticated session | `login_required` | 302 to `redirect_uri` |
| Session exists but consent for the requested scopes has not been granted | `consent_required` | 302 |
| Multiple sessions, AS cannot pick one | `account_selection_required` | 302 |
| Any other interaction needed (step-up, ToS acceptance, password expiry, MFA enrolment) | `interaction_required` | 302 |
| Session exists but `auth_time + max_age < now` (would need re-auth) | `login_required` | 302 |
| `prompt=none` combined with another value | `invalid_request` | 302 |
| `prompt` contains an unrecognized value | Ignore it (SHOULD), or `invalid_request` | — |

**All of these are redirects, not error pages.** Per RFC 6749 §4.1.2.1 the AS redirects to the
validated `redirect_uri` with `error`, optional `error_description`, optional `error_uri`, and
`state` echoed. The **only** cases where you must render an error in the browser instead of
redirecting are: `redirect_uri` missing, malformed, or not registered; or `client_id` invalid.

```
HTTP/1.1 302 Found
Location: https://claude.ai/api/mcp/auth_callback?error=login_required&error_description=No%20active%20session&state=Az1Bc2
Cache-Control: no-store
```

**Trap:** returning `interaction_required` where `login_required` is expected. RPs implementing
silent-renew (hidden iframe + `prompt=none`) branch on the exact string: `login_required`
means "send the user to a visible login", `interaction_required` is often treated as fatal.
Be specific.

**Trap:** honoring `prompt=none` but *still* setting a session cookie or writing an audit
"login" event. `prompt=none` must have no user-visible and no session-mutating side effects.

**Trap:** `prompt=login` and idempotency. If the RP retries (browser back button), a naive
implementation re-prompts forever. Standard fix: once you have performed the forced
reauthentication for a given authorization request id, mark that request as satisfied so a
re-entry does not loop.

---

## 5. `max_age` and `auth_time`

> "Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last
> time the End-User was actively authenticated by the OP. If the elapsed time is greater than
> this value, the OP MUST attempt to actively re-authenticate the End-User." — §3.1.2.1
>
> "When `max_age` is used, the ID Token returned MUST include an `auth_time` Claim Value."

| Input | AS behavior | ID Token |
|---|---|---|
| `max_age` absent | Normal SSO | `auth_time` OPTIONAL |
| `max_age=0` | Always re-authenticate (equivalent to `prompt=login`) | `auth_time` REQUIRED |
| `max_age=N`, `now - auth_time <= N` | Reuse session | `auth_time` REQUIRED |
| `max_age=N`, `now - auth_time > N` | MUST re-authenticate; on success set `auth_time = now` | `auth_time` REQUIRED (new value) |
| `max_age=N` **and** `prompt=none`, session too old | Cannot re-auth silently | `error=login_required` |
| `max_age` not a non-negative integer | `invalid_request` | — |

Also REQUIRED when the RP asks for `auth_time` as an essential claim via the `claims`
parameter: `{"id_token":{"auth_time":{"essential":true}}}`. If you do not implement the
`claims` parameter, set `claims_parameter_supported: false` in discovery — that is the
conformant way to decline.

**Trap:** you must persist `auth_time` **in the session**, as the timestamp of the last
*actual* credential presentation. Re-deriving it from `iat`, from the cookie issuance time, or
resetting it on every silent SSO hop makes `max_age` a no-op and silently defeats step-up auth.

**Trap:** `auth_time` is a JSON **number**, not a string. Serializing NumericDate as `"1754233190"`
breaks strict validators.

---

## 6. `display`, `ui_locales`, and friends

| Parameter | Status | Values / format | AS obligation |
|---|---|---|---|
| `display` | OPTIONAL | `page` (default), `popup`, `touch`, `wap` | Advertise supported values in `display_values_supported`. An OP MAY ignore it. Unrecognized value ⇒ ignore, do not error. |
| `ui_locales` | OPTIONAL | Space-separated **BCP 47** tags, ordered by preference, e.g. `vi-VN vi en` | Best-effort. Advertise in `ui_locales_supported`. "An error SHOULD NOT result if some or all of the requested locales are not supported." |
| `login_hint` | OPTIONAL | String (usually an email or phone) | Pre-fill the identifier field. Do **not** treat as authenticated. |
| `id_token_hint` | OPTIONAL | A previously issued ID Token (may be expired) | §3.1.2.2: the AS MUST "validate that it was the issuer of the ID Token". If the current session's `sub` differs, and `prompt=none`, return `login_required`. |
| `acr_values` | OPTIONAL | Space-separated, ordered by preference | Voluntary. If you satisfy one, assert it in `acr`. |
| `claims_locales` | OPTIONAL | Space-separated BCP 47 | Best-effort claim language. |
| `response_mode` | OPTIONAL | `query` (default for `code`), `fragment`, `form_post` | Advertise `response_modes_supported`. |
| `request` / `request_uri` | OPTIONAL | JWT Request Object | If unsupported: `request_not_supported` / `request_uri_not_supported`, and `request_parameter_supported: false` in discovery. |
| `registration` | OPTIONAL | JSON | If unsupported: `registration_not_supported`. |

Full authorization-request parameter table for `response_type=code`:

| Parameter | Status |
|---|---|
| `scope` | REQUIRED (must include `openid` for OIDC) |
| `response_type` | REQUIRED — `code` |
| `client_id` | REQUIRED |
| `redirect_uri` | REQUIRED (OIDC tightens OAuth's "optional") |
| `state` | RECOMMENDED |
| `code_challenge`, `code_challenge_method` | REQUIRED in practice (OAuth 2.1 / RFC 9700) |
| `nonce`, `display`, `prompt`, `max_age`, `ui_locales`, `id_token_hint`, `login_hint`, `acr_values`, `response_mode`, `claims`, `claims_locales`, `request`, `request_uri`, `registration` | OPTIONAL |
| `resource` | OPTIONAL (RFC 8707) — needed for MCP |

**`redirect_uri` matching (§3.1.2.1):**

> "This URI MUST exactly match one of the Redirection URI values for the Client pre-registered
> at the OpenID Provider, with the matching performed as described in Section 6.2.1 of
> [RFC3986] (Simple String Comparison)."

RFC 9700 §2.1: "Authorization servers MUST utilize exact string matching except for port
numbers in localhost redirection URIs of native apps."

**Trap:** ASP.NET Core's `Uri` normalization will happily equate
`https://x.com/cb` and `https://x.com/cb/` or re-case the host. Compare the **raw registered
string** to the **raw query-string value** with `StringComparer.Ordinal` — after
percent-decoding exactly once. Only relax for `http://127.0.0.1:*/…` and `http://[::1]:*/…`
(note: `127.0.0.1`, not `localhost` — RFC 8252 §7.3).

---

## 7. Authorization endpoint error registry

Return via 302 redirect with `error`, `error_description`, `error_uri`, `state`.

**From RFC 6749 §4.1.2.1:**

| `error` | Meaning |
|---|---|
| `invalid_request` | Missing/duplicated/malformed parameter |
| `unauthorized_client` | Client not allowed this grant/response type |
| `access_denied` | End-user or AS refused |
| `unsupported_response_type` | `response_type` not supported |
| `invalid_scope` | Scope invalid/unknown/malformed |
| `server_error` | 500-equivalent (cannot be a 500 because you must redirect) |
| `temporarily_unavailable` | 503-equivalent |

**Added by OIDC Core §3.1.2.6:**

| `error` | Definition (verbatim) |
|---|---|
| `interaction_required` | "The Authorization Server requires End-User interaction of some form to proceed." |
| `login_required` | "The Authorization Server requires End-User authentication." |
| `account_selection_required` | "The End-User is REQUIRED to select a session at the Authorization Server." |
| `consent_required` | "The Authorization Server requires End-User consent." |
| `invalid_request_uri` | "The `request_uri` in the Authorization Request returns an error or contains invalid data." |
| `invalid_request_object` | "The `request` parameter contains an invalid Request Object." |
| `request_not_supported` | "The OP does not support use of the `request` parameter." |
| `request_uri_not_supported` | "The OP does not support use of the `request_uri` parameter." |
| `registration_not_supported` | "The OP does not support use of the `registration` parameter." |

`error_description` constraint (RFC 6749): ASCII only, and MUST NOT include `"` `\` or
characters outside `%x20-21 / %x23-5B / %x5D-7E`. Percent-encode when placing in the query.

**Token endpoint errors (RFC 6749 §5.2)** — JSON body, `Cache-Control: no-store`:

| `error` | HTTP |
|---|---|
| `invalid_request` | 400 |
| `invalid_client` | 401 (with `WWW-Authenticate` if the client used HTTP Basic) or 400 |
| `invalid_grant` | 400 — bad/expired/reused code, PKCE mismatch, `redirect_uri` mismatch |
| `unauthorized_client` | 400 |
| `unsupported_grant_type` | 400 |
| `invalid_scope` | 400 |

---

## 8. Token endpoint — OIDC additions

§3.1.3.2 validation the AS MUST perform: authenticate the client; verify the code was issued to
this client, is not expired, has not been used; verify `redirect_uri` matches the one from the
authorization request; verify the code came from an OpenID Connect Authentication Request.

§3.1.3.3 successful response:

> "In addition to the parameters defined by OAuth 2.0, the following parameter MUST be included
> in the response: `id_token`, which is the ID Token value associated with the authenticated
> session."
>
> "All Token Responses containing tokens, secrets, or other sensitive information MUST include
> the appropriate `Cache-Control` header set to `no-store` and `Pragma` header set to
> `no-cache`."

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "v1.MRq4...",
  "scope": "openid profile email mcp:read",
  "id_token": "eyJhbGciOi..."
}
```

Exact form parameters on the request (`Content-Type: application/x-www-form-urlencoded`):

```
grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback
&client_id=cid_2Xq7
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&resource=https%3A%2F%2Fmcp.example.com%2Fmcp
```

**Trap:** `token_type` MUST be compared case-insensitively by clients but you should emit
exactly `"Bearer"`. Emitting `"bearer"` breaks a nontrivial number of RPs.

**Trap:** only include `id_token` when the original authorization request carried the `openid`
scope. Refresh-token responses SHOULD include a fresh `id_token` if `openid` was granted —
OIDC Core §12.2 says the ID Token from a refresh MUST have the same `sub`, MUST have a fresh
`iat`/`exp`, SHOULD have the same `auth_time`, and **MUST NOT** have a `nonce` claim (there was
no new authentication request to carry one).

---

## 9. Standard claims and scope → claim mapping

### 9.1 The scope table (§5.4)

| Scope | Claims released |
|---|---|
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` |
| `phone` | `phone_number`, `phone_number_verified` |
| `openid` | `sub` (always) |

> "When a `response_type` value is used that returns an Access Token from the Authorization
> Endpoint, the Claims that are being requested will be returned from the UserInfo Endpoint.
> However, if a `response_type` value is used that does not return an Access Token, which is the
> case for the `response_type` value `id_token`, the resulting Claims will be returned in the
> ID Token." — §5.4

**For the code flow this means: scope-requested claims are returned from UserInfo, not the
ID Token.** Putting them in the ID Token as well is permitted and extremely common (Auth0,
Entra ID, Google all do it) — but it is not what the spec directs, and it bloats the token.
Recommended posture: `sub` + protocol claims in the ID Token; profile/email/address/phone at
UserInfo; make ID-Token claim inclusion an opt-in per-client setting.

### 9.2 Full standard claim table (§5.1)

| Claim | JSON type | Notes |
|---|---|---|
| `sub` | string | ≤255 ASCII, never reassigned |
| `name` | string | Full display name |
| `given_name` | string | |
| `family_name` | string | |
| `middle_name` | string | |
| `nickname` | string | |
| `preferred_username` | string | **Not** guaranteed unique or stable — never key on it |
| `profile` | string (URL) | |
| `picture` | string (URL) | |
| `website` | string (URL) | |
| `email` | string | **Not** guaranteed unique — never key on it |
| `email_verified` | **boolean** | |
| `gender` | string | |
| `birthdate` | string | `YYYY-MM-DD`; `0000` year and `YYYY`-only are allowed |
| `zoneinfo` | string | IANA tz name, e.g. `Asia/Ho_Chi_Minh` |
| `locale` | string | BCP 47, e.g. `vi-VN`; note the spec allows the `en_US` underscore variant |
| `phone_number` | string | E.164 RECOMMENDED, e.g. `+84901234567` |
| `phone_number_verified` | **boolean** | |
| `address` | **JSON object** | Members: `formatted`, `street_address`, `locality`, `region`, `postal_code`, `country` |
| `updated_at` | **number** | NumericDate |

> "Privacy reasons may result in an OpenID Provider choosing not to return some Claims. If a
> Claim is not returned, that Claim Name SHOULD be omitted from the JSON object rather than
> including it with a `null` value." — §5.1

**Trap:** `email_verified`, `phone_number_verified`, `updated_at` are **not strings**. Emitting
`"email_verified": "true"` is the most common OP bug in the wild and breaks Keycloak,
Spring Security, and `Microsoft.AspNetCore.Authentication.OpenIdConnect` consumers.
In C#, `JsonSerializerOptions` with a naive `object`-typed claim bag will do this to you —
type the claim store, do not stringify.

**Trap:** `address` is a nested object, not a flattened set of `address.street_address` keys.

**Trap:** `System.Security.Claims.ClaimsIdentity` stringifies everything. If you build
UserInfo output from a `ClaimsPrincipal`, you must re-type booleans and numbers on the way out.

---

## 10. UserInfo endpoint (§5.3)

| Requirement | Detail |
|---|---|
| Transport | The endpoint URL MUST use the `https` scheme. "Communication with the UserInfo Endpoint MUST utilize TLS." |
| Methods | MUST support **both** HTTP `GET` and HTTP `POST` |
| Auth | OAuth 2.0 Bearer Token per RFC 6750 §2. "When using the HTTP GET method, the Access Token SHOULD be sent in the Authorization header field." |
| Body-form token | If POST with `application/x-www-form-urlencoded`, the token may be the `access_token` form field |
| Success `Content-Type` | `application/json` (plain) or `application/jwt` (signed and/or encrypted) |
| `sub` | "The UserInfo Response MUST always include the `sub` (subject) Claim." And: "The `sub` Claim in the UserInfo Response MUST be verified to exactly match the `sub` Claim in the ID Token." |
| Errors | RFC 6750 §3 |

```
GET /userinfo HTTP/1.1
Host: auth.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "sub": "8f4c1e2a9b6d47f0a1c3",
  "name": "Grace Hopper",
  "preferred_username": "grace",
  "email": "grace@example.com",
  "email_verified": true,
  "updated_at": 1748736000
}
```

### Error responses (RFC 6750 §3.1)

| `error` | HTTP | When |
|---|---|---|
| *(none)* | **401** | No credentials at all. "the resource server SHOULD NOT include an error code or other error information." Header: `WWW-Authenticate: Bearer realm="userinfo"` |
| `invalid_request` | **400** | Missing parameter, repeated parameter, or **two** token-transmission methods used at once (header + form) |
| `invalid_token` | **401** | "expired, revoked, malformed, or invalid for other reasons" |
| `insufficient_scope` | **403** | Token lacks the `openid` scope; include `scope="openid"` in the challenge |

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="userinfo", error="invalid_token", error_description="The Access Token expired"
```

**Trap — the biggest one.** OIDC Core's §5.3.3 example historically omits the `Bearer` auth
scheme (`WWW-Authenticate: error="invalid_token"…`). That is a known spec-text defect.
**Always emit `WWW-Authenticate: Bearer …`** — RFC 6750 §3 requires the scheme, and MCP's
RFC 9728 discovery flow parses it.

**Trap:** ASP.NET Core's JWT bearer handler emits `WWW-Authenticate: Bearer error="invalid_token"`
automatically on 401, but `403` from an authorization policy emits **no** `WWW-Authenticate`.
You must write `insufficient_scope` yourself:

```csharp
Response.StatusCode = StatusCodes.Status403Forbidden;
Response.Headers.WWWAuthenticate =
    "Bearer realm=\"userinfo\", error=\"insufficient_scope\", scope=\"openid\"";
```

**Trap:** `sub` must be the *same* value as in the ID Token for that same client. If you use
pairwise subject identifiers (`subject_types_supported: ["pairwise"]`), the pairwise
computation must be applied at UserInfo too, keyed on the *requesting client* derived from the
access token — not on the raw user id.

**Trap — CORS.** OIDC Core does not require CORS on UserInfo, but browser-based RPs
(and some connector consoles) call it from JS. If you support public browser clients, enable
CORS on `/userinfo`, `/.well-known/openid-configuration`, and the `jwks_uri` — allow the
`Authorization` header. Do **not** enable CORS with credentials on `/authorize`.

**Trap:** do not gate UserInfo on the *presence* of profile scopes. Gate it on `openid`, then
filter the returned claim set by the granted scopes. A token with only `openid` gets
`{"sub": "..."}` and a 200, not a 403.

---

## 11. ID Token validation rules the RP applies (§3.1.3.7)

The AS must not emit anything that trips these. Rules, in order:

| # | Rule | AS-side consequence |
|---|---|---|
| 1 | Decrypt if encrypted, per registration | Only encrypt if the client registered for it |
| 2 | "The Issuer Identifier for the OpenID Provider MUST exactly match the value of the `iss` Claim" | `iss` must equal discovery `issuer` — no trailing slash drift, no `http` vs `https`, no host casing change, no tenant-path variation |
| 3 | "The Client MUST validate that the `aud` Claim contains its `client_id`" | `aud` ⊇ `{client_id}` |
| 4 | "The `aud` Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience" | Multi-audience is legal but many RPs also reject *unknown* extra audiences — keep `aud` minimal |
| 5–6 | If `azp` present, the RP SHOULD verify `azp == client_id` | If you emit `azp`, it must be the `client_id` |
| 7 | TLS server validation MAY substitute for signature check when received directly from the token endpoint | Do not rely on this; always sign |
| 8 | "The Client MUST validate the signature of all other ID Tokens according to JWS using the algorithm specified in the JWT `alg` Header Parameter" | Always include `kid`; keep old keys in JWKS through a rotation overlap window |
| 9 | "The `alg` value SHOULD be the default of RS256 or the algorithm sent by the Client in the `id_token_signed_response_alg` parameter" | Default to RS256. ES256 only when the client registered for it |
| 10 | MAC algorithms use the UTF-8 octets of `client_secret` as the key | Never use HS256 for public clients (secret is not secret) |
| 11 | "The current time MUST be before the time represented by the `exp` Claim" | Set `exp` generously enough for clock skew — 5–15 min lifetime; RPs typically allow ±5 min skew |
| 12 | `iat` may be used to reject tokens issued too far in the past | Do not backdate `iat`; never set it in the future |
| 13 | "If a `nonce` value was sent in the Authentication Request, a `nonce` Claim MUST be present and its value checked" | Byte-exact pass-through |
| 14 | If `acr` was requested, the RP SHOULD check it | Do not assert an `acr` you did not actually satisfy |
| 15 | If `auth_time` was requested, the RP SHOULD check elapsed time | `auth_time` must be the real credential-presentation time |

---

## 12. Discovery metadata (OIDC Discovery 1.0 §3)

Served at `{issuer}/.well-known/openid-configuration`, `Content-Type: application/json`.

> "The `issuer` value returned MUST be identical to the Issuer URL that was used as the prefix
> to `/.well-known/openid-configuration` to retrieve the configuration information. This MUST
> also be identical to the `iss` Claim value in ID Tokens issued from this Issuer."

| Field | Status | Note |
|---|---|---|
| `issuer` | **REQUIRED** | `https` URL, **no query or fragment** |
| `authorization_endpoint` | **REQUIRED** | |
| `token_endpoint` | **REQUIRED** (unless implicit-only) | |
| `jwks_uri` | **REQUIRED** | MUST use `https` |
| `response_types_supported` | **REQUIRED** | `["code"]` is a valid complete answer |
| `subject_types_supported` | **REQUIRED** | `["public"]` and/or `["pairwise"]` |
| `id_token_signing_alg_values_supported` | **REQUIRED** | **`RS256` MUST be included** |
| `userinfo_endpoint` | RECOMMENDED | |
| `registration_endpoint` | RECOMMENDED | DCR |
| `scopes_supported` | RECOMMENDED | MUST list `openid` if OIDC |
| `claims_supported` | RECOMMENDED | |
| `response_modes_supported` | OPTIONAL | default `["query","fragment"]` |
| `grant_types_supported` | OPTIONAL | default `["authorization_code","implicit"]` |
| `token_endpoint_auth_methods_supported` | OPTIONAL | default `["client_secret_basic"]` |
| `display_values_supported`, `claim_types_supported`, `ui_locales_supported`, `claims_locales_supported` | OPTIONAL | |
| `claims_parameter_supported`, `request_parameter_supported`, `request_uri_parameter_supported` | OPTIONAL | default `false` |
| `require_request_uri_registration` | OPTIONAL | default `false` |
| `code_challenge_methods_supported` | (RFC 8414) | **Emit `["S256"]`** — RFC 9700 requires PKCE support be detectable |
| `end_session_endpoint` | (RP-Initiated Logout) | REQUIRED if you support RP-initiated logout |
| `check_session_iframe` | (Session Management) | REQUIRED if you support session management |

**Trap:** §15.1 lists Discovery and Dynamic Client Registration among mandatory-to-implement
OP features. Also mandatory: the Authorization Code Flow and JWS RS256.

**Trap:** trailing slash. If `issuer` is `https://auth.example.com` then the well-known URL is
`https://auth.example.com/.well-known/openid-configuration`, and `iss` is
`https://auth.example.com` — **without** a trailing slash. Pick one form and enforce it in a
single constant. ASP.NET Core's `PathString` and reverse proxies both love to add slashes.

**Trap:** behind a reverse proxy, `Request.Scheme` is `http` unless you configure
`ForwardedHeadersOptions` with `ForwardedHeaders.XForwardedProto | XForwardedHost` and set
`KnownProxies`/`KnownNetworks`. An `iss` of `http://…` is an instant conformance failure.
Better: make the issuer a fixed configured string, never derived from the request.

---

## 13. RP-Initiated Logout 1.0 — do you need it?

**For an MCP-facing AS: no, not for Claude or ChatGPT connectors.** Neither performs
RP-initiated logout. **For an Auth0 replacement: yes** — web app RPs (including ASP.NET Core's
own `OpenIdConnectHandler` with `SignOutScheme`) expect `end_session_endpoint`, and its absence
means "sign out" only clears the app cookie while the OP session persists, so the next login
silently re-authenticates. That surprise is the #1 support ticket for OPs that skip it.

Discovery field: **`end_session_endpoint`** — "URL at the OP to which an RP can perform a
redirect to request that the End-User be logged out."

| Parameter | Status | Semantics |
|---|---|---|
| `id_token_hint` | **RECOMMENDED** | Previously issued ID Token, "a hint about the End-User's current authenticated session with the Client". Accept it even if expired. |
| `logout_hint` | OPTIONAL | OP-defined hint about who is logging out |
| `client_id` | OPTIONAL | "When both `client_id` and `id_token_hint` are present, the OP MUST verify that the Client ID matches the one used when issuing the ID Token." Needed when the ID Token is encrypted. |
| `post_logout_redirect_uri` | OPTIONAL | Where to send the browser afterwards |
| `state` | OPTIONAL | Echoed back on the post-logout redirect |
| `ui_locales` | OPTIONAL | Space-separated BCP 47 |

Registration metadata: **`post_logout_redirect_uris`** — array of URLs the client may use.

Normative rules:

- The `post_logout_redirect_uri` "MUST have been previously registered with the OP."
- "The OP MUST NOT perform post-logout redirection if the `post_logout_redirect_uri` value
  supplied does not exactly match one of the previously registered `post_logout_redirect_uris`
  values." → **exact string match**, same discipline as `redirect_uri`.
- If `id_token_hint` is absent, "the OP MUST NOT perform post-logout redirection unless the OP
  has other means of confirming the legitimacy of the post-logout redirection target."
- On validation failure: "any operations requiring the information that failed to correctly
  validate MUST be aborted" and "the OP MUST NOT perform post-logout redirection to an RP."
- "Logout requests without a valid `id_token_hint` value are a potential means of denial of
  service; therefore, OPs SHOULD obtain explicit confirmation from the End-User before acting
  upon them." → show a "Do you want to sign out?" interstitial when `id_token_hint` is missing.

```
GET /connect/endsession
  ?id_token_hint=eyJhbGciOi...
  &post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fsignedout
  &client_id=cid_2Xq7
  &state=Az1Bc2
```
```
HTTP/1.1 302 Found
Location: https://app.example.com/signedout?state=Az1Bc2
```

**Trap:** there is no `error` parameter contract here. On failure you render an error page; you
do **not** redirect with `?error=`. Do not invent one.

**Trap:** `id_token_hint` will usually be expired by the time the user signs out. Validate
signature, `iss`, and `aud` — but **skip `exp`**. Rejecting on `exp` breaks every real logout.

**Trap:** clear the OP session **before** redirecting. If you redirect first and clear
asynchronously, a fast RP re-login lands on the still-live session.

---

## 14. Session Management 1.0 — do you need it?

**No. Skip it.** Build Back-Channel Logout instead if you need multi-RP logout propagation.

- Adds `check_session_iframe` to discovery and a `session_state` parameter to the
  authorization response.
- Mechanism: RP embeds a hidden cross-origin iframe from the OP and polls it with
  `postMessage`, sending `"<client_id> <session_state>"`; the OP iframe replies `"unchanged"`,
  `"changed"`, or `"error"`. On `"changed"` the RP issues an `prompt=none` authorization
  request to determine whether the user is still signed in.
- `session_state` is a salted hash over client id, RP origin, and OP user-agent state; it
  "MUST NOT contain the space character".
- The spec itself acknowledges browser third-party-cookie/storage partitioning defeats it and
  warns about "infinite loops of re-authentications", pointing readers to Back-Channel Logout
  as the unaffected alternative.

Chrome/Safari/Firefox storage partitioning has made the check-session iframe unreliable in
practice. Implementing it produces a feature that appears to work in development (same-site)
and fails in production (cross-site). Set no `check_session_iframe` in discovery; RPs will
fall back to token-expiry-driven renewal.

---

## 15. ASP.NET Core 10 implementation notes

| Concern | Do this |
|---|---|
| Signing | `Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler.CreateToken`. Prefer RSA-2048 (`RsaSecurityKey`) with `SecurityAlgorithms.RsaSha256`. Always set `kid`. |
| JWKS | Serve at `{issuer}/.well-known/jwks.json`. Keep N+1 keys (current signer + previous) through rotation. `Cache-Control: public, max-age=3600`. |
| Claim typing | Do **not** round-trip UserInfo/ID Token payloads through `ClaimsPrincipal` — it stringifies. Build a `Dictionary<string, object?>` and serialize with `System.Text.Json`. |
| NumericDate | `DateTimeOffset.ToUnixTimeSeconds()` → `long`, serialized as a JSON number. |
| base64url | `Microsoft.IdentityModel.Tokens.Base64UrlEncoder`, or `Base64Url` in .NET 9. Never `Convert.ToBase64String` (padding + `+`/`/`). |
| Constant-time compare | `CryptographicOperations.FixedTimeEquals` for `code_verifier`, client secrets, `state`. |
| Issuer | A single configured immutable string. Never `$"{Request.Scheme}://{Request.Host}"`. |
| Cache headers | `Cache-Control: no-store` + `Pragma: no-cache` on `/token`, `/userinfo`, and every `/authorize` response. |
| Error redirect | `Results.Redirect(uri)` returns 302; build the query with `QueryHelpers.AddQueryString` so `error_description` is encoded correctly. |
| Clock | Use `TimeProvider` (injected) so token lifetimes are testable. |

---

## 16. Conformance self-test checklist

- [ ] `openid` scope conditionally triggers `id_token`; absence does not break plain OAuth
- [ ] ID Token has `iss`/`sub`/`aud`/`exp`/`iat`, `aud == client_id`, `iss ==` discovery `issuer`
- [ ] `nonce` echoed byte-exact when sent; absent when not sent; absent on refresh
- [ ] `auth_time` present whenever `max_age` was sent, and reflects real credential time
- [ ] `max_age` staleness triggers re-auth; with `prompt=none` it yields `login_required`
- [ ] `prompt=none` never renders UI and never mutates session state
- [ ] `prompt=none` returns the *specific* error: `login_required` / `consent_required` / `account_selection_required` / `interaction_required`
- [ ] `prompt` = `none` + anything else ⇒ `invalid_request`
- [ ] All authorize errors are 302 redirects except invalid `client_id` / `redirect_uri`
- [ ] PKCE `S256` enforced; downgrade (verifier without stored challenge) ⇒ `invalid_grant`
- [ ] Code is single-use; reuse revokes the derived token family
- [ ] `redirect_uri` exact string match (localhost port exception only)
- [ ] UserInfo: GET and POST, Bearer, `application/json`, `sub` present and equal to ID Token `sub`
- [ ] UserInfo errors carry `WWW-Authenticate: Bearer …` with `invalid_token` (401) / `insufficient_scope` (403)
- [ ] Booleans are booleans; `updated_at`/`auth_time`/`exp`/`iat` are numbers; `address` is an object
- [ ] Discovery `issuer` identical to well-known prefix and to `iss`; `RS256` in `id_token_signing_alg_values_supported`; `code_challenge_methods_supported: ["S256"]`
- [ ] No `alg=none` code path anywhere
- [ ] Run the OpenID Foundation conformance suite, "Basic OP" + "Config OP" profiles

---

## 17. Sources

- OpenID Connect Core 1.0 (errata set 2): <https://openid.net/specs/openid-connect-core-1_0.html>
- Bilingual mirror used for verbatim English text: <https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html>
- OpenID Connect Discovery 1.0: <https://openid.net/specs/openid-connect-discovery-1_0.html>
- OpenID Connect RP-Initiated Logout 1.0: <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>
- OpenID Connect Session Management 1.0: <https://openid.net/specs/openid-connect-session-1_0.html>
- RFC 6750 (Bearer Token Usage): <https://www.rfc-editor.org/rfc/rfc6750.txt>
- RFC 9700 (OAuth 2.0 Security BCP): <https://www.rfc-editor.org/rfc/rfc9700.txt>

**Verification caveat:** items marked as short quotations were retrieved from the pages above.
The fetch tooling declined to reproduce some long passages verbatim; the azp/at_hash/prompt
paragraph texts here are assembled from partial quotations plus the errata-set-1 mirror. Before
freezing implementation behavior on the three items below, re-read the primary text directly:
(1) the full `azp` bullet in §2, (2) §15.1's exact mandatory-feature list, (3) §5.3.3's
`WWW-Authenticate` example.
