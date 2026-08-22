# Dynamic Client Registration — RFC 7591 / RFC 7592 implementer notes

Target: from-scratch OAuth 2.1 + OIDC AS in C# / ASP.NET Core 9, must interop with
Claude.ai MCP connectors and ChatGPT connectors/Apps SDK.

Primary sources fetched: RFC 7591 (text + html), RFC 7592 (text + html), IANA OAuth
Parameters registries, OIDC Dynamic Client Registration 1.0, MCP authorization spec
(2025-06-18 and 2025-11-25), Anthropic connector authentication + troubleshooting docs,
OpenAI Apps SDK auth docs.

---

## 0. Executive summary — the five things that will break you

| # | Requirement | Source | Consequence if wrong |
|---|---|---|---|
| 1 | `POST /register` MUST accept `application/json` (NOT form-encoded); `POST /token` MUST accept `application/x-www-form-urlencoded` | RFC 7591 §3.1 | ASP.NET Core `[FromForm]`/`[FromBody]` mismatch → `415 Unsupported Media Type` → Claude aborts |
| 2 | Success is **201 Created**, not 200. Errors are **400** with `{"error": ...}` | RFC 7591 §3.2.1, §3.2.2 | Claude/ChatGPT client parsers keyed on 201 |
| 3 | `MUST ignore any client metadata sent by the client that it does not understand` — and MAY register a *subset* rather than reject | RFC 7591 §2, §3.2.1 | Rejecting unknown fields or unwanted `grant_types` is the single most common DCR failure |
| 4 | RFC 7592 update is **full replacement**: "Omitted fields MUST be treated as null or empty values by the server, indicating the client's request to delete them" | RFC 7592 §2.2 | Implementing PUT as a merge/PATCH silently diverges from spec |
| 5 | Open registration → unbounded client rows. Claude DCR "causes Claude to register a new client on every fresh connection" | Anthropic auth docs | DB growth / DoS; requires TTL + GC + quota (see §8) |

---

## 1. Endpoint contract

### 1.1 Transport and method

> "The client registration endpoint MUST accept HTTP POST messages with request parameters
> encoded in the entity body using the 'application/json' format." — **RFC 7591 §3.1**

> "The client registration endpoint MUST be protected by a transport-layer security mechanism."
> — **RFC 7591 §3**

> "the authorization server MUST require the use of a transport-layer security mechanism when
> sending requests to the registration endpoint. The server MUST support TLS 1.2 and MAY support
> additional transport-layer security mechanisms meeting its security requirements."
> — **RFC 7591 §5**

| Aspect | Value |
|---|---|
| Method | `POST` |
| Path | implementation-chosen; advertised as `registration_endpoint` in RFC 8414 metadata |
| Request `Content-Type` | `application/json` |
| Request `Accept` | `application/json` |
| Success status | `201 Created` |
| Error status | `400 Bad Request` (unless otherwise specified) |
| Response `Content-Type` | `application/json` |
| Response headers | `Cache-Control: no-store`, `Pragma: no-cache` |
| TLS | mandatory; TLS 1.2 minimum |

**ASP.NET Core note.** Do not decorate the registration DTO with `[FromForm]`. Anthropic's docs
call this out explicitly: "Dynamic client registration (`/register`) uses `application/json` per
RFC 7591 section 3.1, so don't assume the same parser works for both." Register a
form-urlencoded body parser *only* on `/token`.

### 1.2 Open vs protected registration

> "The client registration endpoint MAY be an OAuth 2.0 [RFC6749] protected resource and it MAY
> accept an initial access token in the form of an OAuth 2.0 access token to limit registration to
> only previously authorized parties." — **RFC 7591 §3.1**

> "To support open registration and facilitate wider interoperability, the client registration
> endpoint SHOULD allow registration requests with no authorization (which is to say, with no
> initial access token in the request)." — **RFC 7591 §3.1**

> "These requests MAY be rate-limited or otherwise limited to prevent a denial-of-service attack
> on the client registration endpoint." — **RFC 7591 §3.1**

**Initial access token** (RFC 7591 §1.2): "OAuth 2.0 access token optionally issued by an
authorization server to a developer or client and used to authorize calls to the client
registration endpoint."

Wire form when present:

```http
POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Host: as.example.com
```

**Interop trap.** Claude and ChatGPT have no way to obtain an initial access token. If you gate
`/register` behind one, you must *not* advertise `registration_endpoint` — advertise
`client_id_metadata_document_supported: true` instead, or use pre-registered credentials. A
`registration_endpoint` that returns `401` is worse than no `registration_endpoint` at all,
because the client will try it and fail rather than fall back.

**Recommended design for the reusable AS:** make it a per-tenant policy switch with three modes —
`open`, `initial_access_token`, `disabled` — where `disabled` also removes `registration_endpoint`
from the RFC 8414 document.

---

## 2. Client metadata registry (complete)

### 2.1 RFC 7591 §2 base fields

Note on "REQUIRED": RFC 7591 marks no field unconditionally REQUIRED in the request. The only
conditional mandate is on `redirect_uris`.

| JSON field | Type | Status | Default | Notes |
|---|---|---|---|---|
| `redirect_uris` | array of string | REQUIRED for redirect-based grants | — | see §2.2 |
| `token_endpoint_auth_method` | string | OPTIONAL | `"client_secret_basic"` | registry §2.4 |
| `grant_types` | array of string | OPTIONAL | `["authorization_code"]` | registry §2.5 |
| `response_types` | array of string | OPTIONAL | `["code"]` | registry §2.5 |
| `client_name` | string | OPTIONAL (RECOMMENDED) | — | shown on consent screen |
| `client_uri` | string (URL) | OPTIONAL (RECOMMENDED) | — | shown on consent screen |
| `logo_uri` | string (URL) | OPTIONAL | — | shown on consent screen |
| `scope` | string, space-delimited | OPTIONAL | — | **not** an array |
| `contacts` | array of string | OPTIONAL | — | typically email addresses |
| `tos_uri` | string (URL) | OPTIONAL | — | shown on consent screen |
| `policy_uri` | string (URL) | OPTIONAL | — | shown on consent screen |
| `jwks_uri` | string (URL) | OPTIONAL | — | mutually exclusive with `jwks` |
| `jwks` | JWK Set object | OPTIONAL | — | mutually exclusive with `jwks_uri` |
| `software_id` | string | OPTIONAL | — | stable across versions/instances |
| `software_version` | string | OPTIONAL | — | |
| `software_statement` | string (JWT) | OPTIONAL | — | request parameter, see §4 |

> "The 'jwks_uri' and 'jwks' parameters MUST NOT both be present in the same request or response."
> — **RFC 7591 §2**

Violation → `400` + `invalid_client_metadata`.

> "The authorization server MUST ignore any client metadata sent by the client that it does not
> understand (for instance, by silently removing unknown metadata from the client's registration
> record during processing)." — **RFC 7591 §2**

**Interop trap.** In ASP.NET Core, `JsonSerializerOptions.UnmappedMemberHandling = Disallow` (or
`[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]`) directly violates this MUST.
Use the default `Skip`, or bind to `JsonElement` / capture extras into
`[JsonExtensionData] Dictionary<string, JsonElement>` and drop them. Do **not** 400 on unknown
fields.

### 2.2 `redirect_uris` — the exact normative text

> "Array of redirection URI strings for use in redirect-based flows such as the authorization code
> and implicit flows. As required by Section 2 of OAuth 2.0 [RFC6749], clients using flows with
> redirection MUST register their redirection URI values. Authorization servers that support
> dynamic registration for redirect-based flows MUST implement support for this metadata value."
> — **RFC 7591 §2**

> "For clients that use redirect-based grant types such as 'authorization_code' and 'implicit',
> authorization servers MUST require clients to register their redirection URI values. This can
> help mitigate attacks where rogue actors inject and impersonate a validly registered client and
> intercept its authorization code or tokens through an invalid redirection URI or open
> redirector." — **RFC 7591 §5**

Registered URIs must be one of: a remote website protected by TLS, `localhost` HTTP, or a
non-HTTP application-specific URL available only to the client application (RFC 7591 §5).

Validation rules to implement, in order:

| Check | Failure → error code |
|---|---|
| `grant_types` contains `authorization_code` or `implicit` but `redirect_uris` missing/empty | `invalid_redirect_uri` |
| Any entry is not an absolute URI | `invalid_redirect_uri` |
| Any entry contains a fragment (`#`) | `invalid_redirect_uri` |
| Scheme is `http` and host is not `localhost`/`127.0.0.1`/`[::1]` | `invalid_redirect_uri` |
| Scheme is not in allowlist (`https`, `http`-loopback, registered custom scheme) | `invalid_redirect_uri` |
| Count exceeds tenant policy cap (suggest 10) | `invalid_redirect_uri` |

MCP spec adds: "All redirect URIs **MUST** be either `localhost` or use HTTPS" and
"Authorization servers **MUST** validate exact redirect URIs against pre-registered values to
prevent redirection attacks."

**Interop trap — loopback ports.** RFC 8252 §7.3 requires port-agnostic matching for
`127.0.0.1`. Claude Code declares `http://localhost/callback` and `http://127.0.0.1/callback` in
its CIMD and binds an ephemeral port (e.g. `http://localhost:3118/callback`). Anthropic's docs:
"your authorization server must accept both with the port component ignored... apply the same
port-agnostic match to `localhost`". So: exact match on scheme+host+path, **ignore port**, for
loopback hosts only. Everything else is byte-exact.

### 2.3 Human-readable field internationalization — RFC 7591 §2.2

Human-readable values MAY carry a BCP 47 language tag delimited by `#`:

```json
{
  "client_name": "My Client",
  "client_name#en-US": "My Client",
  "client_name#ja-Jpan-JP": "クライアント名"
}
```

> "If any human-readable field is sent without a language tag, parties using it MUST NOT make any
> assumptions about the language, character set, or script." — **RFC 7591 §2.2**

**Interop trap.** `#` is not a legal C# property-name character and `client_name#en-US` will not
bind to a POCO. Store these in a side dictionary keyed by the full name. Also: do not naively
`Uri`-parse or HTML-escape-strip on `#`; it is a field-name delimiter here, not a URI fragment.

### 2.4 `token_endpoint_auth_method` registry (IANA, complete)

| Value | Defining spec |
|---|---|
| `none` | RFC 7591 |
| `client_secret_post` | RFC 7591 |
| `client_secret_basic` | RFC 7591 |
| `client_secret_jwt` | OIDC Core 1.0 §9; draft-ietf-oauth-rfc7523bis |
| `private_key_jwt` | OIDC Core 1.0 §9; draft-ietf-oauth-rfc7523bis |
| `tls_client_auth` | RFC 8705 §2.1.1 |
| `self_signed_tls_client_auth` | RFC 8705 §2.2.1 |

Values may also be absolute URIs for non-registered methods.

**Default is `client_secret_basic`** if the field is omitted — this bites you: a client that omits
the field gets a confidential-client registration and a `client_secret`, then fails at `/token`
because it authenticates as a public client.

**Interop trap (critical for Claude/ChatGPT).** Both register as **public clients**. Anthropic:
"DCR and CIMD register Claude as a public client". OpenAI: "For CIMD, ChatGPT supports `none` for
public-client token exchange and `private_key_jwt` for signed client assertion token exchange."
Your AS **must** accept `token_endpoint_auth_method: "none"` at `/register` and must advertise
`"none"` in `token_endpoint_auth_methods_supported`. Anthropic further requires `"none"` in that
list before Claude will even *select* CIMD: "Claude selects CIMD only when your authorization
server metadata advertises **both** `"client_id_metadata_document_supported": true` **and**
`"none"` in `token_endpoint_auth_methods_supported`."

When `token_endpoint_auth_method` is `none`: do **not** issue `client_secret`, and therefore do
**not** emit `client_secret_expires_at`.

### 2.5 `grant_types` / `response_types` registries and their correspondence

`grant_types` values defined in RFC 7591 §2:

| Value |
|---|
| `authorization_code` |
| `implicit` |
| `password` |
| `client_credentials` |
| `refresh_token` |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `urn:ietf:params:oauth:grant-type:saml2-bearer` |

`response_types` values defined in RFC 7591 §2: `code`, `token`.

RFC 7591 §2 correspondence table (grant type → response types the client will use):

| `grant_types` value | `response_types` value |
|---|---|
| `authorization_code` | `code` |
| `implicit` | `token` |
| `password` | (none) |
| `client_credentials` | (none) |
| `refresh_token` | (none) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | (none) |
| `urn:ietf:params:oauth:grant-type:saml2-bearer` | (none) |

The spec's own example error message for an inconsistent pair:

```json
{
  "error": "invalid_client_metadata",
  "error_description": "The grant type 'authorization_code' must be registered along with the response type 'code' but found only 'implicit' instead."
}
```

**OAuth 2.1 note.** OAuth 2.1 removes `implicit` and `password`. For an OAuth 2.1 AS, treat those
two as *unsupported* — but see the subset rule below before deciding to 400.

**Interop trap — the subset rule.** Claude's DCR body sends
`grant_types: ["authorization_code", "refresh_token"]`. Rejecting `refresh_token` (or any grant
you don't want) is a top-listed cause of Claude connector failure. RFC 7591 §3.2.1 authorizes the
gentler path:

> "The authorization server MAY reject or replace any of the client's requested metadata values
> submitted during the registration and substitute them with suitable values."
> — **RFC 7591 §3.2.1**

So: **register the intersection of requested and supported, and echo back what you actually
granted.** Only 400 if the intersection is empty. The response body is authoritative — the client
is expected to read `grant_types` back out of your 201.

### 2.6 OIDC Dynamic Client Registration 1.0 additions

All OPTIONAL.

| JSON field | Meaning | Notable default / values |
|---|---|---|
| `application_type` | kind of application | `"web"` (default) or `"native"` |
| `sector_identifier_uri` | HTTPS URL to JSON array of redirect_uris, for pairwise sub calculation | — |
| `subject_type` | subject identifier type | `"public"` or `"pairwise"` |
| `id_token_signed_response_alg` | JWS alg for ID Token | default `RS256` |
| `id_token_encrypted_response_alg` | JWE alg for ID Token | — |
| `id_token_encrypted_response_enc` | JWE enc for ID Token | default `A128CBC-HS256` if alg set |
| `userinfo_signed_response_alg` | JWS alg for UserInfo | — |
| `userinfo_encrypted_response_alg` | JWE alg for UserInfo | — |
| `userinfo_encrypted_response_enc` | JWE enc for UserInfo | default `A128CBC-HS256` if alg set |
| `request_object_signing_alg` | JWS alg for Request Objects | — |
| `request_object_encryption_alg` | JWE alg for Request Objects | — |
| `request_object_encryption_enc` | JWE enc for Request Objects | default `A128CBC-HS256` if alg set |
| `token_endpoint_auth_signing_alg` | JWS alg for `client_secret_jwt`/`private_key_jwt` assertions | — |
| `default_max_age` | default max auth age, seconds | — |
| `require_auth_time` | whether `auth_time` claim is required | boolean |
| `default_acr_values` | array of default ACR values | — |
| `initiate_login_uri` | HTTPS URI for third-party-initiated login | — |
| `request_uris` | array of pre-registered `request_uri` values | — |

`application_type` allowed values: `"native"`, `"web"`.
`subject_type` allowed values: `"pairwise"`, `"public"`.

OIDC Registration uses the same status codes (201 success, 400 error) and the same two error
codes: `invalid_redirect_uri`, `invalid_client_metadata`.

### 2.7 Other registered metadata worth supporting (IANA registry, full list)

Beyond RFC 7591 / RFC 7592 / OIDC-DCR, the IANA *OAuth Dynamic Client Registration Metadata*
registry also contains:

| Field | Spec |
|---|---|
| `claims_redirect_uris` | UMA 2.0 Grant for OAuth 2.0 |
| `tls_client_certificate_bound_access_tokens` | RFC 8705 §3.4 |
| `tls_client_auth_subject_dn` | RFC 8705 §2.1.2 |
| `tls_client_auth_san_dns` | RFC 8705 §2.1.2 |
| `tls_client_auth_san_uri` | RFC 8705 §2.1.2 |
| `tls_client_auth_san_ip` | RFC 8705 §2.1.2 |
| `tls_client_auth_san_email` | RFC 8705 §2.1.2 |
| `require_signed_request_object` | RFC 9101 §10.5 |
| `require_pushed_authorization_requests` | RFC 9126 §6 |
| `introspection_signed_response_alg` | RFC 9701 §6 |
| `introspection_encrypted_response_alg` | RFC 9701 §6 |
| `introspection_encrypted_response_enc` | RFC 9701 §6 |
| `frontchannel_logout_uri` | OIDC Front-Channel Logout 1.0 |
| `frontchannel_logout_session_required` | OIDC Front-Channel Logout 1.0 |
| `backchannel_logout_uri` | OIDC Back-Channel Logout 1.0 |
| `backchannel_logout_session_required` | OIDC Back-Channel Logout 1.0 |
| `post_logout_redirect_uris` | OIDC RP-Initiated Logout 1.0 |
| `authorization_details_types` | RFC 9396 §10 |
| `dpop_bound_access_tokens` | RFC 9449 §5.2 |
| `client_registration_types` | OpenID Federation 1.0 §5.1.2 |
| `signed_jwks_uri` | OpenID Federation 1.0 §5.2.1 |
| `organization_name`, `description`, `keywords`, `information_uri`, `organization_uri` | OpenID Federation 1.0 §5.2.2 |
| `use_mtls_endpoint_aliases` | FAPI 2.0 §5.2.2.1.1 |
| `nfv_token_signed_response_alg` / `_encrypted_response_alg` / `_encrypted_response_enc` | ETSI GS NFV-SEC 022 |
| `encrypted_response_enc_values_supported`, `vp_formats_supported` | OpenID4VP 1.0 |

Minimum viable set for an Auth0 replacement targeting MCP: RFC 7591 base + OIDC core subset
(`application_type`, `subject_type`, `id_token_signed_response_alg`, `default_max_age`,
`require_auth_time`, `initiate_login_uri`) + `dpop_bound_access_tokens` +
`require_pushed_authorization_requests` + `post_logout_redirect_uris`.

---

## 3. Wire formats

### 3.1 Registration request (RFC 7591 §3.1 example, verbatim)

```http
POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: server.example.com

{
  "redirect_uris": [
    "https://client.example.org/callback",
    "https://client.example.org/callback2"
  ],
  "client_name": "My Example Client",
  "client_name#ja-Jpan-JP": "...",
  "token_endpoint_auth_method": "client_secret_basic",
  "logo_uri": "https://client.example.org/logo.png",
  "jwks_uri": "https://client.example.org/my_public_keys.jwks",
  "example_extension_parameter": "example_value"
}
```

### 3.2 What Claude actually sends

From Anthropic docs + field reports. Treat as the acceptance test:

```json
{
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "client_name": "Claude",
  "client_uri": "https://claude.ai",
  "scope": "<scopes from your WWW-Authenticate `scope` param, else scopes_supported>"
}
```

Claude appends `offline_access` to the requested scope when your AS metadata lists it in
`scopes_supported`, in order to obtain a refresh token.

Redirect URIs you must be able to accept:

| Surface | redirect_uri |
|---|---|
| Claude.ai web / Desktop / mobile / Cowork | `https://claude.ai/api/mcp/auth_callback` |
| Claude Code (native, RFC 8252 loopback) | `http://localhost/callback` and `http://127.0.0.1/callback`, **port ignored** |
| ChatGPT (current) | `https://chatgpt.com/connector/oauth/{callback_id}` |
| ChatGPT (legacy, still supported) | `https://chatgpt.com/connector_platform_oauth_redirect` |

**ChatGPT trap.** The current ChatGPT redirect has a *per-connector-instance* `{callback_id}` path
segment. Any allowlist that hardcodes the full path will reject it. Allowlist by
scheme+host+path-prefix for these two known hosts, or accept whatever the DCR request declares
(which is the correct DCR behavior) and rely on exact-match enforcement at `/authorize`.

### 3.3 Success response — RFC 7591 §3.2.1

> "The successful registration response uses an HTTP 201 Created status code with a body of type
> 'application/json'."

> "Additionally, the authorization server MUST return all registered metadata about this client,
> including any fields provisioned by the authorization server itself." — **RFC 7591 §3.2.1**

| JSON field | Status | Notes |
|---|---|---|
| `client_id` | **REQUIRED** | "It SHOULD NOT be currently valid for any other registered client, though an authorization server MAY issue the same client identifier to multiple instances of a registered client at its discretion." |
| `client_secret` | OPTIONAL | "If issued, this MUST be unique for each `client_id`." Omit entirely for `token_endpoint_auth_method: "none"`. |
| `client_id_issued_at` | OPTIONAL | seconds since 1970-01-01T00:00:00Z UTC (integer, not string, not ISO 8601) |
| `client_secret_expires_at` | **REQUIRED if `client_secret` is issued** | seconds since epoch, or `0` meaning never expires |
| `registration_access_token` | REQUIRED (RFC 7592) | see §5 |
| `registration_client_uri` | REQUIRED (RFC 7592) | fully qualified URL |
| …all registered metadata | MUST | echo back everything you actually stored |

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "client_id": "s6BhdRkqt3",
  "client_secret": "cf136dc3c1fc93f31185e5885805d",
  "client_id_issued_at": 2893256800,
  "client_secret_expires_at": 2893276800,
  "registration_access_token": "reg-23410913-abewfq.123483",
  "registration_client_uri": "https://server.example.com/register/s6BhdRkqt3",
  "redirect_uris": [
    "https://client.example.org/callback",
    "https://client.example.org/callback2"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "client_name": "My Example Client",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

**Traps:**
- `client_id_issued_at` / `client_secret_expires_at` are **integers, Unix seconds**. Emitting
  `DateTimeOffset` as ISO 8601 breaks strict parsers. In C#: `ToUnixTimeSeconds()` and
  serialize as `long`.
- `client_secret_expires_at: 0` means *never expires*. It does **not** mean *expired at epoch*.
- Omitting `client_secret_expires_at` while issuing a `client_secret` violates a REQUIRED.
- The `Cache-Control: no-store` / `Pragma: no-cache` pair is part of the spec's example and is
  the right default for a credential-bearing response.

### 3.4 Error response — RFC 7591 §3.2.2

> "When a registration error condition occurs, the authorization server returns an HTTP 400 status
> code (unless otherwise specified)."

| JSON field | Status |
|---|---|
| `error` | REQUIRED — single ASCII error code string |
| `error_description` | OPTIONAL — human-readable ASCII text for debugging |

Complete error-code registry for the registration endpoint:

| `error` value | When | HTTP |
|---|---|---|
| `invalid_redirect_uri` | "The value of one or more redirection URIs is invalid." | `400` |
| `invalid_client_metadata` | "The value of one of the client metadata fields is invalid and the server has rejected this request." Also used for inconsistent/unsupported combinations and for `jwks` + `jwks_uri` both present. | `400` |
| `invalid_software_statement` | "The software statement presented is invalid." (bad signature, expired, malformed JWT, unknown `iss`) | `400` |
| `unapproved_software_statement` | "The software statement presented is not approved for use by this authorization server." (valid + trusted signature, but policy says no) | `400` |

Verbatim example (RFC 7591 §3.2.2):

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "error": "invalid_redirect_uri",
  "error_description": "The redirection URI http://sketchy.example.com is not allowed by this server."
}
```

**Trap.** There is no `invalid_request` at this endpoint. Malformed JSON is best answered
`400 invalid_client_metadata`. Do **not** return ASP.NET Core's default RFC 7807
`ProblemDetails` body (`{"type":..,"title":..,"status":..,"errors":{..}}`) — it has no `error`
field and clients will not parse it. Suppress the automatic 400 model-state response:

```csharp
builder.Services.Configure<ApiBehaviorOptions>(o => o.SuppressModelStateInvalidFilter = true);
```

and hand-write the error body.

---

## 4. Software statements (RFC 7591 §2.3, §3.1.1)

Definition (§1.2): "A digitally signed or MACed JSON Web Token (JWT) that asserts metadata values
about the client software. In some cases, a software statement will be issued directly by the
client developer."

Request parameter (§3.1.1): `software_statement` — "A software statement containing client
metadata values about the client software as claims. This is a string value containing the entire
signed JWT."

Normative requirements:

> "the software statement MUST be digitally signed or MACed using JSON Web Signature (JWS) and
> MUST contain an 'iss' (issuer) claim denoting the party attesting to the claims in the software
> statement." — **RFC 7591 §2.3**

> "it is RECOMMENDED that software statements be digitally signed using the 'RS256' signature
> algorithm, although particular applications MAY specify the use of different algorithms."
> — **RFC 7591 §2.3**

> "If the same client metadata name is present in both locations [software statement and plain
> JSON], the value of a claim in the software statement MUST take precedence."
> — **RFC 7591 §2.3** (when the software statement is trusted by the AS)

The criteria by which servers decide to trust a software statement are explicitly out of scope.

Implementation checklist:

| Step | Failure → |
|---|---|
| Parse as compact JWS; reject `alg: none` | `invalid_software_statement` |
| `iss` present and in your trusted-issuer table | `invalid_software_statement` (unknown issuer) |
| Signature verifies against that issuer's key | `invalid_software_statement` |
| `exp` / `nbf` honored if present | `invalid_software_statement` |
| Issuer trusted but policy denies this software | `unapproved_software_statement` |
| Merge: software-statement claims override plain JSON claims | — |

**Trap.** Do not use `MicrosoftIdentityModel` `JwtSecurityTokenHandler` defaults here — its claim
type mapping renames claims (`sub` → the long ClaimTypes URI). Use `JsonWebTokenHandler` with
`MapInboundClaims = false`, or read the payload as raw JSON. The whole point is that claim names
must equal client-metadata field names byte for byte.

**Trap 2.** `iss` in a software statement is the *attesting party* (the software publisher), not
the AS and not the client. Do not validate it against your own issuer.

---

## 5. RFC 7592 — registration management

### 5.1 The two provisioned fields

| Field | Status | Definition |
|---|---|---|
| `registration_client_uri` | REQUIRED | "String containing the fully qualified URL of the client configuration endpoint for this client." |
| `registration_access_token` | REQUIRED | "String containing the access token to be used at the client configuration endpoint." |

> "The client MUST use its registration access token in all calls to this endpoint as an OAuth 2.0
> Bearer Token" — **RFC 7592 §2**

> "The location of this endpoint is communicated to the client through the `registration_client_uri`
> member of the client information response." — **RFC 7592 §2**

### 5.2 Method matrix

| Operation | Method | Success | Body |
|---|---|---|---|
| Read | `GET {registration_client_uri}` | `200 OK` | full client information response |
| Update | `PUT {registration_client_uri}` | `200 OK` | full client information response |
| Delete | `DELETE {registration_client_uri}` | `204 No Content` | empty |

All three carry `Authorization: Bearer {registration_access_token}`.

```http
GET /register/s6BhdRkqt3 HTTP/1.1
Accept: application/json
Host: server.example.com
Authorization: Bearer reg-23410913-abewfq.123483
```

```http
DELETE /register/s6BhdRkqt3 HTTP/1.1
Host: server.example.com
Authorization: Bearer reg-23410913-abewfq.123483
```

### 5.3 Update semantics — full replacement, not merge

> "Omitted fields MUST be treated as null or empty values by the server, indicating the client's
> request to delete them" — **RFC 7592 §2.2**

> "The updated client metadata fields request MUST NOT include the `registration_access_token`,
> `registration_client_uri`, `client_secret_expires_at`, or `client_id_issued_at` fields"
> — **RFC 7592 §2.2**

> "The client MUST include its `client_id` field in the request, and it MUST be the same as its
> currently issued client identifier." — **RFC 7592 §2.2**

> "If the client includes the `client_secret` field in the request, the value of this field MUST
> match the currently issued client secret" — **RFC 7592 §2.2**

The server MAY ignore null/empty values, and MAY substitute invalid values with defaults.

| Field in PUT body | Rule |
|---|---|
| `client_id` | MUST be present, MUST equal current |
| `client_secret` | if present, MUST equal current; client MUST NOT overwrite it with a chosen value |
| `registration_access_token` | MUST NOT be present |
| `registration_client_uri` | MUST NOT be present |
| `client_secret_expires_at` | MUST NOT be present |
| `client_id_issued_at` | MUST NOT be present |
| everything else | absent ⇒ delete |

```http
PUT /register/s6BhdRkqt3 HTTP/1.1
Accept: application/json
Content-Type: application/json
Host: server.example.com
Authorization: Bearer reg-23410913-abewfq.123483

{
  "client_id": "s6BhdRkqt3",
  "client_secret": "cf136dc3c1fc93f31185e5885805d",
  "redirect_uris": [
    "https://client.example.org/callback",
    "https://client.example.org/alt"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "client_secret_basic",
  "client_name": "My New Example",
  "logo_uri": "https://client.example.org/newlogo.png"
}
```

**Trap — this is a PUT, and PUT means PUT.** Implementing it as a JSON-merge/PATCH is the single
most common RFC 7592 deviation. If the client omits `logo_uri`, the logo is deleted. Write the
storage layer as "construct a fresh metadata record from the request, carry over only the
server-provisioned fields" — never `existing.Merge(incoming)`.

**Trap — secret rotation.** Read and update responses MAY return a *different* `client_secret` and
`registration_access_token` than the initial registration. `client_id` MUST NOT change. If you
rotate the registration access token on read/update, the client must use the new value on the
next call, so the old one must be invalidated atomically in the same response.

### 5.4 Delete semantics

On `204 No Content`, the AS invalidates `client_id`, `client_secret`, and
`registration_access_token` immediately. It SHOULD invalidate all grants, access tokens, and
refresh tokens associated with the client. The `client_id` becomes unusable at the authorization
and token endpoints.

> "If a client is deprovisioned from a server, any outstanding registration access token for that
> client MUST be invalidated" — **RFC 7592 §5**

### 5.5 Error responses at the configuration endpoint

| Condition | HTTP | Body |
|---|---|---|
| Missing/invalid/expired registration access token | `401 Unauthorized` | per RFC 6750, `WWW-Authenticate: Bearer error="invalid_token"` |
| Token valid but client does not exist | `401 Unauthorized` — and the token SHOULD be revoked | — |
| Authenticated but not permitted this operation | `403 Forbidden` | — |
| Server does not support the method (e.g. DELETE) | `405 Method Not Allowed` | — |
| Invalid metadata on update, no default available | `400` | RFC 7591 error codes: `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement` |

**Trap — 401, not 404, for a nonexistent client.** RFC 7592 deliberately collapses "no such
client" into `401` so the endpoint is not a client-id enumeration oracle. Returning `404` leaks
which `client_id` values exist. In ASP.NET Core this means: do the token lookup first, and if it
resolves to nothing — whether the token is bad or the client is gone — return the same `401`.

**Trap — timing.** Compare registration access tokens in constant time
(`CryptographicOperations.FixedTimeEquals`), and store them hashed (SHA-256) exactly like a
client secret. They are bearer credentials with full control over the client record.

### 5.6 Registration access token security

> "the registration access token is a Bearer Token and acts as the sole authentication for use at
> the client configuration endpoint, it MUST be protected by the developer or client"
> — **RFC 7592 §5**

> "the registration access token MAY be rotated when the developer or client does a read or update
> operation" — **RFC 7592 §5**

**Design note for the C# AS.** Since it is the *sole* authenticator, scope it hard: the token
grants rights over exactly one `client_id`, at exactly one endpoint, and nothing else. Do not
mint it from the same JWT pipeline as access tokens — a bug that makes it accepted at `/mcp` or
at the token endpoint is a full compromise. Prefer an opaque, high-entropy, storage-backed
handle (≥256 bits from `RandomNumberGenerator`) with a distinct table and a distinct prefix
(e.g. `rat_`).

---

## 6. RFC 7592 in the MCP world: should you even expose it?

Neither Claude nor ChatGPT uses RFC 7592. Claude does not read, update, or delete its
registrations — it just registers again. Exposing the configuration endpoint therefore adds
attack surface (a second bearer-credential system) for zero MCP interop value.

But for an **Auth0 replacement reusable across customer projects**, RFC 7592 is the only
standardized way a client can rotate its own secret or clean up after itself, and it is what makes
the TTL/GC story in §8 humane (a client can delete instead of waiting for GC).

Recommendation: implement it, but make it a per-tenant switch defaulting to **on**, and when off
simply omit `registration_access_token` / `registration_client_uri` from the 201 response
(RFC 7592 fields are only REQUIRED when you support the management protocol) and return `405` on
the configuration endpoint methods.

---

## 7. Client registration is not the only path — and for MCP it should not be the default

The MCP spec **downgraded DCR between revisions**. This matters for architectural choices.

| Spec revision | DCR | CIMD |
|---|---|---|
| MCP 2025-06-18 | "Authorization servers and MCP clients **SHOULD** support the OAuth 2.0 Dynamic Client Registration Protocol (RFC7591)." | not mentioned |
| MCP 2025-11-25 | "Authorization servers and MCP clients **MAY** support the OAuth 2.0 Dynamic Client Registration Protocol (RFC7591)... This option is included for backwards compatibility with earlier versions of the MCP authorization spec." | "Authorization servers and MCP clients **SHOULD** support OAuth Client ID Metadata Documents" |

MCP 2025-11-25 client priority order:

1. pre-registered client information, if available
2. CIMD, if AS advertises `client_id_metadata_document_supported`
3. DCR, if AS advertises `registration_endpoint`
4. prompt the user

Anthropic's own guidance: "For servers expecting high traffic from the directory, prefer **CIMD or
`oauth_anthropic_creds` over DCR**. DCR causes Claude to register a new client on every fresh
connection, which can result in very large numbers of registered clients on your authorization
server."

OpenAI's guidance: "Use Client ID Metadata Documents (CIMD) as the preferred client registration
method when your authorization server supports it... DCR is still supported. If you include
`registration_endpoint`, ChatGPT can register dynamically."

**Conclusion for this project:** implement RFC 7591 correctly (it is the compatibility floor and
customer projects will need it), but implement CIMD too and advertise both. AS metadata should
carry:

```json
{
  "registration_endpoint": "https://as.example.com/register",
  "client_id_metadata_document_supported": true,
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["openid", "offline_access", "..."]
}
```

CIMD server-side obligations relevant to registration storage (MCP 2025-11-25):

- **SHOULD** fetch metadata documents when encountering URL-formatted `client_id`s
- **MUST** validate the fetched document's `client_id` matches the URL exactly
- **SHOULD** cache metadata respecting HTTP cache headers
- **MUST** validate redirect URIs in the authorization request against those in the document
- **MUST** validate the document is valid JSON with required fields (`client_id`, `client_name`,
  `redirect_uris`)
- **SHOULD** consider SSRF risks — the AS is fetching an attacker-supplied URL

CIMD does not create a client row, which is exactly why it dodges §8.

---

## 8. Open registration: abuse, DoS, TTL, quotas

This is the operationally hardest part and the RFCs give you almost nothing — one MAY. Everything
below §8.1 is design, anchored to the normative hooks that do exist.

### 8.1 What the RFCs actually mandate

| Statement | Source |
|---|---|
| "These requests MAY be rate-limited or otherwise limited to prevent a denial-of-service attack on the client registration endpoint." | RFC 7591 §3.1 |
| "Unless used as a claim in a software statement, the authorization server MUST treat all client metadata as self-asserted. For instance, a rogue client might use the name and logo of a legitimate client that it is trying to impersonate." | RFC 7591 §5 |
| "an authorization server MUST take appropriate steps to mitigate this risk by looking at the entire registration request and client configuration." | RFC 7591 §5 |
| "it must be extremely careful with any URL provided by the client that will be displayed to the user (e.g., `logo_uri`, `tos_uri`, `client_uri`, and `policy_uri`)." | RFC 7591 §5 |
| "SHOULD check to see if the `logo_uri`, `tos_uri`, `client_uri`, and `policy_uri` have the same host and scheme as the those defined in the array of `redirect_uris` and that all of these URIs resolve to valid web pages." | RFC 7591 §5 |
| "If an authorization server receives a registration request for a client that is not intended to have multiple instances registered simultaneously and the authorization server can infer a duplication of registration (e.g., it uses the same `software_id` and `software_version` values as another existing client), the server SHOULD treat the new registration as being suspect and reject the registration." | RFC 7591 §5 |
| "An authorization server SHOULD NOT issue the same client secret to multiple instances of a registered client, even if they are issued the same client identifier, or else the client secret could be leaked, allowing malicious impostors to impersonate a confidential client." | RFC 7591 §5 |
| "An authorization server COULD issue a warning if the domain/site of the logo doesn't match the domain/site of redirection URIs. An authorization server could also refuse registration requests from a known software identifier that is requesting different redirection URIs or a different client URI." | RFC 7591 §5 |

### 8.2 The Claude-specific volume problem

Claude "re-runs discovery and registration on every connect attempt". Every user × every
reconnect = one new client row, forever, all with the same
`redirect_uris: ["https://claude.ai/api/mcp/auth_callback"]`. An unbounded `Clients` table is
both a disk-exhaustion vector and a slow poison for any query that scans clients.

### 8.3 Recommended controls for an industrial AS

**Rate limiting** (the RFC's `MAY`, made a `MUST` by operations):

| Dimension | Suggested limit | Response |
|---|---|---|
| per source IP | 10 registrations / minute, 100 / hour | `429 Too Many Requests` + `Retry-After` |
| per `software_id` | 20 / hour | `429` |
| per redirect_uri host | 60 / hour | `429` |
| global | tenant-configured ceiling | `429` |

`429` is not defined by RFC 7591 (which specifies `400` for *registration error conditions*), but
rate limiting is a transport-level condition, not a metadata validation error — `429` with
`Retry-After` is correct and is what Anthropic's own troubleshooting doc tells server operators to
look for. In ASP.NET Core 9 use the built-in
`builder.Services.AddRateLimiter(...)` with a `PartitionedRateLimiter` partitioned on
`(clientIp, redirectUriHost)`, and a sliding-window limiter. Put it in front of the endpoint via
`.RequireRateLimiting("dcr")`.

**Deduplication instead of proliferation.** RFC 7591 §5 blesses treating duplicate registrations
as suspect. A softer, interop-safe variant: compute a canonical fingerprint over the
*security-relevant* metadata —

```
sha256(sorted(redirect_uris) ‖ sorted(grant_types) ‖ sorted(response_types)
       ‖ token_endpoint_auth_method ‖ software_id ‖ software_statement_thumbprint)
```

— and if a live client with that fingerprint already exists for the tenant, **return the existing
`client_id` with a fresh `registration_access_token`** rather than minting a new row. This is
legal: RFC 7591 §3.2.1 says the `client_id` "SHOULD NOT be currently valid for any other
registered client, though an authorization server MAY issue the same client identifier to multiple
instances of a registered client at its discretion." Note the interacting constraint: if you
reuse a `client_id` across instances you MUST NOT reuse the `client_secret` (§5) — which is moot
for Claude/ChatGPT because they register with `token_endpoint_auth_method: "none"` and get no
secret at all. **Restrict fingerprint-dedup to public clients** for exactly that reason.

**TTL and garbage collection.** Not in the RFC; required in practice.

| Client state | Retention | Rationale |
|---|---|---|
| registered, never used at `/authorize` | **24 hours**, then hard delete | a client that never started a flow is abandoned or a probe |
| used at `/authorize`, never reached `/token` | 7 days | abandoned consent |
| has ≥1 live grant (access/refresh token or consent record) | never GC'd while a grant lives | deleting would break a working connector |
| all grants revoked/expired | 30 days after last grant expiry | allows refresh-token recovery windows |

Implement as a hosted `BackgroundService` running hourly, batched (`DELETE ... LIMIT 1000`), with
the predicate driven by a `LastUsedAt` column updated at `/authorize` and `/token`. Index
`(TenantId, LastUsedAt)` and `(TenantId, CreatedAt)`.

Deleting a client MUST cascade to its grants and its registration access token (RFC 7592 §5 logic
applied to server-initiated deprovisioning).

**Quotas.** Per tenant: a hard cap on live dynamic clients (e.g. 10,000), and a cap on
never-used clients (e.g. 1,000). On breach, `429` for the never-used cap (transient — GC will
free room) and `400 invalid_client_metadata` with a clear `error_description` for the hard cap
(non-transient without operator action).

**Storage hygiene.**
- Store `client_secret` and `registration_access_token` hashed, never plaintext. They are shown
  exactly once, in the 201/200 body.
- Cap request body size (`RequestSizeLimit`, suggest 64 KB) — `jwks` and `contacts` are
  attacker-controlled arrays.
- Cap array lengths: `redirect_uris` ≤ 10, `contacts` ≤ 10, `grant_types` ≤ 10,
  `response_types` ≤ 10, `request_uris` ≤ 10. Cap string lengths (`client_name` ≤ 256, URIs
  ≤ 2048). Violations → `400 invalid_client_metadata`.
- Cap `jwks` key count (≤ 10) and reject keys under 2048-bit RSA / non-P-256+ EC.

**SSRF.** `jwks_uri`, `sector_identifier_uri`, `logo_uri`, `initiate_login_uri`, `request_uris`,
and CIMD `client_id` are all attacker-supplied URLs that your server may fetch. RFC 7591 §5's
"resolve to valid web pages" SHOULD is an *invitation to SSRF* — implement it only behind a
hardened fetcher: HTTPS only, resolve DNS first and reject any non-globally-routable address
(RFC 1918, 100.64.0.0/10, loopback, link-local, IPv6 ULA/link-local), re-check after each
redirect, cap redirects at 2, cap body size, 5 s timeout, no credentials forwarded. Anthropic
applies exactly this policy to *your* hostname, which is a good model to copy.

**Consent-screen safety.** Since all metadata is self-asserted (RFC 7591 §5 MUST), the consent
screen must:
- HTML-encode `client_name` and treat it as untrusted text, never as markup
- never hotlink `logo_uri` directly; proxy/cache it, or suppress logos entirely for
  dynamically-registered clients
- display the **redirect URI hostname prominently** — MCP 2025-11-25 makes this a MUST
  ("**MUST** clearly display the redirect URI hostname during authorization")
- warn when the only registered redirect URIs are loopback (MCP 2025-11-25 SHOULD)
- optionally flag when `logo_uri`/`client_uri` host ≠ `redirect_uris` host (RFC 7591 §5 SHOULD)

---

## 9. Neighbouring requirements that DCR interacts with (do not get these wrong either)

These are outside RFC 7591/7592 but are the reason a correct DCR implementation still fails.

| Requirement | Source | Detail |
|---|---|---|
| PKCE `S256` mandatory | MCP auth spec; Anthropic docs | Claude "includes a PKCE `code_challenge` with `code_challenge_method=S256` in every authorization request". Metadata MUST advertise `"code_challenge_methods_supported": ["S256"]`. MCP clients "**MUST** refuse to proceed" if absent — including for OIDC Discovery documents. |
| `resource` parameter (RFC 8707) | MCP auth spec | Sent on **both** authorization and token requests, set to canonical MCP server URI. Your AS must accept it and mint `aud` accordingly. ChatGPT: "Expect ChatGPT to append `resource=https%3A%2F%2Fyour-mcp.example.com`". |
| Refresh token rotation for public clients | MCP auth spec / OAuth 2.1 §4.3.1 | "For public clients, authorization servers **MUST** rotate refresh tokens". Return the new refresh token in the same response that invalidates the old. |
| RFC 6749 error codes on refresh failure | Anthropic docs | "Return RFC 6749-compliant error codes (`invalid_grant`, not `invalid_request` or a custom code) when a refresh token is no longer valid" |
| `/token` accepts form-encoded | RFC 6749 §4.1.3; Anthropic docs | `Content-Type: application/x-www-form-urlencoded`. A JSON-only parser returns `415` and breaks the flow. |
| Endpoint latency budget | Anthropic docs | Claude waits **10 s** for discovery, registration, and token endpoints; **30 s** for refresh. Exceeding it fails the flow even if the server eventually succeeds. Your `/register` handler must not do synchronous outbound fetches (logo validation, jwks_uri fetch) inline — queue them. |
| Exact redirect URI matching at `/authorize` | MCP auth spec; OAuth 2.1 | "Authorization servers **MUST** validate exact redirect URIs against pre-registered values". Exception: port-agnostic for loopback (RFC 8252 §7.3). |
| AS metadata discovery | MCP auth spec | Serve RFC 8414 `/.well-known/oauth-authorization-server` and/or OIDC `/.well-known/openid-configuration`. Only one is strictly needed but serving both maximizes interop. |
| Issuer must match token signer | Anthropic docs | "The `issuer` value in your authorization server metadata must match the issuer that signs your tokens." |
| Anthropic egress range | Anthropic docs | `160.79.104.0/21` — allowlist if you have a WAF. A WAF `403`/`429` in front of `/register` presents as "Couldn't reach the MCP server". |

---

## 10. Conformance checklist for the C# implementation

`/register` (RFC 7591):

- [ ] `POST` only; other methods `405`
- [ ] Accepts `Content-Type: application/json`; rejects nothing else silently
- [ ] Unknown metadata fields silently ignored (never `400`)
- [ ] `redirect_uris` required when `grant_types` implies redirection
- [ ] `jwks` + `jwks_uri` together → `400 invalid_client_metadata`
- [ ] Grant/response type intersection registered as a subset, echoed in response, not rejected
- [ ] `token_endpoint_auth_method: "none"` accepted; no `client_secret` issued
- [ ] Missing `token_endpoint_auth_method` defaults to `client_secret_basic`
- [ ] Success `201` + `Cache-Control: no-store` + `Pragma: no-cache`
- [ ] Response echoes **all** stored metadata plus server-provisioned fields
- [ ] `client_id_issued_at` / `client_secret_expires_at` serialized as Unix-second integers
- [ ] `client_secret_expires_at` present whenever `client_secret` is
- [ ] Errors are `400` with `{"error": "...", "error_description": "..."}` — no ProblemDetails
- [ ] All four error codes reachable: `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement`
- [ ] `software_statement` verified (JWS, `iss`, no `alg: none`), claims take precedence
- [ ] Rate limited; `429` + `Retry-After` on breach
- [ ] Body size and array/string length caps enforced
- [ ] Secrets and registration access tokens stored hashed
- [ ] Responds within 10 s (no inline outbound fetches)

`/register/{client_id}` (RFC 7592):

- [ ] Bearer `registration_access_token` required on all three methods
- [ ] `GET` → `200` full client information response
- [ ] `PUT` → full replacement; omitted fields deleted
- [ ] `PUT` rejects `registration_access_token`, `registration_client_uri`, `client_secret_expires_at`, `client_id_issued_at`
- [ ] `PUT` requires matching `client_id`; `client_secret` if present must match current
- [ ] `DELETE` → `204`, cascades to grants and tokens
- [ ] Bad token **or** missing client → `401` (never `404`)
- [ ] Insufficient permission → `403`
- [ ] Unsupported method → `405`
- [ ] Token comparison constant-time; token stored hashed
- [ ] Rotated tokens invalidate predecessors atomically

Interop acceptance tests:

- [ ] Claude DCR body (§3.2) registers successfully and returns `token_endpoint_auth_method: "none"`
- [ ] `https://claude.ai/api/mcp/auth_callback` accepted and exactly matched at `/authorize`
- [ ] `http://localhost:PORT/callback` matches registered `http://localhost/callback` for any PORT
- [ ] `https://chatgpt.com/connector/oauth/{anything}` accepted
- [ ] `refresh_token` grant registered, not rejected
- [ ] Metadata advertises `registration_endpoint`, `code_challenge_methods_supported: ["S256"]`, `"none"` in `token_endpoint_auth_methods_supported`, and `client_id_metadata_document_supported: true`

---

## 11. Sources

- [RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591.txt)
- [RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592.txt)
- [IANA OAuth Parameters registries](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [MCP Authorization 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Anthropic — Authentication for connectors](https://claude.com/docs/connectors/building/authentication)
- [Anthropic — Troubleshooting connectors](https://claude.com/docs/connectors/building/troubleshooting)
- [OpenAI Apps SDK — Auth](https://developers.openai.com/apps-sdk/build/auth)
- [Debugging remote MCP connectors on Claude.ai — Brendan Long](https://www.brendanlong.com/debugging-claude-ai-mcp-connectors.html)
