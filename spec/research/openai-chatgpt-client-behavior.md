# ChatGPT (OpenAI) as an OAuth client of our Authorization Server

Research date: **2026-08-03**. Target: a from-scratch OAuth 2.1 + OIDC AS in ASP.NET Core 9 that
**both** Claude.ai and ChatGPT can drive against an MCP server.

Everything below was fetched, not recalled. Sources with fetch status at the bottom.
Anything I could not confirm from a primary source is marked **UNVERIFIED** inline.

---

## 0. The five things that will break the implementation if you get them wrong

> **Rows 1 and 2 were corrected on 2026-08-17 against a live ChatGPT connection.** As first written
> they said advertising `private_key_jwt` and implementing client assertions were both mandatory.
> Measured: a server advertising only `none` links successfully. What is actually mandatory is
> **reading the client's whole document** — see row 1. Both rows are stated below as measured; the
> struck-through reasoning is kept because it is what a reader would otherwise re-derive.

| # | Requirement | Why it bites |
|---|---|---|
| 1 | `token_endpoint_auth_methods_supported` MUST contain **`none`**, and the CIMD reader MUST read **both spellings** of the client's auth-method member as one offer | Claude picks CIMD *only* if `none` is present. ChatGPT's document declares `private_key_jwt` in the RFC 7591 singular **and** `["none","private_key_jwt"]` in the plural: read one and skip the other, and you select a method you cannot complete. ~~Advertising `private_key_jwt` too~~ — measured unnecessary, and advertising it unimplemented is worse than omitting it. |
| 2 | Implementing `private_key_jwt` is **optional**, not required | ~~A CIMD implementation that only handles public clients returns `invalid_client` and the connector never links.~~ Measured 2026-08-17: with both members read, ChatGPT authenticates as a **public client** and the connection completes — `POST /token` → `200`, no assertion presented. It negotiates down to what the AS metadata offers. This would flip back only if ChatGPT ever published a document offering `private_key_jwt` *alone*, which is worth a re-measurement rather than a standing assumption. |
| 3 | `resource` (RFC 8707) MUST be accepted on **both** `/authorize` and `/token`, and copied into `aud` | Both clients always send it. Rejecting or ignoring it produces tokens the MCP server must refuse. Wrong error code = `invalid_target`, not `invalid_request`. |
| 4 | PKCE `S256` mandatory + advertised as `"code_challenge_methods_supported": ["S256"]` | Both clients send `code_challenge_method=S256` unconditionally. Both read the metadata field before starting. |
| 5 | Redirect URI registration must handle **three shapes**: fixed HTTPS (Claude), templated HTTPS per-connector (ChatGPT `.../{callback_id}`), and **port-agnostic loopback** (Claude Code) | Exact-match-only rejects Claude Code; naive prefix-match on the ChatGPT template is an open-redirect. |

---

## 1. Client registration: does ChatGPT require DCR? Does it support CIMD?

**Answer: CIMD is supported and is OpenAI's documented preference. DCR is supported as fallback. Neither is strictly required if you use a pre-registered client.**

> "We recommend using OAuth with Client ID Metadata Documents for client registration when your
> authorization server supports CIMD."
> — developers.openai.com/api/docs/mcp

> "ChatGPT supports CIMD with public-client token exchange (`none`) or signed client assertion token
> exchange (`private_key_jwt`). Dynamic client registration remains supported when configured."
> — developers.openai.com/api/docs/mcp

> "Prefer Client ID Metadata Documents (CIMD) when your authorization server supports CIMD… Support
> DCR when the plugin builder chooses it or CIMD is not available."
> — developers.openai.com/apps-sdk/guides/security-privacy

Selection is driven by AS metadata:

| AS metadata field | Effect on ChatGPT |
|---|---|
| `"client_id_metadata_document_supported": true` | CIMD path enabled (preferred) |
| `registration_endpoint` present | DCR path available; "ChatGPT calls your `registration_endpoint` once for the connector instance, receives a generated `client_id`, and reuses that client for the instance" |
| neither | Requires a pre-registered client id entered in the connector UI |

### Historical noise — ignore these, they are superseded

Two OpenAI community threads circulate widely and are **out of date**:

- *"Dynamic client registration should be optional for custom connectors"* (Oct 2025) — describes a
  DCR-only era. Superseded by the current Apps SDK docs which lead with CIMD.
- *"OAuth Client ID is no longer optional"* (Nov 21–24 2025) — a temporary UI enforcement bug,
  reported resolved 2025-11-24.

Do not design around either. The current documented behavior is CIMD-preferred.

### Re-measured 2026-08-17: the live documents now carry BOTH spellings

Fetched from this repository's CI network on 2026-08-17. Both documents changed since the
2026-08-03 capture in `spec/cimd-live-2026-08-03.json`, and in the same way:

```jsonc
// https://chatgpt.com/oauth/client.json  and  https://chatgpt.com/oauth/mcp/client.json
"token_endpoint_auth_method": "private_key_jwt",              // ← added since 2026-08-03
"token_endpoint_auth_methods_supported": ["none","private_key_jwt"]
```

On 2026-08-03 each document carried only the plural. It now carries the RFC 7591 singular **as
well**, naming `private_key_jwt` as its preference while the plural still offers `none`.

**What that broke.** `CimdDocument.TryReadAuthMethod` read the singular *or* the plural —
`if`/`else if` — so the singular won and the array offering `none` was never read. The client
resolved as confidential, and `/token` refused it: `invalid_client`, *"This client is registered for
an authentication method this server does not offer."* In the ChatGPT UI that is **"There was a
problem connecting. Try again later"** with nothing else to go on. Fixed by reading both members and
treating their union as the offer; `none` still wins when the offer holds it.

**Consequence for the table in §0 row 1.** Supporting `private_key_jwt` is still the requirement for
honouring ChatGPT's stated preference, and it is still unimplemented here. What changed is that
"ChatGPT declares both, so a `none`-only server interoperates" is only true of a server that reads
the whole document. The claim is now pinned by a test rather than by this paragraph:
`The_live_chatgpt_document_is_a_public_client`.

**The client_id in production is per-connector, and it is not `/oauth/mcp/client.json`.** A
deployment's authorization-server log named `https://chatgpt.com/oauth/<callback-id>/client.json` —
minted per connector instance, at the `/oauth/<id>/client.json` path the Apps SDK documents, with
`redirect_uris: ["https://chatgpt.com/connector/oauth/<callback-id>"]`. Fetched 2026-08-17: it
carries the same two auth-method members as the two well-known documents. Reproducing against
`/oauth/mcp/client.json` therefore reproduces the shape but not the URL, which matters for anyone
reading a log and looking for the id they tested with.

### Measured from a live failed connection, 2026-08-17

Not reproduced from outside — the authorization server's own rejection log, from a founder's
connection attempts:

```
Rejected Token request 0HNNS26JC6IR2:00000002: ClientAuthMethodNotOffered [X-18]
  -> 400 invalid_client: This client is registered for an authentication method this server
     does not offer.
     client_id=https://chatgpt.com/oauth/<callback-id>/client.json;
     registered=PrivateKeyJwt; enabled=None ClientSecretBasic ClientSecretPost
```

What the surrounding lines settle, which black-box probing could not:

| Step | Result |
|---|---|
| `/authorize` with the per-connector `client_id` | reached, CIMD resolved |
| Scopes `openid email offline_access docs:read docs:write` | accepted — no `invalid_scope` |
| `resource` = the MCP URL | accepted — no `invalid_target` |
| Login, then `/consent` | reached and rendered, `client-logo` proxied 200 |
| `/token` | **`invalid_client`** — the only failing step |

So every other hypothesis for a ChatGPT connection failure — scope advertised but refused, resource
indicator unregistered, consent loop, redirect mismatch — is measured **not** to apply to this
deployment. The token exchange is the whole of it.

### Measured from a live successful connection, 2026-08-17 — three UNVERIFIED items closed

The fix above was deployed and a founder linked the connector. The handshake completed:
`server/discover` ×4, `tools/list` ×2, `resources/read` ×2, all `200`. That run answers three
questions this document had been carrying as unverified, and **one of the answers is the opposite
of what the vendor documentation implied**.

| # | Was | Measured |
|---|---|---|
| 1 | Does ChatGPT present a `client_assertion` once resolved as a public client? | **No.** `POST /token` → `200`, and no `ClientCredentialsUnexpected` was raised. It authenticated as a public client, exactly as our metadata's `token_endpoint_auth_methods_supported` invites. |
| 2 | Does ChatGPT probe the RFC 9728 §3.1 path-inserted PRM form? (U-01) | **Yes, and only that one.** `/.well-known/oauth-protected-resource/mcp` fetched twice from `Python/3.12 aiohttp/3.13.5`; the root form requested **zero** times. |
| 3 | Does ChatGPT request `offline_access`? | **Yes.** The authorization request carried `scope=openid email offline_access docs:read docs:write`. |

**Row 2 is the one to act on.** §3 of this document reasoned from OpenAI's docs — which show only
the root form — that the path-inserted form was the doubtful one, and recommended serving both as
cheap insurance. It is the reverse: the path-inserted form is the only one ChatGPT asks for, so a
server that served only the shape OpenAI documents would fail every ChatGPT connection while
appearing to follow the vendor's own instructions. **Serve both, and treat the path-inserted form
as the load-bearing one.**

Row 1 retires the caveat on the `none`-over-`private_key_jwt` policy in
`CimdDocument.TryReadAuthMethod`: preferring `none` when the document offers both is what the
client actually does, not only what this server would rather have.

Row 3 fills the `Refresh` cell in §6's table, which read UNVERIFIED because the Apps SDK documents
neither refresh tokens nor `offline_access`. It requests it when the AS metadata advertises it —
the same behaviour Claude documents.

### ChatGPT's actual CIMD document (observed in the wild)

```json
{
  "client_id": "https://chatgpt.com/oauth/<id>/client.json",
  "client_uri": "https://chatgpt.com/",
  "redirect_uris": ["https://chatgpt.com/connector/oauth/<id>"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_name": "ChatGPT",
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "RS256",
  "jwks_uri": "https://chatgpt.com/oauth/jwks.json"
}
```

Source: Altinity/altinity-mcp issue #118, which also records the exact failure mode of a
`none`-only CIMD implementation:

> `"invalid_client","error_description":"unknown OAuth client"` … `token_endpoint_auth_method must be "none" (got "private_key_jwt")`

**This is the single highest-value finding in this document.** The MCP spec's CIMD example and
Claude's CIMD both use `token_endpoint_auth_method: "none"`, so most reference implementations only
handle the public-client case. ChatGPT does not fit that mould.

Cross-check: the JWKS location `/oauth/jwks.json` is independently confirmed by the Apps SDK docs —
> "The JWKS is served from `/oauth/jwks.json` on the metadata origin."

---

## 2. Redirect URIs

| Client | Redirect URI | Match rule |
|---|---|---|
| ChatGPT (current) | `https://chatgpt.com/connector/oauth/{callback_id}` | exact, per-connector; value comes from the CIMD `redirect_uris` |
| ChatGPT (legacy, still accepted) | `https://chatgpt.com/connector_platform_oauth_redirect` | exact |
| Claude.ai / Desktop / mobile / Cowork | `https://claude.ai/api/mcp/auth_callback` | exact |
| Claude (future) | `https://claude.com/api/mcp/auth_callback` | exact — Anthropic says allowlist it now |
| Claude Code | `http://localhost/callback`, `http://127.0.0.1/callback` | **port MUST be ignored** (RFC 8252 §7.3) |

> "The production redirect endpoint is `https://chatgpt.com/connector/oauth/{callback_id}`, displayed
> in the app management page. Legacy deployments still accept
> `https://chatgpt.com/connector_platform_oauth_redirect`." — Apps SDK auth

> "Claude Code declares `http://localhost/callback` and `http://127.0.0.1/callback` in its Client ID
> Metadata Document, so your authorization server must accept both with the port component ignored."
> — claude.com/docs/connectors/building/authentication

**Interop trap.** OAuth 2.1 §2.3.1 is strict:

> "Authorization servers MUST require clients to register their complete redirect URI (including the
> path component). Authorization servers MUST reject authorization requests that specify a redirect
> URI that doesn't exactly match one that was registered, with an exception for loopback redirects,
> where an exact match is required except for the port URI component."

So: **exact string match for everything except loopback; for loopback compare scheme+host+path and
ignore the port.** Do not implement a generic prefix match to accommodate ChatGPT's `{callback_id}` —
the concrete value arrives in the CIMD document, so it is exact-matchable at request time.

Also OAuth 2.1 §4.1.2.1:
> "If the redirect URI is invalid or if the `client_id` is missing or invalid, the authorization
> server MUST NOT redirect the user agent" — render an error page, do not bounce.

---

## 3. Discovery: which documents, in what order

### ChatGPT's documented sequence

> 1. Protected resource metadata from `GET https://your-mcp.example.com/.well-known/oauth-protected-resource`
> 2. OAuth authorization server metadata from `https://auth.yourcompany.com/.well-known/oauth-authorization-server`
>    or OpenID Connect metadata at `.well-known/openid-configuration`
> — Apps SDK auth

Then (per the same page) `registration_endpoint` if DCR, `authorization_endpoint`, `token_endpoint`,
then `Authorization: Bearer <token>` on MCP requests.

**RESOLVED 2026-08-17 — and the answer inverts the guess.** Whether ChatGPT probes the RFC 9728 §3.1
*path-inserted* PRM form (`/.well-known/oauth-protected-resource/mcp`) was open because OpenAI's docs
only ever show the root form, while Claude's docs document trying path-inserted first. Measured on a
live connection: ChatGPT fetched the **path-inserted form twice and the root form not at all**. So it
is the root form that is optional here, and serving only the shape OpenAI documents would fail every
ChatGPT connection. **Serve both paths, and treat the path-inserted one as load-bearing.** See the
measurement table in §1.

### Claude's sequence (documented precisely)

1. `401` + `WWW-Authenticate: Bearer resource_metadata="…"` → follow that URL. This is the preferred path.
2. Fallback probe on the MCP origin: `/.well-known/oauth-protected-resource/<mcp-path>` **then**
   `/.well-known/oauth-protected-resource`.
3. AS metadata: `/.well-known/oauth-authorization-server` (RFC 8414) **first**, then
   `/.well-known/openid-configuration`. "A `404` on one is expected if the other returns `200`."

### MCP spec normative order (implement to this — it is the superset)

For issuer URLs **with** a path component (e.g. `https://auth.example.com/tenant1`), clients MUST try:

1. `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`
2. `https://auth.example.com/.well-known/openid-configuration/tenant1`
3. `https://auth.example.com/tenant1/.well-known/openid-configuration`

For issuer URLs **without** a path component:

1. `https://auth.example.com/.well-known/oauth-authorization-server`
2. `https://auth.example.com/.well-known/openid-configuration`

**ASP.NET Core action:** if your issuer has no path, map 2 routes on the AS and 2 on the RS. If your
issuer has a tenant path, map all 3 AS forms. Map them as literal routes, not a catch-all.

**Validation the clients apply to you** (MCP spec, citing RFC 8414 §3.3):
> "the `issuer` value in the document **MUST** be identical to the issuer identifier used to construct
> the well-known URL. If they differ, the client **MUST NOT** use the metadata."

So `issuer` in your JSON must be byte-identical to the value in `authorization_servers[]`.

RFC 9728 §3.3 imposes the mirror rule on the PRM:
> "The `resource` value returned MUST be identical to the protected resource's resource identifier
> value into which the well-known URI path suffix was inserted… If these values are not identical, the
> data contained in the response MUST NOT be used."

Claude restates this operationally: "The protected resource metadata document's `resource` field must
match your MCP server URL exactly as the user enters it in Claude, including any path component."

---

## 4. The `resource` parameter (RFC 8707)

**Both clients send it. On both requests.**

> "Expect ChatGPT to append `resource=https%3A%2F%2Fyour-mcp.example.com` to both the authorization
> and token requests." — Apps SDK auth

> "Claude sends the RFC 8707 `resource` parameter on authorization and token requests, set to the
> canonical form of your MCP server URL — lowercase scheme and host, no trailing slash, no fragment,
> no default port — including any path component." — claude.com troubleshooting

RFC 8707 §2 normative rules:

| Rule | Text |
|---|---|
| Format | "Its value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a fragment component." |
| Query | "It SHOULD NOT include a query component, but it is recognized that there are cases that make a query component a useful and necessary part." |
| Multiplicity | "Multiple `resource` parameters MAY be used to indicate that the requested token is intended to be used at multiple resources." |
| Audience binding | "The authorization server SHOULD audience-restrict issued access tokens to the resource(s) indicated by the `resource` parameter." |

RFC 8707 §2.1 error handling:
> "If the authorization server fails to parse the provided value(s) or does not consider the
> resource(s) acceptable, it should reject the request with an error response using the error code
> `invalid_target`."

**Exact error code string: `invalid_target`.** Not `invalid_request`, not `invalid_resource`.

**Interop trap (real, documented):** Microsoft Entra fails this with `AADSTS9010010` (surfaced as
`invalid_target`) because Claude sends the full MCP URL *including path* as `resource`, and Entra
only knows `api://{client-id}`. Our AS must accept a registered resource URI **with a path
component** as a first-class thing, not just an origin.

**Canonicalisation to implement:** lowercase scheme + host, strip default port (443), strip trailing
slash, reject fragment, preserve path. Compare canonical-to-canonical, never byte-to-byte against
raw user input. MCP spec: implementations "SHOULD accept uppercase scheme and host components for
robustness."

---

## 5. PKCE

| Client | Behavior |
|---|---|
| ChatGPT | "performs the authorization-code flow with PKCE using the `S256` code challenge" |
| Claude | "includes a PKCE `code_challenge` with `code_challenge_method=S256` on **every** authorization request, regardless of which registration mechanism it uses" |

OAuth 2.1 §4.1.1:
> "Clients MUST use `code_challenge` and `code_verifier` and authorization servers MUST enforce their
> use except under the conditions described in Section 7.5.1."

Both clients read `"code_challenge_methods_supported": ["S256"]` from metadata **before** starting.
Omitting the field can abort the flow even if you implement S256 correctly.

**Do not implement `plain`.** Advertise `["S256"]` only. Reject `code_challenge_method=plain` with
`invalid_request`; reject a missing `code_challenge` with `invalid_request`.

---

## 6. Scopes and consent

| Aspect | ChatGPT | Claude |
|---|---|---|
| Source of requested scopes | `scopes_supported` from PRM; OIDC scopes auto-added | `scope` param on the `401` `WWW-Authenticate` first, else PRM `scopes_supported` |
| OIDC scopes | "If your provider advertises OIDC scopes (for example, `openid`, `email`, `profile`) in `scopes_supported`, ChatGPT requests those scopes by default" | not documented as automatic |
| Refresh | **Measured 2026-08-17** — requests `offline_access` when the AS metadata advertises it, same as Claude. The Apps SDK documents neither refresh tokens nor `offline_access`, so this came from a live authorization request, not from a doc | "Claude also appends `offline_access` when your authorization server metadata lists it in `scopes_supported`" |
| Step-up | via `_meta["mcp/www_authenticate"]` with `error="insufficient_scope"` | `403` + `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` |

**Trap (ChatGPT-specific):** advertising `openid email profile` in `scopes_supported` causes ChatGPT
to request them by default. OpenAI warns: "Verify every advertised scope is enabled for the OAuth
client." If your AS rejects a scope it advertises, ChatGPT fails with `invalid_scope`. Only advertise
scopes every client is permitted to request.

**Trap (Claude-specific):** the MCP spec says protected resources **SHOULD NOT** put `offline_access`
in PRM `scopes_supported` — it belongs in the *AS* metadata `scopes_supported`. Claude reads it from
the AS metadata. Putting it in the PRM is the common mistake.

**Consent screen requirement for CIMD** (this is a security requirement, not cosmetic):
> "Because the document is self-asserted, the consent screen must display the **host of the
> `client_id` URL** (not the `client_name` field) as the relying party, and the listed `redirect_uris`
> should be required to be same-origin with the `client_id` URL." — claude.com lazy-authentication

Plus, for loopback clients, the MCP spec "requires authorization servers to display the redirect URI
hostname clearly on the consent screen and recommends an extra warning when the only registered
redirect URIs are loopback addresses."

---

## 7. Required AS metadata — the union document to serve

Serve this at `/.well-known/oauth-authorization-server` **and** `/.well-known/openid-configuration`.

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth2/v1/authorize",
  "token_endpoint": "https://auth.example.com/oauth2/v1/token",
  "registration_endpoint": "https://auth.example.com/oauth2/v1/register",
  "jwks_uri": "https://auth.example.com/oauth2/v1/keys",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
  "client_id_metadata_document_supported": true,
  "scopes_supported": ["openid", "profile", "email", "offline_access", "files:read", "files:write"],
  "authorization_response_iss_parameter_supported": true
}
```

Field-by-field justification:

| Field | Required by | Note |
|---|---|---|
| `issuer` | RFC 8414 §3.3 validation | MUST equal the URL used to build the well-known path |
| `client_id_metadata_document_supported` | ChatGPT + Claude CIMD selection | boolean `true`, not string |
| `token_endpoint_auth_methods_supported` | **both** | MUST include `none` (Claude gate) **and** `private_key_jwt` (ChatGPT CIMD) |
| `code_challenge_methods_supported` | both, read pre-flight | `["S256"]` only |
| `registration_endpoint` | DCR fallback | Claude falls back here if either CIMD gate fails |
| `authorization_response_iss_parameter_supported` | MCP spec / RFC 9207 §2.3 | "Authorization servers that include the `iss` parameter MUST advertise this by setting `authorization_response_iss_parameter_supported` to `true`" |
| `scopes_supported` | scope selection | include `offline_access` here (**not** in PRM) |

**Claude's CIMD gate, verbatim** — this is why `none` is non-negotiable:
> "Claude selects CIMD only when your authorization server metadata advertises **both**
> `"client_id_metadata_document_supported": true` **and** `"none"` in
> `token_endpoint_auth_methods_supported`… If either is missing, Claude falls back to DCR."

---

## 8. Protected Resource Metadata (served by the MCP server, not the AS)

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["files:read", "files:write"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://example.com/docs/mcp"
}
```

RFC 9728 §2 field status:

| Status | Fields |
|---|---|
| REQUIRED | `resource` |
| RECOMMENDED | `scopes_supported`, `resource_name` |
| OPTIONAL | `authorization_servers`, `jwks_uri`, `bearer_methods_supported`, `resource_signing_alg_values_supported`, `resource_documentation`, `resource_policy_uri`, `resource_tos_uri`, `tls_client_certificate_bound_access_tokens`, `authorization_details_types_supported`, `dpop_signing_alg_values_supported`, `dpop_bound_access_tokens_required`, `signed_metadata` |

MCP spec overrides RFC 9728 here: `authorization_servers` **MUST** be present with at least one entry.

**Claude-specific:** "If you list more than one, Claude uses the first entry and does not fall back to
later entries — list your primary issuer first."

Serve at **both** `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/<mcp-path>`.

---

## 9. Exact wire formats

### 9.1 Authorization request (what both clients send)

```
GET /oauth2/v1/authorize
  ?response_type=code
  &client_id=https%3A%2F%2Fchatgpt.com%2Foauth%2F<id>%2Fclient.json
  &redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2F<id>
  &code_challenge=<43-128 char base64url>
  &code_challenge_method=S256
  &state=<opaque>
  &scope=files%3Aread%20files%3Awrite
  &resource=https%3A%2F%2Fmcp.example.com%2Fmcp HTTP/1.1
Host: auth.example.com
```

Note `client_id` **is a URL** under CIMD. Your `client_id` column cannot be a GUID type.

### 9.2 Authorization response (include `iss` — RFC 9207)

```
HTTP/1.1 302 Found
Location: https://chatgpt.com/connector/oauth/<id>?code=<code>&state=<opaque>&iss=https%3A%2F%2Fauth.example.com
```

MCP spec: AS **SHOULD** include `iss` "in authorization responses, **including error responses**."

### 9.3 Token request — public client (`none`), i.e. Claude / Claude Code

```
POST /oauth2/v1/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback
&client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fclaude-code-client-metadata
&code_verifier=<verifier>
&resource=https%3A%2F%2Fmcp.example.com%2Fmcp
```

### 9.4 Token request — `private_key_jwt`, i.e. ChatGPT

```
POST /oauth2/v1/token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2F<id>
&client_id=https%3A%2F%2Fchatgpt.com%2Foauth%2F<id>%2Fclient.json
&code_verifier=<verifier>
&resource=https%3A%2F%2Fmcp.example.com%2Fmcp
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=<signed JWT, RS256>
```

`client_assertion_type` exact string (RFC 7523 §2.2):
`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`

Assertion JWT validation (RFC 7523 §3), all MUST:

| Claim | Rule |
|---|---|
| `iss` | "MUST contain a unique identifier for the entity that issued the JWT" — for client auth, the `client_id` (the CIMD URL) |
| `sub` | "the subject MUST be the `client_id` of the OAuth client" |
| `aud` | "MUST contain a value that identifies the authorization server as an intended audience"; **"The authorization server MUST reject any JWT that does not contain its own identity as the intended audience."** |
| `exp` | "MUST contain an `exp` claim that limits the time window during which the JWT can be used" |
| `nbf`, `iat`, `jti` | OPTIONAL for client auth — but implement `jti` replay caching anyway |

Verify the signature against the JWKS at the CIMD's `jwks_uri`
(`https://chatgpt.com/oauth/jwks.json`), **not** against any locally stored key.

**`aud` trap:** implementations disagree on whether `aud` is the token endpoint URL or the issuer.
RFC 7523 only requires "its own identity". **Accept both** the issuer identifier and the exact token
endpoint URL. Rejecting one is a very common cause of `invalid_client` with no useful diagnostics.

### 9.5 `401` challenge from the MCP server

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="files:read"
```

Claude: "The `401` status is required — Claude does not honor a `WWW-Authenticate` header on a `200`
response." A `200` carrying `isError: true` produces **no auth prompt at all**; the model just reads
"please sign in" as text. This is the #1 reported lazy-auth bug.

### 9.6 `403` scope step-up

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="files:write", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error_description="File write permission required for this operation"
```

Claude: "A `403` triggers re-authentication **only** when accompanied by
`WWW-Authenticate: Bearer error="insufficient_scope"`; any other `403` is surfaced as a terminal error."

ChatGPT's tool-level equivalent (Apps SDK), returned inside a tool result:

```json
{
  "_meta": {
    "mcp/www_authenticate": [
      "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", error=\"insufficient_scope\", error_description=\"...\""
    ]
  },
  "isError": true
}
```

---

## 10. Error code registry — exact strings

### Authorization endpoint (OAuth 2.1 §4.1.2.1) — HTTP 400 or redirect with `error=`

`invalid_request` · `unauthorized_client` · `access_denied` · `unsupported_response_type` ·
`invalid_scope` · `server_error` · `temporarily_unavailable`

Plus `invalid_target` (RFC 8707 §2.1) for a bad `resource`.

> "If the redirect URI is invalid or if the `client_id` is missing or invalid, the authorization
> server MUST NOT redirect the user agent."

### Token endpoint (OAuth 2.1 §3.2.4) — HTTP 400, `application/json`

`invalid_request` · `invalid_client` · `invalid_grant` · `unauthorized_client` ·
`unsupported_grant_type` · `invalid_scope`

Plus `invalid_target` for a bad/unacceptable `resource`.

`invalid_client` SHOULD be HTTP 401 when the client attempted authentication via the
`Authorization` header; 400 otherwise.

### Bearer / resource server (OAuth 2.1 §5.3.2)

| Code | HTTP |
|---|---|
| `invalid_request` | 400 |
| `invalid_token` | 401 |
| `insufficient_scope` | 403 |

MCP spec status table: `401` = "Authorization required or token invalid"; `403` = "Invalid scopes or
insufficient permissions"; `400` = "Malformed authorization request".

### DCR endpoint (RFC 7591 §3.2.2) — HTTP 400, `application/json`

`invalid_redirect_uri` · `invalid_client_metadata` · `invalid_software_statement` ·
`unapproved_software_statement`

Success is **HTTP 201 Created**, `application/json`. Response: `client_id` (REQUIRED),
`client_secret` (OPTIONAL), `client_id_issued_at` (OPTIONAL), `client_secret_expires_at` (REQUIRED if
a secret was issued), plus echoed metadata.

RFC 7591 §2 client metadata field names: `redirect_uris`, `token_endpoint_auth_method`, `grant_types`,
`response_types`, `client_name`, `client_uri`, `logo_uri`, `scope`, `contacts`, `tos_uri`,
`policy_uri`, `jwks_uri`, `jwks`, `software_id`, `software_version`.

### Refresh failures — Claude is explicit

> "Return RFC 6749-compliant error codes (`invalid_grant`, not `invalid_request` or a custom code)
> when a refresh token is no longer valid."

---

## 11. CIMD implementation requirements (draft-ietf-oauth-client-id-metadata-document-00)

`client_id` URL rules (§3), all MUST:
- "MUST have an `https` scheme, MUST contain a path component, MUST NOT contain single-dot or
  double-dot path segments"
- "MUST NOT contain a fragment component and MUST NOT contain a username or password"

Document rules (§4.1):
- `client_id` inside the document MUST equal the fetch URL by "simple string comparison as defined in
  RFC3986 Section 6.2.1"
- "the `token_endpoint_auth_method` property MUST NOT include `client_secret_post`,
  `client_secret_basic`, `client_secret_jwt`, or any other method based around a shared symmetric
  secret"
- "`client_secret` and `client_secret_expires_at` properties MUST NOT be used"

MCP spec adds: the document "MUST include at least the following properties: `client_id`,
`client_name`, `redirect_uris`".

AS obligations:

| Rule | Section | Text |
|---|---|---|
| Fetch on URL-shaped `client_id` | §4.2 | "SHOULD fetch the document indicated by the `client_id`" |
| Fail closed | §4.3 | "If fetching the metadata document fails, the authorization server SHOULD abort the authorization request" |
| Cache | §4.4 | "MAY cache"; "MUST NOT cache error responses… MUST NOT cache documents which are invalid or malformed" |
| Redirect URI | §4.5 | "MUST require registration of redirect URIs, and MUST ensure that the redirect URI in a request is an exact match of a registered redirect URI" |
| SSRF | §6.5 | "SHOULD avoid fetching any URLs using private or loopback addresses" |
| Size cap | §6.6 | "recommended maximum response size for client metadata documents is 5 kilobytes" |

MCP spec restates the AS side as MUSTs: "MUST validate that the fetched document's `client_id`
matches the URL exactly"; "MUST validate redirect URIs presented in an authorization request against
those in the metadata document"; "MUST validate the document structure is valid JSON and contains
required fields".

**ASP.NET Core CIMD fetcher checklist:** dedicated `HttpClient` with no redirects followed (or
re-validate each hop), 5 KB `MaxResponseContentBufferSize`, short timeout, DNS resolution filtered
against RFC 1918 / loopback / link-local / CGNAT, `IMemoryCache` honouring `Cache-Control` with a
sane floor and ceiling, negative results **not** cached.

**No error code is defined by the CIMD draft.** Use `invalid_client` for a document that fails to
fetch/parse/self-reference, and `invalid_request` for a `redirect_uri` not in the document (and per
OAuth 2.1, do not redirect in that case).

---

## 12. Comparison table — Claude vs ChatGPT vs what we must build

| Requirement | Claude | ChatGPT | What our AS must do |
|---|---|---|---|
| **CIMD supported** | Yes (`oauth_cimd`) | Yes, **preferred** | `"client_id_metadata_document_supported": true`; accept URL-shaped `client_id` everywhere |
| **CIMD gating condition** | Selects CIMD **only if** `client_id_metadata_document_supported:true` **AND** `"none"` in `token_endpoint_auth_methods_supported` | Reads `client_id_metadata_document_supported` | Advertise **both** `none` and `private_key_jwt` |
| **CIMD `token_endpoint_auth_method`** | `none` (public client) | Declares **both**: `private_key_jwt` in the singular, `["none","private_key_jwt"]` in the plural. Measured 2026-08-17 to authenticate as a **public client** when the AS offers only `none` | Read **both** members as one offer; implementing only `none` interoperates |
| **DCR supported** | Yes (`oauth_dcr`), out of the box | Yes, fallback / per-connector-instance | Expose `registration_endpoint`, 201 + RFC 7591 errors. Anthropic warns DCR creates "very large numbers of registered clients" |
| **Pre-registered client** | Yes — client id + optional secret in Advanced settings; also `oauth_anthropic_creds` | Yes — OAuth Client ID field in connector UI | Support static clients too; makes both paths debuggable |
| **Redirect URI** | `https://claude.ai/api/mcp/auth_callback` (+ future `claude.com`); Claude Code loopback, **port-agnostic** | `https://chatgpt.com/connector/oauth/{callback_id}`; legacy `https://chatgpt.com/connector_platform_oauth_redirect` | Exact match, except loopback ignores port (OAuth 2.1 §2.3.1 / RFC 8252 §7.3) |
| **PRM path probed** | `/.well-known/oauth-protected-resource/<path>` then root | **path-inserted only** — measured 2026-08-17, root form fetched zero times | Serve **both**; the path-inserted form is the load-bearing one |
| **AS metadata path** | `oauth-authorization-server` then `openid-configuration` | either | Serve **both**, identical `issuer` |
| **`resource` param** | Yes, both requests, canonical form incl. path | Yes, both requests | Accept, validate, reject bad values with `invalid_target`, copy into `aud` |
| **PKCE** | `S256` always | `S256` always | Enforce S256, advertise `["S256"]`, no `plain` |
| **Scope source** | `401` `scope` param → PRM `scopes_supported` | PRM `scopes_supported` + auto OIDC scopes | Only advertise scopes every client may actually request |
| **`offline_access`** | Appended if in **AS** metadata `scopes_supported` | **Same** — measured 2026-08-17, requested when the AS advertises it | List in AS metadata, not PRM |
| **Refresh tokens** | Reactive on 401 + proactive 5 min early; requires rotation for public clients; `invalid_grant` on expiry | CIMD declares `refresh_token` grant; docs silent — **UNVERIFIED** | Issue refresh tokens, **rotate** them, return new one in the same response that invalidates the old |
| **`iss` in auth response** | MCP spec SHOULD | MCP spec SHOULD | Emit `iss`, advertise `authorization_response_iss_parameter_supported: true` |
| **Token endpoint content type** | `application/x-www-form-urlencoded` required; `415` breaks it | same (standard) | Ensure form parsing on `/token`, JSON on `/register` |
| **Timeouts** | 10 s discovery/register/token; 30 s refresh | **UNVERIFIED** | Keep p99 well under 10 s; no synchronous downstream calls in `/token` |
| **Egress IPs** | `160.79.104.0/21`; AS host must also be reachable | **UNVERIFIED** | Don't WAF-block the AS host |
| **Consent screen** | Must show `client_id` URL **host**, warn on loopback-only | not documented | Render CIMD host, not `client_name` |
| **Server-side tool contract** | n/a | `search` + `fetch` read-only tools for deep research / company knowledge | MCP server concern, not AS |

---

## 13. Things I could not verify — do not guess in code

1. **ChatGPT's PRM probe order.** ~~Only the root `/.well-known/oauth-protected-resource` is
   documented.~~ **RESOLVED 2026-08-17:** it fetches the *path-inserted* form and never the root
   one — the reverse of what the documentation implied. Serve both; the path-inserted form is the
   one that matters. See §1.
2. **ChatGPT refresh-token behavior** — lifetime expectations, proactive vs reactive refresh.
   **Partly resolved 2026-08-17:** it *does* request `offline_access` when the AS advertises it.
   Refresh timing and rotation expectations remain **UNVERIFIED**.
3. **ChatGPT's OAuth timeouts and egress IP ranges.** Claude publishes both; OpenAI publishes
   neither. **UNVERIFIED**
4. **Whether ChatGPT validates `iss` (RFC 9207) in the authorization response.** Not documented.
   Emitting it is harmless and MCP-spec-recommended. **UNVERIFIED**
5. **The literal `{callback_id}`/`<id>` values** are per-connector and only appear in the OpenAI app
   management UI and in the fetched CIMD document. Do not hardcode. **By design, not a gap.**
6. **Whether ChatGPT enforces the CIMD 5 KB / SSRF rules on its own document** — irrelevant to us; we
   enforce them as the AS.
7. **`token_endpoint_auth_signing_alg_values_supported`** — ChatGPT's CIMD declares `RS256`. Whether
   it would accept `ES256` if we advertised only that is **UNVERIFIED**. Support RS256.

---

## 14. Sources (all fetched 2026-08-03)

**OpenAI (primary)**
- https://developers.openai.com/apps-sdk/build/auth — richest single source: redirect URIs, discovery order, `resource`, PKCE, CIMD/DCR, AS metadata, `securitySchemes`, `mcp/www_authenticate`
- https://developers.openai.com/apps-sdk/guides/security-privacy — CIMD-preferred / DCR-fallback, `none` vs `private_key_jwt`, "Return a `401` for expired or malformed tokens"
- https://developers.openai.com/plugins/build/auth — same guidance, plus `id_token_hint` note
- https://developers.openai.com/api/docs/mcp — `search`+`fetch` deep-research tools; "CIMD with public-client token exchange (`none`) or signed client assertion token exchange (`private_key_jwt`)"
- https://developers.openai.com/api/docs/guides/tools-connectors-mcp — **Responses API only**; developer supplies the token in an `authorization` field. Different product, not the connector OAuth flow. Do not confuse them.

**Observed ChatGPT behavior**
- https://github.com/Altinity/altinity-mcp/issues/118 — verbatim ChatGPT CIMD document + the `private_key_jwt` rejection failure mode

**Anthropic (primary)**
- https://claude.com/docs/connectors/building/authentication — auth type matrix, CIMD gate, callback URLs, token refresh, latency budgets, egress range
- https://claude.com/docs/connectors/building/lazy-authentication — canonical `401`/`403` shapes, CIMD worked example, consent-screen rule, discovery caching
- https://claude.com/docs/connectors/building/troubleshooting — confirms Claude sends `resource`; Entra `AADSTS9010010`; discovery fallback order
- https://claude.ai/oauth/claude-code-client-metadata — Claude Code's live CIMD document

**Specs**
- https://modelcontextprotocol.io/specification/draft/basic/authorization
- https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery
- https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
- https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-00.html
- https://www.rfc-editor.org/rfc/rfc9728.txt (Protected Resource Metadata)
- https://www.rfc-editor.org/rfc/rfc8707.txt (Resource Indicators)
- https://www.rfc-editor.org/rfc/rfc7591.txt (DCR)
- https://www.rfc-editor.org/rfc/rfc7523.txt (JWT client assertions)
- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13 (OAuth 2.1)

**Stale — read only as history**
- https://community.openai.com/t/dynamic-client-registration-should-be-optional-for-custom-connectors/1356365 (Oct 2025, DCR-only era)
- https://community.openai.com/t/oauth-client-id-is-no-longer-optional/1367103 (Nov 2025 UI bug, resolved)
