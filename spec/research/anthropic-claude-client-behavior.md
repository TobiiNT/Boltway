# Anthropic Claude MCP connector — client wire behavior

**Purpose:** build an OAuth 2.1 + OIDC Authorization Server in C# / ASP.NET Core 10 (`net10.0`) that Claude
connects to on the first try, with no vendor-specific patching.

**Sources fetched 2026-08-03.** ~~raw copies in `./raw/`~~ — **there is no such directory, and git
history has never held one.** What is checked in is this distillation and the URLs it was made
from; where the raw bodies went is not recorded anywhere, so a claim below that rests on wording
rather than on a quoted URL cannot currently be re-checked against the fetched text. The two
vendor CIMD documents are the exception and are captured verbatim, at
`../cimd-live-2026-08-03.json` and `../cimd-live-2026-08-17.json`, which
`CimdClientResolverTests` reads.

| Source | URL |
|---|---|
| Authentication for connectors | `https://claude.com/docs/connectors/building/authentication.md` |
| Lazy authentication | `https://claude.com/docs/connectors/building/lazy-authentication.md` |
| Enterprise Managed Auth | `https://claude.com/docs/connectors/building/enterprise-managed-auth.md` |
| Troubleshooting | `https://claude.com/docs/connectors/building/troubleshooting.md` |
| Testing | `https://claude.com/docs/connectors/building/testing.md` |
| MCP / tool hints | `https://claude.com/docs/connectors/building/mcp.md` |
| MCP authorization spec 2025-11-25 | `https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization.md` |
| Claude CIMD doc | `https://claude.ai/oauth/mcp-oauth-client-metadata` |
| Claude Code CIMD doc | `https://claude.ai/oauth/claude-code-client-metadata` |
| IP ranges | `https://platform.claude.com/docs/en/api/ip-addresses` |
| RFC 8252 §7.3, RFC 6749 §4.1.2.1/§5.2, RFC 6750 §3.1, RFC 8707 §2 | rfc-editor.org (verbatim) |

Field report mined: a deployment's own `docs/integration/idp-configuration.md` and
`docs/mcp-connector-build-spec.md`, written while wiring an MCP connector to this AS.

---

## 0. The two client identities, verbatim

These are the actual bytes served today. Our AS dereferences these URLs at `/authorize` when
`client_id` is an HTTPS URL.

**`https://claude.ai/oauth/mcp-oauth-client-metadata`** — Claude.ai web, Desktop, mobile, Cowork:

```json
{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

**`https://claude.ai/oauth/claude-code-client-metadata`** — Claude Code CLI:

```json
{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

Implementation consequences, non-obvious:

| Observation | Consequence for our AS |
|---|---|
| `token_endpoint_auth_method: "none"` on both | Both Claude clients are **public clients**. Token endpoint must accept PKCE-only requests with no secret. Refresh rotation is mandatory (OAuth 2.1 §4.3.1). |
| Web doc declares `urn:ietf:params:oauth:grant-type:jwt-bearer` | Same client identity is used for Enterprise Managed Auth. Don't reject the doc for declaring a grant we haven't enabled — **validate per-request, not at import**. |
| Claude Code doc declares **portless** `http://localhost/callback` and `http://127.0.0.1/callback` | Registered value has no port; runtime value does (`http://localhost:3118/callback`). Exact-string matching fails 100% of the time. See §3. |
| Neither declares `scope` | Never require a `scope` field in a CIMD doc. |
| `client_uri` and `response_types` are commonly dropped by importers (Auth0 preview warns on exactly these) | Treat unknown/extra members as ignorable; never fail the document for them. |

---

## 1. Redirect URIs — exact values and matching rules

| Surface | Redirect URI registered | Runtime value | Match rule |
|---|---|---|---|
| Claude.ai web, Desktop, mobile, Cowork | `https://claude.ai/api/mcp/auth_callback` | identical | **Exact string** |
| Claude Code (CLI) | `http://localhost/callback` | `http://localhost:<ephemeral>/callback` | Exact **ignoring port** |
| Claude Code (CLI) | `http://127.0.0.1/callback` | `http://127.0.0.1:<ephemeral>/callback` | Exact **ignoring port** |
| IPv6 loopback (spec-required, not in Claude's doc) | `http://[::1]/callback` | `http://[::1]:<port>/callback` | Exact **ignoring port** |

Normative basis:

> **RFC 8252 §7.3 (verbatim):** "The authorization server MUST allow any port to be specified at
> the time of the request for loopback IP redirect URIs, to accommodate clients that obtain an
> available ephemeral port from the operating system at the time of the request."

> **Anthropic, authentication.md:** "Claude Code declares `http://localhost/callback` and
> `http://127.0.0.1/callback` in its Client ID Metadata Document, so your authorization server
> **must accept both with the port component ignored**. RFC 8252 section 7.3 requires this for the
> IP-literal form (`127.0.0.1`); **apply the same port-agnostic match to `localhost`** so Claude
> Code works, even though RFC 8252 section 8.3 discourages `localhost`."

> **MCP spec §Redirect URI security:** "Authorization servers **MUST** validate exact redirect URIs
> against pre-registered values" … "All redirect URIs **MUST** be either `localhost` or use HTTPS."

**The trap:** RFC 8252 only mandates port-agnostic matching for the *IP literal*. `localhost` is
explicitly discouraged by §8.3, so a strictly-conforming AS rejects it — and Claude Code breaks.
We must deliberately extend the rule to `localhost`.

**Implementation (ASP.NET Core), the matching algorithm:**

```
bool RedirectUriAllowed(Uri requested, IReadOnlyList<Uri> registered):
  # 1. scheme must be https, OR http with a loopback host
  if requested.Scheme == "http" and not IsLoopbackHost(requested.Host): reject
  # 2. no fragment ever (RFC 6749 §3.1.2)
  if requested.Fragment != "": reject
  # 3. exact ordinal compare on scheme + host + path + query
  #    port compared ONLY when host is not loopback
  foreach r in registered:
     if OrdinalEq(r.Scheme, requested.Scheme)
        and OrdinalEq(r.Host, requested.Host)      # host is case-insensitive, normalize lower
        and OrdinalEq(r.AbsolutePath, requested.AbsolutePath)
        and OrdinalEq(r.Query, requested.Query)
        and (IsLoopbackHost(requested.Host) or r.Port == requested.Port):
        return true
  return false

IsLoopbackHost(h) = h in { "127.0.0.1", "::1", "[::1]", "localhost" }
```

Do **not** use `Uri.Equals` (it compares ports) and do **not** use `Uri.AbsoluteUri` string compare.
Note `System.Uri` normalizes `http://localhost/callback` to port 80 and
`http://localhost:3118/callback` to 3118 — so a naive compare of `.AbsoluteUri` silently fails.

**Error when no match:** per RFC 6749 §4.1.2.1, an invalid `redirect_uri` **MUST NOT** be redirected
to. Render an error page directly with HTTP **400** and body error `invalid_request`. Never redirect
the error back to an unvalidated URI.

---

## 2. How Claude obtains a `client_id`, and the precedence order

Three mechanisms. Anthropic's own names for them (these strings appear on the directory submission
form, so use them in docs):

| Anthropic type string | Mechanism | Availability |
|---|---|---|
| `oauth_dcr` | RFC 7591 Dynamic Client Registration | Out of the box |
| `oauth_cimd` | Client ID Metadata Document | Out of the box |
| `oauth_anthropic_creds` | Anthropic holds your `client_id`/`client_secret` | Email `mcp-review@anthropic.com` |
| `custom_connection` | Custom URL/creds at connection time | Email `mcp-review@anthropic.com` |
| `static_headers` | Fixed API key/bearer as a request header, entered by an org admin | Beta |
| `none` | Authless | Supported |

### 2.1 The selection rule Claude actually applies

> **Anthropic, authentication.md:** "Claude selects CIMD only when your authorization server
> metadata advertises **both** `"client_id_metadata_document_supported": true` **and** `"none"` in
> `token_endpoint_auth_methods_supported` — the second is required because Claude's CIMD client
> authenticates as a public client at your token endpoint. **If either is missing, Claude falls back
> to DCR.**"

> **MCP spec §Client Registration Approaches:** "Clients supporting all options **SHOULD** follow the
> following priority order: 1. Use pre-registered client information … 2. Use Client ID Metadata
> Documents … 3. Use Dynamic Client Registration as a fallback … 4. Prompt the user."

### 2.2 The conflict — and the safe rule

The MCP spec says CIMD outranks DCR. **Measured behavior on a live Auth0 tenant contradicts this**:
with both `registration_endpoint` and `client_id_metadata_document_supported: true` advertised,
DCR was chosen, and the field report's fix was to switch DCR off entirely ("**DCR wins if it is
still advertised**, so it has to be switched off").

**Therefore our AS advertises exactly one client-acquisition mechanism at a time. Never two.**

| Configured mode | `registration_endpoint` in metadata | `client_id_metadata_document_supported` | `"none"` in `token_endpoint_auth_methods_supported` |
|---|---|---|---|
| **CIMD (our default)** | **ABSENT** | `true` | present |
| DCR (opt-in) | present | absent | present |
| Pre-provisioned only | absent | absent | present |

This must be enforced in config validation at startup — refuse to boot on an ambiguous combination,
with a message naming the offending pair. Advertising both is the single most expensive
misconfiguration in this whole document, because the failure is silent and looks like a client bug.

### 2.3 CIMD validation our AS must perform

Normative, MCP spec §CIMD "For Authorization Servers":

| Rule | Level | Our behavior | Error |
|---|---|---|---|
| Fetch metadata document when `client_id` is a URL | SHOULD | GET the URL, HTTPS only | `invalid_client` |
| Validate fetched document's `client_id` **matches the URL exactly** | **MUST** | ordinal string compare, no normalization | `invalid_client` |
| Cache metadata respecting HTTP cache headers | SHOULD | honor `Cache-Control`/`ETag`; floor 5 min, ceiling 24 h | — |
| Validate redirect URIs in the authorization request against the document | **MUST** | §1 algorithm | `invalid_request` |
| Validate document is valid JSON with required fields | **MUST** | require `client_id`, `client_name`, `redirect_uris` | `invalid_client` |
| `client_id` URL uses `https` scheme **and contains a path component** | **MUST** | reject `https://claude.ai` (no path) | `invalid_client` |

Consent-screen requirements (these are security MUSTs, not cosmetics):

> **MCP spec:** "the consent screen must display the **host of the `client_id` URL** (not the
> `client_name` field) as the relying party" … "Authorization servers **MUST** clearly display the
> redirect URI hostname during authorization" … "**SHOULD** display additional warnings for
> `localhost`-only redirect URIs."

So for Claude the consent screen shows **`claude.ai`** (derived from the URL), and for a Claude Code
connection it additionally warns that the redirect is loopback. `client_name` ("Claude") is
self-asserted and may be shown only as secondary text.

**SSRF guard on the CIMD fetch** (our own requirement — the AS is fetching an attacker-suppliable
URL): HTTPS only; resolve DNS and reject non-globally-routable addresses; no redirects followed
cross-host; response body cap (e.g. 64 KiB); hard timeout ≤2 s so the fetch fits inside Claude's
10 s `/authorize` budget; deny-by-default allowlist option for enterprise deployments.

**The `redirect_uris` same-origin rule:** the spec says redirect URIs "should be required to be
same-origin with the `client_id` URL". Claude's own document **violates this for Claude Code**
(`client_id` host is `claude.ai`, redirect host is `localhost`). So implement it as: HTTPS redirect
URIs must be same-origin with the `client_id` URL; loopback redirect URIs are exempt.

---

## 3. `/authorize` — exactly what Claude sends

Confirmed from Anthropic docs plus a measured live request (field report, 2026-07-29).

| Parameter | Sent? | Value | Notes |
|---|---|---|---|
| `response_type` | always | `code` | Only `code` is in either CIMD doc. |
| `client_id` | always | the CIMD URL, e.g. `https://claude.ai/oauth/mcp-oauth-client-metadata` | Or the DCR/pre-provisioned id. |
| `redirect_uri` | always | see §1 | |
| `code_challenge` | **always** | base64url(SHA-256(verifier)) | |
| `code_challenge_method` | **always** | `S256` | "on every authorization request, regardless of which registration mechanism it uses" |
| `state` | yes | opaque | Client-side CSRF; we echo it unmodified. |
| `scope` | yes (unless we advertise none) | see §5 | Space-delimited. May include `offline_access`. |
| `resource` | **always** | canonical MCP server URL, e.g. `https://mcp.example.com/mcp` | RFC 8707. "MCP clients **MUST** send this parameter regardless of whether authorization servers support it." |
| `prompt` | **NOT sent** | — | No Anthropic doc mentions it; the measured live request did not carry it. **Our AS must never require `prompt=consent`.** (The `prompt=consent` seen in the field report was the engineer's own curl probe, not Claude.) |
| `nonce` | not observed | — | This is an OAuth flow, not an OIDC id_token flow. Do not require `nonce`. |
| `audience` | **NOT sent** | — | Auth0-proprietary. Claude sends `resource`, never `audience`. See §9 trap #1. |

Measured live request shape (field report, verbatim characterization): "`client_id` the CIMD URL,
`code_challenge_method=S256`, `resource` carrying the RFC 8707 resource identifier, `scope` the two
the resource server publishes plus `offline_access`."

**Our AS `/authorize` obligations:**

| Check | Failure mode | Status + error |
|---|---|---|
| `client_id` resolvable (CIMD fetch / lookup) | unknown client | **400** `invalid_client`, rendered page, no redirect |
| `redirect_uri` matches (§1) | mismatch | **400** `invalid_request`, rendered page, **no redirect** |
| `code_challenge` present | missing | redirect with `error=invalid_request` |
| `code_challenge_method` == `S256` | `plain` or absent | redirect with `error=invalid_request` |
| `response_type` == `code` | other | redirect with `error=unsupported_response_type` |
| `scope` all known | unknown scope | redirect with `error=invalid_scope` |
| `resource` parseable + known | bad/unknown | redirect with `error=invalid_target` (RFC 8707 §2) |
| user denies consent | — | redirect with `error=access_denied` |

Registry of valid `error` values at the authorization endpoint (**RFC 6749 §4.1.2.1**, verbatim list):
`invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`,
`invalid_scope`, `server_error`, `temporarily_unavailable`. Plus `invalid_target` from RFC 8707 §2.

**PKCE is mandatory and must be advertised**, or Claude refuses to even start:

> **MCP spec:** "If `code_challenge_methods_supported` is absent, the authorization server does not
> support PKCE and MCP clients **MUST** refuse to proceed." … "Authorization servers providing
> OpenID Connect Discovery 1.0 **MUST** include `code_challenge_methods_supported` in their metadata
> to ensure MCP compatibility."

Our AS: `"code_challenge_methods_supported": ["S256"]`. **Do not list `plain`** — OAuth 2.1 removes
it, and listing it invites downgrade.

---

## 4. `/token` — content type, grants, refresh, errors

### 4.1 Content type — the classic 415

> **Anthropic:** "Your `/token` endpoint must accept `Content-Type: application/x-www-form-urlencoded`
> per RFC 6749 section 4.1.3. Claude sends **both the initial token exchange and refresh requests**
> with this content type. Some web frameworks default to JSON-only body parsing — if your endpoint
> returns `415 Unsupported Media Type`, register a form-urlencoded body parser. Dynamic client
> registration (`/register`) uses `application/json` per RFC 7591 section 3.1, so **don't assume the
> same parser works for both**."

ASP.NET Core specific: a `[ApiController]` action with a `[FromBody]` model binds JSON via the
input formatter and will answer **415** to form posts. Bind with `[FromForm]`, or read
`Request.Form` directly. Two different parsers for two different endpoints:

| Endpoint | Content-Type accepted | Binding |
|---|---|---|
| `POST /token` | `application/x-www-form-urlencoded` | `[FromForm]` / `Request.Form` |
| `POST /register` (only if DCR enabled) | `application/json` | `[FromBody]` |

Add a conformance test that POSTs form-encoded garbage and asserts **400 with an OAuth JSON body**,
never 415. The field report uses exactly this probe:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$ISSUER/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=invalid&client_id=test'
# expect 400 + OAuth error body. 415 == the flow will fail at exchange.
```

### 4.2 Grants Claude uses

| `grant_type` | When | Required params |
|---|---|---|
| `authorization_code` | initial exchange | `code`, `redirect_uri`, `client_id`, `code_verifier`, `resource` |
| `refresh_token` | reactive + proactive refresh | `refresh_token`, `client_id`, (`scope`, `resource`) |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | Enterprise Managed Auth only | `assertion`, `client_id`, `scope`, `resource` |

`client_secret` is **absent** — public client. Requiring it yields `invalid_client` and a dead flow.

### 4.3 Refresh behavior and timing

> **Anthropic:** "Claude refreshes tokens **reactively on a 401 response**, with a **proactive
> refresh up to five minutes before the stored expiry**."

| Requirement | Level | Our AS |
|---|---|---|
| Return `invalid_grant` when a refresh token is no longer valid | required by Anthropic | exact string `invalid_grant`, **not** `invalid_request`, not a custom code |
| Rotate refresh tokens for public clients | **MUST** (OAuth 2.1 §4.3.1, adopted by MCP spec) | issue new RT, invalidate old in the **same response** |
| Access token lifetime | SHOULD be short | default 1 h. Must be **> 5 min** or proactive refresh thrashes. |

**Rotation + reuse detection, the concurrency trap:** Claude may fire a proactive refresh and a
reactive refresh close together. Strict "old RT used twice ⇒ revoke the whole family" (RFC 6819 /
OAuth 2.1 replay detection) will nuke a live connection on a benign race. Implement a **grace
window**: accept the immediately-preceding refresh token for ~30 s and return the *same* new pair
(idempotent replay), and only treat reuse *outside* the window, or reuse of an older generation, as
a breach that revokes the family. Without this, users see random disconnects that are almost
impossible to diagnose.

Token endpoint `error` registry (**RFC 6749 §5.2**, verbatim list): `invalid_request`,
`invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`.
Plus `invalid_target` (RFC 8707 §2). Note **`invalid_client` pairs with HTTP 401**; all other token
errors are HTTP 400.

---

## 5. Scopes — selection strategy and step-up

Claude never invents scopes. It reads them, in this priority order:

> **MCP spec §Scope Selection Strategy:** "1. **Use `scope` parameter** from the initial
> `WWW-Authenticate` header in the 401 response, if provided. 2. **If `scope` is not available**,
> use all scopes defined in `scopes_supported` from the Protected Resource Metadata document,
> omitting the `scope` parameter if `scopes_supported` is undefined."

> **Anthropic:** "Claude also appends `offline_access` when your authorization server metadata lists
> it in `scopes_supported`, to obtain a refresh token."

**Consequence: if our AS metadata does not list `offline_access` in `scopes_supported`, Claude does
not request it, and on IdPs that gate refresh tokens on it, no refresh token is ever issued.**
Our AS: list `offline_access` in `scopes_supported`, and issue a refresh token when it's granted.

Step-up (scope upgrade), resource-server side but it constrains our AS's consent UX:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="files:read files:write user:profile", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", error_description="Additional file write permission required"
```

| Behavior | Value |
|---|---|
| Scopes requested on re-auth | union of the `403` challenge scopes and the discovery-time scope |
| Earlier step-up scopes carried forward? | **Not reliably** — always re-list scopes the user still needs in the `403` |
| `403` challenge cache | **per user, per server, ~15 minutes**, most-recent-wins, cleared on use |
| `403` without `error="insufficient_scope"` | terminal error, **no** re-auth prompt |

Our AS must therefore **grant exactly the requested scope set** and support re-consent that *widens*
a grant without revoking the existing one.

---

## 6. Discovery — what Claude fetches, in what order, and caching

### 6.1 Protected resource metadata (resource-server side, RFC 9728)

| Field | Requirement |
|---|---|
| `resource` | "must match your MCP server URL **exactly as the user enters it** in Claude, including any path component" |
| `authorization_servers` | "Claude uses the **first entry** and **does not fall back** to later entries — list your primary issuer first" |
| `bearer_methods_supported` | `["header"]` |

### 6.2 Fallback probing when `WWW-Authenticate` has no `resource_metadata`

Claude probes the **MCP server's origin**, in order:

1. `/.well-known/oauth-protected-resource/<mcp-path>`
2. `/.well-known/oauth-protected-resource`

"Treat this as a fallback — it only works when your platform serves `/.well-known/*` paths, and it
adds round-trips to every connection."

### 6.3 Authorization server metadata — our AS must answer at least one

> **Anthropic:** "your server only needs to answer **one** of the two discovery endpoints — Claude
> tries `/.well-known/oauth-authorization-server` (RFC 8414) first, then falls back to
> `/.well-known/openid-configuration`. A `404` on one is expected if the other returns `200`."

For an issuer **with a path component** (`https://auth.example.com/tenant1`) the MCP spec requires
clients to try, in order:

1. `https://auth.example.com/.well-known/oauth-authorization-server/tenant1` (path **insertion**)
2. `https://auth.example.com/.well-known/openid-configuration/tenant1` (path **insertion**)
3. `https://auth.example.com/tenant1/.well-known/openid-configuration` (path **appending**)

**Our AS must serve all of these for multi-tenant issuers.** This is a routing requirement, not a
document requirement — the same JSON, reachable at three shapes. In ASP.NET Core, register catch-all
routes `/.well-known/oauth-authorization-server/{**tenant}` and
`/.well-known/openid-configuration/{**tenant}` *in addition to* `/{tenant}/.well-known/openid-configuration`.
Most implementations ship only #3 and are unreachable by a spec-conformant client.

### 6.4 Discovery caching

> **Anthropic:** discovery documents are cached "**globally, keyed by URL**, with a staleness window
> of about **five minutes** by default. All Claude users connecting to the same server URL share a
> single cache entry." Refresh is "lazy and best-effort"; on failure Claude "serves the stale entry."

Consequence: a metadata change takes ~5 min to propagate globally, and a broken discovery endpoint
does **not** immediately break live connections. Do not chase phantom failures within 5 min of a
metadata deploy. Serve `Cache-Control: max-age=300` on metadata.

---

## 7. The 401 handshake (resource server, but our AS ships the middleware)

Canonical shape:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp", scope="orders:read"

{"error":"invalid_token","error_description":"Authentication required for this tool"}
```

| Rule | Detail |
|---|---|
| Status **must** be `401` | "Claude does not honor a `WWW-Authenticate` header on a `200` response" |
| Body is advisory | "the `401` status and `WWW-Authenticate` header carry the protocol signal" |
| `200` + `isError:true` | **No auth prompt.** Claude passes the text to the model as a tool result and moves on. This is *the* symptom when users see "please sign in" as chat text instead of a Connect button. |
| `403` | Triggers re-auth **only** with `WWW-Authenticate: Bearer error="insufficient_scope"`. Any other `403` is a terminal error. |
| `resource_metadata` URL origin | Need **not** be same-origin as the MCP server; any HTTPS location. |
| Gate placement | Must happen **before** the JSON-RPC message reaches the MCP SDK — once a tool handler runs, its return is already destined for a `200`. |

RFC 6750 §3.1 `error` registry (verbatim): `invalid_request`, `invalid_token`, `insufficient_scope`.

---

## 8. Latency budgets — hard timeouts

| Operation | Budget | Source |
|---|---|---|
| OAuth **discovery** | **10 s** | authentication.md §Endpoint latency |
| **Registration** (DCR) | **10 s** | " |
| **Token** (initial exchange) | **10 s** | " |
| **Refresh** token request | **30 s** | " |

> "If no response arrives within that window the flow is treated as a failure, **even if your server
> eventually completes the request**. Aim well under these limits."

Design consequences for our AS:

- The CIMD fetch happens *inside* the `/authorize` request. Budget it ≤2 s with a hard
  `HttpClient.Timeout`, and serve stale-on-error from cache rather than blocking.
- Never do a synchronous cold-start DB migration, JWKS re-fetch, or key-derivation on the token path.
- Argon2/bcrypt password verification on the login page is fine; on `/token` it is not.
- "check that any reverse proxy, API gateway, or WAF in front of the endpoint isn't holding the
  response" — disable response buffering on these endpoints (`IHttpResponseBodyFeature.DisableBuffering()`).
- Emit a structured warning log whenever any of these endpoints exceeds 25% of its budget.

---

## 9. Network and hosting constraints

| Constraint | Value |
|---|---|
| Anthropic **outbound** egress (to our AS and MCP server) | **`160.79.104.0/21`** (IPv4) |
| Anthropic inbound (API/Console, not relevant here) | `160.79.104.0/23`, IPv6 `2607:6bc0::/48` |
| Connectors are **IPv4-only** | "a hostname that only publishes `AAAA` records can't be reached" — our AS **must** have an `A` record |
| DNS must resolve to globally routable addresses | Any private (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), loopback, or link-local address in the answer set ⇒ rejected before any HTTP request leaves Anthropic |
| Mixed public/non-public answers | **Every** returned address must be globally routable |
| Redirects | A `3xx` to a **different host** drops the `Authorization` header ⇒ `401` ⇒ "Authorization with the MCP server failed". Register the URL the server actually listens on. |
| HTTPS | All AS endpoints **MUST** be served over HTTPS (MCP spec); all redirect URIs **MUST** be `localhost` or HTTPS |
| Origin header | Overly strict `Origin` validation is a listed cause of `initialize` timeouts — allow Anthropic's requests |

Note the asymmetry: discovery requests to the **authorization server** come from the same egress
range as requests to the MCP server, so a WAF in front of the IdP breaks the flow even when the MCP
server is perfectly reachable. This is the #1 field failure mode.

---

## 10. Enterprise Managed Auth (RFC 7523 jwt-bearer)

Beta, Team/Enterprise plans. Worth building because Claude's own CIMD document already declares the
grant, and it is the only way to connect users with no consent screen.

Exact request Claude sends:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=eyJhbGciOi...
&client_id=your-registered-client-id
&scope=openid profile
&resource=https://mcp.example.com
```

| Requirement | Level | Detail |
|---|---|---|
| Advertise `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported` | **MUST** | "The grant type must be listed here for the feature to be offered to the customer, **even if your token endpoint would already accept it silently**." |
| Per-tenant **allowlist** of trusted issuer URLs | **MUST** | "An assertion whose `iss` is not on the tenant's allowlist **must be rejected with `invalid_grant`**, even if the signature is valid." |
| Validate signature, `iss`, `aud`, `exp`, `sub`, `client_id` | **MUST** | RFC 7523 §3 processing rules |
| Accept the request **with or without** `resource` | required | "Some identity provider configurations cannot pass a resource indicator through" — use it for audience binding when present |
| DCR + EMA | **unsupported** | "The identity provider stamps a fixed `client_id` into every assertion … A client created on the fly through DCR cannot satisfy this requirement." ⇒ **another reason our default is CIMD, not DCR.** |
| Authless servers | N/A | "A fully authless server never returns `401`, so there is no point at which Claude can exchange an assertion." |

---

## 11. The `resource` parameter and audience binding

> **MCP spec §Resource Parameter Implementation:** the `resource` parameter "1. **MUST** be included
> in both authorization requests and token requests. 2. **MUST** identify the MCP server that the
> client intends to use the token with. 3. **MUST** use the canonical URI of the MCP server as
> defined in RFC 8707 Section 2." … "MCP clients **MUST** send this parameter regardless of whether
> authorization servers support it."

Canonical form Claude sends: "lowercase scheme and host, no trailing slash, no fragment, no default
port — including any path component."

| Valid canonical URIs | Invalid |
|---|---|
| `https://mcp.example.com/mcp` | `mcp.example.com` (missing scheme) |
| `https://mcp.example.com` | `https://mcp.example.com#fragment` (fragment) |
| `https://mcp.example.com:8443` | |
| `https://mcp.example.com/server/mcp` | |

Our AS:

- Accept `resource` on `/authorize` **and** `/token`; bind the issued token's `aud` to it.
- **SHOULD accept uppercase scheme/host** for robustness (spec says so explicitly), normalizing to
  lowercase before comparison. Strip a single trailing slash before comparison.
- Reject unknown/unparseable values with **`invalid_target`** (RFC 8707 §2), never `invalid_request`.
- Emit `aud` as the canonical resource string. The resource server compares canonically, not
  byte-for-byte against what the user typed — but our AS should still emit the canonical form so a
  strict RS (like the field report's, which "rejects a token without an `aud` element matching
  exactly") works unmodified.
- If Claude omits `resource` (EMA case), fall back to a configured default audience rather than
  failing — but log it.

---

## 12. Our AS metadata document — the exact bytes to emit

Default (CIMD) profile. Every field here is load-bearing for Claude:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "revocation_endpoint": "https://auth.example.com/revoke",
  "introspection_endpoint": "https://auth.example.com/introspect",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "scopes_supported": ["openid", "profile", "email", "offline_access", "story:read", "story:write"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "client_id_metadata_document_supported": true,
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "resource_indicators_supported": true,
  "authorization_response_iss_parameter_supported": true
}
```

Checklist of the fields that break Claude if wrong:

| Field | Must be | Breaks how |
|---|---|---|
| `code_challenge_methods_supported` | contains `"S256"`, omits `"plain"` | Client **refuses to proceed** if absent |
| `token_endpoint_auth_methods_supported` | contains `"none"` | CIMD not selected; falls back to DCR |
| `client_id_metadata_document_supported` | `true` | CIMD not selected |
| `registration_endpoint` | **absent** in CIMD mode | DCR may win and fail |
| `scopes_supported` | contains `offline_access` | No refresh token requested |
| `grant_types_supported` | contains the jwt-bearer URN | EMA not offered to customers |
| `issuer` | exactly matches the `iss` our tokens carry | "Authorization with the MCP server failed" |

**`issuer` mismatch** is called out explicitly in troubleshooting: "The `issuer` value in your
authorization server metadata **must match the issuer that signs your tokens**." Assert this at
startup, not in a comment.

Also serve `/.well-known/openid-configuration` with the identical document — hosted IdPs mostly
serve only that path and clients probe both.

---

## 13. Auth0 trap → what our AS must do instead

This table is the deliverable. Every row is a place where a market-leading IdP cost real hours;
each becomes a **default** in our implementation, plus a test that proves it.

| # | Auth0 trap (measured) | Root cause | What our AS must do **by default** | Proof / test |
|---|---|---|---|---|
| 1 | `resource` parameter **silently ignored**; tenant default `resource_parameter_profile: "audience"` requires the proprietary `audience` param instead | Vendor predates RFC 8707 and kept its own parameter | **Honor RFC 8707 `resource` natively on `/authorize` and `/token`.** Bind `aud` from it. Never require a proprietary `audience` param; accept `audience` only as a silent alias. | Authorize with only `resource=` set ⇒ token `aud` equals it. |
| 2 | Setting a "Default Audience" papers over #1 — requests resolve to the right API *by accident* | Implicit fallback hides a misconfiguration | **No implicit default audience when `resource` is present.** A configured default applies only when `resource` is absent (EMA), and logs a warning. | Two resources configured; omit `resource` ⇒ warning logged, not a silent wrong `aud`. |
| 3 | DCR-registered client registers fine but **cannot reach any API** without a manually created client-grant with `subject_type: "user"`; `allow_all` on the resource server does **not** waive it | Vendor's third-party-client model requires an admin action per client that no hook can automate | **A validly registered/CIMD-resolved client needs no out-of-band grant to run a user-consent flow.** User consent *is* the authorization. Client-level API grants may exist as an optional policy, **off by default**. | Fresh CIMD client, zero admin steps ⇒ `/authorize` returns 302. |
| 4 | `registration_endpoint` **stays advertised** after DCR is disabled; no setting removes it | Metadata is static, decoupled from the feature flag | **Metadata is generated from live configuration.** DCR off ⇒ key absent. Startup **refuses to boot** if DCR and CIMD are both advertised. | Toggle DCR off ⇒ key gone from both well-known docs. |
| 5 | Advertising DCR + CIMD together ⇒ **"DCR wins"**, and the DCR path then fails | Client precedence differs from the spec's stated order | **Advertise exactly one acquisition mechanism.** Config validation rejects ambiguity with a named error. | Config with both ⇒ startup fails with a specific message. |
| 6 | `client_id_metadata_document_supported` defaults to **false** and is invisible in the dashboard; clients silently fall back to DCR | Capability exists but is not advertised | **CIMD on by default and advertised.** | Fresh install ⇒ `true` in metadata. |
| 7 | CIMD **advertised before it works**: `/authorize` answers `{"error":"invalid_request","message":"Unknown client: https://claude.ai/oauth/mcp-oauth-client-metadata"}` until a one-time out-of-band import | Advertisement decoupled from capability; wrong error code blames the client | **Resolve any well-formed CIMD `client_id` on first sight, no import step.** If resolution genuinely fails, answer **`invalid_client`** (not `invalid_request`) with an `error_description` naming which check failed (fetch/self-reference/redirect mismatch). | Never-seen CIMD URL ⇒ 302, zero admin steps. Malformed doc ⇒ `invalid_client` + specific description. |
| 8 | Every connection **and every retry** mints a permanent `tpc_` application; free tier caps at **10**; then `403 too_many_entities` | DCR creates durable state per connection | **CIMD creates no per-connection persistent client.** Any DCR support: quota-limited, TTL-expiring, GC'd unused registrations. | 100 sequential connects ⇒ client-table row count unchanged. |
| 9 | That quota failure produces **no log entry** (administrative op) and no consent screen — user sees only "Couldn't connect" | Unobservable failure path | **Every rejection is logged with a correlation id, on every path including admin/quota.** Return the id in `error_description` (or an `X-Request-Id` header) so a user report is traceable. | Force each rejection class ⇒ each emits exactly one structured log with a correlation id. |
| 10 | Connection must be **"promoted to domain level"** or third-party clients get `no connections enabled for the client`; browser shows only "Oops!, something went wrong" | Two-tier connection model, undocumented next to DCR | **No two-tier connection model.** Every configured identity source is usable by every valid client unless explicitly restricted. Restrictions surface as a specific, user-visible error. | Fresh install, CIMD client ⇒ all connections offered. |
| 11 | CIMD import **does not** promote connections ⇒ social login silently missing from the login page (no error, just an absent button) | Silent partial capability | **A configured-but-unavailable login method renders a disabled control with a reason**, never silently vanishes. | Disable a connection for a client ⇒ login page states why. |
| 12 | Real errors visible only in Monitoring → Logs; browser shows a generic apology | Error detail withheld from the response | **`/authorize` failures render the OAuth error code + description in the response body** (safe subset), not a generic page. `curl` must be a sufficient debugging tool. | `curl -D-` on each failure ⇒ code + description in body. |
| 13 | Scope strings compared **literally**, incl. a trailing space (`"story:read "` ≠ `story:read`), rendered identically in the dashboard | No input normalization | **Normalize and validate scope strings on write**: trim, reject internal whitespace and non-printable chars, reject duplicates. | Configure `"story:read "` ⇒ rejected at write time with the offending codepoint named. |
| 14 | Consent screen **mangles** `resource:action` scope names — assumes `action:resource`, renders "read: story your read" | Generated consent text from a naming convention | **Consent renders each scope's configured human description verbatim.** Never derive text by parsing the scope name. Missing description ⇒ show the raw scope + a config warning. | Scope with a description ⇒ exact string on consent. |
| 15 | Fixing #14 needs a hidden tenant flag `use_scope_descriptions_for_consent` | Sane behavior is opt-in | **This is the only behavior; no flag.** | — |
| 16 | Patching the whole `flags` object **silently drops** the key instead of setting it | Partial-update semantics that discard unknown/whole-object writes | **Config writes are all-or-nothing and read-back-verified**; unknown keys are rejected loudly, never ignored. | PATCH with an unknown key ⇒ 400 naming the key. |
| 17 | Undocumented settings discoverable only by sending an invalid value and reading the validation error | Documentation gap | **Every config key is enumerable via an introspection endpoint** with type, allowed values, default, current value. Validation errors name allowed values. | `GET /admin/config/schema` lists every key. |
| 18 | `sub` shaped `auth0\|<24 hex>` needs sanitization before use as a tenant/path key | Provider-specific subject syntax | **`sub` is opaque and never used raw as a path/filename/SQL identifier.** Expose a stable tenant id distinct from `sub`. Document the `sub` charset we emit. | `sub` containing `/`, `..`, `\|` ⇒ tenant id unaffected, no traversal. |
| 19 | Exact-port redirect matching would break Claude Code | RFC 8252 §7.3 unimplemented for `localhost` | **Port-agnostic loopback matching for `127.0.0.1`, `::1`, and `localhost`** (§1). | Register portless; request `:51004` ⇒ accepted. Non-loopback host with wrong port ⇒ rejected. |
| 20 | Pre-provisioned credentials **cannot be tested before submission** — the client has no way to obtain the `client_id` until it's configured on the far side | Chicken-and-egg in the fallback path | **CIMD is the default**, so there is no untestable pre-flight path. Pre-provisioned clients remain supported for customers who need them. | End-to-end test runs with zero out-of-band credential exchange. |
| 21 | Only one of `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` is served (Auth0/Okta/Entra/Keycloak mostly serve only the latter) | Partial discovery surface | **Serve both**, identical bodies, plus the three path-insertion/appending shapes for path-bearing issuers (§6.3). | All five URLs return 200 with equal JSON. |
| 22 | Entra: token request fails `AADSTS9010010` / `invalid_target` because the MCP URL isn't an Application ID URI; default `api://{client-id}` is insufficient | Audience identifiers restricted to a proprietary namespace | **Any HTTPS URL (with path) can be registered as a resource identifier**, no namespace constraint, no separate "expose an API" ceremony. | Register `https://mcp.example.com/mcp` ⇒ tokens issue with that `aud`. |

### Cross-cutting principles these 22 rows imply

1. **Metadata is derived from live config, never hand-maintained.** (#4, #5, #6, #21)
2. **Advertised capability == actual capability.** Startup fails otherwise. (#4, #5, #6, #7)
3. **Every failure is legible from `curl` alone**, with a correlation id. (#9, #12, #17)
4. **No hidden flags for correct behavior**; the sane path is the only path. (#14, #15)
5. **No admin action per connection.** Consent is the authorization. (#3, #7, #8, #20)
6. **Normalize on write, compare exactly on read.** (#13, #11 of §11 canonical URIs)

---

## 14. Pre-submission conformance checklist (executable)

```bash
ISSUER=https://auth.example.com
MCP=https://mcp.example.com/mcp

# 1. Both discovery docs, identical bodies
diff <(curl -s "$ISSUER/.well-known/oauth-authorization-server" | jq -S .) \
     <(curl -s "$ISSUER/.well-known/openid-configuration"       | jq -S .)

# 2. The seven fields Claude depends on
curl -s "$ISSUER/.well-known/oauth-authorization-server" | jq '{
  issuer, code_challenge_methods_supported, token_endpoint_auth_methods_supported,
  client_id_metadata_document_supported, registration_endpoint,
  grant_types_supported, scopes_supported }'
# expect: S256 present, "none" present, CIMD true, registration_endpoint ABSENT,
#         jwt-bearer URN present, offline_access present

# 3. /token parses form encoding -> 400 with OAuth body, never 415
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$ISSUER/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=invalid&client_id=test'

# 4. CIMD client works with zero admin steps -> expect 302
CID=https://claude.ai/oauth/mcp-oauth-client-metadata
curl -s -o /dev/null -w '%{http_code}\n' -G "$ISSUER/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=https://claude.ai/api/mcp/auth_callback" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "state=probe" \
  --data-urlencode "scope=story:read offline_access" --data-urlencode "resource=$MCP"

# 5. Claude Code loopback, portless registration vs ported request -> expect 302
CCID=https://claude.ai/oauth/claude-code-client-metadata
curl -s -o /dev/null -w '%{http_code}\n' -G "$ISSUER/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CCID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:51004/callback" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "resource=$MCP"

# 6. Latency: every endpoint well under budget
for p in .well-known/oauth-authorization-server .well-known/openid-configuration .well-known/jwks.json; do
  curl -s -o /dev/null -w "$p %{time_total}s\n" "$ISSUER/$p"; done
```

Plus, from outside your own network (WAF/DNS realism):
`dig +short auth.example.com` must return only globally routable **IPv4** addresses, and
`curl -sI $MCP` must not be a `3xx` to another host.

---

## 15. Open items / lower confidence

| Item | Confidence | Note |
|---|---|---|
| `prompt` parameter | **High that it is not sent** | Absent from all Anthropic docs and from the measured live request. Treat as optional; never require it. |
| Precedence when DCR + CIMD both advertised | **Medium** | Spec says CIMD wins; one measured Auth0 case says DCR won. Resolved by never advertising both. Worth re-measuring once against our own AS. |
| `nonce` / `id_token` | Not observed | Claude drives an OAuth (not OIDC-login) flow against the MCP AS. Support OIDC, don't require it. |
| Exact proactive-refresh jitter | Only "up to five minutes before expiry" is documented | Keep access-token lifetime comfortably above 5 min. |
| `static_headers` wire format | Beta, not documented on the fetched pages | Fetch `/docs/connectors/custom/remote-mcp` if we need to support it. |
