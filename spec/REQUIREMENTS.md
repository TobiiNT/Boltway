# Consolidated Requirements — OAuth 2.1 + OIDC Authorization Server (C# / ASP.NET Core on .NET 10)

**Product goal:** a reusable, industrial-grade authorization server (an Auth0 replacement) that
Claude.ai / Claude Code and ChatGPT MCP connectors can both drive with **zero vendor-specific
patching and zero out-of-band admin steps per connection**.

**Consolidated from** twelve primary-source research passes, checked in at
[`spec/research/`](./research/): `oauth21-core.md`, `pkce-and-native-apps.md`,
`discovery-metadata.md`, `protected-resource-metadata-and-mcp.md`,
`dynamic-client-registration.md`, `client-id-metadata-document.md`,
`token-formats-and-lifecycle.md`, `resource-indicators-and-audience.md`, `oidc-core.md`,
`security-bcp-and-hardening.md`, `anthropic-claude-client-behavior.md`,
`openai-chatgpt-client-behavior.md`. (This line pointed at
`/tmp/…/scratchpad/research/` — an authoring machine's working directory — for as long as the files
have been in the repository. A provenance pointer nobody can dereference is provenance nobody can
check.)

Those twelve were written against **ASP.NET Core 9** and their target lines now say .NET 10, because
that is what `Directory.Build.props` sets and a stale target line is a false statement about this
project. **What was not re-done is the research**: no framework-specific note in them has been
re-measured against .NET 10, so read a "the default is X" or "the built-in Y" claim there as dated
to when it was written. The `.NET 9` mentions that remain are deliberate and are a different kind of
statement — they say when an API *appeared* (`System.Buffers.Text.Base64Url`), which is why the
struck multi-target row in `docs/DESIGN.md` §1.2 rests on one.

**Requirement ID scheme.** `S-nn` conformance/spec, `E-nn` endpoint, `X-nn` error code,
`N-nn` non-negotiable, `C-nn` client compatibility, `A-nn` Auth0-trap, `D-nn` deferred,
`U-nn` unverified/open. `U` rows are questions rather than requirements; everything else is binding
unless its own row says otherwise.

~~Total: **207 numbered requirements** (43 S, 24 E, 41 X, 16 N, 32 C, 22 A, 12 D, 17 U … 190 are
binding).~~ **The per-prefix counts are deleted rather than corrected.** They were wrong on five of
the eight prefixes — S, E, X, N and D had each grown since the tally was written — and no test, no
script and no CI job reads this document, so nothing would have caught the sixth. A hand-maintained
count that has drifted once will drift again, and a wrong number here is worse than no number:
`docs/DESIGN.md` §6 quoted a *third* figure back at this file as though it were a build artifact.
Count them from the tables if a count is needed; the tables are the fact. A number may go back here
when something asserts it — that would be the requirement-coverage test `DESIGN.md` §6 lists under
"never cut" and which has never been built.

**Reference deployment used in all examples**
(a path-less issuer — see S-08 for why this is a *requirement*, not a convenience):

| Symbol | Value |
|---|---|
| Issuer | `https://auth.example.com` |
| MCP resource identifier | `https://mcp.example.com/mcp` |

---

# 1. Conformance matrix

Levels are **for v1 of this product**, not the RFC's own level. "MUST" here means *we ship it and a
test proves it*. Where a spec's own level and ours diverge, the divergence is called out.

| ID | Spec | Title | What we implement | v1 level | Lands in |
|---|---|---|---|---|---|
| S-01 | **draft-ietf-oauth-v2-1-15** (2 Mar 2026; WG state "I-D Exists", no RFC number — **cite the draft revision**) | OAuth 2.1 | Authorization-code grant only; PKCE mandatory for **all** clients; exact redirect-URI matching; refresh rotation; `Cache-Control: no-store`; 303-not-307; six token-endpoint error codes | **MUST** | `/authorize`, `/token`, core domain |
| S-02 | RFC 6749 | OAuth 2.0 | Only the back-compat surface OAuth 2.1 §10.2 mandates: **accept** (never require) `redirect_uri` at `/token` and enforce it per 6749 when present; §4.1.2.1 no-redirect rule; error registries | **MUST** | `/token`, `/authorize` |
| S-03 | RFC 6750 | Bearer Token Usage | `Authorization: Bearer` (case-insensitive scheme match) only; `WWW-Authenticate` challenge construction incl. charset limits; 400/401/403 mapping | **MUST** | RS middleware, `/userinfo` |
| S-04 | RFC 7636 | PKCE | `S256` only; Appendix B test vector in CI; `FixedTimeEquals`; verifier grammar `43*128unreserved`; store challenge+method+`PkceWasRequested` on the code | **MUST** | `/authorize`, `/token` |
| S-05 | RFC 8252 | OAuth for Native Apps | §7.3 loopback port exception extended to `localhost` (see N-04); §7.1 private-use schemes with the `.`-in-scheme rule; §8.4 explicit `ClientType` column; §8.6 no silent re-consent for public clients | **MUST** | redirect matcher, consent page, client store |
| S-06 | RFC 9700 | OAuth 2.0 Security BCP | §2.1 exact matching, §2.1.1 PKCE, §2.2.2 rotation, §2.3 audience restriction, §2.4 no ROPC, §4.8.2 downgrade defence, §4.12 303, §4.13 proxy sanitisation, §4.16 clickjacking | **MUST** | cross-cutting |
| S-07 | RFC 6819 | Threat Model | The concrete controls 9700 defers to it for: clickjacking headers, `state` guidance, hashed credential storage, entropy | **SHOULD** | cross-cutting |
| S-08 | RFC 8414 | AS Metadata | Full §2 field set; §3 **path-insertion** well-known rule; §3.3 issuer identity; §4 code-point comparison. **Path-less issuer is a product requirement** — a path-bearing issuer needs 4 live URLs (see E-01..E-05) | **MUST** | `/.well-known/oauth-authorization-server*` |
| S-09 | OIDC Discovery 1.0 | OP Metadata | Same document body served from `/.well-known/openid-configuration`; the 3 OIDC-REQUIRED fields 8414 does not define (`jwks_uri`, `subject_types_supported`, `id_token_signing_alg_values_supported`) | **MUST** | `/.well-known/openid-configuration*` |
| S-10 | OIDC Core 1.0 (errata set 2) | OpenID Connect | Code flow OP: `openid`-gated ID token, `nonce` pass-through, `auth_time`/`max_age`, `prompt`, standard claims, UserInfo. **Conditional on the `openid` scope** — MCP clients omit it | **MUST** | `/authorize`, `/token`, `/userinfo` |
| S-11 | OIDC RP-Initiated Logout 1.0 | Logout | `end_session_endpoint`, `id_token_hint` (validate sig/iss/aud, **skip `exp`**), exact-match `post_logout_redirect_uris`, confirmation interstitial when hint absent | **SHOULD** | `/logout` |
| S-12 | OIDC Session Management 1.0 | check_session iframe | **Not implemented.** Broken by browser storage partitioning; omit `check_session_iframe` from metadata | **NOT** | — |
| S-13 | RFC 7591 | Dynamic Client Registration | Full: `application/json` in, `201` out, MUST-ignore-unknown, subset-registration, 4 error codes, Unix-second integers | **MUST** (but **not advertised by default** — see N-06 / A-05) | `/register` |
| S-14 | OIDC Dynamic Client Registration 1.0 | DCR additions | `application_type`, `subject_type`, `id_token_signed_response_alg`, `default_max_age`, `require_auth_time`, `initiate_login_uri`, `post_logout_redirect_uris`. **`application_type: "web"` must not forbid loopback redirects** | SHOULD | `/register` |
| S-15 | RFC 7592 | DCR Management | GET/PUT/DELETE at `registration_client_uri`; **PUT is full replacement**; `401` (never `404`) for unknown client; hashed, constant-time registration access tokens | SHOULD (per-tenant switch, default on) | `/register/{client_id}` |
| S-16 | **draft-ietf-oauth-client-id-metadata-document-02** (6 Jul 2026 — MCP still links **-00**, section numbers differ) | CIMD | URL-shaped `client_id`; §3 URL rules; §4 document rules; §4.1 no symmetric secrets; §4.2 redirect registration; §5 fetch rules (200-only, no redirects); §5.2 caching; §6 metadata flag; §8.6 SSRF | **MUST — the default client-acquisition path** | `/authorize`, `/token`, CIMD fetcher |
| S-17 | RFC 9728 | Protected Resource Metadata | Consumed at the AS (`protected_resources`); **produced** by the bundled RS middleware: path-**insertion** well-known, `resource` identity rule, `resource_metadata` in `WWW-Authenticate` | **MUST** | RS middleware, `/.well-known/oauth-protected-resource*` |
| S-18 | RFC 8707 | Resource Indicators | `resource` accepted (repeatable) at `/authorize` **and** `/token`; grant-set semantics; refresh bound to the **full** grant; `invalid_target`; `aud` = the registered canonical identifier | **MUST** | `/authorize`, `/token`, token minting |
| S-19 | RFC 9068 | JWT Profile for Access Tokens | `typ: at+jwt`; the 7 REQUIRED claims; `scope` as a space-delimited **string**; distinct `aud` per resource; RS256 in the supported set | **MUST** | token minting, RS middleware |
| S-20 | RFC 7662 | Token Introspection | POST, form-encoded, caller-authenticated **and** authorized; `200 {"active":false}` for inactive; `aud`+`iss` always in the active response | **MUST** | `/introspect` |
| S-21 | RFC 7009 | Token Revocation | POST, form-encoded, client-authenticated; `200` for unknown tokens; refresh→access cascade via grant-id denylist; `unsupported_token_type` | **MUST** | `/revoke` |
| S-22 | RFC 7519 | JWT | Registered claims, NumericDate as JSON **number**, `aud` string-or-array with single-audience emitted as a bare string | **MUST** | token minting |
| S-23 | RFC 7515 | JWS | `alg` in the protected header, verifier-side algorithm allow-list, `kid` always present, `alg: none` unreachable | **MUST** | signing, validation |
| S-24 | RFC 7517 | JWK / JWK Set | `kty`/`use: "sig"`/`alg`/`kid`; distinct `kid` per key; **public parameters only** | **MUST** | `/.well-known/jwks.json` |
| S-25 | RFC 7518 | JWA | RS256 (default, MTI per 9068 §2.1) + ES256; RSA ≥ 2048; no HS*; no `none` | **MUST** | key management |
| S-26 | RFC 7521 / **RFC 7523** | Assertion framework / JWT client auth + grant | (a) `private_key_jwt` client auth verified against the CIMD `jwks_uri` — ~~required by ChatGPT~~ **offered by ChatGPT**, per §10; **implemented**, opt-in via `TokenEndpointAuthMethods`, with a required `IClientAssertionReplayStore`; (b) `urn:ietf:params:oauth:grant-type:jwt-bearer` grant for Claude Enterprise Managed Auth, with a per-tenant issuer allowlist — **not implemented** | **MUST** (a); **SHOULD** (b) | `/token` |
| S-27 | RFC 9207 | AS Issuer Identification | `iss` on **every** authorization response including error redirects; `authorization_response_iss_parameter_supported: true` | **MUST** | `/authorize` |
| S-28 | RFC 3986 §6.2.1 | Simple String Comparison | The comparison primitive for `redirect_uri`, `client_id` (CIMD), `issuer`, `iss`, `resource`. **`System.Uri` may never be the comparison input** | **MUST** | every comparator |
| S-29 | RFC 6890 | Special-Use IP Addresses | Full v4+v6 blocklist enforced on every outbound fetch (CIMD, `jwks_uri`, `logo_uri`, `sector_identifier_uri`, `request_uris`) | **MUST** | outbound HTTP handler |
| S-30 | RFC 9111 | HTTP Caching | Honour `Cache-Control` on CIMD/JWKS fetches with a clamped TTL (floor 300 s, ceiling 86 400 s); never cache CIMD errors | **MUST** | CIMD cache |
| S-31 | RFC 9110 / RFC 7235 | HTTP semantics / auth framework | `auth-param` quoting (`resource_metadata`, `scope`, `error_description` MUST be quoted-strings, comma-separated); 303 semantics; 405/413/429 | **MUST** | challenge builder, routing |
| S-32 | RFC 4648 §5 | base64url | Unpadded, `-`/`_`, no line breaks — for PKCE, `at_hash`, `jti`, thumbprints | **MUST** | crypto helpers |
| S-33 | BCP 195 / RFC 9325 / RFC 8996 | TLS | TLS 1.2 minimum (prefer 1.3); HSTS 1 y + subdomains + preload; `https` on every OAuth URL except loopback redirects | **MUST** | Kestrel/ingress |
| S-34 | RFC 8259 | JSON | `application/json`; omit nulls; **omit zero-element arrays** in metadata (8414 §3.2 MUST) | **MUST** | serializers |
| S-35 | **MCP Authorization, revision `2026-07-28`** (current released) | Model Context Protocol | AS-side: OAuth 2.1 MUST, CIMD SHOULD, DCR MAY-deprecated, RFC 8414-or-OIDC-Discovery MUST, `resource` MUST, PKCE discovery MUST, refresh rotation MUST for public clients, `iss` SHOULD, consent-screen redirect-hostname MUST | **MUST** | cross-cutting |
| S-36 | RFC 9126 | Pushed Authorization Requests | **Deferred to v1.1** — but `IAuthorizationRequestSource` seam ships in v1 (D-01) | NOT (seam only) | `/authorize` |
| S-37 | RFC 9449 | DPoP | **Deferred** (D-02). Advertise nothing DPoP-related | NOT | — |
| S-38 | RFC 8705 | mTLS client auth / cert-bound tokens | **Deferred** (D-03) | NOT | — |
| S-39 | RFC 8693 | Token Exchange | **Deferred** (D-04). Note: this is the *only* spec where `audience` is a standard parameter, and only on `/token` | NOT | — |
| S-40 | RFC 9396 | Rich Authorization Requests | Not implemented (D-05) | NOT | — |
| S-41 | RFC 8628 | Device Authorization Grant | Not implemented (D-06) | NOT | — |
| S-42 | RFC 9470 | Step-Up Authentication Challenge | Not implemented; scope step-up via `insufficient_scope` covers the MCP case (D-07) | NOT | — |
| S-43 | RFC 7638 | JWK Thumbprint | Optional `kid` derivation only; the DPoP `jkt` use is deferred | MAY | key management |

**Two conformance deviations we take deliberately, and must document:**

- OIDC Discovery §3 says "Dynamic OpenID Providers **MUST support** `code`, `id_token`, and
  `id_token token`" and `grant_types_supported` "MUST support `authorization_code` and `implicit`".
  We publish `"response_types_supported": ["code"]` and never `implicit`, because OAuth 2.1 §10
  removes them. We will fail the OIDC "Dynamic OP" conformance profile on exactly these two rows and
  pass "Basic OP" + "Config OP".
- OAuth 2.1 draft-15 §7.5.1.1 offers a PKCE carve-out for confidential clients using the OIDC
  `nonce`. We do **not** take it: §4.1.3's final bullet makes a code issued under the carve-out
  unredeemable, so the draft is self-contradictory here. PKCE is required for every client (N-02).

---

# 2. Endpoint contract table

Legend for **Auth**: `anon` = must be reachable with no credentials; `client` = OAuth client
authentication; `user` = interactive end-user session; `bearer` = access token; `rat` = RFC 7592
registration access token.

| ID | Method | Path | Content-Type in | Content-Type out | Auth | CORS | Defined by |
|---|---|---|---|---|---|---|---|
| E-01 | GET, HEAD | `/.well-known/oauth-authorization-server` | — | `application/json` | **anon** | `*` | RFC 8414 §3 |
| E-02 | GET, HEAD | `/.well-known/openid-configuration` | — | `application/json` | **anon** | `*` | OIDC Discovery §4 |
| E-03 | GET, HEAD | `/.well-known/oauth-authorization-server/{*tenant}` | — | `application/json` | **anon** | `*` | RFC 8414 §3.1 insertion; MCP probe #1 |
| E-04 | GET, HEAD | `/.well-known/openid-configuration/{*tenant}` | — | `application/json` | **anon** | `*` | RFC 8414 §5; MCP probe #2 |
| E-05 | GET, HEAD | `/{tenant}/.well-known/openid-configuration` | — | `application/json` | **anon** | `*` | OIDC Discovery §4.1 append; MCP probe #3 |
| E-06 | GET, HEAD | `/{tenant}/.well-known/oauth-authorization-server` | — | `application/json` | **anon** | `*` | No spec. Served anyway — client libraries and gateways construct it |
| E-07 | GET, HEAD | `/.well-known/jwks.json` | — | `application/json` | **anon** | `*` | RFC 8414 §2 `jwks_uri`; RFC 7517 §5 |
| E-08 | **GET** (POST optional) | `/authorize` | query string | **303/302 redirect**, or `text/html` + `400` on the no-redirect paths | **user** | **MUST NOT** (OAuth 2.1 §3.1) | OAuth 2.1 §4.1.1; OIDC Core §3.1.2 |
| E-09 | POST | `/consent` | `application/x-www-form-urlencoded` (+ antiforgery token) | **303** | **user** | none | Product; RFC 9700 §4.12 governs the status code |
| E-10 | **POST** | `/token` | **`application/x-www-form-urlencoded`** | `application/json` + `Cache-Control: no-store` | `client` (incl. `none`) | `*` | OAuth 2.1 §3.2 |
| E-11 | POST | `/register` | **`application/json`** | `application/json`, **201** | anon (or initial access token) | `*` | RFC 7591 §3.1 |
| E-12 | GET | `/register/{client_id}` | — | `application/json`, 200 | `rat` | `*` | RFC 7592 §2.1 |
| E-13 | PUT | `/register/{client_id}` | `application/json` | `application/json`, 200 | `rat` | `*` | RFC 7592 §2.2 |
| E-14 | DELETE | `/register/{client_id}` | — | empty, **204** | `rat` | `*` | RFC 7592 §2.3 |
| E-15 | POST | `/introspect` | `application/x-www-form-urlencoded` | `application/json` + `no-store` | `client` (**mandatory**) | `*` | RFC 7662 §2.1 |
| E-16 | POST | `/revoke` | `application/x-www-form-urlencoded` | empty body, **200** + `no-store` | `client` | `*` | RFC 7009 §2.1 |
| E-17 | **GET and POST** | `/userinfo` | — / `application/x-www-form-urlencoded` | `application/json` + `no-store` | `bearer` (`openid` scope) | `*` (expose `WWW-Authenticate`) | OIDC Core §5.3 |
| E-18 | GET | `/logout` (`end_session_endpoint`) | query string | 302 or `text/html` interstitial | user session | none | OIDC RP-Initiated Logout §2 |
| E-19 | GET | `/login`, `/error` | — | `text/html` | anon | none | Product. Same CSP/`Referrer-Policy` headers as `/authorize` |
| E-20 | POST | `/login` | `application/x-www-form-urlencoded` (+ antiforgery) | **303** | anon | none | Product. **303 is mandatory here** — RFC 9700 §4.12 |
| E-21 | GET | `/admin/config/schema` | — | `application/json` | admin | none | Product (A-17) |
| **Bundled resource-server middleware** (shipped with the AS so a customer MCP server is correct by default) | | | | | | | |
| E-22 | GET, HEAD | `/.well-known/oauth-protected-resource` | — | `application/json` | **anon** | `*` | RFC 9728 §3 (root form) |
| E-23 | GET, HEAD | `/.well-known/oauth-protected-resource/{*rest}` | — | `application/json` | **anon** | `*` | RFC 9728 §3.1 (**path-insertion** — catch-all route is mandatory) |
| E-24 | POST | `/mcp` | `application/json` | `application/json` / SSE | `bearer` | — | MCP Streamable HTTP `2026-07-28`. GET/DELETE → **405** |

**Endpoint-level rules that are easy to lose:**

- **E-08 has no CORS.** OAuth 2.1 §3.2 / RFC 9700 §2.6: "CORS **MUST NOT** be supported at the
  authorization endpoint." Therefore never call `app.UseCors(policy)` globally — use per-endpoint
  `RequireCors("oauth-public")`.
- **E-10 vs E-11 use different parsers.** A `[FromBody]`-bound record on `/token` returns **415** to
  both Claude and ChatGPT and kills the flow. Bind `/token` from `Request.Form`/`[FromForm]` and
  `/register` from JSON. Ship a test that POSTs form-encoded garbage to `/token` and asserts
  `400` + an OAuth JSON body, never `415`.
- **Every `/.well-known/*` route is `.AllowAnonymous()`.** A global
  `AddAuthorization(o => o.FallbackPolicy = RequireAuthenticatedUser())` 401s the discovery documents
  — a documented, repeatedly-observed real-world connector failure.
- **Unmatched `/.well-known/*` returns a bare `404` with `Cache-Control: no-store`** — never HTML,
  never a SPA fallback, never a 302 to a login page. MCP clients probe sequentially on 404 and will
  parse a 200-with-HTML as garbage.
- **`MapGet` covers HEAD** in ASP.NET Core; some probes issue HEAD first.
- **Trailing-slash variants** of the well-known paths must return byte-identical bodies.
- **Latency budget applies per endpoint** (C-29): 10 s for E-01..E-07, E-10, E-11; 30 s for the
  refresh path of E-10. Failure at the budget is terminal even if the server later completes.

---

# 3. The AS metadata document we publish

One superset object, serialized once, served byte-identically from **E-01 through E-06**. RFC 8414
§2 ("Additional authorization server metadata parameters MAY also be used") and OIDC Discovery §3
("Additional OpenID Provider Metadata parameters MAY also be used") both permit the superset, and a
single object eliminates drift between the two documents.

```jsonc
{
  // RFC 8414 §2 REQUIRED · OIDC Discovery §3 REQUIRED.
  // Emitted from the RAW CONFIGURED STRING. Never `new Uri(issuer).ToString()` (adds "/"),
  // never derived from Request.Host/Request.Scheme (RFC 9700 §4.13 + host-header injection).
  // Byte-identical to: every ID-Token `iss`, every access-token `iss`, the RFC 9207 `iss`
  // response parameter, and the prefix of the URL this document was fetched from (RFC 8414 §3.3).
  "issuer": "https://auth.example.com",

  // RFC 8414 §2 REQUIRED · OIDC Discovery §3 REQUIRED.
  "authorization_endpoint": "https://auth.example.com/authorize",

  // RFC 8414 §2 REQUIRED · OIDC Discovery §3 REQUIRED.
  "token_endpoint": "https://auth.example.com/token",

  // RFC 8414 §2 OPTIONAL · OIDC Discovery §3 **REQUIRED** · RFC 9068 §4 SHOULD.
  // Non-negotiable in practice: no `at+jwt` validator works without it.
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",

  // OIDC Discovery §3 RECOMMENDED. Present because we serve OIDC RPs, not because MCP needs it.
  "userinfo_endpoint": "https://auth.example.com/userinfo",

  // RFC 8414 §2 OPTIONAL (RFC 7009 §5 advertises the endpoint here).
  "revocation_endpoint": "https://auth.example.com/revoke",

  // RFC 8414 §2 OPTIONAL (RFC 7662).
  "introspection_endpoint": "https://auth.example.com/introspect",

  // OIDC RP-Initiated Logout 1.0 §2.1 — REQUIRED if we support RP-initiated logout.
  "end_session_endpoint": "https://auth.example.com/logout",

  // NOTE — `registration_endpoint` (RFC 8414 §2 / RFC 7591) is DELIBERATELY ABSENT in the default
  // CIMD profile. See N-06 and A-05: with both CIMD and DCR advertised, a live Auth0 measurement
  // showed the client choosing DCR, contradicting the MCP spec's stated priority order. The AS
  // refuses to boot if this key and `client_id_metadata_document_supported` are both present.
  // In the opt-in DCR profile this key appears and `client_id_metadata_document_supported` does not.

  // RFC 8414 §2 RECOMMENDED · OIDC Discovery §3 RECOMMENDED ("MUST support the `openid` scope").
  // `offline_access` MUST be here (not in the resource's PRM): Claude appends it only when the AS
  // metadata lists it, and without it no refresh token is ever requested.
  // Rule: never advertise a scope any valid client would be refused — ChatGPT requests every
  // advertised OIDC scope by default.
  "scopes_supported": [
    "openid", "profile", "email", "offline_access",
    "mcp:tools", "story:read", "story:write"
  ],

  // RFC 8414 §2 REQUIRED · OIDC Discovery §3 REQUIRED.
  // `token` / `id_token token` deliberately absent — OAuth 2.1 §10.1 removes implicit.
  "response_types_supported": ["code"],

  // RFC 8414 §2 OPTIONAL, default ["query","fragment"]. Published explicitly.
  "response_modes_supported": ["query", "form_post"],

  // RFC 8414 §2 OPTIONAL — **MUST be published explicitly**, because the spec default is
  // ["authorization_code","implicit"] and silence would advertise implicit from an OAuth 2.1 server.
  //
  // CORRECTED. This array listed `client_credentials` and the jwt-bearer URN, and neither belonged
  // in a document headed "what we publish":
  //   - the shipped default is exactly ["authorization_code","refresh_token"];
  //   - `client_credentials` has a handler and is opt-in, so it appears only where a deployment
  //     added it;
  //   - the jwt-bearer URN CANNOT be published at all — `KnownGrantTypes` names only the grants
  //     `TokenEndpoint` has an arm for, and configuring anything else fails startup. That is N-06
  //     working, and the array above was N-06 broken on the document N-06 is about.
  // Claude Enterprise Managed Auth does require it: "The grant type must be listed here for the
  // feature to be offered to the customer, even if your token endpoint would already accept it
  // silently." That is C-32, it is unmet, and S-26(b) is where it says so.
  "grant_types_supported": [
    "authorization_code",
    "refresh_token"
  ],

  // RFC 8414 §2 OPTIONAL, default ["client_secret_basic"]. Published explicitly.
  // "none" is REQUIRED by Claude's CIMD selection gate.
  // "private_key_jwt" is REQUIRED by ChatGPT, whose live CIMD declares exactly that.
  // Omitting either locks out one vendor.
  "token_endpoint_auth_methods_supported": [
    "none", "private_key_jwt", "client_secret_basic", "client_secret_post"
  ],

  // RFC 8414 §2: "MUST be present if either of these authentication methods [private_key_jwt,
  // client_secret_jwt] are specified"; "Servers SHOULD support RS256"; "The value `none` MUST NOT
  // be used." ChatGPT signs assertions RS256.
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],

  // RFC 8414 §2 OPTIONAL, same MUST-be-present rule, `none` forbidden.
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
  "revocation_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
  "introspection_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],

  // RFC 8414 §2 OPTIONAL ("If omitted, the authorization server does not support PKCE").
  // MCP 2026-07-28 escalates: absent ⇒ clients "MUST refuse to proceed", in BOTH documents, and
  // "Authorization servers providing OpenID Connect Discovery 1.0 MUST include
  // `code_challenge_methods_supported`". `plain` is never listed (OAuth 2.1 / RFC 9700 §2.1.1).
  "code_challenge_methods_supported": ["S256"],

  // draft-ietf-oauth-client-id-metadata-document-02 §6 + MCP client-registration priority.
  // JSON boolean `true`, never the string "true". Gate #1 for CIMD selection by both vendors.
  "client_id_metadata_document_supported": true,

  // RFC 9207 §3 — MUST be true if we emit `iss`, and we emit it on every authorization response
  // including error redirects. MCP: a client that sees `true` and no `iss` MUST reject the response.
  "authorization_response_iss_parameter_supported": true,

  // OIDC Discovery §3 **REQUIRED** (no RFC 8414 counterpart).
  "subject_types_supported": ["public"],

  // OIDC Discovery §3 **REQUIRED**; "The algorithm RS256 MUST be included."
  // RS256 is also MTI per RFC 9068 §2.1 and is the interop floor for both vendors.
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],

  // OIDC Discovery §3 RECOMMENDED.
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr",
    "name", "given_name", "family_name", "preferred_username", "picture",
    "email", "email_verified", "locale", "zoneinfo", "updated_at"
  ],
  "claim_types_supported": ["normal"],

  // OIDC Discovery §3 OPTIONAL. Published explicitly because the spec default for
  // `request_uri_parameter_supported` is **true** — silence would claim a feature we do not have.
  "claims_parameter_supported": false,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "require_request_uri_registration": false,

  // RFC 9728 §4 OPTIONAL. Cheap defence-in-depth; clients cross-check it against the PRM's
  // `authorization_servers`. A partial list is explicitly permitted, so absence is not rejection.
  "protected_resources": ["https://mcp.example.com/mcp"],

  // RFC 8414 §2 OPTIONAL.
  "service_documentation": "https://auth.example.com/docs",
  "op_policy_uri": "https://auth.example.com/privacy",
  "op_tos_uri": "https://auth.example.com/terms",
  "ui_locales_supported": ["en-US", "vi-VN"],

  // NON-STANDARD. Not defined by RFC 8707 (which registers no metadata field at all) and not in
  // the IANA registry. Widely emitted in practice; harmless; we emit it as a courtesy signal but
  // MUST NOT rely on any client reading it. See U-06.
  "resource_indicators_supported": true

  // DELIBERATELY ABSENT:
  //   registration_endpoint                    — see N-06 / A-05 (present only in DCR profile)
  //   signed_metadata                          — RFC 8414 §2.1, no consumer
  //   pushed_authorization_request_endpoint    — PAR deferred (D-01); advertising it invites use
  //   require_pushed_authorization_requests    — would break both vendors if true
  //   dpop_signing_alg_values_supported        — DPoP deferred (D-02); advertising invites proofs we reject
  //   check_session_iframe                     — Session Management not implemented (S-12)
  //   tls_client_certificate_bound_access_tokens / mtls_endpoint_aliases — mTLS deferred (D-03)
}
```

**Serialization rules for this document (all enforced by test):**

1. `Content-Type: application/json`, status `200`, `Cache-Control: public, max-age=300` + `ETag`.
   Claude caches discovery globally by URL with a ~5-minute staleness window, so `max-age=300`
   matches reality; a metadata change takes ~5 min to propagate and a transient discovery failure
   does **not** break live connections (do not chase phantom failures inside that window).
2. **Zero-element arrays MUST be omitted**, not emitted as `[]` (RFC 8414 §3.2). `System.Text.Json`
   does not do this for you.
3. Nulls omitted (`JsonIgnoreCondition.WhenWritingNull`).
4. The document is **generated from live configuration**, never hand-maintained. A disabled feature
   removes its key. Startup asserts: `issuer` is `https`, has no query/fragment, has no trailing
   slash, and is `Ordinal`-equal to the token-signing issuer constant.
5. Startup **refuses to boot** if `registration_endpoint` and `client_id_metadata_document_supported`
   are both present (N-06).

**Companion: the Protected Resource Metadata the bundled RS middleware publishes** (E-22/E-23):

```jsonc
{
  "resource": "https://mcp.example.com/mcp",          // RFC 9728 §2 REQUIRED; §3.3 identity rule
  "authorization_servers": ["https://auth.example.com"], // OPTIONAL in 9728, MUST in MCP.
                                                       // Claude uses ONLY the first entry.
  "scopes_supported": ["mcp:tools", "story:read", "story:write"], // RECOMMENDED. NO `offline_access`.
  "resource_name": "Example MCP",                      // RECOMMENDED
  "bearer_methods_supported": ["header"],              // OPTIONAL; header only — no body, no query
  "resource_documentation": "https://example.com/docs/mcp"
}
```

---

# 4. Error code reference

**Delivery** column: `redirect` = query params on a 302/303 to the *validated* `redirect_uri`;
`json` = OAuth JSON body; `html` = AS-rendered page on the AS's own origin; `header` =
`WWW-Authenticate`.

### 4.1 Authorization endpoint (E-08)

Every redirect below **MUST** also carry `state` verbatim (if it was sent) and `iss` (RFC 9207).

| ID | `error` | HTTP | Delivery | Exact condition |
|---|---|---|---|---|
| X-01 | *(none)* | **400** | **html** | `client_id` missing, malformed, unknown, or disabled. OAuth 2.1 §4.1.2.1 forbids redirecting. Body carries `invalid_client` for machine readers |
| X-02 | *(none)* | **400** | **html** | `redirect_uri` missing with ≠1 registered, malformed, has a fragment or userinfo, or does not match. **Never redirect.** Body carries `invalid_request` |
| X-03 | `invalid_client` | 400 | html | CIMD: fetch failed / status ≠ 200 / redirect encountered / >5 KB / resolved to a special-use IP / body not JSON / `client_id` field ≠ fetch URL / `client_secret*` present / `jwks`+`jwks_uri` both present / private key material present |
| X-04 | `invalid_request` | 303 | redirect | `code_challenge` absent; `code_challenge_method` absent (defaults to `plain`, unsupported) or not `S256`; `code_challenge` violates `43*128unreserved` (padding, `+`/`/`, wrong length); any parameter repeated (except `resource`); `prompt` contains `none` with another value; `max_age` not a non-negative integer |
| X-05 | `unauthorized_client` | 303 | redirect | Client is known but `authorization_code` is not among its grant types, or `code` not among its response types |
| X-06 | `access_denied` | 303 | redirect | User clicked Deny; policy refusal |
| X-07 | `unsupported_response_type` | 303 | redirect | `response_type` ≠ `code` |
| X-08 | `invalid_scope` | 303 | redirect | Unknown scope token; scope not permitted for this client; (RFC 9068 §3) `resource` absent and the scopes map to two different default audiences |
| X-09 | `invalid_target` | 303 | redirect | `resource` not an absolute URI / has a fragment / non-`https` scheme; unknown to the resource registry; client not permitted for it (**same string and description as "unknown" — never distinguish, it is an enumeration oracle**); policy requires `resource` and it was omitted |
| X-10 | `server_error` | 303 | redirect | **Any unhandled exception after `redirect_uri` is trusted.** OAuth 2.1 §4.1.2.1: this code exists precisely "because a 500 … cannot be returned to the client via an HTTP redirect". An HTTP 500 from `/authorize` past that line is a defect |
| X-11 | `temporarily_unavailable` | 303 redirect / **503** html | both | Dependency down, load shedding — a transient driver failure, a name-resolution failure, a connect timeout. **Which half depends on where it failed**, and for a store outage it is usually the second: reading the client is what validates `redirect_uri`, so there is normally no address it is safe to redirect to. **Not `server_error`** — nothing about the request was wrong. Also the CIMD path when we prefer retry over hard failure, and there only after `redirect_uri` is validated |
| X-12 | `login_required` | 303 | redirect | `prompt=none` and no authenticated session, **or** `max_age` exceeded and re-auth would be needed |
| X-13 | `consent_required` | 303 | redirect | `prompt=none` and consent for the requested scopes has not been granted |
| X-14 | `account_selection_required` | 303 | redirect | `prompt=none`, multiple sessions, AS cannot pick |
| X-15 | `interaction_required` | 303 | redirect | `prompt=none` and any other interaction is needed (step-up, ToS, password expiry, MFA enrolment). **Be specific** — RPs doing silent renew branch on the exact string |
| X-16 | `request_not_supported` / `request_uri_not_supported` / `registration_not_supported` | 303 | redirect | `request` / `request_uri` / `registration` parameter present; we publish `false` for all three |

Charset for `error` and `error_description` on this surface: `%x20-21 / %x23-5B / %x5D-7E` —
ASCII only, **no `"`, no `\`**. Sanitise before emitting; build the query with
`QueryHelpers.AddQueryString`, never string concatenation.

**The redirect column read `302` on every row above until 2026-08-22, and was wrong the whole
time.** `OAuthErrors` has specified `303` since it was written, `Every_authorize_redirect_is_303
_never_302_or_307` has asserted it, and OAuth 2.1 §7.5.3 requires it: only `303` unambiguously
rewrites a POST to a GET, and several of these arise from the consent POST — under `302` a user
agent may replay the credentials to the client's redirect URI. Nothing enforced the document
against the table, so the two disagreed silently. Corrected here; the behaviour never changed.

**X-11 had no emitter until the same day.** The row said "dependency down, load shedding" and a
dependency going down produced X-10 `server_error`, because the endpoint's exception boundary did
not distinguish a crash from an outage. It does now — see §4.2 for the measurement that prompted
it, which was the same fault one endpoint over.

### 4.2 Token endpoint (E-10)

`application/json`, `Cache-Control: no-store`. `400` unless stated.

| ID | `error` | HTTP | Delivery | Exact condition |
|---|---|---|---|---|
| X-17 | `invalid_request` | 400 | json | Missing/repeated/malformed parameter; more than one client-authentication mechanism; credentials in both header and body; **`code_verifier` present when no `code_challenge` was sent** (OAuth 2.1 §3.2.4 names this case explicitly); token presented in a query string |
| X-18 | `invalid_client` | **401** if the client authenticated via the `Authorization` header (**MUST** include a matching `WWW-Authenticate`), else **400** | json + header | Unknown client, failed secret, failed `private_key_jwt` assertion (bad signature, `iss`≠`sub`≠`client_id`, `aud` not our identity, expired, replayed `jti`), unresolvable CIMD `client_id`. **Not a blanket 401** |
| X-19 | `invalid_grant` | 400 | json | Code unknown/expired/already-redeemed; code issued to another client; `redirect_uri` (if sent) ≠ the one used at `/authorize`; PKCE verifier mismatch; PKCE presence XOR violation in either direction; malformed `code_verifier`; refresh token unknown/expired/revoked/consumed-outside-grace; refresh token issued to another client; grant no longer active; jwt-bearer assertion whose `iss` is not on the tenant allowlist |
| X-20 | `unauthorized_client` | 400 | json | The authenticated client is not allowed this grant type |
| X-21 | `unsupported_grant_type` | 400 | json | Unknown `grant_type`, including `password` (permanently unimplemented). **Not `invalid_request`** — §3.2.4 explicitly excludes grant type from that code |
| X-22 | `invalid_scope` | 400 | json | Requested scope exceeds the grant; effective scope at the resolved resource is empty |
| X-23 | `invalid_target` | 400 | json | `resource` malformed/unknown/not permitted; `resource` not in this code's or this refresh token's **grant set**; more than one `resource` at `/token` under the single-resource policy. **Never `invalid_grant`** — clients treat that as "refresh token is dead" and discard it, turning a recoverable error into a re-consent loop |
| X-43 | *(none)* | **503** + `Retry-After` | empty | The store backing the exchange could not be reached — a transient driver failure, a name-resolution failure, a connect timeout. **Not `server_error`**: nothing about the request was wrong and the same request succeeds once the dependency returns, so the client must be told to come back rather than to give up. Body is empty; the status and `Retry-After` carry the whole meaning |

`access_denied`, `unsupported_response_type`, `server_error`, `temporarily_unavailable`,
`invalid_token`, `insufficient_scope` are **never** emitted from `/token`.

X-43 does not change that, and the near-miss is worth naming: `temporarily_unavailable` means
exactly what X-43 means, and RFC 6749 registers it in §4.1.2.1 for the **authorization** endpoint.
§5.2's set for `/token` does not include it. So X-43 answers with a status and a `Retry-After` and
no `error` member at all — the same shape as X-31, for the same reason. A client that branches on
`error` sees no member rather than a string the RFC does not define for this endpoint.

**Why this is a row rather than an ambient 500.** Measured 2026-08-22 03:43:16 UTC: DNS for the
database host failed with `EAI_AGAIN`, the driver exception reached the endpoint unhandled, and the
request became a bare `500` after five seconds. The client stopped refreshing, replayed its expired
access token, then sent none — and the person holding it was told to check their credentials and
permissions. Both were fine; the store answered normally seventy seconds later. A `500` says the
request cannot succeed and says nothing about when it might, which on this endpoint spends a
re-authorization on an outage that has already ended.

**X-43 is one requirement across four surfaces, not four requirements.** `/token` shipped first and
was the only one for a day, which is long enough for "X-43 is the token endpoint's rule" to become
what people remember. It is not: it is *a store that cannot be reached is a refusal that says come
back, wherever it happens*, and the rows in §4.1, §4.4 and §4.5 are the same rule at the other
three. What differs between them is the code, and only because the specifications differ — §5.2 and
RFC 6750 register nothing that means this, while §4.1.2.1 registers `temporarily_unavailable`, so
`/authorize` says it and the rest say nothing. Anything else on those rows — an empty body, a
`Retry-After`, one log line naming the requirement — is identical by construction: they share
`StoreLoadShed` and `TransientStoreFailure`.

### 4.3 Registration endpoints (E-11..E-14)

| ID | `error` | HTTP | Delivery | Exact condition |
|---|---|---|---|---|
| X-24 | `invalid_redirect_uri` | 400 | json | Redirect-based grant with missing/empty `redirect_uris`; a non-absolute URI; a fragment; `http` with a non-loopback host; disallowed scheme; count over the tenant cap |
| X-25 | `invalid_client_metadata` | 400 | json | `jwks` and `jwks_uri` both present; inconsistent `grant_types`/`response_types` with an **empty** intersection; malformed JSON; a length/array cap breached; client attempted to set `client_id`; hard tenant client-quota reached |
| X-26 | `invalid_software_statement` | 400 | json | `software_statement` not a valid JWS, `alg: none`, unknown `iss`, bad signature, expired |
| X-27 | `unapproved_software_statement` | 400 | json | Signature and issuer trusted, but policy declines this software |
| X-28 | *(RFC 6750 body)* | **401** | header | E-12/13/14: registration access token missing, invalid, expired — **or the client does not exist**. `401`, never `404`, so the endpoint is not a client-id enumeration oracle |
| X-29 | *(none)* | 403 | — | Authenticated but not permitted this operation |
| X-30 | *(none)* | 405 | — | Method not supported at the configuration endpoint |
| X-31 | *(none)* | **429** + `Retry-After` | json | Rate limit or never-used-client soft quota breached. Not an RFC 7591 error condition — it is transport-level, so `429` is correct |

There is **no `invalid_request`** at the registration endpoint. Do not emit ASP.NET Core's default
`ProblemDetails` body — it has no `error` member and neither vendor's parser will read it.

### 4.4 Resource server / UserInfo (E-17, E-24)

| ID | `error` | HTTP | Delivery | Exact condition |
|---|---|---|---|---|
| X-32 | *(omitted per RFC 6750 §3.1)* | **401** | header | No `Authorization` header at all. Bare `WWW-Authenticate: Bearer resource_metadata="…", scope="…"`. **Exception:** OpenAI requires both `error` and `error_description` to trigger its auth UI — we emit `error="invalid_token"` even here, which satisfies both vendors |
| X-33 | `invalid_token` | **401** | header | Any RFC 9068 §4 validation failure: `typ` ≠ `at+jwt`/`application/at+jwt`; `iss` mismatch; **`aud` does not contain this resource identifier**; bad signature; unknown `kid`; `alg` not on the allow-list; expired; revoked (grant-id denylist) |
| X-34 | `insufficient_scope` | **403** | header | Valid token, missing scope. **MUST** include `scope="…"` listing *all* scopes needed for the operation in one challenge, plus `resource_metadata`. A 403 without `error="insufficient_scope"` is terminal for Claude — no re-auth prompt |
| X-35 | `invalid_request` | **400** | header | Token in a query string; token in two places at once; malformed `Authorization` header. **Not 401** — getting this backwards makes clients retry-loop forever on refresh |
| X-43 | *(none)* | **503** + `Retry-After` | empty | The directory backing `/userinfo` could not be reached. **Never `invalid_token`** — it is the nearest registered code and every conformant client reads it as "discard this credential", so a store that is briefly gone would cost a re-authorization per session. RFC 6750 registers nothing meaning "come back shortly", so the status and the header carry it and no `WWW-Authenticate` is sent: this is not a challenge |

`WWW-Authenticate` construction (RFC 7235 + RFC 6750 §3): parameters are comma-separated;
`resource_metadata`, `scope`, `error`, `error_description`, `realm` **MUST** be quoted-strings
(a URL contains `:` and `/`, which are not `tchar`); each may appear at most once; `"` (%x22) and
`\` (%x5C) are forbidden inside values — **an unescaped quote in `error_description` truncates the
header and eats `resource_metadata`**, which is the discovery entry point.

### 4.5 Introspection and revocation (E-15, E-16)

| ID | Behaviour | HTTP | Body | Exact condition |
|---|---|---|---|---|
| X-36 | `{"active":false}` | **200** | json | Introspected token unknown, expired, revoked, or wrong audience. RFC 7662 §2.3: "not considered an error response." **Returning 401 here makes conformant resource servers think their registration broke.** Return exactly two-field JSON — no `sub`, no `scope`, no leakage |
| X-37 | `invalid_request` | 400 | json | `token` parameter missing (introspection or revocation) |
| X-38 | `invalid_client` | 401 | json + header | Introspection/revocation caller credentials absent or invalid |
| X-39 | *(empty)* | **200** | empty | Revocation success **or unknown/invalid/already-revoked token** (RFC 7009 §2.2 MUST). Also when the token belongs to a different client — do not confess |
| X-40 | `unsupported_token_type` | 400 | json | Token type this AS refuses to revoke |
| X-43 | *(none)* | **503** + `Retry-After` | empty | The store backing the lookup could not be reached. **Neither X-36 nor an active response is available**: `{"active":true}` fails open on the denylist this endpoint exists to consult, and `{"active":false}` is a definite answer built from no information — a resource server acting on it drops a live session. RFC 7662 §2.3 defers to RFC 6749 §5.2, whose set is closed, so there is no `error` to send. Applies to introspection only; revocation is idempotent and X-39 already covers a token it could not find |
| X-41 | *(none)* | 503 + `Retry-After` | — | Revocation endpoint overloaded; client must assume the token still exists |

### 4.6 The interaction and management surfaces

Not OAuth endpoints, and they have no rows in the error table — see `OAuthSurface.Interaction` and
`OAuthSurface.Administration`. X-43 reaches them anyway, because a store is a store.

| ID | `error` | HTTP | Delivery | Exact condition |
|---|---|---|---|---|
| X-43 | *(none)* | **503** + `Retry-After` | **html** | `Interaction`: the sign-in, consent, recovery and self-service pages. The deployment's own error page is rendered, in the reader's language — a bare status reaches a browser as the browser's error page, which says nothing about coming back |
| X-43 | *(none)* | **503** + `Retry-After` | empty | `Administration`: `/admin/*`, `/account/*`. A script in a page branches on the status and can use nothing else |

**The sign-in page is why this is a row and not a tidy-up.** Every other X-43 surface is a machine
being told something false; here it is a person, on the page where the only available conclusion is
about themselves. ~~The lookup throws today, so the answer is a bare `500`~~ — that was the state
this row was written against, and one refactor away sat the branch that re-renders the form saying
*"that username and password did not match"*, which is the exact sentence the outage behind X-43 put
in front of somebody whose credentials were fine. **It is closed**: `InteractionEndpoints` maps its
pages into `ShedsOnStoreFailure(OAuthSurface.Interaction, rendered: true)`, so a store that cannot
be reached renders the deployment's error page at `503` instead. What has not changed is the
surrounding fact — **no `UseExceptionHandler` is registered anywhere in this server**, and the filter
catches only what `TransientStoreFailure.Describes` recognises, so any *other* unhandled exception on
these pages is still a bare `500`.

**Applied as an endpoint filter, not forty `catch` blocks.** The protocol endpoints each hold their
own because each had something to decide; these forty-odd all answer the same way, and forty copies
is forty chances for the next route to be added without one. The filter returns an `IResult`, so
`RejectionResult` still writes and logs it — A-09's chokepoint is about who writes, not where the
`catch` sits.

Still **not** covered, stated rather than implied: a handler that has already begun writing its
response rethrows instead, the same call `/authorize`'s boundary makes, because a second write
produces a body the caller cannot parse.

---

# 5. Non-negotiables — ranked

These are the requirements where being wrong is a **security defect**, not an interop bug. Ranked by
(exploitability × blast radius). Each has a stated failure mode and a mechanical guard.

| Rank | ID | Requirement | If wrong | Mechanical guard |
|---|---|---|---|---|
| 1 | **N-01** | **`aud` is bound to the validated `resource`, or the request is rejected with `invalid_target`. Never accept-and-ignore, never stamp a house default when `resource` was present.** | RFC 9700 §4.9.1 access-token phishing: a user adds an attacker's MCP server; the client does everything right; the AS stamps a default `aud`; the attacker replays the token at the legitimate MCP server and acts as the user. **RFC 8707 registers no discovery flag, so a client cannot tell "honoured" from "ignored".** | Test: token issued for resource A presented at resource B ⇒ 401 `invalid_token`. Test: `resource` present but unknown ⇒ `invalid_target`, never a token |
| 2 | **N-02** | **PKCE `S256` required for every client, every authorization-code flow, with the presence check as a strict XOR against a stored `PkceWasRequested` boolean — both directions → `invalid_grant`.** | RFC 9700 §4.8 PKCE downgrade → full account takeover. The attacker-controllable flag is "did the request contain `code_challenge`" | Making PKCE unconditional removes the flag by construction. Keep the XOR anyway — someone will add a legacy escape hatch. RFC 7636 Appendix B vector in CI |
| 3 | **N-03** | **`redirect_uri` comparison is RFC 3986 §6.2.1 Simple String Comparison on raw strings with `StringComparison.Ordinal`. `System.Uri` is never the comparison input.** | .NET's `Uri` lowercases scheme+host, **elides default ports**, resolves dot segments, and percent-decodes. Each normalization silently widens the match set. Prefix/wildcard matching is an open redirector that leaks `code` and `state` | Architecture test failing the build on `Uri.Equals`/`AbsolutePath`/`AbsoluteUri` in the matcher. Normalize at **registration**, compare exactly at request time |
| 4 | **N-04** | **The loopback port exception ignores the port on BOTH sides, is gated on `scheme=="http"` AND host ∈ {`127.0.0.1`, `::1`, `localhost`}, and compares host + escaped path + escaped query exactly.** | Applying the port exception to non-loopback hosts accepts `https://claude.ai:1337/api/mcp/auth_callback`. Dropping the path lets any local process harvest codes. Accepting `127.1`, `2130706433`, `0.0.0.0`, `[::ffff:127.0.0.1]` widens it further | Allowlist the three host **strings**; never call `IPAddress.IsLoopback` on parsed input. 16-row matcher test matrix incl. `http://localhost:0/callback` (reject) |
| 5 | **N-05** | **CIMD fetch is SSRF-hardened: `https` only, `AllowAutoRedirect = false`, `SocketsHttpHandler.ConnectCallback` connecting to the *validated* `IPAddress`, `MapToIPv4()` before RFC 6890 range checks, 5 KB cap on **bytes read**, 3 s connect / 5 s total, no proxy/cookies/credentials/decompression. Same handler for `jwks_uri` and `logo_uri`.** | `client_id` is an attacker-supplied URL the AS fetches. `AllowAutoRedirect` **defaults to `true` in .NET** — a stock `HttpClient` violates the draft's MUST NOT *and* opens public-host→302→`169.254.169.254`. Resolve-then-fetch is a TOCTOU/DNS-rebinding hole | Tests: `https://169.254.169.254/c.json` blocked before any socket connect; `::ffff:169.254.169.254` blocked; 302 to an internal IP blocked at the hop; 6 KB doc rejected |
| 6 | **N-06** | **Advertised capability == actual capability, generated from live config. Exactly one client-acquisition mechanism is advertised. Startup refuses to boot if `registration_endpoint` and `client_id_metadata_document_supported` are both present.** | Advertising a capability you don't have (CIMD advertised before it works; `registration_endpoint` still advertised after DCR is disabled) produces silent, unattributable connection failures that look like client bugs. Measured: with both advertised, DCR won and then failed | Startup assertion with a named error. Test: toggle DCR off ⇒ key gone from **both** well-known documents |
| 7 | **N-07** | **Authorization-code replay: run the *full* validation on the replayed code first (client auth, `client_id` binding, PKCE, `redirect_uri`); revoke descendant tokens **only if it all passes**.** | The naive "seen twice ⇒ nuke the grant" is a **DoS**: an attacker with a sniffed code but no verifier/secret kills the legitimate client's tokens (OAuth 2.1 §7.5.2 SHOULD NOT). Retain redeemed codes with their challenge and binding until original expiry so step 2a is possible | Test: replay with a wrong verifier ⇒ `invalid_grant` **and the original tokens still work**. Redemption itself is an atomic `UPDATE … WHERE redeemed_at IS NULL`; rows-affected is the authority |
| 8 | **N-08** | **Refresh rotation with whole-family revocation on reuse, plus a bounded 30–60 s idempotency window; exactly one successor per parent, ever.** | Public clients (both vendors) MUST rotate — RFC 9700 §2.2.2. Without family revocation there is no replay signal. **Forking the family on concurrent redemption is a real CVE class (GHSA-392p-2q2v-4372) and defeats detection entirely.** Without the grace window, Claude's proactive+reactive refresh race produces user-visible forced logouts that look like incidents | Conditional `UPDATE … WHERE consumed_at IS NULL`; the loser reads the winner's successor. Tests: replay outside the window ⇒ family revoked; two concurrent redemptions ⇒ one successor, both callers get it |
| 9 | **N-09** | **`typ: at+jwt` on every access token; `typ: JWT` on ID tokens; `ValidTypes` pinned and `ValidAlgorithms` pinned on every verifier. `alg: none` has no code path.** | RFC 9068 §5 cross-JWT confusion: an ID token accepted as an access token. `TokenValidationParameters.ValidTypes` is **unset by default**, so the stock ASP.NET Core configuration is non-conformant. Unpinned `ValidAlgorithms` is the RS256→HS256 confusion bug | Test asserting an ID token presented as a bearer token ⇒ 401 `invalid_token` |
| 10 | **N-10** | **ID Token `aud` is the `client_id`. Access token `aud` is the resource. They are never unified.** | Putting the resource URL in the ID Token `aud` makes every conformant RP reject at OIDC Core §3.1.3.7 rule 3 — and it surfaces client-side with no error code you control | Test asserting the two `aud` values differ for the same grant |
| 11 | **N-11** | **The `/authorize` control flow is ordered `client_id` → `redirect_uri` → *(redirect now permitted)* → everything else, and the user is authenticated before any automatic redirect.** | Reversing it makes the AS an open redirector on your trusted domain that leaks `state` — and `prompt=none` makes it zero-interaction. `access_denied` still redirects by spec, so trusting the registered URI is the only real mitigation | Test: unregistered `redirect_uri` ⇒ 400 with **no** `Location` header. Any `?returnUrl=` on login/logout/error pages gated by `Url.IsLocalUrl` |
| 12 | **N-12** | **303, never 307/308, on any redirect that follows a credential- or consent-carrying POST.** | RFC 9700 §4.12: 307 makes the browser **re-POST the user's password to the client**. `Results.Redirect(url, permanent:false, preserveMethod:true)` emits exactly 307 and ASP.NET Core has no built-in 303 helper | Architecture test failing the build on `preserveMethod: true` or a 307/308 literal anywhere in the AS project |
| 13 | **N-13** | **`issuer` is one configured immutable byte string, asserted `Ordinal`-equal across: AS metadata, ID Token `iss`, access token `iss`, the RFC 9207 `iss` parameter, and the well-known URL prefix. Never derived from `Request.Host`/`Request.Scheme`.** | Host-header injection rewrites the issuer and mints tokens under an attacker-chosen `iss`. Behind a proxy, `Request.Scheme` is `http` and the whole flow fails conformance. Clients compare with Simple String Comparison and MCP **forbids** them from normalizing, so `…/com` ≠ `…/com/` | Startup assertion + a test that `cmp`s the five values. `ForwardedHeaders` with `ForwardLimit=1` and an **explicit** `KnownProxies` entry — clearing `KnownProxies`/`KnownNetworks` without re-adding the proxy trusts `X-Forwarded-*` from anyone |
| 14 | **N-14** | **Consent screen shows the host of the `client_id` URL as the relying party, the requested `redirect_uri` hostname, and an explicit warning when every registered redirect URI is loopback. `client_name`/`logo_uri` are self-asserted, HTML-encoded, length-capped, and logos are proxied — never hotlinked. Consent is never auto-approved on repeat for public clients.** | Anyone can publish `{"client_name":"Claude"}` at `https://evil.example/c.json`. CIMD cannot prevent localhost impersonation by itself — the hostname display **is** the mitigation (MCP: MUST). RFC 8252 §8.6: skipping repeat consent for unauthenticated clients is the classic "we made it faster" regression | Test: a CIMD doc claiming `client_name: "Claude"` from another origin renders that origin's host prominently. Hotlinked logo ⇒ CSP `default-src 'self'` blocks it |
| 15 | **N-15** | **Clickjacking prevention on every user-facing endpoint: CSP `frame-ancestors 'none'` (per-client allowlist only via CSP), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `default-src 'self'`, `base-uri 'none'`, and antiforgery on the consent POST. `form-action` is `'self'` **plus, per response, the origins that response's own form must be allowed to reach** — nothing else, ever a wildcard, and never a value derived from an unvalidated parameter.** | RFC 9700 §4.16: "Authorization servers **MUST** prevent clickjacking." The RFC's own example header `X-Frame-Options: ALLOW-FROM` is **dead** — Chrome never implemented it, Firefox removed it; emitting it either gives no protection or breaks your allowlisted client. `state` protects the *client*; it does nothing for your consent page. **`form-action` is written as a per-response value because a literal `'self'` is a page whose only button does nothing:** Chrome and Safari apply the directive to the redirect chain a submission follows, so the consent POST's 303 to the client and the sign-in page's 303 to the upstream are both blocked by it — measured on the real host, after `curl` had reported the redirect as correct for a day. `curl` does not enforce CSP | Headers set in `Response.OnStarting` so Razor/Identity UI cannot clobber them — and so the widening, which is known only after the client or provider is resolved, reaches the header. Test asserting the headers on `/authorize`, `/login`, `/consent`, `/logout`, **and error pages**; tests asserting `form-action`'s *sources* — `'self'` alone on `/error`, `'self'` + the validated redirect on `/consent`, `'self'` + the provider origin on `/login`. A test that follows a redirect asserts nothing here |
| 16 | **N-16** | **Store only hashes (SHA-256) of authorization codes, refresh tokens, client secrets, and registration access tokens; compare with `CryptographicOperations.FixedTimeEquals`; generate with `RandomNumberGenerator` (never `Random`/`Guid.NewGuid()`); ≥256 bits.** | Database disclosure becomes account takeover; `==` comparison is a timing oracle on server-held secrets. Registration access tokens are the *sole* authenticator for full control of a client record — mint them from a separate pipeline with a distinct prefix so a bug can never make them valid at `/token` or `/mcp` | Test asserting the JWKS response body contains none of `d`,`p`,`q`,`dp`,`dq`,`qi`; test asserting no plaintext token column |

---

# 6. Client compatibility requirements (Claude + ChatGPT, merged)

| ID | Dimension | Claude (web/Desktop/mobile/Cowork) | Claude Code | ChatGPT | What our AS must do |
|---|---|---|---|---|---|
| C-01 | `client_id` shape | CIMD URL `https://claude.ai/oauth/mcp-oauth-client-metadata` | CIMD URL `https://claude.ai/oauth/claude-code-client-metadata` | CIMD URL `https://chatgpt.com/oauth/client.json` and `https://chatgpt.com/oauth/mcp/client.json` | `client_id` column is a **string, not a GUID**. Store a `ClientKind` discriminator (`Cimd`/`Dynamic`/`PreRegistered`) — never re-derive "is this CIMD?" from a `https://` prefix (CIMD §7.1) |
| C-02 | CIMD selection gate | Requires **both** `client_id_metadata_document_supported: true` **and** `"none"` in `token_endpoint_auth_methods_supported`; else falls back to DCR | same | Reads `client_id_metadata_document_supported` | Advertise both, plus `private_key_jwt` (C-05) |
| C-03 | Client auth at `/token` | `token_endpoint_auth_method: "none"` (public) | `"none"` (public) | **`private_key_jwt`**, RS256, `jwks_uri: https://chatgpt.com/oauth/jwks.json` | Implement **both** paths. A `none`-only CIMD implementation returns `invalid_client "unknown OAuth client"` and ChatGPT never links |
| C-04 | **ChatGPT's field-name defect** | — | — | Publishes `token_endpoint_auth_methods_supported` (**plural array**, an RFC 8414 *server* field) instead of RFC 7591's `token_endpoint_auth_method` | Read **both** spellings. For CIMD the effective default when absent MUST be `none`, **not** RFC 7591's `client_secret_basic` — which CIMD §4.1 forbids, so a spec-literal AS rejects every ChatGPT document |
| C-05 | `token_endpoint_auth_methods_supported` | needs `none` | needs `none` | needs `private_key_jwt` | `["none","private_key_jwt","client_secret_basic","client_secret_post"]` |
| C-06 | Redirect URI | `https://claude.ai/api/mcp/auth_callback` — exact. Anthropic says allowlist `https://claude.com/api/mcp/auth_callback` now too | Declares **portless** `http://localhost/callback` and `http://127.0.0.1/callback`; requests `http://localhost:3118/callback` | `https://chatgpt.com/connector/oauth/{callback_id}` (per-connector, arrives in the CIMD) + legacy `https://chatgpt.com/connector_platform_oauth_redirect` | Exact ordinal match, **except loopback ignores the port on both sides**. Never prefix-match ChatGPT's template — the concrete value is in the CIMD, so it is exact-matchable |
| C-07 | IPv6 loopback | — | not declared, but RFC 8252 §7.3 requires support for clients that do | — | Support `http://[::1]:{port}/…` for any client that registers it |
| C-08 | PKCE | `S256` on **every** request | `S256` | `S256` | Enforce S256; reject absent/`plain` method with `invalid_request` |
| C-09 | PKCE discovery | Refuses to proceed if `code_challenge_methods_supported` is absent | same | same | Emit `["S256"]` in **every** metadata document, including `/.well-known/openid-configuration` where OIDC never defines the field |
| C-10 | `resource` (RFC 8707) | Always, on `/authorize` **and** `/token`, canonical form incl. path | same | Always, both requests | Accept repeatable `string[]`; bind `aud`; reject with `invalid_target` |
| C-11 | `audience` (Auth0-proprietary) | **Never sent** | never | never | Honour `resource` natively. Accept `audience` only as a silent alias in a compat mode that is **off by default**, and when both are sent, **`resource` wins** — the opposite of Auth0's precedence. Document this as a migration behaviour change |
| C-12 | `prompt` | **Not sent** | not sent | not documented | Never require `prompt=consent` |
| C-13 | `nonce` / `openid` | Not observed — this is an OAuth flow, not an OIDC login | not observed | requests OIDC scopes if advertised | OIDC is **conditional on the `openid` scope**. Requiring `openid` on every `/authorize` breaks both vendors. Never require `nonce` in the code flow; never invent one |
| C-14 | Grants declared | `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:jwt-bearer` | `authorization_code`, `refresh_token` | `authorization_code`, `refresh_token` | Never reject a *document* for declaring a grant we haven't enabled — validate **per request** |
| C-15 | `/token` content type | form-urlencoded on initial **and** refresh | same | same | `[FromForm]`. A `415` kills the flow at exchange |
| C-16 | `/register` content type | JSON (DCR only) | — | JSON (DCR only) | Different parser from `/token` |
| C-17 | DCR body | `grant_types: ["authorization_code","refresh_token"]`, `token_endpoint_auth_method: "none"` | — | per-connector-instance | Register the **intersection** and echo it back in the 201. Rejecting `refresh_token` is the top cause of DCR failure |
| C-18 | DCR volume | Registers a new client on **every fresh connection** | — | once per connector instance | Prefer CIMD (creates no client row). If DCR is on: fingerprint-dedup public clients, TTL + GC, per-tenant quotas |
| C-19 | Refresh timing | Reactive on 401 **and** proactive up to 5 min before expiry | same | undocumented (**U-09**) | Access-token TTL **must exceed 5 min** or proactive refresh thrashes. 30–60 s idempotency window is mandatory, not optional |
| C-20 | Refresh error code | Explicitly requires `invalid_grant`, "not `invalid_request` or a custom code" | same | standard | `invalid_grant`, HTTP 400 |
| C-21 | Refresh rotation | Required (public client) | required | required | "If you rotate, return the new refresh token in the same response that invalidates the old one" |
| C-22 | `offline_access` | Appended **only if** listed in **AS metadata** `scopes_supported` | same | undocumented (**U-09**) | List it in AS metadata. MCP says resources **SHOULD NOT** list it in PRM `scopes_supported` — putting it there is the common mistake |
| C-23 | Scope source | `scope` from the 401 `WWW-Authenticate`, else PRM `scopes_supported` | same | PRM `scopes_supported` + auto-added OIDC scopes | **Never advertise a scope any valid client would be refused** — ChatGPT requests every advertised OIDC scope by default and fails with `invalid_scope` if you reject one |
| C-24 | Scope step-up | `403` + `error="insufficient_scope"` + `scope=` triggers re-auth; any other `403` is terminal | same | **No MCP-side mechanism.** `_meta["mcp/www_authenticate"]` with `isError: true` is **SEP-1489, draft** — absent from the `2025-11-25` and `2026-07-28` schemas, where the substring `authenticat` does not occur at all. Measured 2026-08-25, `mcp-tool-challenge-2026-08-25.md`. A per-tool refusal that wants to be actionable uses the `403` in the first column | Grant exactly the requested set; support re-consent that **widens** a grant without revoking it. 403 challenge cached per user/server ~15 min, most-recent-wins |
| C-25 | 401 handshake | `401` is **required** — "Claude does not honor a `WWW-Authenticate` header on a `200` response". A `200` + `isError:true` produces **no auth prompt at all** | same | same; "Both `error` and `error_description` required to trigger authentication UI" | Gate before the JSON-RPC message reaches the MCP SDK. Emit `error="invalid_token"` + `error_description` even on the no-credentials case |
| C-26 | PRM discovery | Header first; fallback probes `/.well-known/oauth-protected-resource/<path>` **then** root | same | root form documented; path-inserted **U-01** | Serve **both** shapes |
| C-27 | PRM `authorization_servers` | Uses **only the first entry**, no fallback | same | undocumented | List the primary issuer first |
| C-28 | PRM `resource` | "must match your MCP server URL **exactly as the user enters it** in Claude, including any path" | same | RFC 9728 §3.3 identity rule | Emit the deployed URL exactly; document the trailing-slash convention |
| C-29 | Latency budgets | **10 s** discovery/registration/token; **30 s** refresh — terminal even if the server later completes | same | **U-10** (undocumented) | CIMD fetch happens *inside* `/authorize`: budget ≤2 s, serve stale-on-error. No synchronous migrations, JWKS re-fetch, or Argon2 on `/token`. Disable response buffering. Warn-log at 25 % of budget |
| C-30 | Discovery caching | Global, keyed by URL, ~5 min staleness, lazy refresh, **serves stale on failure** | same | undocumented | `Cache-Control: max-age=300`. Expect ~5 min propagation for metadata changes |
| C-31 | Network | Egress `160.79.104.0/21`; **IPv4-only** (an `AAAA`-only host is unreachable); every resolved address must be globally routable; a 3xx to a different host drops `Authorization` | same | **U-11** | The AS host must be WAF-reachable from the same range as the MCP server — a WAF in front of the IdP breaks the flow even when the MCP server is fine. **This is the #1 field failure mode.** Publish an `A` record |
| C-32 | Enterprise Managed Auth | `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` + `assertion`. Requires the URN in `grant_types_supported` to be *offered*. **Incompatible with DCR** (the IdP stamps a fixed `client_id`) | — | — | Per-tenant issuer allowlist; an assertion whose `iss` is not on it MUST be rejected with `invalid_grant` even if the signature is valid. Accept the request with or without `resource`. Another reason CIMD is the default |

---

# 7. Auth0-trap requirements (restated positively, with acceptance criteria)

Each row is a place a market-leading IdP cost real hours. Each becomes a **default**, with a test.

| ID | Positive requirement | Acceptance criterion (executable) |
|---|---|---|
| A-01 | Honour RFC 8707 `resource` natively on `/authorize` and `/token` and bind `aud` from it. Never require a proprietary `audience` parameter | Authorize + exchange with only `resource=` set ⇒ the issued token's `aud` equals it byte-for-byte |
| A-02 | No implicit default audience when `resource` is present. A configured default applies **only** when `resource` is absent, and emits a warning log | Two resources registered; omit `resource` ⇒ warning logged and the documented default used. Send an unknown `resource` ⇒ `invalid_target`, **never** a silently-defaulted token |
| A-03 | A validly registered / CIMD-resolved client needs **no out-of-band grant** to run a user-consent flow. User consent *is* the authorization. Client-level API grants exist only as optional policy, off by default | Fresh CIMD `client_id` never seen before, zero admin steps ⇒ `/authorize` returns 302 |
| A-04 | Metadata is generated from live configuration; a disabled feature removes its key | Toggle DCR off ⇒ `registration_endpoint` absent from **both** well-known documents in the same process, no restart needed |
| A-05 | Advertise exactly one client-acquisition mechanism. Config validation rejects ambiguity by name | Config with both CIMD and DCR ⇒ **startup fails** with a message naming the offending pair |
| A-06 | CIMD is on by default and advertised | Fresh install ⇒ `"client_id_metadata_document_supported": true` in both documents |
| A-07 | Resolve any well-formed CIMD `client_id` on first sight, with no import step. On genuine resolution failure answer **`invalid_client`** (not `invalid_request`) with an `error_description` naming which check failed | Never-seen CIMD URL ⇒ 302, zero admin steps. Malformed document ⇒ `invalid_client` + a description identifying fetch / self-reference / redirect-mismatch |
| A-08 | CIMD creates **no per-connection persistent client record**. Any DCR support is quota-limited, TTL-expiring, and GC'd | 100 sequential connects via CIMD ⇒ client-table row count unchanged |
| A-09 | Every rejection is logged with a correlation id, on **every** path including admin/quota rejections, and the id is returned in `error_description` or an `X-Request-Id` header | Force each rejection class ⇒ each emits exactly one structured log carrying a correlation id that appears in the response |
| A-10 | No two-tier connection model. Every configured identity source is usable by every valid client unless explicitly restricted; restrictions surface as a specific, user-visible error | Fresh install, CIMD client ⇒ all configured connections offered |
| A-11 | A configured-but-unavailable login method renders a **disabled control with a stated reason**, never silently vanishes | Disable a connection for a client ⇒ the login page states why |
| A-12 | `/authorize` failures render the OAuth error code and a safe description **in the response body**. `curl` alone must be a sufficient debugging tool. That description is for the client's author and stays English — §4.1.2.1 permits no character outside `%x20-21 / %x23-5B / %x5D-7E` — so the page carries a **second**, localized sentence above it for the person reading it, chosen by what they can do about the refusal | `curl -D-` on each failure class ⇒ code + description present in the body. On a non-English deployment ⇒ the reader's sentence is translated and the description is not, labelled and in `lang="en"` |
| A-13 | Scope strings are normalized and validated **on write**: trimmed, internal whitespace and non-printable characters rejected, duplicates rejected | Configure `"story:read "` (trailing space) ⇒ rejected at write time with the offending codepoint named |
| A-14 | Consent renders each scope's **configured human description verbatim**. Never derive consent text by parsing the scope name | A scope with a description ⇒ that exact string on the consent page. A scope without one ⇒ the raw scope plus a configuration warning |
| A-15 | Correct consent rendering is the **only** behaviour — no opt-in flag | No configuration key exists to disable A-14 |
| A-16 | Config writes are all-or-nothing and read-back-verified; unknown keys are rejected loudly, never silently dropped | PATCH with an unknown key ⇒ 400 naming the key |
| A-17 | Every config key is enumerable via an introspection endpoint with type, allowed values, default, and current value; validation errors name allowed values | `GET /admin/config/schema` lists every key |
| A-18 | `sub` is opaque and never used raw as a path segment, filename, cache key, or SQL identifier. A stable tenant id distinct from `sub` is exposed. The `sub` charset we emit is documented | `sub` containing `/`, `..`, `\|` ⇒ tenant id unaffected, no traversal, no cache-key collision. (CIMD `client_id` values contain `:` and `/` — encode before use in a route or cache key) |
| A-19 | Port-agnostic loopback matching for `127.0.0.1`, `::1`, **and** `localhost` | Register portless, request `:51004` ⇒ accepted. Non-loopback host with a differing port ⇒ rejected |
| A-20 | CIMD is the default, so there is no untestable pre-flight credential-exchange path. Pre-provisioned clients remain supported for customers who need them | End-to-end test runs with zero out-of-band credential exchange |
| A-21 | Serve **both** `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` with identical bodies, plus the three path-insertion/appending shapes for path-bearing issuers | All five URLs return 200; `diff <(jq -S .) <(jq -S .)` is empty |
| A-22 | Any HTTPS URL **including a path component** can be registered as a resource identifier — no proprietary namespace, no separate "expose an API" ceremony (cf. Entra's `api://{client-id}` and `AADSTS9010010`) | Register `https://mcp.example.com/mcp` ⇒ tokens issue with exactly that `aud`. Comparing `aud` to the request **origin** only is a shipped real-world bug (cloudflare/workers-oauth-provider #108) that broke ChatGPT custom connectors |

**Cross-cutting principles these 22 rows encode:** metadata derived from live config, never
hand-maintained (A-04/05/06/21) · advertised capability == actual capability, enforced at startup
(A-04/05/06/07) · every failure legible from `curl` with a correlation id (A-09/12/17) · no hidden
flags for correct behaviour (A-14/15) · no admin action per connection (A-03/07/08/20) · normalize on
write, compare exactly on read (A-13/19/22).

---

# 8. Explicitly deferred

| ID | Not in v1 | One-line reason | Seam that must exist now |
|---|---|---|---|
| D-01 | **PAR (RFC 9126)** | Absent from the entire MCP authorization spec; neither vendor sends `request_uri`; advertising `require_pushed_authorization_requests: true` would break both immediately | ~~**`IAuthorizationRequestSource`** in `/authorize`, with `QueryStringSource` as the only v1 implementation. Adding `ParRequestUriSource` is then additive.~~ **The seam does not exist.** Neither name appears anywhere in `src/` or `tests/`; `/authorize` reads its parameters directly in `AuthorizeEndpoint.ReadRequest`, and `docs/DESIGN.md` §3.3 records the same absence from the design side. This row said the deferral was *the one that costs real rework later* — FAPI 2.0 requires PAR, so regulated customers will ask — and then named a mitigation that was never built, which makes the cost the whole of it rather than the additive part. **This column is what a deferral is worth**, so a seam named here and absent from the tree is worse than an undeferred feature: it is the same work, plus a document saying it was handled |
| D-02 | **DPoP (RFC 9449)** | Not in the MCP spec; both vendors send `Authorization: Bearer`; issuing `token_type: DPoP` breaks them outright. RFC 9700 §2.2.1 is a SHOULD and §2.2.2's MUST is discharged by rotation (N-08) | Keep the access-token minting path pluggable so a `cnf`/`jkt` claim can be injected without restructuring. **Advertise nothing DPoP-related** — an advertised `dpop_signing_alg_values_supported` invites proofs we would reject. Guarded on three sides: `MetadataTests.The_document_advertises_nothing_dpop_related` (prefix match over the AS document), `ProtectedResourceMetadataEndpointTests.Optional_members_that_are_not_configured_are_absent` (the two named RFC 9728 members), and `CimdClientResolverTests.No_captured_vendor_document_asks_for_dpop` — **the tripwire**, which reads the dated `spec/cimd-live-*.json` captures and goes red when a vendor starts advertising RFC 9449 §5.2's `dpop_bound_access_tokens`. The first two say we have not shipped it; the third says nobody is asking for it yet, and it is the one with an expiry date |
| D-03 | **mTLS client auth / certificate-bound tokens (RFC 8705)** | No consumer-connector demand; requires ingress-level cert plumbing | The `token_endpoint_auth_method` dispatch is a strategy interface; add `tls_client_auth` as another strategy |
| D-04 | **Token Exchange (RFC 8693)** | Not used by either vendor. Note it is the only spec where `audience` is a standard parameter, and only at `/token` | The grant dispatcher is table-driven on `grant_type`; `resource`/`audience` parsing already returns `string[]` |
| D-05 | **Rich Authorization Requests (RFC 9396)** | No demand; `scope` + `resource` covers the MCP model | `authorization_details_types_supported` simply stays absent; the grant record already carries an extensible property bag |
| D-06 | **Device Authorization Grant (RFC 8628)** | No MCP client uses it | Grant dispatcher (D-04) plus a second user-interaction surface — additive |
| D-07 | **Step-Up Authentication Challenge (RFC 9470)** | The MCP step-up story is scope-based (`insufficient_scope`), already covered by X-34 | `acr`/`auth_time` are already first-class on the session and in the ID Token |
| D-08 | **OIDC Session Management 1.0** | Defeated by browser storage partitioning; works in dev (same-site), fails in prod (cross-site) | Omit `check_session_iframe`. If multi-RP logout propagation is ever needed, build **Back-Channel Logout** instead |
| D-09 | **Front-/Back-Channel Logout** | No v1 customer requires multi-RP logout propagation | Session records already carry `sid` and the set of clients that used the session |
| D-10 | **Federation beyond a single upstream (Google)** | Multiple upstream IdPs multiply the `sub`-disambiguation surface: a second issuer or an enterprise/SAML connection is exactly when `identity.ts`-style disambiguation becomes necessary | Local `sub` is minted by us, never passed through from upstream. A `(upstream_issuer, upstream_subject) → local_sub` mapping table exists from day one, even with one row per user |
| D-11 | **Pairwise subject identifiers** | `subject_types_supported: ["public"]` is sufficient for both vendors | ~~`sub` is produced by an `ISubjectIdentifierService` taking `(user, client)`~~ — **there is no seam, and this column claimed one for a release.** The interface existed and nothing on the token path ever called it: `TokenIssuer` takes `grant.Subject`, a `SubjectId`, and `/userinfo` takes `account.Subject`. Its signature could not have been wired without loading a `UserAccount` per token issuance, which the token path does not do — so it would not have saved the hunt it existed to prevent. Deleted 2026-08-22 on the precedent the top-level README sets for the JavaScript layer: the one nobody uses is the one that will be wrong when somebody finally does, and this one already was. **What pairwise actually costs now:** threading `(subject, client)` through `TokenIssuer` and `UserInfoEndpoint`, a stable per-client salt treated as permanent once set — rotating it changes every `sub` and breaks every relying party — and `subject_types_supported` moving off `["public"]`. It is in the history if it is ever wanted |
| D-12 | **`claims` request parameter, `request`/`request_uri` (JAR)** | No demand; we publish `false` for all three, which is the conformant way to decline | If JAR is added, note RFC 8707 §2.1: inside a request object `"resource"` is `string \| string[]`, so it must bind to a `JsonElement` union |

---

# 9. Open questions / UNVERIFIED

Honest list. Nothing here should be turned into a confident requirement without a live measurement.

| ID | Question | Status | Risk if we guess wrong | How to resolve |
|---|---|---|---|---|
| U-01 | Does ChatGPT probe the RFC 9728 **path-inserted** PRM form (`/.well-known/oauth-protected-resource/mcp`) before the root form? | **UNVERIFIED.** OpenAI's docs only ever show the root form; Claude's docs explicitly document trying path-inserted first | None if we serve both | Mitigated by design: serve both (E-22, E-23). One extra route |
| U-02 | **CIMD vs DCR precedence when both are advertised.** MCP 2026-07-28 ranks CIMD above DCR; a field measurement on a live Auth0 tenant recorded **DCR winning**, and the fix was to disable DCR entirely | **CONFLICTING PRIMARY SOURCES.** Spec text vs one measurement | High: silent connection failure that looks like a client bug | Resolved defensively by N-06 (advertise exactly one, refuse to boot on both). **Re-measure once against our own AS** with both advertised, then decide whether the constraint can be relaxed |
| U-03 | Does Claude's PRM/metadata fetch tolerate `Content-Type: application/json; charset=utf-8`? | **UNVERIFIED** — not stated in any fetched doc | Low; a charset parameter is standard | Assume yes; test with a live client before submission |
| U-04 | Is ChatGPT's `{callback_id}` redirect path stable per connector instance across re-authorization? | **UNVERIFIED.** Vendor doc implies per-connector, not per-session | Medium: caching a registered redirect URI could go stale | Verify before caching a resolved redirect URI; re-read the CIMD on every authorization if in doubt (the 300 s cache floor makes this cheap) |
| U-05 | Does ChatGPT validate the RFC 9207 `iss` parameter in the authorization response? | **UNVERIFIED** | None — emitting it is harmless and MCP-recommended | Emit unconditionally |
| U-06 | Is `resource_indicators_supported` read by anything? | **NOT SPEC-BACKED.** RFC 8707 registers no metadata field; the IANA registry has no such entry | None if we don't rely on it | Emit as a courtesy; never branch on a client reading it |
| U-07 | Would ChatGPT accept `ES256` for `private_key_jwt` if we advertised only that? | **UNVERIFIED.** Its CIMD declares `token_endpoint_auth_signing_alg: RS256` | Medium: advertising ES256-only could lock ChatGPT out | Always support RS256; advertise `["RS256","ES256"]` |
| U-08 | Correct `aud` for an RFC 7523 client assertion: token endpoint URL or issuer identifier? | **AMBIGUOUS IN THE SPEC.** RFC 7523 §3 only requires "its own identity"; implementations disagree | High: `invalid_client` with no useful diagnostics — a very common failure | **Accept both** the issuer identifier and the exact token endpoint URL (RFC 9126 §2 endorses exactly this tolerance) |
| U-09 | ChatGPT's refresh-token semantics: lifetime expectations, proactive vs reactive refresh, whether it requests `offline_access` | **UNVERIFIED.** Its CIMD declares the `refresh_token` grant, so it can refresh; no documented semantics | Medium: a too-short refresh TTL or a too-tight reuse window could disconnect ChatGPT users | Apply Claude's documented behaviour (proactive ≤5 min early, reactive on 401) as the design envelope for both; instrument refresh intervals in production |
| U-10 | ChatGPT's OAuth timeouts | **UNVERIFIED.** Anthropic publishes 10 s / 30 s; OpenAI publishes nothing | Low if we hold Claude's budget | Design to the stricter Claude budget (C-29) |
| U-11 | ChatGPT's egress IP ranges | **UNVERIFIED.** OpenAI publishes none | Medium if a customer runs a default-deny WAF | Do not build an IP allowlist as a required control; document that a default-deny WAF in front of the AS will break ChatGPT with no way to allowlist |
| U-12 | Is `prompt` ever sent by Claude? | **HIGH CONFIDENCE NOT SENT** — absent from all Anthropic docs and from a measured live request. (The `prompt=consent` seen in the field report was an engineer's own curl probe) | High if we *require* it | Treat as optional; never require. Handle it correctly if it appears (X-12..X-15) |
| U-13 | Three OIDC Core passages could not be reproduced verbatim by the fetcher (copyright refusal) and were assembled from partial quotes plus the errata-set-1 mirror: the full `azp` bullet in §2, §15.1's mandatory-feature list, and §5.3.3's `WWW-Authenticate` example | **PROVENANCE GAP** | Low–medium: `azp` emission rules and the OIDC mandatory-feature list | Re-read the primary text before freezing `azp` behaviour. Interim posture is already safe: keep `aud` a single string and **omit `azp` entirely** |
| U-14 | RFC 9700 §4.14.2's two rotation bullets were quoted from the identical passage in `draft-ietf-oauth-security-topics-16` §4.13.2 because `rfc-editor.org`'s render truncated before §4.14. The key revocation sentence was cross-verified against the published RFC | **PROVENANCE GAP** (low) | Low — the substance is corroborated by OAuth 2.1 §4.3.1, which we quote directly | Re-verify against the RFC text file, not the HTML render |
| U-15 | OAuth 2.1 is **draft-15, not an RFC.** WG state is "I-D Exists", not yet in IESG processing; the milestone to submit to IESG is Dec 2026, and the draft expires 3 Sep 2026 | **MOVING TARGET** | Medium: normative text may change before publication; §4.1.3 vs §7.5.1.1 is already internally contradictory (see the "conformance deviations" note in §1) | Cite the exact draft revision in all our docs, never "OAuth 2.1" unqualified. Pin a copy of `draft-ietf-oauth-v2-1-15.txt` in the repo. Re-diff on each new revision, and `pinned-drafts.yml` is what says when: it asks the datatracker weekly and goes red on a revision, so this line stopped being an instruction nobody is prompted to follow |
| U-16 | CIMD is **draft-02** (6 Jul 2026) but the MCP spec still links **-00**, and section numbers moved between them | **VERSION SKEW** | Medium: following MCP's section references lands on the wrong text | Use the -00↔-02 section mapping table in `client-id-metadata-document.md`. Implement to **-02**; -02's §4 has an open `TBD` for `client_id_expires_at` — do not implement it, but do not choke on it |
| U-17 | Whether a strict CIMD **same-origin** policy between `client_id` and `redirect_uris` is safe to ship as a default | **PARTIALLY RESOLVED.** Both vendors' HTTPS redirect URIs are same-origin with their `client_id` — but **Claude Code violates it** (`client_id` host `claude.ai`, redirect host `localhost`) | High: a naive same-origin default breaks Claude Code | Ship it as: HTTPS redirect URIs MUST be same-origin with the `client_id` URL; **loopback redirect URIs are exempt**. Plus an admin allowlist escape hatch (CIMD Appendix A recommends an exempt path for developers) |

---

# 10. Live measurement, 2026-08-03 — corrections to §6 and §9

All four CIMD documents fetched directly. Bodies recorded verbatim in
[`spec/cimd-live-2026-08-03.json`](./cimd-live-2026-08-03.json) — the captures live beside this file,
not under `research/`, and `spec/cimd-live-2026-08-17.json` is the later one `D-02`'s tripwire also
reads. Three rows above are **wrong or overstated** and are
corrected here; this section wins on conflict.

| Row | Said | Measured | Correction |
|---|---|---|---|
| C-03 / C-05 | ChatGPT **requires** `private_key_jwt`; a `none`-only AS locks it out | ChatGPT declares `"token_endpoint_auth_methods_supported":["none","private_key_jwt"]` — **both** | ChatGPT can authenticate as a public client. Supporting both is still right, but `private_key_jwt` is **not** a lockout risk. Downgrade "REQUIRED by ChatGPT" to "offered by ChatGPT" |
| C-06 / U-04 | ChatGPT redirect is a template `https://chatgpt.com/connector/oauth/{callback_id}` | Concrete: `https://chatgpt.com/connector_platform_oauth_redirect` and `https://chatgpt.com/connector/oauth/mcp` | Both are exact-matchable literals from the document. No template handling needed. U-04 drops to low risk |
| U-03 | Charset tolerance on metadata fetch unverified | `chatgpt.com` serves `application/json; charset=utf-8`; `claude.ai` serves bare `application/json` | **Resolved: tolerating a charset parameter is mandatory.** A fetcher comparing the Content-Type by equality against `application/json` rejects every ChatGPT document. Parse the media type, ignore parameters |

**Confirmed unchanged by measurement:** Claude Code declares portless `http://localhost/callback`
and `http://127.0.0.1/callback` (N-04/A-19 are real, not theoretical) · Claude declares the
`jwt-bearer` URN, Claude Code does not (C-32) · Claude uses RFC 7591's singular
`token_endpoint_auth_method`, ChatGPT uses the plural RFC 8414 *server* field name — C-04's
field-name defect is real and both spellings must be read · no document declares `scope` ·
ChatGPT declares a `logo_uri` on a third-party CDN host, so N-14's proxy-never-hotlink rule has a
live case on day one.

---

# 11. User management

These are the requirements for the design in
[`docs/USER-MANAGEMENT.md`](../docs/USER-MANAGEMENT.md), written here rather than only cited there
because a load-bearing cross-reference in these documents already pointed at a section that does not
exist — `DESIGN.md` §7, cited twice as the traceability test that fails the build for an uncovered
requirement. That test still does not exist; `DESIGN.md` §0 and §6 now say so at both ends.

~~Not built. … **The mechanical guards below are ones that must be built, not ones that exist.**~~
**It is built and it ships.** `AdminEndpoints`, `AccountEndpoints`, `MeEndpoints` and
`RecoveryEndpoints` are mapped, `IScopeEntitlementPolicy` and `IAdminAuditStore` are seams in
`Boltway.AuthorizationServer.Abstractions`, and `UserAdministration` is the single implementation
`S-53` asks for. `N-17`'s guard is `AdminSurfaceTests`, over the routing table, as its own row
specifies.

**That header was contradicting its own table**, which is the reason it is corrected rather than
quietly rewritten: rows below it carry measurements taken *on the running code* — `S-45`, `S-52`,
`S-55`, `S-56`, `S-57`, `S-58`, `S-59`, `S-60` and `S-62` all do — while the preamble above them
still said the guards were unbuilt. A reader who trusted the header would have read every one of
those measurements as a plan. `S-55` and `S-56` are the two that had not been brought forward and
are corrected in this pass: both recorded an absence that has since been filled, in the present
tense.

**Read each row for what its own guard is**, because they are not uniform and the differences are
recorded deliberately. `S-45` says append-only is built and the same-transaction half is not, and
names the window rather than assuming it closed. `S-59` is met for the interaction seams and not for
the stores, with the feed measurement in its row rather than a sentence claiming either.
`S-60` is explicit that "signed out everywhere" is true one access-token lifetime later.

Grouped in one section rather than merged into §2 and §5 because the subsystem was unbuilt when it
was written. ~~They move to their kind's section when it ships.~~ It has shipped and they have not
moved, so that sentence is a pending edit rather than a rule — an id keeps its number wherever the
row sits, so nothing is broken by the delay, but nothing is served by it either.

## 11.1 Non-negotiable

| Rank | ID | Requirement | If wrong | Mechanical guard |
|---|---|---|---|---|
| — | **N-17** | **No `/admin/*` or `/account/*` endpoint may be reachable with a cookie principal. Bearer only.** | The sign-in pages share the origin. A cookie-authenticated admin API turns any XSS or CSRF against the login page into takeover of the whole directory rather than of one session. Bearer-only also removes CSRF by construction — there is no ambient credential to attach | Architecture test over the routing table: every endpoint under those prefixes carries the bearer policy and no cookie scheme. Not a review convention — `DESIGN.md` gives the reasoning for why the sixteen `N-nn` have guards |

A deployment may add a second layer by serving the admin API from its own hostname: ASP.NET Core's
cookie handler sets no `Domain`, so the session cookie is host-only and the browser will not carry
it across. That is a deployment choice and cannot be a library requirement — `N-17` and its test are
what hold when a deployment serves both from one host.

**The rule is about those two prefixes, and self-service pages live under a third.** A person
changing their own password cannot be made to run an OAuth client, so `/me/*` (`E-46`) is a
cookie-authenticated interaction page like `/consent`, with antiforgery, calling the application
service in process rather than calling `/account/*` over HTTP. That is a different rule, not a hole
in this one: `N-17` exists because an XSS on the login page would otherwise reach `users:write`,
which is everyone, while `/me/*` reaches exactly the account already signed in and `S-49` makes a
password change require the current password. The test stays mechanical because the prefixes are
disjoint — nothing under `/admin/` or `/account/` may carry a cookie scheme, nothing under `/me/`
may carry bearer.

## 11.2 Spec

| ID | Requirement | Why |
|---|---|---|
| **S-44** | The scope entitlement filter runs at `/authorize` **and again at token issuance** | A consent granted while someone was entitled must stop minting the scope when they are not. Once is a grant that outlives the entitlement |
| **S-45** | Every administrative mutation writes its audit entry **in the same transaction** as the change, and the audit table is append-only through every surface. **Append-only is built; the same transaction is not** — measured: every relational store creates its own `DbContext` per call, so two cannot share one, and closing that means giving the storage layer an ambient context and changing the lifetime and thread-safety of every write in a directory holding live credentials. The entry is written immediately after the change and the window is named in `IAdminAuditStore.RecordAsync` rather than assumed closed | A change that lands without its line is a half-state whose surviving half is the invisible one. An audit log an administrator can edit proves nothing about administrators |
| **S-46** | Every lookup by a human-chosen key filters on `RealmId`; the username index is `(realm, username_normalized)` | A column that exists and is not enforced reads as tenancy and is not — the `A-09` shape. Enforcing it with one realm configured is what makes multi-tenancy a config change rather than an audit of every query |
| **S-47** | Reset and verification tokens are single-use, hashed at rest, expiring (15 min / 24 h), and **all outstanding reset tokens for a subject are destroyed when its password changes by any route** | An old link that still works after a reset is a second key to the account |
| **S-48** | `POST /account/password/forgot` returns the same response and performs the same work whether or not the account exists | Otherwise the endpoint is an oracle for which addresses are registered, in both the body and the timing |
| **S-49** | `POST /account/password` requires the current password even with a valid bearer token | A stolen token should not be convertible into a permanent credential |
| **S-50** | A reset completed through email revokes every refresh family for the subject. An operator `set-password` does not, unless `--revoke-sessions` | Different reasons: self-service reset usually follows a loss of control; an operator resetting for a colleague who forgot is not responding to a compromise, and signing them out of every device is a surprise |
| **S-51** | Accounts are disabled or anonymised, never deleted. Anonymise keeps the subject row | Deleting a subject with outstanding grants leaves dangling references, and erasure that empties the audit trail is erasure the audited party can order |
| **S-52** | The resource server reads its verification keys through a **source evaluated per validation**, never a collection mutated in place while requests read it. The AS host's source is the local `SigningKeyRing` — public halves only — never an HTTP fetch of its own JWKS | Measured, on the code as it then stood: `JwksRefresher` called `Add`/`Remove` on the same `IList<SecurityKey>` that `AccessTokenValidator` passes into validation, from a background timer, unsynchronised — a rotation was therefore a concurrent mutation during enumeration. That type no longer exists; `JwksKeySource` publishes a new snapshot and `SigningKeySource` is read per validation, which is what closed it. And an authorization server that fetches its own JWKS over its own edge has made startup depend on the component most likely to be broken when it matters |
| **S-53** | Every administrative operation has **one implementation**, called by both the CLI and the HTTP handler. Neither caller holds the rule, the password generator, or the audit write | Two implementations of one operation drift, and the half that drifts first is the audit line on the operator path — the path used during an incident. The connector's schema pair next door drifted in about a month |
| **S-54** | The admin API is a distinct resource with a distinct `aud`. No access token is ever valid at both an MCP connector and the admin API | A document connector ingests third-party documents verbatim and a model reads them. A token valid at both surfaces turns a sentence inside an ingested document into privilege escalation against the user directory. `N-01` is the mechanism; this is the deployment rule that keeps it load-bearing |
| **S-55** | Every page the server renders goes through `IInteractionRenderer`, `/error` included | ~~Measured: login and consent go through the seam and `/error` does not.~~ A customer who implements the renderer restyled two pages of three and found out from a screenshot. **Closed, and by the mechanism this row asked for**: `IInteractionRenderer` now carries `RenderError` — and `RenderLogout`, `RenderAccount`, `RenderChangePassword`, `RenderSessions` and the rest — as **default interface members**, so widening the seam does not break existing implementations. `RejectionResult` calls `RenderError` for the error page. Two things the defaults do not hide, both deliberate: a default member has no dependency injection, so it draws the library's *unthemed* shell rather than the deployment's registered layout — a visible mismatch that is the signal to write the page — and `/error` renders where something has already failed, so its caller wraps the call in a `try` and writes a built-in document if the implementation throws |
| **S-56** | A signed-in person can sign out | ~~Measured: no `Logout` endpoint and no `SignOutAsync` call anywhere in `src`.~~ The session ended when the cookie expired or the browser closed, which on a shared machine is not an option the person has, and `N-15`'s acceptance criteria already named `/logout` among the pages whose headers are asserted — against a page that did not exist. **Shipped.** `InteractionEndpoints` maps `GET` and `POST /logout`, `IUserSignIn.SignOutAsync` is called from there and from `/me`, `LogoutFlowTests` asserts the flow including `N-15`'s headers, and `E-45` is the row. **It is mapped if and only if `EndSessionEnabled` is set** — the same switch that decides whether `end_session_endpoint` appears in the metadata document, which is `N-06` rather than a convenience: the page and the advertisement cannot disagree because one condition governs both |
| **S-57** | Page text goes through `IStringLocalizer` over a dictionary a deployment supplies — **constants and explicit per-string English fallback, not an embedded resx**, because satellite assemblies belong to the assembly owning the resource file and a consumer cannot add a language to ours. Startup instead refuses a translation whose placeholders do not match the English arity, which is the failure a resx could not have caught: a `ConsentClientAsking` without `{0}` renders a grammatical sentence with the client's host silently absent. `ui_locales_supported` and `RequestLocalizationOptions.SupportedUICultures` are **compared at map time** and a mismatch in either direction refuses to start. Stronger than generating one from the other: it catches an advertised locale nobody serves *and* a served locale nobody advertises, and it does not care which configuration call ran first | Measured when written: there was no lookup and no reader of `ui_locales` anywhere in `src`, so a deployment could advertise `vi` and serve English to everyone who asked. Both halves are closed — the reader is `UiLocalesRequestCultureProvider`, the advertise/serve comparison is `RequireAdvertisedLocalesAreServed`, and `InteractionText.Problems` is the placeholder check. The resx was not built and is not wanted: Measured on .NET 10: with a neutral resx present, a key missing from `vi` resolves to English with `ResourceNotFound=false` — the key is returned only when the name is in no resource file at all, which the startup assert is for |
| **S-58** | Culture resolution is `UseRequestLocalization` with `SupportedUICultures` as the allowlist and a custom `RequestCultureProvider` for OIDC `ui_locales`. The choice survives `/authorize` → `/login` → `/consent` because `AuthorizeEndpoint.LocalReturn` appends the **resolved** culture to the interaction URL, where the framework's `QueryStringRequestCultureProvider` reads it back. `<html lang>` carries `CurrentUICulture.Name`, and `dir="rtl"` accompanies it for a right-to-left primary subtag | Framework components, not new mechanism: the middleware already matches against the supported list and falls back to the default, so a query parameter never becomes a `CultureInfo`. **This entry named `CookieRequestCultureProvider` as what carried the choice, and nothing in the tree has ever written that cookie** — measured: `/authorize?…&ui_locales=vi` answered an English login page, because `/authorize` percent-encodes its whole query into one `returnUrl` value and no parameter named `ui_locales` survives to the page. Forwarding the resolved culture is what closed it; emitting the resolved rather than the requested one is what keeps `ui_locales` out of the document |
| **S-60** | Revoking a subject's sessions is **one set operation on the grants**, never enumerate-then-revoke, and no response or message anywhere claims the person is signed out. `IGrantStore.RevokeAllForSubjectAsync` returns how many grants *that call* transitioned | Two separate failures. Enumerate-then-revoke leaves a window in which a grant created in between survives, and this runs precisely when somebody is responding to a compromise. And the reach is partial by construction: refresh chains die with the grant — measured, the refresh handler loads it and refuses when it is not active — while an access token already issued is signed rather than looked up, and `IsRevokedAsync` is called by nothing in this repository. "Signed out everywhere" is true one access-token lifetime later, and an operator acting on it now is the person who most needs that stated |
| **S-61** | Anonymise revokes sessions **before** it rewrites the account, and the account row is never deleted | These are two writes and no store here can make them one. Anonymising first and dying in between leaves a tombstone whose refresh tokens still mint — a session belonging to somebody the directory says is gone. This order leaves an ordinary account whose owner has been signed out, which is visible and rerunnable. The row stays because erasing a subject with outstanding grants leaves dangling references, and a trail the audited party can empty is not a trail |
| **S-59** | The interaction contracts are **published**, so a customer taking the renderer or layout seam can run the suite that defines it | ~~`Boltway.Interaction.Tests` is already `IsPackable=true` … and no such package is published anywhere.~~ **Both halves of that were wrong, and the resolution is not where it said.** `tests/Boltway.Interaction.Tests` is `IsPackable=false`; what carries the contracts is `testing/Boltway.Interaction.Testing`, a separate project holding `InteractionRendererContract` and `InteractionLayoutContract`, and it is **published** — `Boltway.Interaction.Testing` answers 0.1.0 on nuget.org, measured 2026-08-23 by `curl https://api.nuget.org/v3-flatcontainer/boltway.interaction.testing/index.json`. The reason quoted from the csproj is intact and now sits on the project that ships. **The requirement is met for the renderer and layout seams and not for the stores**: `testing/Boltway.Storage.Testing` holds seven store contracts, packs, and returns `BlobNotFound` on the same feed at the same measurement — while `Boltway.Storage.Tests`, which is `IsPackable=false` today, is on the feed at 0.1.0 from when it was not. `InteractionRendererContract` asserts `N-14`'s hostname display, the loopback warning, both antiforgery fields, single-encoding of non-ASCII text and CSP conformance, and asserts none of it about wording, so it is the thing that makes handing the consent page to a customer safe rather than hopeful |
| **S-62** | The sign-in form accepts a username **or** a verified email address. Exactly one store method resolves an account by address, it requires `EmailVerified`, and **only the sign-in form may call it** | `/forgot` accepted an address and `/login` did not, so somebody who reset their password by email could not then use that address to sign in — measured, and reported by a user rather than by a test. The lookup this needs is the one federation must never have: an attacker who registers the victim's address at an upstream that does not verify it must not inherit the account. That used to be guaranteed by the method not existing, which is the strongest form and is now spent. It is replaced by two rules — the interface may carry exactly one lookup by address and it is the verifying one (`ExternalLoginFlowTests`, by reflection, asserting the *name* rather than a count), and the IL may contain exactly one caller (`StructuralRuleTests.Only_the_sign_in_form_resolves_an_account_by_address`). Both carry a control that fails if the thing they search for is renamed, because an absence assertion whose subject disappeared reports a pass |

## 11.3 Endpoints

`users:read`, `users:write`, `users:self`, and — added after this section was written —
`roles:read` and `roles:write`. Routed or absent, never advertised-and-404 (`N-06`).
`AdminScopes.Administrative` is the one list `AdminRoleScopePolicy` and the host's admin-resource
registration both read, so a scope is gated and advertised in the same commit or not at all;
`users:self` is deliberately not on it.

| ID | Endpoint | Scope |
|---|---|---|
| E-25 | `GET /admin/users` — keyset paginated, never `OFFSET` | `users:read` |
| E-26 | `GET /admin/users/{handle}` | `users:read` |
| E-27 | `POST /admin/users` — password returned once | `users:write` |
| E-28 | `PATCH /admin/users/{handle}` — role, email, enabled | `users:write` |
| E-29 | `POST /admin/users/{handle}/password` | `users:write` |
| E-30 | `DELETE /admin/users/{handle}/sessions` — revokes every grant; returns the count | `users:write` |
| E-31 | `POST /admin/users/{handle}/anonymise` — tombstone, revoking sessions first | `users:write` |
| E-32 | `GET /admin/audit` | `users:read` |
| E-33 | `GET /account` | `users:self` |
| E-34 | `POST /account/password` | `users:self` |
| E-35 | `GET /account/sessions` | `users:self` |
| E-36 | `DELETE /account/sessions/{grant}` | `users:self` |
| E-37 | `GET /account/consents` | `users:self` |
| E-38 | `DELETE /account/consents/{**clientId}` — catch-all, because a CIMD `client_id` is a URL and contains `/` | `users:self` |
| E-39 | `POST /account/password/forgot` — rate limited per account and per source | public |
| E-40 | `POST /account/password/reset` | public |
| E-41 | `POST /account/email/verify` | public |
| E-48 | `GET /admin/roles`, `POST /admin/roles` | `roles:read` **or** `users:read` to list; `roles:write` **or** `users:write` to create |
| E-49 | `PATCH /admin/roles/{id}`, `DELETE /admin/roles/{id}` | `roles:write` **or** `users:write` |
| E-50 | `GET·POST·PATCH·DELETE /admin/users/{handle}/service-account` — singular, because one account holds at most one | `users:read` to read; `users:write` to mutate |


**E-48, E-49 and E-50 ship and had no rows here.** They are added at the end of the range rather
than inserted, because an id is matched by hand from code comments and renumbering a table is how
a citation silently comes to mean something else. Two things about them are decisions rather than
shape. The role endpoints accept a **narrow-or-broad pair** — `roles:read` is genuinely less
sensitive than `users:read` because a definitions list holds no person, while `roles:write` is
*not* a lesser tier of `users:write`, since redefining a role changes what every holder's next
token may do; it is separate so a credential can be scoped to the role domain, and it is gated
exactly as hard. And the service account is a property of a person rather than a member of a
client collection, which is why it is singular and under the account with no id of its own.
`AuthorizationServerPaths.AdminUserServiceAccount` cites `E-33` in its doc comment, which is
`GET /account` — that citation predates this row and belongs to nothing.

Pages, because a link in an email lands on one and `E-40`/`E-41` on their own mail somebody a URL
that answers `405`. Cookie-authenticated where they need a principal, and under prefixes disjoint
from the two above — see `N-17`.

| ID | Endpoint | Auth |
|---|---|---|
| E-42 | `GET /reset?token=…` — the form | public |
| E-43 | `POST /reset` — sets the password, redirects to `/login` | public |
| E-44 | `GET /verify-email?token=…` — landing page | public |
| E-45 | `GET /logout`, `POST /logout` — `S-56`. Not user management; blocked on nothing | cookie |
| E-46 | `GET·POST /me`, `/me/password`, `/me/sessions`, `/me/consents` — self-service **pages**. `/me` also posts to `E-47` to link a provider | cookie + antiforgery |
| E-47 | `POST /external/{scheme}/start`, `GET /external/{scheme}/callback`, `POST /external/{scheme}/link` — federated sign-in and linking (`D-10`). `link` is submitted from `/me` and checks the session on **both** legs: at `start` so a signed-out person is refused before being sent to an upstream to authenticate for nothing, and at `callback` so the subject that finishes is the subject that began. A link is refused, never re-pointed, when the upstream identity already belongs to another local account | all three anonymous at the route; both POSTs validate antiforgery in the handler; `link` additionally requires a cookie session, twice |

## 11.4 Error

| ID | Condition | Response |
|---|---|---|
| **X-42** | The entitlement filter leaves the requested scope set empty | `invalid_scope`. The client asked for nothing this subject can have; a filtered-to-narrower set is a normal grant and is not an error |

## 11.5 Deferred

| ID | Not in this design | One-line reason | Seam that must exist now |
|---|---|---|---|
| D-13 | **Multi-factor authentication** | A second factor needs a **new table**, and an empty new table is a cheap migration — unlike a `NOT NULL` column on a populated `users` table, which is why `RealmId` is in this design and this is not | None required. The sign-in path already returns a result type rather than a bool, so an additional step is additive |
| D-14 | **SCIM** | A directory-sync protocol is a product, not a feature, and no customer has asked | `IUserStore` is already the whole surface a provisioning adapter would need |
| D-15 | **Impersonation** | "Sign in as this user" defeats the audit trail this design adds, and the incident where it matters is the one where the log becomes ambiguous | Deliberately none |

---

## Appendix — five commands that must pass before any submission

**One expectation here was unsatisfiable and is corrected below.** The second command asked for the
`jwt-bearer` URN in `grant_types_supported`. No deployment can produce that: `KnownGrantTypes` lists
exactly the grants `TokenEndpoint` has an arm for, configuring a name outside it is a **startup
failure** rather than a runtime one, and `OptionsValidationTests.A_grant_with_no_handler_is_refused`
pins the URN by name. So a server that passed this line would be advertising a grant it refuses —
`N-06` — and one that fails it is correct. `S-26`(b) is where the grant's own status lives, and
`C-32` still records that Claude Enterprise Managed Auth needs the URN advertised before the feature
is offered: that is a real client requirement this server does not meet, and the appendix is not the
place to make it look met. Put the line back in the commit that implements RFC 7523's grant.

```bash
ISSUER=https://auth.example.com
MCP=https://mcp.example.com/mcp

# A-21: both discovery documents, byte-equal after canonical JSON sort
diff <(curl -s "$ISSUER/.well-known/oauth-authorization-server" | jq -S .) \
     <(curl -s "$ISSUER/.well-known/openid-configuration"       | jq -S .)

# The seven fields that break Claude if wrong (C-02, C-05, C-09, C-22, C-32, N-06, N-13)
curl -s "$ISSUER/.well-known/oauth-authorization-server" | jq '{
  issuer, code_challenge_methods_supported, token_endpoint_auth_methods_supported,
  client_id_metadata_document_supported, registration_endpoint,
  grant_types_supported, scopes_supported }'
# expect: S256 present; "none" AND "private_key_jwt" present; CIMD true;
#         registration_endpoint ABSENT; offline_access present;
#         grant_types_supported = ["authorization_code","refresh_token"] (+ "client_credentials"
#         only where a deployment enabled it) and the jwt-bearer URN ABSENT.

# C-15: /token parses form encoding -> 400 with an OAuth body, never 415
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$ISSUER/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=invalid&client_id=test'

# A-03/A-07: a never-seen CIMD client works with zero admin steps -> expect 302
curl -s -o /dev/null -w '%{http_code}\n' -G "$ISSUER/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=https://claude.ai/oauth/mcp-oauth-client-metadata" \
  --data-urlencode "redirect_uri=https://claude.ai/api/mcp/auth_callback" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "state=probe" \
  --data-urlencode "scope=story:read offline_access" --data-urlencode "resource=$MCP"

# N-04/A-19: portless registration vs ported request -> expect 302
curl -s -o /dev/null -w '%{http_code}\n' -G "$ISSUER/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=https://claude.ai/oauth/claude-code-client-metadata" \
  --data-urlencode "redirect_uri=http://127.0.0.1:51004/callback" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "resource=$MCP"
```

Plus, from **outside** your own network: `dig +short auth.example.com` must return only globally
routable **IPv4** addresses (C-31), and `curl -sI $MCP` must not be a `3xx` to another host.

