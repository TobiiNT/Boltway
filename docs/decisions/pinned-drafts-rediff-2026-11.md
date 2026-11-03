# Re-diff of the pinned drafts: CIMD -02 to -03, OAuth 2.1 -15 to -17

**Date:** 2026-11-03 · **Status:** decision record; the open items in §4 are open · **Scope:** the
authorization server and the resource server

`U-15` requires a re-diff whenever a pinned Internet-Draft is revised, and `pinned-drafts.yml` went
red on two at once: `draft-ietf-oauth-client-id-metadata-document` reached -03 (2 November 2026)
and `draft-ietf-oauth-v2-1` reached -17 (31 October 2026, with -16 in between). This is the
re-diff. The pinned copies in `spec/` are now -03 and -17.

**How it was measured.** Both pairs were diffed word by word with page furniture stripped, every
hunk was read, and every normative change was checked against the code by reading it. The Document
History appendices were a checklist, not the source: CIMD -03's omits about eight changes that bind
an authorization server, and OAuth 2.1 -17's omits several, among them a CORS "will need to" that became MUST. Everything below that this change acts on
was re-read against the code before acting. The items in §4 were read, not executed; each says
which.

## 1. Section numbers that moved

Every citation in `src/`, `tests/`, `testing/`, `hosts/` and the current documents was moved to the
new numbers. Dated documents keep theirs and now say which revision they mean (`CIMD-02 §8.6`).
Requirement ids did not move.

**CIMD.** §1 to §4 kept their numbers. Everything from §5 on moved:

| -02 | -03 | |
|---|---|---|
| §5 Client Information Discovery | §6 | §5 is now *Client Authentication* |
| §5.1 Metadata Discovery Errors | §6.1 | now defines transient and terminal failures |
| §5.2 Metadata Caching | §6.2 | the "own upper and/or lower bounds" sentence is gone; see §2 |
| §6 Authorization Server Metadata | §8 | |
| §7.1, §7.2 Implementation Considerations | §9.1, §9.2 | |
| §8.1 Relationship between redirect_uris and client_id or client_uri | §10.2 | `client_uri` dropped from the title |
| §8.2 Client Authentication | §5 (rules), §5.1 (non-normative examples), §10.3 (key material) | split three ways |
| §8.3 to §8.5 | §10.4 to §10.6 | |
| §8.6 SSRF | §10.7 | plus §10.7.1 *Accept Header* |
| §8.7 Maximum Response Size | §10.11 | |
| §8.8 Displaying Logos | §10.9 | |
| §8.9 Client ID Domain Trust | §10.8 | |
| §8.10 CIMD Services | §10.13 | |
| §9, §10, §11 | §11, §12, §13 | |

New in -03: §4.4, §4.5, §7 *Authorization Response*, §10.1, §10.10, §10.12.

**OAuth 2.1.** Only §7 moved. New §1.7.1 *Value Sizes*, new §7.5.2 *PKCE "plain" Code Challenge
Method*, new §7.9 *Consent Phishing*, and §9 grew subsections.

| -15 | -17 |
|---|---|
| §7.3.2 Access Token Privilege Restriction | merged into §7.1.4, which already had the same title. -17's §7.3.2 is a new section, *Impersonation of Browser-Based Applications* |
| §7.5.2 Reuse of Authorization Codes | §7.5.3 |
| §7.5.3 HTTP 307 Redirect | §7.5.4 |
| §7.9 to §7.14.2 | §7.10 to §7.15.2 |

Quotations that the new text reworded were brought to the new wording. Most were editorial
("denial-of-service", "the 303 status code", "conflict over which").

## 2. Acted on in this change

- **CIMD-03 §3 prohibits a path of `/`.** -02 called it NOT RECOMMENDED and the code left it
  alone on purpose. `CimdClientIdUrl` now refuses it, and the test row that accepted
  `https://host/` moved to the refusal theory.
- **CIMD-03 §5: abort when no declared method is supported.** "When an authorization server does
  not support any of the token endpoint authentication methods declared in the Client ID Metadata
  Document, the authorization server MUST abort the authorization request and token requests with
  invalid_client." The choice ignored the deployment's enabled methods, so a document offering only
  `private_key_jwt` on a server with that method off (the default) passed `/authorize` and failed
  at `/token`, after sign-in and consent. The resolver registered by `AddCimdClientResolver` now
  reads `AuthorizationServerOptions.TokenEndpointAuthMethods`.
- **CIMD-03 §6.1: terminal failures stay terminal.** A document that was retrieved and refused, or
  a status other than 200, already skipped the stale window, but the cached entry stayed. Each such
  answer counts against the breaker, and once the breaker opened it served whatever was cached. The
  third 404 in a row brought back the document the first had refused. Found by reading; the test
  that pins the fix fails without it. A terminal answer now evicts the entry.
- **CIMD-03 §6.2 changed the ground under S-30's floor.** The "MAY define its own upper and/or
  lower bounds" sentence that justified a floor over `max-age=0` is gone. -03 says "SHOULD enforce
  a maximum effective cache duration" and "SHOULD also enforce a minimum effective cache duration
  when none is otherwise indicated", and separately "MAY implement rate limiting ... even if that
  results in fetching the URL less often than requested by the cache headers". The floor stays, and
  its comment now rests on that last sentence.
- **`RedirectProvesIdentity` is re-cited, not changed.** -17 §7.3.1 rewrote the sentence the 0.6.0
  rationale quoted (via RFC 8252 §8.6, whose own text is unchanged): claimed https redirects "do not
  authenticate the client, and do not make the client a confidential client". The new §7.3.2 permits
  what the flag does, for a browser-based application, almost word for word. The flag is read only
  by `PublicClientReconsentGuard`; at `/token` the client stays public. The comments now say both.

## 3. Already compliant, checked

Recorded so the next re-diff does not repeat the reading.

- **CIMD:**
  - no normalization of the Client Identifier URL (§3)
  - symmetric methods refused in either member, and `jwks` with `jwks_uri` refused (§4.1)
  - loopback redirect port exception (§4.2)
  - `client_uri` never restricted (§4.4)
  - no cookies on the fetch (§11.1)
  - `none` assumed when both auth members are absent (§5)
  - a `none` client presenting credentials is `invalid_client` (§5)
  - the plural member is recognised (§5)
  - an algorithm allowlist (§5)
  - `Accept: application/json` sent (§6)
  - no redirect to the client when the document is unusable (§6.1)
  - `iss` in every authorization response (§7)
  - logos proxied and type-checked (§10.9)
  - consent reuse scoped to client and resource (§10.12; see 4.8)
- **OAuth 2.1:**
  - `plain` refused and only `S256` advertised (§4.1.1, §7.5.2)
  - `iss` REQUIRED (§4.1.2, §4.1.2.1)
  - client and redirect URI validated before any error redirect (§4.1.2.1)
  - RS refuses wrong audience and insufficient scope (§7.1.4 "must" became MUST)
  - a bare `Bearer` challenge is now legal (§5.3.1)
  - no challenge for methods without an HTTP scheme (§3.2.4)
  - reduced scope on refresh with `scope` returned (§4.3.1)
  - `redirect_uri` accepted and enforced at `/token` (§10.2)
- **The §7.5.1.1 PKCE carve-out** and §4.1.3's "reject the token request if there was no
  code_challenge" bullet still contradict each other in -17. `N-02` still declines the carve-out.

## 4. Not acted on, and open

Each is a sentence in the new text this server does not meet, or meets only on one reading. None
is a regression: every one was equally unmet, or not yet written, against the old pin. They are
here rather than fixed because each is a change of behaviour a deployment would notice, or a
reading of an ambiguous sentence. Measured by reading the code unless it says otherwise.

1. **CIMD-03 §5, `private_key_jwt` when it is enabled.** "When a client declares private_key_jwt
   as a token endpoint auth method and the authorization server supports this method, the
   authorization server MUST require client authentication". With `PrivateKeyJwt` enabled, a
   document offering `["none","private_key_jwt"]` still resolves to `none`.

   That preference is measured to be what one vendor's client does: on 2026-08-17 it linked as a
   public client and sent no assertion. Following the MUST would break that client on any
   deployment that enables `private_key_jwt`. The same section also says the server "SHOULD
   select one of the values ... that it supports", and §5.1 says a server "may reject" a client
   that then uses `none`, so the draft does not agree with itself. Off by default, so no default
   deployment is affected. **Recommendation:** keep the preference and raise it on the draft's
   tracker.
2. **CIMD-03 §6, the `grant_types` / `response_types` intersection.** "If the intersection of
   either of these two properties is empty, the Authorization Server MUST reject the request with
   invalid_client."

   The pipeline refuses a client that declares no `authorization_code` or no `code`, but with
   `unauthorized_client` by redirect, and it reads an empty array as "did not say" (C-14). Meeting
   it means the resolver learns the server's supported grants, and the refusal moves to the
   no-redirect path §6.1 asks for.

   **Closed 2026-11-03.** The registered resolver intersects both members with
   `GrantTypesSupported` and `code`, keeps the intersection on the record, and refuses an empty
   one as `invalid_client` when it reads the document. An empty array is now an empty
   intersection rather than "did not say"; an absent member still is.
3. **CIMD-03 §10.1, client_id confusion.** The server "SHOULD reject a Client Identifier URL that
   is equal ... to its own issuer identifier, or to the identifier of any authorization server or
   resource server it has a trust relationship with". Not checked. An issuer with no path can never
   be equal, because §3 requires a path. A resource identifier with one, such as an MCP endpoint,
   could be.

   **Closed 2026-11-03.** Refused before any fetch when the identifier equals the validated issuer
   or a registered resource's canonical identifier.
4. **CIMD-03 §6.1, refresh tokens on a terminal failure.** "A terminal failure caused by a
   client_id mismatch SHOULD invalidate the client's outstanding refresh tokens immediately." The
   resolver has no store access by design (A-08), so nothing revokes.
5. **CIMD-03 §5, JWT `typ`.** Client assertions "SHOULD include an explicit typ header parameter",
   and servers "SHOULD validate JWT types". `Rfc9068ValidationParameters` sets no `ValidTypes` on
   purpose. Its reason, that RFC 7523 registers no `typ`, is now outdated by this sentence.
   Requiring one would refuse every current client, so the likely shape is to accept a missing
   `typ` and refuse a wrong one.

   **Closed 2026-11-03, in that shape.** No `typ`, `JWT` and `client-authentication+jwt` pass,
   case-insensitively; any other declared type is refused.
6. **CIMD-03 §5, "MUST include either jwks or jwks_uri properties".** The sentence sits in the
   `private_key_jwt` paragraph, and this server applies it there: a `private_key_jwt` document with
   no `jwks_uri` is refused, and so, more strictly than -03, is one with only inline `jwks`, because
   `ClientRecord` has no slot for inline keys. Read literally the sentence covers every document,
   including `none` ones, which would refuse every captured vendor document. This server reads it
   as scoped.
7. **OAuth 2.1 -17 §9.3.2, refresh lifetime for browser-based applications.** The server "MUST NOT,
   when issuing a rotated refresh token, extend the lifetime of the new refresh token beyond the
   lifetime of the initial refresh token, if the initial refresh token had a pre-established
   expiration time". Each rotation here gets a fresh `RefreshTokenLifetime`, with no cap for the
   family. This binds only where browser-based applications receive refresh tokens. The server
   cannot tell one from another client, so a cap would be a per-client option.

   **Closed 2026-11-03, as that option:** `RefreshTokenExpiryIsFixed` on `ClientRecord` and
   `ConfiguredClient` (`"refreshTokenExpiryIsFixed": true` in the host's `CLIENTS`). Set, a
   successor expires at the earlier of its own lifetime and its predecessor's expiry. Off by
   default, and a deployment sets it on its browser applications.
8. **OAuth 2.1 -17 §3.2, CORS on userinfo.** Endpoints a browser-based application may call "MUST
   also send the CORS header fields to allow access". `/token` and discovery do. `/userinfo` sends
   none. Revocation and introspection are for confidential clients only, so a browser application
   never calls them.

   **Closed 2026-11-03.** `/userinfo` answers with `Access-Control-Allow-Origin: *` on every
   status, and its preflight is answered.
9. **CIMD-03 §10.12 and consent.** The MUST is "scoped at least to the pair of Client Identifier
   URL and resource", and reuse is. Scopes are a union across resources, though, so consent to
   scope A on R1 and scope B on R2 admits B on R1 without a prompt. That is finer than the MUST
   names, and worth deciding on its own.
10. **OAuth 2.1 -17 §4.1.1, "no normalization applied".**
    - Registration lowercases scheme and host, so a client registered as `https://App.example/cb`
      that sends exactly that fails the match. It fails closed.
    - The loopback branch compares the scheme case-insensitively. **Closed 2026-11-03:** it now
      requires the request to begin with the registration's scheme and host exactly. A
      differently cased host was already refused; only the scheme was not.
11. **OAuth 2.1 -17 §2.3, "The query string component MUST NOT include any parameters defined for
    use in the authorization response."** A registered redirect URI carrying `state` or `code` is
    not refused, and the response would repeat the parameter. The draft does not say whether the
    server enforces this at registration.

    **Closed 2026-11-03, at registration:** `RedirectUriError.QueryHasResponseParameter`. Rows
    stored before the rule still load, since refusing them would stop a store from starting.

Also seen on the way, outside the drafts: `ClientLogoEndpoint` fetches the logo through the same
transport, which sends `Accept: application/json`. A strict image host could answer 406. This was
not measured.

## 5. Decided, not changed

Recorded 2026-11-03, after the items in §4 that could close did (TobiiNT/Boltway#63 and #64 mark
theirs in place). What is left is a decision to keep the current behaviour, and each says why, so
the next re-diff reads a reason rather than an open question.

- **§4 item 1, `private_key_jwt` beside `none`: kept.** The preference for `none` is what a
  measured vendor client does, and following the MUST would break it on any deployment that
  enables `private_key_jwt`. The draft disagrees with itself here (§5's MUST, its own "SHOULD
  select one of the values ... that it supports", and §5.1's "may reject"). The question for the
  draft's authors, not yet asked: *when a document offers both `none` and `private_key_jwt` and the
  server supports both, is selecting `none` a conforming choice?* Raising it on the draft's issue
  tracker is the owner's call, since it speaks for this project in public.
- **§4 item 4, refresh tokens on a client_id mismatch: kept, and weaker than it reads.** Nothing
  revokes, because the resolver has no store (A-08). The tokens are unusable all the same: `/token`
  resolves the client on every request, and since #62 a terminal answer evicts the cached
  document, so the next refresh fetches, meets the same mismatch, and is `invalid_client`. If the
  client publishes a corrected document they work again, which is the difference from
  invalidation, and it is accepted.
- **§4 item 6, "MUST include either jwks or jwks_uri": scoped reading kept.** Applied to the
  `private_key_jwt` paragraph it sits in. The literal reading would refuse the captured vendor
  documents that declare only `none` and publish no keys - half of those in
  `spec/cimd-live-2026-08-17.json` (the other half carry a `jwks_uri`).
- **§4 item 9, scopes per resource in a remembered consent: kept.** The MUST, client and resource,
  is met. Scopes per resource would change `ConsentRecord` and the schema of three stores, for a
  case that needs one client consented on two resources with different scopes and then asking for
  a mix. Worth doing when a deployment has that shape.
- **§4 item 10, registration lowercases scheme and host: kept.** Registration is an operator's
  input, normalized once on write, and the request side is compared raw. Stopping the lowercasing
  would make a registration typed with a capital stop matching the lowercase URI its client
  sends, which is a working client broken to satisfy a sentence about requests.
- **`RedirectProvesIdentity` keeps its name.** It looked at odds with -17 §7.3.1's "do not
  authenticate the client", and it is not: -17 §7.3.2, the sentence that permits what the flag
  does, calls the same thing "proof of identity of a browser-based application". Renaming would
  also break the `redirectProvesIdentity` key in a live deployment's `CLIENTS`.

