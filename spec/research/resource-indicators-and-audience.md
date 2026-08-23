# Resource Indicators (RFC 8707) & Audience Restriction — Implementer's Reference

Target: from-scratch OAuth 2.1 + OIDC AS in C# / ASP.NET Core 10 (`net10.0`), must interop with
Claude.ai MCP connectors and ChatGPT connectors.

**Primary sources fetched and quoted below (not from memory):**

| Spec | What it gives you |
|---|---|
| RFC 8707 (Feb 2020, Standards Track) | the `resource` parameter, `invalid_target`, audience-restriction rule |
| RFC 9700 (OAuth 2.0 Security BCP) | §2.3, §4.9.3, §4.10.2 — audience restriction is SHOULD, RS rejection is MUST |
| RFC 9068 (JWT Profile for Access Tokens) | how `resource` becomes `aud`; the RS validation list; `invalid_token` |
| RFC 9728 (Protected Resource Metadata) | §1.2 Resource Identifier definition, §7.4 attack narrative |
| RFC 8693 (Token Exchange) | the *only* place `audience` is a standard OAuth parameter |
| RFC 7519 §4.1.3 | `aud` claim wire type and rejection rule |
| RFC 6749 §4.1.2.1, §5.2 | exact HTTP shape of the two error responses |
| MCP auth spec 2025-06-18 and 2025-11-25 | what Claude/ChatGPT actually put on the wire |
| IANA OAuth Parameters registry | registered usage locations (a real trap — see §9) |

---

## 1. The `resource` parameter — exact syntax

> **RFC 8707 §2:** "resource — Indicates the target service or resource to which access is
> being requested. Its value **MUST** be an absolute URI, as specified by Section 4.3 of
> [RFC3986]. The URI **MUST NOT** include a fragment component. It **SHOULD NOT** include a
> query component, but it is recognized that there are cases that make a query component a
> useful and necessary part of the resource parameter, such as when one or more query
> parameters are used to scope requests to an application. The "resource" parameter URI value
> is an identifier representing the identity of the resource, which **MAY** be a locator that
> corresponds to a network-addressable location where the target resource is hosted. Multiple
> "resource" parameters **MAY** be used to indicate that the requested token is intended to be
> used at multiple resources."

> **RFC 8707 §2:** "The client **SHOULD** provide the most specific URI that it can for the
> complete API or set of resources it intends to access. […] The client **SHOULD** use the base
> URI of the API as the "resource" parameter value unless specific knowledge of the resource
> dictates otherwise."

| Rule | Normative level | Source | Concrete check in ASP.NET Core | Error on violation |
|---|---|---|---|---|
| Absolute URI (RFC 3986 §4.3) | MUST | 8707 §2 | `Uri.TryCreate(v, UriKind.Absolute, out u)` **plus** scheme allowlist | `invalid_target` |
| No fragment component | MUST NOT | 8707 §2 | `u.Fragment.Length == 0` **and** `!raw.Contains('#')` | `invalid_target` |
| Query component | SHOULD NOT (allowed) | 8707 §2 | `u.Query.Length == 0` unless resource is registered as query-bearing | `invalid_target` |
| May repeat the parameter | MAY | 8707 §2 | bind to `string[]`, never `string` | see §6 |
| Most specific URI | SHOULD | 8707 §2 | client-side; AS just must not truncate to origin | — |
| Appears on `/authorize` | registered | IANA / 8707 §2.1 | — | — |
| Appears on `/token` (all grant types) | registered | IANA / 8707 §2.2 | — | — |

**RFC 9728 §1.2** narrows it further for anything that publishes protected-resource metadata
(every MCP server does):

> "Resource Identifier: The protected resource's resource identifier, which is a URL that uses
> the **https** scheme and has **no fragment** component. As specified in Section 2 of [RFC8707],
> it also **SHOULD NOT** include a query component […]"

So for MCP: scheme allowlist is `https` (plus `http` on loopback for local dev only).

### Canonical URI, as MCP defines it

MCP 2025-11-25 / 2025-06-18, *Canonical Server URI*:

> "MCP clients **SHOULD** provide the most specific URI that they can for the MCP server they
> intend to access […] While the canonical form uses lowercase scheme and host components,
> implementations **SHOULD** accept uppercase scheme and host components for robustness and
> interoperability."

Valid: `https://mcp.example.com/mcp`, `https://mcp.example.com`, `https://mcp.example.com:8443`,
`https://mcp.example.com/server/mcp`.
Invalid: `mcp.example.com` (no scheme), `https://mcp.example.com#fragment`.

> "While both `https://mcp.example.com/` (with trailing slash) and `https://mcp.example.com`
> (without trailing slash) are technically valid absolute URIs according to RFC 3986,
> implementations **SHOULD** consistently use the form without the trailing slash […]"

---

## 2. Normalization: compare loosely, emit strictly

This is the single highest-yield design decision. **Do not** compare the raw client string to
your registered identifier with `==`.

**Rule: normalize the incoming value for *lookup*; put your *registered* identifier in `aud`.**

Normalization function (RFC 3986 §6.2.2–6.2.3 syntax-based normalization):

| Step | Do | Do NOT |
|---|---|---|
| scheme | lowercase | — |
| host | lowercase (IDN → A-label) | — |
| port | strip if default for scheme (443/https, 80/http) | assume port is always absent |
| path | keep byte-exact, **case-sensitive** | lowercase it |
| empty path | treat `""` and `"/"` as equivalent **for lookup only** | rewrite the emitted `aud` |
| percent-encoding | normalize unreserved chars to decoded form | double-decode |
| fragment | reject the whole request | strip and continue |
| trailing slash | tolerate on input | invent one on output |

```csharp
// Compare-only key. Never emitted.
static string? ResourceKey(string raw)
{
    if (raw.Contains('#')) return null;                       // MUST NOT include fragment
    if (!Uri.TryCreate(raw, UriKind.Absolute, out var u)) return null;
    if (!u.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)) return null;
    if (u.Fragment.Length != 0) return null;
    var path = u.AbsolutePath == "/" ? "" : u.AbsolutePath.TrimEnd('/');
    var port = u.IsDefaultPort ? "" : $":{u.Port}";
    return $"{u.Scheme.ToLowerInvariant()}://{u.Host.ToLowerInvariant()}{port}{path}{u.Query}";
}
```

**ASP.NET Core traps in that one function:**

- `new Uri("https://mcp.example.com").ToString()` returns `"https://mcp.example.com/"` — the
  `Uri` class *adds* a trailing slash. If you round-trip through `Uri.ToString()` and then emit
  that as `aud`, an MCP server whose RFC 9728 `resource` is `https://mcp.example.com` (no slash)
  will reject every token you issue. Keep the registered string; never emit `Uri.ToString()`.
- `Uri.TryCreate("c:\\x", UriKind.Absolute, out _)` returns **true** (scheme `c`). The scheme
  allowlist is not optional.
- `u.Fragment` is `""` for `https://a/b#` in some framework versions; the raw `Contains('#')`
  check is belt-and-braces and costs nothing.
- `Uri` normalizes some percent-encodings and dot-segments before you see them; if you need the
  exact bytes the client sent (you generally don't), read `Request.QueryString.Value` yourself.

---

## 3. Reading a repeatable parameter in ASP.NET Core

`resource` **MAY appear multiple times**. Getting this wrong is the most common ASP.NET-specific
bug in this area.

```csharp
// /authorize  (GET, query string)
string[] resources = HttpContext.Request.Query["resource"].ToArray();

// /token  (POST, application/x-www-form-urlencoded)
var form = await HttpContext.Request.ReadFormAsync(ct);
string[] resources = form["resource"].ToArray();
```

| Anti-pattern | What actually happens |
|---|---|
| `Request.Query["resource"].ToString()` | `StringValues.ToString()` **comma-joins**: two resources become one bogus string `"https://a,https://b"` which then fails `Uri.TryCreate` → spurious `invalid_target` |
| `[FromQuery] string resource` | simple-type model binder takes `FirstValue`; the second and later resources are **silently dropped** — the worst outcome, because you issue a token for a subset the client did not ask for |
| `[FromQuery] string[] resource` / `StringValues` | correct |

Also: if you carry the authorization request through **PAR (RFC 9126)**, the `resource` values
arrive in the POST body of `/par` and must be persisted with the request URI and replayed at
`/authorize`. If you use **JAR**, RFC 8707 §2.1 fixes the JSON shape:

> "For an authorization request sent as a JSON Web Token (JWT), such as when using the JWT
> Secured Authorization Request [JWT-SAR], a single "resource" parameter value is represented
> as a JSON string while multiple values are represented as an array of strings."

So in a JAR request object, `"resource"` is `string | string[]` — a `JsonElement` union, not a
`string`.

---

## 4. `/authorize` behavior

> **RFC 8707 §2.1:** "When the "resource" parameter is used in an authorization request to the
> authorization endpoint, it indicates the identity of the protected resource(s) to which access
> is being requested. […] In the code flow […] the requested resource is applicable to the **full
> authorization grant**."

> **RFC 8707 §2.1:** "If the client omits the "resource" parameter when requesting authorization,
> the authorization server **MAY** process the request with no specific resource or by using a
> predefined default resource value. Alternatively, the authorization server **MAY** require
> clients to specify the resource(s) they intend to access and **MAY** fail requests that omit the
> parameter with an "invalid_target" error."

> **RFC 8707 §2.1:** "If the authorization server fails to parse the provided value(s) or does not
> consider the resource(s) acceptable, it **should** reject the request with an error response using
> the error code "invalid_target" as the value of the "error" parameter and can provide additional
> information regarding the reasons for the error using the "error_description"."

**What the authorization request establishes:** the *grant set* — the set of resources the
resource owner consented to. Persist it on the authorization code record.

### Wire format — RFC 8707 Figure 2 (verbatim)

```
GET /as/authorization.oauth2?response_type=code
   &client_id=s6BhdRkqt3
   &state=tNwzQ87pC6llebpmac_IDeeq-mCR2wLDYljHUZUAWuI
   &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
   &scope=calendar%20contacts
   &resource=https%3A%2F%2Fcal.example.com%2F
   &resource=https%3A%2F%2Fcontacts.example.com%2F HTTP/1.1
Host: authorization-server.example.com
```

### Error response shape at `/authorize`

Per RFC 6749 §4.1.2.1 the error goes **in a redirect**, not in the HTTP body — but only after
`client_id` and `redirect_uri` have been validated:

> **RFC 6749 §4.1.2.1:** "If the request fails due to a missing, invalid, or mismatching
> redirection URI, or if the client identifier is missing or invalid, the authorization server
> **SHOULD** inform the resource owner of the error and **MUST NOT** automatically redirect the
> user-agent to the invalid redirection URI."

```http
HTTP/1.1 302 Found
Location: https://client.example.org/cb?error=invalid_target
   &error_description=Unknown%20resource%20https%3A%2F%2Fevil.example
   &state=tNwzQ87pC6llebpmac_IDeeq-mCR2wLDYljHUZUAWuI
```

`state` MUST be echoed. `error` and `error_description` MUST be limited to
`%x20-21 / %x23-5B / %x5D-7E` (RFC 6749 §4.1.2.1) — i.e. no `"` and no `\`, ASCII only. In
ASP.NET Core, do **not** hand-concatenate; use `QueryHelpers.AddQueryString` and strip non-ASCII
from `error_description` first.

Validation ordering matters: resolve + validate `client_id` and `redirect_uri` **first**, then
validate `resource`. A bad `resource` is a redirectable error; a bad `redirect_uri` is not.

---

## 5. `/token` behavior — the "within the granted set" rule

> **RFC 8707 §2.2:** "When the "resource" parameter is used on an access token request made to the
> token endpoint, **for all grant types**, it indicates the target service or protected resource
> where the client intends to use the requested access token."

> **RFC 8707 §2.2:** "The resource value(s) that is acceptable to an authorization server in
> fulfilling an access token request is at its sole discretion based on local policy or
> configuration. In the case of a "refresh_token" or "authorization_code" grant type request, such
> policy **may limit the acceptable resources to those that were originally granted by the resource
> owner or a subset thereof**. In the "authorization_code" case where the requested resources are a
> subset of the set of resources originally granted, the authorization server will issue an access
> token based on that subset of requested resources, whereas **any refresh token that is returned is
> bound to the full original grant**."

Implementation rules:

| Grant type | Reference set the requested `resource` must be within | On violation |
|---|---|---|
| `authorization_code` | resources recorded on the authorization code (the grant set from `/authorize`) | `invalid_target` |
| `refresh_token` | resources of the **full original grant** — *not* the narrower set used on the previous code exchange | `invalid_target` |
| `client_credentials` | resources the client is registered/authorized for (no user grant exists) | `invalid_target` |
| `urn:…:token-exchange` | RFC 8693 policy | `invalid_target` |

The refresh case is the one implementations get wrong. RFC 8707's own Figures 3–6 are the
conformance test:

```
# Figure 3 — code exchange, narrows to ONE of the two granted resources
POST /as/token.oauth2 HTTP/1.1
Host: authorization-server.example.com
Authorization: Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
&code=10esc29BWC2qZB0acc9v8zAv9ltc2pko105tQauZ
&resource=https%3A%2F%2Fcal.example.com%2F
```

```json
// Figure 4 — aud is the requested resource; scope downscoped; refresh token bound to FULL grant
{
   "access_token":"eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc3In0…",   // aud=https://cal.example.com/ , scope=calendar
   "token_type":"Bearer",
   "expires_in":3600,
   "refresh_token":"4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH7kic16BDC2",
   "scope":"calendar"
}
```

```
# Figure 5 — refresh asks for the OTHER resource. This MUST succeed.
grant_type=refresh_token
&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH7kic16BDC2
&resource=https%3A%2F%2Fcontacts.example.com%2F
```

```json
// Figure 6
{ "access_token":"…",   // aud=https://contacts.example.com/ , scope=contacts
  "token_type":"Bearer", "expires_in":3600, "scope":"contacts" }
```

If your refresh handler stores the *narrowed* resource on the refresh token instead of the full
grant set, Figure 5 returns `invalid_target` and you have a spec violation that no MCP client
will trigger (they use one resource) but every multi-resource customer will.

### Error response shape at `/token`

> **RFC 6749 §5.2:** "The authorization server responds with an HTTP **400 (Bad Request)** status
> code (unless specified otherwise) […] The parameters are included in the entity-body of the HTTP
> response using the "application/json" media type"

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store

{
  "error": "invalid_target",
  "error_description": "resource https://evil.example was not granted for this authorization code"
}
```

Exact JSON field names: `error` (REQUIRED), `error_description` (OPTIONAL), `error_uri` (OPTIONAL).
No other members are defined; do not add `message`, `detail`, or an RFC 7807 `ProblemDetails`
envelope — ASP.NET Core's default `ProblemDetails` output (`{"type":…,"title":…,"status":…}`) is
**not** a valid OAuth error response and MCP clients will fail to parse it. Suppress the default
problem-details mapping on `/token` and write the body yourself.

---

## 6. Multiple resources + scope

> **RFC 8707 §2.2:** "The semantics of such a request are that the client is asking for a token
> with the requested scope that is usable at **all** the requested target services. Effectively, the
> requested access rights of the token are the cartesian product of all the scopes at all the
> target services. To the extent possible, when issuing access tokens, the authorization server
> **should downscope** the scope value associated with an access token to the value the respective
> resource is able to process and needs to know. […] As specified in Section 5.1 of [RFC6749], the
> authorization server **must** indicate the access token's effective scope to the client in the
> "scope" response parameter value when it differs from the scope requested by the client."

> **RFC 8707 §3:** "Although multiple occurrences of the "resource" parameter may be included in a
> token request, **using only a single "resource" parameter is encouraged**. If a bearer token has
> multiple intended recipients (audiences), then the token is valid at more than one protected
> resource and can be used by any one of those resources to access any of the others. Thus, a high
> degree of trust between the involved parties is needed when using access tokens with multiple
> audiences. Furthermore, an authorization server **may be unwilling or unable** to fulfill a token
> request with multiple resources."

And the hard constraint from the JWT profile:

> **RFC 9068 §3:** "The authorization server **MUST NOT** issue a JWT access token if the
> authorization granted by the token would be ambiguous."

> **RFC 9068 §5:** "Authorization servers should use particular care when handling requests that
> might lead to ambiguous authorization grants. For example, if a request includes multiple
> resource indicators, the authorization server should ensure that each scope string included in
> the resulting JWT access token, if any, can be unambiguously correlated to a specific resource
> among the ones listed in the "aud" claim."

**Recommended policy for this AS** (defensible, spec-compliant, and matches what Claude/ChatGPT do):

| Endpoint | Multiple `resource` values | Behavior |
|---|---|---|
| `/authorize` | **allowed** | records the grant set; consent screen names each resource |
| `/token` | **rejected by default**, configurable per client | `invalid_target`, `error_description="only one resource may be requested per access token"` |

RFC 8693 §2.1.1 explicitly blesses this error choice:

> "An authorization server can use the "invalid_target" error code, defined in Section 2.2.2, to
> inform a client that it requested access to **too many target services simultaneously**."

Downscoping algorithm at `/token` for the single-resource case:

```
granted_scopes        = scopes on the code/refresh token
resource_scopes       = scopes registered for the resolved resource
effective_scopes      = granted_scopes ∩ resource_scopes ∩ (requested scope, if present)

if effective_scopes == ∅            -> 400 invalid_scope   (or invalid_target, see §8)
if effective_scopes != requested    -> MUST include "scope" in the 200 response
```

Emitting `scope` in the response whenever it differs is a **must** (RFC 6749 §5.1, restated by
RFC 8707 §2.2). Clients that manage step-up flows rely on it.

---

## 7. `resource` → `aud`: the mapping

> **RFC 8707 §2:** "The authorization server **SHOULD** audience-restrict issued access tokens to the
> resource(s) indicated by the "resource" parameter. Audience restrictions can be communicated in
> JSON Web Tokens [RFC7519] with the "aud" claim and the top-level member of the same name provides
> the audience restriction information in a Token Introspection [RFC7662] response. The
> authorization server may use the **exact** "resource" value as the audience or it **may map** from
> that value to a more general URI or abstract identifier for the given resource."

> **RFC 9068 §3:** "If the request includes a "resource" parameter (as defined in [RFC8707]), the
> resulting JWT access token "aud" claim **SHOULD** have the same value as the "resource" parameter
> in the request."

> **RFC 9068 §3:** "If the request does not include a "resource" parameter, the authorization server
> **MUST** use a default resource indicator in the "aud" claim. If a "scope" parameter is present in
> the request, the authorization server **SHOULD** use it to infer the value of the default resource
> indicator to be used in the "aud" claim. […] If the values in the "scope" parameter refer to
> different default resource indicator values, the authorization server **SHOULD** reject the request
> with **"invalid_scope"** as described in Section 4.1.2.1 of [RFC6749]."

> **RFC 9068 §5:** "To prevent cross-JWT confusion, authorization servers **MUST** use a distinct
> identifier as an "aud" claim value to uniquely identify access tokens issued by the same issuer
> for distinct resources."

Wire type of `aud` (RFC 7519 §4.1.3):

> "In the general case, the "aud" value is an **array of case-sensitive strings**, each containing a
> StringOrURI value. In the special case when the JWT has one audience, the "aud" value **MAY** be a
> single case-sensitive string containing a StringOrURI value."

| Situation | `aud` JSON | Note |
|---|---|---|
| one resource | `"aud": "https://mcp.example.com/mcp"` | string — this is what RFC 9068 Figure 2 shows and what RS libraries handle most reliably |
| multiple resources | `"aud": ["https://a.example", "https://b.example"]` | array |

**Interop trap:** many RS validators (and some naive `System.Text.Json` DTOs with
`public string Aud { get; set; }`) crash or silently mis-parse when `aud` flips between string and
array. Emit the **single string** form whenever there is exactly one audience. On the RS side,
always deserialize as a union. `Microsoft.IdentityModel.JsonWebTokens.JsonWebToken.Audiences`
handles both; a hand-rolled DTO will not.

Token JWT header/claims, RFC 9068 Figure 2 (verbatim):

```json
// header
{"typ":"at+JWT","alg":"RS256","kid":"RjEwOwOA"}
// claims
{
  "iss": "https://authorization-server.example.com/",
  "sub": "5ba552d67",
  "aud": "https://rs.example.com/",
  "exp": 1639528912,
  "iat": 1618354090,
  "jti": "dbe39bf3a3ba4238a513f51d6e1691c4",
  "client_id": "s6BhdRkqt3",
  "scope": "openid profile reademail"
}
```

Note `"typ":"at+JWT"` — the RS check is case-insensitive against `at+jwt`. Setting `typ: "JWT"`
(the ASP.NET/`JwtSecurityTokenHandler` default) will be rejected by any RFC 9068-conformant RS.

For opaque tokens + introspection (RFC 7662), the audience travels as the top-level `aud` member
of the introspection response — same rule, different envelope.

---

## 8. `invalid_target`: when to use it, and against what

> **RFC 8707 §2:** "The following error code is provided for an authorization server to indicate
> problems with the requested resource(s) in response to an authorization request or access token
> request. **It can also be used to inform the client that it has requested an invalid combination
> of resource and scope.**
>
> invalid_target — The requested resource is invalid, missing, unknown, or malformed."

Exact string, all lowercase, no spaces: `invalid_target`

### Decision table

| Condition | Error code | HTTP | Why not the alternative |
|---|---|---|---|
| Not an absolute URI / has fragment / bad scheme | `invalid_target` | 400 (token) / 302 (authorize) | `invalid_request` is defensible but 8707 §2 says "malformed" belongs to `invalid_target`; clients key off `invalid_target` to fall back |
| Syntactically fine, **unknown** to the AS registry | `invalid_target` | 400 / 302 | this is the literal definition ("unknown") |
| **Known** resource, client not authorized for it | `invalid_target` | 400 / 302 | `unauthorized_client` means "not authorized to use this **grant type**" (RFC 6749 §5.2) — wrong axis. Do not leak whether the resource exists |
| Known + client authorized, but **not in the grant set** of this code/refresh token | `invalid_target` | 400 | **never `invalid_grant`** — see below |
| Resource is fine, requested scope is empty at that resource | `invalid_scope` | 400 | scope is the failing axis; `invalid_target` also permitted by 8707 §2 for "invalid combination" |
| Scope strings map to two different default audiences and no `resource` was sent | `invalid_scope` | 400 | RFC 9068 §3 names this exact case |
| More than one `resource` on `/token` and policy forbids it | `invalid_target` | 400 | RFC 8693 §2.1.1 |
| `resource` omitted and your policy requires it | `invalid_target` | 400 / 302 | RFC 8707 §2.1 names this exact case |

**Why `invalid_grant` is dangerous here:** OAuth clients treat `invalid_grant` on a refresh as
"the refresh token is dead" and discard it, forcing full re-consent. Returning `invalid_grant`
for a resource-scoping problem turns a recoverable client error into an infinite re-auth loop.
`invalid_target` tells the client to retry with a different `resource`.

### Registry quirk — read this before writing a strict validator

IANA "OAuth Extensions Error Registry", entry `invalid_target`:

- **Usage Location: "implicit grant error response, token error response"** — reference RFC 8707.

The registry does **not** list "authorization code grant error response", yet RFC 8707 §2.1 tells
you in prose to return `invalid_target` from `/authorize`. Follow the prose (that is what every
deployed AS does, and what MCP clients expect); just don't be surprised when a conformance tool
flags it. Correspondingly, IANA "OAuth Parameters":

- `resource` — Parameter Usage Location: **"authorization request, token request"** — RFC 8707.
- `audience` — Parameter Usage Location: **"token request"** — **RFC 8693 §2.1** (not 8707).

---

## 9. `resource` vs `audience` — the vendor-extension question

**There is no standard `audience` parameter on `/authorize`.** The IANA registry has exactly one
`audience` entry and its usage location is *token request*, defined by **RFC 8693 (Token
Exchange)** — i.e. it is standard only inside a
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` request.

> **RFC 8693 §2.1:** "audience — OPTIONAL. The **logical name** of the target service where the
> client intends to use the requested security token. This serves a purpose similar to the
> "resource" parameter but with the client providing a **logical name** for the target service.
> Interpretation of the name requires that the value be something that both the client and the
> authorization server understand. An OAuth client identifier, a SAML entity identifier, and an
> OpenID Connect Issuer Identifier are examples of things that might be used as "audience"
> parameter values. However, "audience" values used with a given authorization server must be
> **unique within that server** […] Multiple "audience" parameters may be used […] The "audience"
> and "resource" parameters **may be used together** to indicate multiple target services with a mix
> of logical names and resource URIs."

> **RFC 8693 §2.1:** "resource — OPTIONAL. A URI that indicates the target service or resource where
> the client intends to use the requested security token. […] The value of the "resource" parameter
> **MUST be an absolute URI** […] that **MAY include a query component** and **MUST NOT include a
> fragment component**."

(Note the one-word divergence: RFC 8693 says a query "MAY" be included; RFC 8707 says "SHOULD NOT".
Same wire syntax, different advice. Accept queries; discourage them.)

### Where the `audience`-on-`/authorize` habit comes from

Auth0 predates RFC 8707 and uses a proprietary `audience` query parameter on `/authorize` to name
the target API. That usage is **not** in any RFC. Auth0 now ships a "Resource Parameter
Compatibility Profile" that must be explicitly enabled; per Auth0's own docs, with it enabled
"Auth0 will use the resource parameter if it is available to define the token's audience", it
applies to the authorization flow, PAR, JAR, CIBA and the refresh-token grant — **and crucially,
"if both the resource and audience are available, the audience will still be used."**

### Why a from-scratch AS should honor `resource` natively

1. **MCP clients do not send `audience`.** MCP 2025-06-18 and 2025-11-25 both say: MCP clients
   **MUST** implement RFC 8707; the `resource` parameter **MUST** be included in both authorization
   requests and token requests; and **"MCP clients MUST send this parameter regardless of whether
   authorization servers support it."** Claude.ai and ChatGPT connectors send `resource`, full stop.
   An AS that only understands `audience` cannot be driven by them at all — the client has nowhere
   to put the value.
2. **No discovery signal exists.** RFC 8707 registers a parameter and an error code and **nothing
   else** — there is no `resource_indicators_supported` AS-metadata field (grep the RFC: it never
   mentions metadata or discovery). A client cannot negotiate; it must send `resource`
   unconditionally and hope. That makes "silently ignore `resource`" indistinguishable from
   "honored `resource`" from the client's side — a silent security downgrade (see §11).
3. **`audience` is a logical name; `resource` is a locator.** RFC 9700 §4.10.2: *"To prevent
   phishing, it is necessary to use the actual URL the client will send requests to."* A logical
   name cannot be checked against where the token is actually sent. RFC 8707 §3 makes the same
   point: *"Whenever feasible, the "resource" parameter should correspond to the network-addressable
   location of the protected resource. This makes it possible for the client to validate that the
   resource being requested controls the corresponding network location, reducing the risk of
   malicious endpoints obtaining tokens meant for other resources."*
4. **RFC 9728 alignment.** The RS publishes its identifier as the `resource` field of its protected
   resource metadata. `resource` on the wire === that field === `aud` in the token. One value, three
   places, string-comparable end to end. `audience` breaks that chain.

### Recommended precedence policy (note this is the *opposite* of Auth0's)

| Input | Behavior |
|---|---|
| `resource` only | honor it — normalize, resolve, set `aud` |
| neither | RFC 9068 §3 default-audience path, or reject with `invalid_target` if policy requires it |
| `audience` only (compat mode, off by default) | resolve as a logical name against the same registry |
| **both** | **`resource` wins.** Log the conflict. |

Rationale: `resource` is the standards-track, locator-valued, phishing-resistant one, and it is the
only one MCP clients can send. Auth0 gives `audience` priority purely for backward compatibility
with pre-8707 tenants; a new AS has no such debt. Document the difference loudly if you are
migrating a customer off Auth0 — a tenant that sends both and relied on `audience` winning will
change behavior.

---

## 10. How a resource server validates `aud`

The RS-side contract, so you can write the matching validator and the conformance test.

> **RFC 7519 §4.1.3:** "Each principal intended to process the JWT **MUST** identify itself with a
> value in the audience claim. If the principal processing the claim does not identify itself with
> a value in the "aud" claim when this claim is present, then the JWT **MUST be rejected**."

> **RFC 9068 §4:** "Resource servers receiving a JWT access token **MUST** validate it in the
> following manner. […] The resource server **MUST** verify that the "typ" header value is "at+jwt"
> or "application/at+jwt" and reject tokens carrying any other value. […] The issuer identifier for
> the authorization server […] **MUST** exactly match the value of the "iss" claim. […] **The resource
> server MUST validate that the "aud" claim contains a resource indicator value corresponding to an
> identifier the resource server expects for itself. The JWT access token MUST be rejected if "aud"
> does not contain a resource indicator of the current resource server as a valid audience.** […] The
> resource server **MUST** validate the signature […] **MUST** reject any JWT in which the value of
> "alg" is "none" […] The current time **MUST** be before the time represented by the "exp" claim."

> **RFC 9068 §4:** "in case of any failure in the validation checks listed above, the […] response
> **MUST** include the error code **"invalid_token"**." (RFC 6750 §3.1 → **HTTP 401** +
> `WWW-Authenticate: Bearer error="invalid_token"`.)

> **RFC 9700 §2.3:** "every resource server is obliged to verify, for every request, whether the
> access token sent with that request was meant to be used for that particular resource server. If
> it was not, the resource server **MUST refuse** to serve the respective request."

MCP restates it as a client-facing MUST: *"MCP servers MUST only accept tokens specifically intended
for themselves and MUST reject tokens that do not include them in the audience claim"*, and
*"MCP servers MUST NOT accept or transit any other tokens."*

ASP.NET Core RS configuration (the matching half):

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = "https://as.example.com";
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience  = true,                                  // default true — never turn off
            ValidAudiences    = new[] { "https://mcp.example.com/mcp" }, // the RFC 9728 `resource` value, byte-exact
            ValidateIssuer    = true,
            ValidIssuer       = "https://as.example.com",
            ValidateLifetime  = true,
            ClockSkew         = TimeSpan.FromMinutes(2),
            ValidTypes        = new[] { "at+jwt", "application/at+jwt" }, // RFC 9068 §4 typ check
        };
    });
```

**RS-side traps:**

- `ValidateAudience = false` is the single most common MCP-server misconfiguration and it converts
  the whole of RFC 8707 into decoration.
- Comparing only the **origin** of the request URL against `aud` breaks every resource identifier
  that has a path. This is a documented, real, shipped bug: cloudflare/workers-oauth-provider #108,
  where `handleApiRequest` computed `${protocol}//${host}` and compared it by strict equality to an
  `aud` of `https://example.com/api` — **ChatGPT custom connectors**, which send full-path resource
  indicators, could not sign in. Compare the full canonical identifier, including path.
- `ClockSkew` defaults to **5 minutes** in `Microsoft.IdentityModel`; RFC 9068 §4 says "usually no
  more than a few minutes". Fine, but set it explicitly.
- Trailing slash: `https://mcp.example.com/mcp` ≠ `https://mcp.example.com/mcp/` under strict
  equality. Register both in `ValidAudiences`, or normalize before comparison — but keep the **emitted**
  value stable (see §2).

---

## 11. Why a default-audience AS is a real vulnerability, not a style issue

The failure mode: the AS parses the request, **ignores `resource`**, and stamps a house default —
often the tenant's "default API", the `client_id`, or the issuer URL — into `aud`. Every token it
ever issues has the same audience.

**Concrete attack (RFC 9700 §4.9.1, "Access token phishing by counterfeit resource server"):**

1. A general-purpose client (Claude.ai, ChatGPT) is configured at runtime with an MCP server URL —
   RFC 9700 calls this "late binding", and says it is "typical in situations where the client uses a
   service implementing a standardized API […] and where the client is configured by a user or
   administrator." Exactly the MCP connector model.
2. The user adds `https://evil.example/mcp`, operated by an attacker but trusting the same AS.
3. The client does everything right: `resource=https%3A%2F%2Fevil.example%2Fmcp` on `/authorize` and
   `/token`, PKCE, the lot.
4. The AS ignores `resource` and issues `aud: "https://api.default.example"`.
5. The client sends the bearer token to `https://evil.example/mcp`.
6. The attacker replays that exact token at the **legitimate** `https://mcp.example.com/mcp`.
   That RS validates `aud == "https://api.default.example"` → **accepts**. The attacker now acts as
   the user at a server the user never intended to expose.

RFC 9700 §4.10.2 states the defense and the precondition in one breath:

> "The audience can be expressed using logical names or physical addresses (like URLs). **To prevent
> phishing, it is necessary to use the actual URL the client will send requests to.** In the phishing
> case, this URL will point to the counterfeit resource server. If the attacker tries to use the
> access token at the legitimate resource server (which has a different URL), the resource server
> will detect the mismatch (wrong audience) and refuse to serve the request."
>
> "In deployments where the authorization server knows the URLs of all resource servers, the
> **authorization server may just refuse to issue access tokens for unknown resource server URLs**."
>
> "For this to work, **the client needs to tell the authorization server the intended resource
> server**. The mechanism in [RFC8707] can be used for this […]"

RFC 9728 §7.4 gives the sibling attack, specific to discovery-driven clients:

> "Without audience-restricted access tokens, a malicious resource server (RS1) may be able to use
> the WWW-Authenticate header to get a client to request an access token with a scope used by a
> legitimate resource server (RS2), and after the client sends a request to RS1, then RS1 could
> **reuse the access token at RS2**. […] the use of audience-restricted access tokens and Resource
> Indicators [RFC8707] is **RECOMMENDED** when using the features in this specification."

RFC 8707 §3 is the one-sentence version:

> "An audience-restricted access token that is legitimately presented to a resource **cannot then be
> taken by that resource and presented elsewhere** for illegitimate access to other resources."

**The multi-tenant variant** (directly relevant to a per-customer AS):

> **RFC 8707 §3:** "Some servers may host user content or be multi-tenant. In order to avoid attacks
> where one tenant uses an access token to illegitimately access resources owned by a different
> tenant, it is important to use a specific resource URI **including any portion of the URI that
> identifies the tenant, such as a path component**. This will allow access tokens to be
> audience-restricted in a way that identifies the tenant and prevents their use, due to an invalid
> audience, at resources owned by a different tenant."

Which is precisely why truncating `resource` to its origin (the Cloudflare bug in §10) is a
*security* bug and not just an interop bug: it erases the tenant discriminator.

**Two additional silent-failure modes to design against:**

- **Silent ignore.** Since there is no discovery flag for RFC 8707 support (§9.2), a client cannot
  tell "honored" from "ignored". The AS must therefore be binary: either resolve the `resource` and
  bind `aud` to it, or return `invalid_target`. Never accept-and-ignore.
- **`aud` = `client_id` or `aud` = issuer.** Both make `aud` useless as a recipient discriminator and
  violate RFC 9068 §5's "MUST use a distinct identifier as an "aud" claim value to uniquely identify
  access tokens issued by the same issuer for distinct resources."

---

## 12. Unknown vs. known-but-not-granted

Both return `invalid_target`. They differ in *where in the pipeline* they fire and in what you log.

| # | State | Where detected | Response | `error_description` (safe wording) |
|---|---|---|---|---|
| 1 | Malformed URI / fragment / non-https | request parse | `invalid_target` | `"resource must be an absolute https URI without a fragment"` |
| 2 | Well-formed, **not in the AS resource registry** | registry lookup | `invalid_target` | `"unknown resource"` |
| 3 | In registry, **client not permitted** to target it | client policy | `invalid_target` | `"unknown resource"` ← deliberately identical to #2 |
| 4 | Permitted, but **not in this grant's** resource set | code/refresh record | `invalid_target` | `"resource not included in the authorization grant"` |
| 5 | In the grant set, but the intersection of scopes is empty | scope resolution | `invalid_scope` | `"no granted scopes apply to the requested resource"` |
| 6 | >1 resource on `/token` | policy | `invalid_target` | `"only one resource may be requested per access token"` |

Notes:

- **#2 vs #3 must be indistinguishable to the client.** Distinguishing them turns `/token` into an
  oracle enumerating which resource servers a tenant hosts. Same code, same description; log the
  distinction server-side only.
- **#4 is the one that must not be `invalid_grant`** (see §8) and must not be silently narrowed to a
  default. Silently substituting a default audience here reintroduces §11 exactly.
- **Never** fall back to "issue with default audience" for any row. RFC 9068 §3's default-audience
  path applies **only** when `resource` is *absent*, never when it is present-and-rejected.

---

## 13. Interop traps checklist

| # | Trap | Consequence | Fix |
|---|---|---|---|
| 1 | Strict OAuth 2.1 "no repeated parameters" check applied to `resource` | Legal RFC 8707 multi-resource request rejected as `invalid_request` | Exempt `resource` (and `audience`) from the uniqueness rule — RFC 6749 §5.2 lists "repeats a parameter" under `invalid_request`, but RFC 8707 §2 explicitly permits repetition |
| 2 | `StringValues.ToString()` on `resource` | comma-joined garbage → spurious `invalid_target` | `.ToArray()` |
| 3 | `[FromQuery] string resource` | second+ values silently dropped → token narrower than requested, no error | `string[]` / `StringValues` |
| 4 | `Uri.ToString()` round-trip adds trailing slash | emitted `aud` ≠ RS's registered identifier → 401 on every request | keep the registered string; normalize only for lookup |
| 5 | Comparing `aud` to request **origin** only | path-bearing resource identifiers always fail — this is cloudflare/workers-oauth-provider #108, which broke **ChatGPT custom connectors** | compare `scheme://host[:port]/path` |
| 6 | `aud` emitted as a 1-element **array** | brittle RS deserializers (`public string Aud`) fail | emit a bare string for one audience |
| 7 | `typ: "JWT"` instead of `at+JWT` | RFC 9068 §4 conformant RS rejects with `invalid_token` | set `typ` = `at+JWT` on access tokens (ID tokens stay `JWT`) |
| 8 | Refresh token bound to the *narrowed* resource | RFC 8707 Figures 5–6 fail; client cannot pivot to the second granted resource | bind refresh to the **full original grant** |
| 9 | ASP.NET `ProblemDetails` on `/token` | client sees `{"type":…,"title":…}` and cannot find `error` | write `{"error":…,"error_description":…}` yourself, `Cache-Control: no-store` |
| 10 | `resource` accepted at `/authorize` but dropped through PAR / JAR / consent storage | `/token` sees an empty grant set → `invalid_target` after a successful consent | persist resources on the PAR record, the auth code, and the refresh token |
| 11 | Ignoring `resource` "for now" because clients still work | silent security downgrade; §11 attack is live and no client can detect it | honor or reject — never accept-and-ignore |
| 12 | Rejecting `resource` you should accept | Claude/ChatGPT sign-in fails at the very first `/authorize`, before any consent UI | pre-register the MCP server's canonical URI (the RFC 9728 `resource` value) in the AS registry as part of onboarding |
| 13 | Assuming `audience` on `/authorize` is standard | migration surprises off Auth0 | it is not — IANA lists `audience` for *token request*, RFC 8693 only |
| 14 | `error_description` containing non-ASCII or `"` | RFC 6749 §4.1.2.1 charset violation; some clients fail to parse the redirect | restrict to `%x20-21 / %x23-5B / %x5D-7E` |

---

## 14. Minimal conformance test matrix

| Test | Request | Expected |
|---|---|---|
| T1 | `/authorize` with two `resource` params (RFC 8707 Fig. 2) | 302 to `redirect_uri` with `code`; both resources on the grant |
| T2 | code exchange with `resource` = one of the two (Fig. 3) | 200; `aud` = that one; `scope` downscoped and echoed |
| T3 | refresh with `resource` = the **other** one (Fig. 5) | 200; `aud` = the other one |
| T4 | refresh with `resource` = a third, never granted | 400 `{"error":"invalid_target"}` — **not** `invalid_grant` |
| T5 | `resource=https://mcp.example.com#frag` | `invalid_target` |
| T6 | `resource=mcp.example.com` | `invalid_target` |
| T7 | `resource=HTTPS://MCP.EXAMPLE.COM:443/mcp` | 200; `aud` = registered `https://mcp.example.com/mcp` (case + default port normalized, path preserved) |
| T8 | `resource=https://mcp.example.com/MCP` (path case differs) | `invalid_target` — path is case-sensitive |
| T9 | two `resource` params on `/token` | 400 `invalid_target` (single-resource policy) |
| T10 | no `resource` anywhere, one scope family | 200; `aud` = the scope-derived default (RFC 9068 §3) |
| T11 | no `resource`, scopes spanning two default audiences | 400 `invalid_scope` (RFC 9068 §3) |
| T12 | valid token for resource A presented at resource B | RS returns 401 + `WWW-Authenticate: Bearer error="invalid_token"` |
| T13 | both `resource` and `audience` sent | `resource` wins; conflict logged |
| T14 | trailing-slash variants `…/mcp` and `…/mcp/` | same resolved resource; emitted `aud` identical in both cases |

---

## 15. One-screen summary for the AS pipeline

```
/authorize
  1. resolve client_id, validate redirect_uri        -> non-redirectable errors here
  2. read string[] resource                          -> Query["resource"].ToArray()
  3. for each: syntax check (abs URI, https, no #)   -> invalid_target (302)
  4. normalize -> registry lookup                    -> invalid_target (302) if unknown/not permitted
  5. record the resolved canonical identifiers as the GRANT SET on the auth code
  6. show them on the consent screen (RFC 8707 §2.1: "inform the user about the resources")

/token
  1. authenticate client, validate code/refresh + PKCE
  2. read string[] resource from the FORM body
  3. count > 1 and policy is single-resource         -> invalid_target (400)
  4. count == 0 -> RFC 9068 §3 default-audience path (or invalid_target if required)
  5. syntax + normalize + registry                   -> invalid_target (400)
  6. membership in the grant set                     -> invalid_target (400), NOT invalid_grant
  7. effective_scope = granted ∩ resource_scopes ∩ requested
     empty                                           -> invalid_scope (400)
  8. mint: typ=at+JWT, aud = REGISTERED canonical id (string if single), scope = effective_scope
  9. refresh token (if issued) binds to the FULL grant set, not the narrowed one
 10. response includes "scope" whenever it differs from what was requested (RFC 6749 §5.1)
```
