# RFC 9728 (Protected Resource Metadata) + MCP Authorization — Implementer's Distillation

**Target:** from-scratch OAuth 2.1 + OIDC Authorization Server in C# / ASP.NET Core 9, plus the
resource-server (MCP) side that must trust it. Must interop with Claude.ai and ChatGPT connectors.

**Sources fetched (not from memory):**

| Source | URL | Status as of 2026-08-03 |
|---|---|---|
| RFC 9728 — OAuth 2.0 Protected Resource Metadata | `https://www.rfc-editor.org/rfc/rfc9728.txt` | Proposed Standard |
| RFC 6750 — Bearer Token Usage | `https://www.rfc-editor.org/rfc/rfc6750.txt` | Proposed Standard |
| RFC 8707 — Resource Indicators | `https://www.rfc-editor.org/rfc/rfc8707.txt` | Proposed Standard |
| MCP Authorization | `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization` | **current released revision = `2026-07-28`** |
| MCP AS Discovery | `.../2026-07-28/basic/authorization/authorization-server-discovery` | released |
| MCP Client Registration | `.../2026-07-28/basic/authorization/client-registration` | released |
| MCP Auth Security Considerations | `.../2026-07-28/basic/authorization/security-considerations` | released |
| MCP Security Best Practices | `.../docs/2026-07-28/tutorials/security/security_best_practices` | released |
| MCP Streamable HTTP transport | `.../2026-07-28/basic/transports/streamable-http` | released |
| Claude connector auth | `https://claude.com/docs/connectors/building/authentication` | vendor doc |
| OpenAI Apps SDK auth | `https://developers.openai.com/apps-sdk/build/auth/` | vendor doc |

> The `/specification/draft/...` authorization pages were also fetched and are **textually identical**
> to `2026-07-28` on every normative statement checked. No draft-only requirements found.

---

## 0. The 60-second version

```
1. Client POSTs /mcp with no token
2. RS → 401 + WWW-Authenticate: Bearer resource_metadata="https://rs/.well-known/oauth-protected-resource/mcp", scope="..."
3. Client GETs that URL             → PRM JSON  { resource, authorization_servers[], scopes_supported[] }
4. Client GETs AS metadata          → probes 2-3 well-known URLs in fixed priority order
5. Client obtains client_id         → CIMD (URL as client_id) | pre-registered | DCR (deprecated)
6. Client → /authorize  ... &resource=<canonical RS URI>&code_challenge=...&code_challenge_method=S256
7. AS → 302 redirect_uri?code=...&iss=<issuer>
8. Client → /token  code + code_verifier + resource=<same canonical RS URI>
9. AS issues access token with aud == the resource value
10. Client → /mcp  Authorization: Bearer <token>;  RS validates aud === its own resource identifier
```

Two things the AS must get right that nothing else compensates for: **`aud` must equal the `resource`
value** (step 9), and **`issuer` in AS metadata must equal the URL it was fetched from** (step 4).

---

# PART A — RFC 9728: Protected Resource Metadata

## A.1 Complete metadata field list (RFC 9728 §2)

Emit these from the resource server at the well-known URL. Exact JSON member names.

| JSON field | Req. level (§2) | Type | Normative text / notes | Trap |
|---|---|---|---|---|
| `resource` | **REQUIRED** | string | "The protected resource's resource identifier, as defined in Section 1.2." §1.2: *"a URL that uses the `https` scheme and has no fragment component"*; SHOULD NOT include a query component | Must match the request URL byte-for-byte after path re-insertion (§3.3) |
| `authorization_servers` | OPTIONAL by RFC — **REQUIRED by MCP** | array\<string\> | "JSON array containing a list of OAuth authorization server issuer identifiers … that can be used with this protected resource." | MCP: *"MUST include the `authorization_servers` field containing at least one authorization server."* Claude uses **only the first entry** and does not fall back |
| `jwks_uri` | OPTIONAL | string | "URL of the protected resource's JSON Web Key (JWK) Set document … This URL **MUST** use the `https` scheme." | This is the *RS's own* keys (for signed responses), **not** the AS signing keys. Do not put your AS JWKS here |
| `scopes_supported` | **RECOMMENDED** | array\<string\> | "JSON array containing a list of scope values … used in authorization requests to request access to this protected resource." | Should be the *minimal* set (MCP Scope Minimization). MCP: **SHOULD NOT** include `offline_access` here |
| `bearer_methods_supported` | OPTIONAL | array\<string\> | Registry of defined values: **`"header"`, `"body"`, `"query"`** | Emit `["header"]` only. MCP forbids tokens in the query string |
| `resource_signing_alg_values_supported` | OPTIONAL | array\<string\> | JWS `alg` values supported by the protected resource. "The value `none` **MUST NOT** be used." | For signed RS *responses*, not token validation |
| `resource_name` | **RECOMMENDED** | string | "Human-readable name of the protected resource intended for display to the end user." | Shown in some consent UIs |
| `resource_documentation` | OPTIONAL | string (URL) | Developer docs page | |
| `resource_policy_uri` | OPTIONAL | string (URL) | Data-use requirements page | |
| `resource_tos_uri` | OPTIONAL | string (URL) | Terms of service page | |
| `tls_client_certificate_bound_access_tokens` | OPTIONAL | boolean | mTLS-bound tokens. "If omitted, the default value is `false`." | |
| `authorization_details_types_supported` | OPTIONAL | array\<string\> | RAR (`authorization_details`) `type` values | |
| `dpop_signing_alg_values_supported` | OPTIONAL | array\<string\> | JWS `alg` values accepted for DPoP proof JWTs | |
| `dpop_bound_access_tokens_required` | OPTIONAL | boolean | "whether the protected resource always requires the use of DPoP-bound access tokens. If omitted, the default value is `false`." | Setting `true` breaks Claude/ChatGPT today — neither sends DPoP |
| `signed_metadata` | OPTIONAL | string (JWT) | §2.2: "The signed metadata **MUST** be digitally signed or MACed … using a JSON Web Signature (JWS)" and **MUST contain an `iss` claim** | §3.3: signed values **take precedence** over the plain JSON members |

**Internationalization (§2.1):** human-readable values MAY be repeated with a BCP 47 language tag
appended after a `#`, e.g. `resource_name#ja-Jpan-JP`. Your serializer must not reject `#` in member names.

## A.2 Well-known URI construction — the path-insertion rule (RFC 9728 §3, §3.1)

> §3: *"Protected resources supporting metadata **MUST** make a JSON document containing metadata as
> specified in Section 2 available at a URL formed by **inserting** a well-known URI string into the
> protected resource's resource identifier … By default, the well-known URI string used is
> `/.well-known/oauth-protected-resource`."*

> §3.1: *"If the resource identifier value contains a path or query component, any terminating slash
> (`/`) following the host component **MUST** be removed before inserting `/.well-known/` and the
> well-known URI path suffix between the host component and the path and/or query components."*

**Insertion, not appending.** This is the single most-failed requirement.

| Resource identifier | Correct PRM URL | Wrong (common) |
|---|---|---|
| `https://resource.example.com` | `https://resource.example.com/.well-known/oauth-protected-resource` | — |
| `https://resource.example.com/resource1` | `https://resource.example.com/.well-known/oauth-protected-resource/resource1` | ~~`https://resource.example.com/resource1/.well-known/oauth-protected-resource`~~ |
| `https://mcp.example.com/mcp` | `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` | ~~`.../mcp/.well-known/...`~~ |
| `https://mcp.example.com/tenants/acme/mcp` | `https://mcp.example.com/.well-known/oauth-protected-resource/tenants/acme/mcp` | |

IANA registered well-known suffix (§8.3): **`oauth-protected-resource`**.

```csharp
// URI construction — put this in a shared helper and unit-test it against the table above.
static Uri PrmUrl(Uri resourceId)
{
    // resourceId MUST be https and MUST NOT have a fragment (RFC 9728 §1.2)
    var path  = resourceId.AbsolutePath.TrimEnd('/');          // "" or "/mcp"
    var query = resourceId.Query;                              // "" or "?x=1"
    return new Uri($"{resourceId.Scheme}://{resourceId.Authority}" +
                   $"/.well-known/oauth-protected-resource{path}{query}");
}
```

```csharp
// ASP.NET Core 9: a single catch-all route serves every path-inserted variant.
// {*rest} is REQUIRED — a plain "/.well-known/oauth-protected-resource" route will 404
// the "/mcp" suffix form and silently break discovery.
app.MapGet("/.well-known/oauth-protected-resource/{*rest}", (string? rest, HttpContext ctx) => { ... })
   .AllowAnonymous();
app.MapGet("/.well-known/oauth-protected-resource", (HttpContext ctx) => { ... })
   .AllowAnonymous();
```

## A.3 Response requirements (RFC 9728 §3.2)

> *"A successful response **MUST** use the `200 OK` HTTP status code and return a JSON object using
> the `application/json` content type that contains a set of metadata parameters as its members."*

Exact wire example from §3.2:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
 "resource":
   "https://resource.example.com",
 "authorization_servers":
   ["https://as1.example.com",
    "https://as2.example.net"],
 "bearer_methods_supported":
   ["header", "body"],
 "scopes_supported":
   ["profile", "email", "phone"],
 "resource_documentation":
   "https://resource.example.com/resource_documentation.html"
}
```

§7.10 Metadata Caching: *"Implementations should utilize HTTP caching directives such as
`Cache-Control` with `max-age` … to enable caching of retrieved metadata for appropriate time periods."*
→ emit `Cache-Control: public, max-age=3600`.

**ASP.NET Core traps for this endpoint:**

- It **MUST be anonymous.** `.AllowAnonymous()`, or a global `RequireAuthorization()` fallback policy
  will 401 the discovery document and the whole flow deadlocks. (Confirmed real-world failure mode in
  Claude connector reports.)
- Do **not** let `UseHttpsRedirection` or a HSTS/redirect middleware 30x this path.
- Content type must be exactly `application/json` — not `application/json; charset=utf-8`? (charset is
  tolerated in practice, but `text/json` / `text/plain` is not.)
- Serialize with `JsonIgnoreCondition.WhenWritingNull` so optional fields vanish rather than emit `null`.

## A.4 Metadata validation (RFC 9728 §3.3) — what a correct client enforces against you

> *"The `resource` value returned **MUST** be identical to the protected resource's resource identifier
> value into which the well-known URI path suffix was inserted to create the URL used to retrieve the
> metadata. If these values are not identical, the data contained in the response **MUST NOT** be used."*

> *"The recipient **MUST** validate that any signed metadata was signed by a key belonging to the issuer
> and that the signature is valid. If the signature does not validate or the issuer is not trusted, the
> recipient **SHOULD** treat this as an error condition."*

§6 String Operations: comparisons are **Unicode code-point-to-code-point**, and
*"Unicode Normalization **MUST NOT** be applied at any point."* → no `ToLowerInvariant()`, no
`Uri`-normalizing round-trip before comparing. Use `StringComparison.Ordinal`.

**Trap:** if the user types `https://mcp.example.com/mcp/` (trailing slash) into Claude but your PRM
says `"resource": "https://mcp.example.com/mcp"`, the identity check fails and the connector dies with
a generic error. Claude's doc states this explicitly: *"The protected resource metadata document's
`resource` field must match your MCP server URL exactly as the user enters it in Claude, including any
path component."*

## A.5 The `WWW-Authenticate` challenge (RFC 9728 §5, §5.1)

> §5: *"A protected resource **MAY** use the `WWW-Authenticate` HTTP response header field … to return a
> URL to its protected resource metadata to the client."*

New auth-param registered in §8 (Registry: OAuth Extensions Error / WWW-Authenticate params):

> §5.1: *"`resource_metadata`: The URL of the protected resource metadata."*

Exact example from §5.1:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata=
  "https://resource.example.com/.well-known/oauth-protected-resource"
```

*(the line break is RFC line-wrapping only — emit it on one physical line)*

> §5.1: *"This parameter **MAY** also be used in `WWW-Authenticate` responses using authorization schemes
> other than 'Bearer' [RFC6750], such as the DPoP scheme defined by [RFC9449]."*
> *"The `resource_metadata` parameter **MAY** be combined with other parameters defined in other extensions."*

### Exact quoting rules — this is where implementations break

RFC 7235 `auth-param = token BWS "=" BWS ( token / quoted-string )`. A URL contains `:` and `/`, which
are **not** in `tchar`. Therefore:

| Param | Value form | Quoted? |
|---|---|---|
| `resource_metadata` | absolute https URL | **MUST be a quoted-string** — bare is a protocol violation and several parsers drop it |
| `scope` | space-delimited list | quoted-string (space is not a tchar) |
| `error` | `invalid_token` etc. | quoted-string in RFC 6750's own example; always quote |
| `error_description` | free text | quoted-string, mandatory |
| `realm` | free text | quoted-string |

Separator between params is `,` (comma), optionally followed by whitespace. Do **not** use `;`.

**Canonical 401 to emit (MCP-flavoured, single line):**

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="The access token is expired", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"
Content-Length: 0
```

```csharp
// ASP.NET Core 9 — JwtBearer's default challenge does NOT include resource_metadata.
// You must add it in OnChallenge or via JwtBearerOptions.Challenge.
options.Events = new JwtBearerEvents
{
    OnChallenge = ctx =>
    {
        ctx.HandleResponse();                       // suppress the default header
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        var prm = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(ctx.Error))
            parts.Add($"error=\"{Sanitize(ctx.Error)}\"");
        if (!string.IsNullOrEmpty(ctx.ErrorDescription))
            parts.Add($"error_description=\"{Sanitize(ctx.ErrorDescription)}\"");
        parts.Add($"resource_metadata=\"{prm}\"");
        parts.Add("scope=\"mcp:tools\"");
        ctx.Response.Headers.WWWAuthenticate = "Bearer " + string.Join(", ", parts);
        return Task.CompletedTask;
    }
};
```

`Sanitize` must strip anything outside the RFC 6750 charsets below, and **must** strip `"` and `\`
— an unescaped quote in `error_description` truncates the header and eats `resource_metadata`.

### RFC 6750 §3 charset constraints (verbatim)

| Field | Allowed octets |
|---|---|
| `scope` values | `%x21 / %x23-5B / %x5D-7E`, with `%x20` (space) as the delimiter |
| `error`, `error_description` | `%x20-21 / %x23-5B / %x5D-7E` |
| `error_uri` | must conform to URI-reference syntax |

Note what is excluded: `%x22` (`"`) and `%x5C` (`\`) in every case. Each of `realm`, `scope`, `error`,
`error_description`, `error_uri` may appear **at most once** per challenge.

RFC 6750 §2.1 credentials ABNF:

```abnf
b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
credentials = "Bearer" 1*SP b64token
```

### §5.2 Changes to resource metadata

> *"At any point, for any reason determined by the resource server, the protected resource **MAY** respond
> with a new `WWW-Authenticate` challenge that includes a value for the protected resource metadata URL
> to indicate that its metadata may have changed. If the client receives such a `WWW-Authenticate`
> response, it **SHOULD** retrieve the updated protected resource metadata and use the new metadata
> values obtained, after validating them as described in Section 3.3."*

→ This is your AS-migration lever: change `authorization_servers`, return a fresh 401 with
`resource_metadata`, clients re-discover. No client-side coordination needed.

### §5.3 / §5.4

> §5.3: *"The way in which the client identifier is established at the authorization server is out of
> scope for this specification."* … *"This specification is intended to be deployed in scenarios where
> the client has no prior knowledge about the resource server."*

> §5.4: *"Resource servers **MAY** return other `WWW-Authenticate` headers indicating various
> authentication schemes."* → multiple challenges are legal; MCP clients pick `Bearer`.

## A.6 The AS-side field (RFC 9728 §4)

Your authorization server metadata MAY advertise which resources it serves:

| Field | Level | Definition |
|---|---|---|
| `protected_resources` | OPTIONAL | *"JSON array containing a list of resource identifiers for OAuth protected resources that can be used with this authorization server. Authorization servers **MAY** choose not to advertise some supported protected resources even when this parameter is used."* |

§7.6 tells clients to cross-check `authorization_servers` (in PRM) against `protected_resources` (in AS
metadata) *"when both sets are enumerable."* Emitting it is cheap defence-in-depth; emitting a
**partial** list is explicitly allowed, so clients must not treat absence as rejection.

## A.7 Security Considerations that translate into code (RFC 9728 §7)

| § | Normative statement | Concrete action |
|---|---|---|
| 7.1 TLS Requirements | *"Implementations **MUST** support TLS. They **MUST** follow the guidance in [BCP195]"* | TLS 1.2+ (prefer 1.3); no plaintext listener except loopback dev |
| 7.2 Scopes | *"The client **SHOULD** still follow OAuth best practices and request tokens with as limited a scope as possible."* | Keep `scopes_supported` minimal; drive elevation via `insufficient_scope` |
| 7.3 Impersonation Attacks | *"TLS certificate checking **MUST** be performed by the client"* … *"the client **MUST** ensure that the resource identifier URL it is using as the prefix for the metadata request exactly matches the value of the resource metadata parameter."* | Server side: never emit a `resource` that differs from the deployed URL |
| 7.4 Audience-Restricted Access Tokens | *"the client **SHOULD** request audience-restricted access tokens using [RFC8707], and the authorization server **SHOULD** support audience-restricted access tokens."* … *"the use of audience-restricted access tokens and Resource Indicators is RECOMMENDED"* | **This is the AS's core obligation.** See Part C.4 |
| 7.7 SSRF | *"Clients **SHOULD** take appropriate precautions against SSRF attacks, such as blocking requests to internal IP address ranges."* | Applies to **your AS too** when it fetches CIMD documents — see D.7 |
| 7.9 | Unsigned vs signed metadata differ in trust properties | Only use `signed_metadata` if you can rotate the signing key |
| 7.10 Metadata Caching | see A.3 | `Cache-Control: public, max-age=3600` |

---

# PART B — RFC 6750 error codes (the exact strings)

RFC 6750 §3.1 — complete registry, verbatim definitions, and the mapped status code:

| `error` value | Verbatim definition (§3.1) | HTTP status | When you emit it |
|---|---|---|---|
| `invalid_request` | *"The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed."* | **400** | Token in both header and body; malformed `Authorization` |
| `invalid_token` | *"The access token provided is expired, revoked, malformed, or invalid for other reasons."* | **401** | Signature fail, `exp` past, **`aud` mismatch**, unknown `kid`, revoked |
| `insufficient_scope` | *"The request requires higher privileges than provided by the access token."* | **403** | Valid token, wrong scope |

RFC 6750 §3 example:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  error="invalid_token",
                  error_description="The access token expired"
```

**Trap:** an *absent* `Authorization` header is not an error condition — RFC 6750 says the challenge
SHOULD NOT include an `error` code in that case. Emit bare
`WWW-Authenticate: Bearer resource_metadata="…", scope="…"` with no `error`.
**But** OpenAI's connector doc says ChatGPT wants *"Both `error` and `error_description` parameters
required to trigger authentication UI."* Emitting `error="invalid_token"` even on the no-token case is
the pragmatic interop choice; it costs nothing and satisfies both.

---

# PART C — MCP Authorization (revision `2026-07-28`)

## C.1 Which specs MCP makes mandatory

Verbatim from the Overview section, with the exact modal verb:

| # | Statement | Level |
|---|---|---|
| 1 | *"Authorization servers **MUST** implement OAuth 2.1 with appropriate security measures for both confidential and public clients."* | **MUST** |
| 2 | *"Authorization servers and MCP clients **SHOULD** support OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00)."* | SHOULD |
| 3 | *"Authorization servers and MCP clients **MAY** support the OAuth 2.0 Dynamic Client Registration Protocol (RFC7591). Note that Dynamic Client Registration is **deprecated** and retained for backwards compatibility …"* | MAY (deprecated) |
| 4 | *"MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728). MCP clients **MUST** use OAuth 2.0 Protected Resource Metadata for authorization server discovery."* | **MUST** |
| 5 | *"MCP authorization servers **MUST** provide at least one of the following discovery mechanisms: OAuth 2.0 Authorization Server Metadata (RFC8414) [or] OpenID Connect Discovery 1.0. MCP clients **MUST** support both discovery mechanisms …"* | **MUST** |

Roles: *"A protected **MCP server** acts as an OAuth 2.1 **resource server**, capable of accepting and
responding to protected resource requests using access tokens."* — this is the "MCP servers act as
resource servers" requirement, stated as a role definition and enforced by #4 above.

Transport scoping: *"Implementations using an HTTP-based transport **SHOULD** conform to this
specification. Implementations using an STDIO transport **SHOULD NOT** follow this specification, and
instead retrieve credentials from the environment."*

Additional referenced specs in the Standards Compliance list: RFC 6750, RFC 8414, RFC 7591, RFC 8707,
RFC 9728, **RFC 9207 (Authorization Server Issuer Identification)**, CIMD draft-00, OIDC Discovery 1.0,
OIDC Dynamic Client Registration 1.0, and OAuth 2.1 `draft-ietf-oauth-v2-1-13`.

## C.2 The exact discovery chain

### Step 1 — 401 from the MCP endpoint

MCP servers **MUST** implement *one of*:

> *"1. **WWW-Authenticate Header**: Include the resource metadata URL in the `WWW-Authenticate` HTTP header
> under `resource_metadata` when returning `401 Unauthorized` responses, as described in RFC9728 §5.1.
> 2. **Well-Known URI**: Serve metadata at a well-known URI as specified in RFC9728. This can be either:
> at the path of the server's MCP endpoint … or at the root."*

> *"MCP clients **MUST** support both discovery mechanisms and use the resource metadata URL from the
> parsed `WWW-Authenticate` headers when present; otherwise, they **MUST** fall back to constructing and
> requesting the well-known URIs **in the order listed above**."*

**Implement both.** The header is authoritative; the well-known paths are the fallback.

### Step 2 — PRM fetch

Fallback probe order when no header (from the spec's own sequence diagram), for an MCP endpoint at
`https://example.com/mcp`:

| Order | URL | On 404 |
|---|---|---|
| 1 | `https://example.com/.well-known/oauth-protected-resource/mcp` | try 2 |
| 2 | `https://example.com/.well-known/oauth-protected-resource` | *"Abort or use pre-configured values"* |

PRM **MUST** contain `authorization_servers` with ≥ 1 entry (see A.1).

> *"When multiple authorization servers are listed in `authorization_servers`, each is an independent
> OAuth 2.0 authorization server … Clients **MUST** maintain separate registration state (client
> credentials, tokens) per authorization server and **MUST NOT** assume that credentials valid for one
> authorization server will be accepted by another."*

### Step 3 — AS metadata discovery (probe order is normative)

> *"MCP uses the default `oauth-authorization-server` well-known URI suffix defined in RFC 8414 §3.1 …
> MCP does not define an application-specific well-known URI suffix."*
> *"MCP clients **MUST** attempt multiple well-known endpoints when discovering authorization server metadata."*

**Issuer WITH a path component** — e.g. `https://auth.example.com/tenant1` — clients **MUST** try in order:

| Order | URL |
|---|---|
| 1 | `https://auth.example.com/.well-known/oauth-authorization-server/tenant1` |
| 2 | `https://auth.example.com/.well-known/openid-configuration/tenant1` |
| 3 | `https://auth.example.com/tenant1/.well-known/openid-configuration` |

**Issuer WITHOUT a path component** — e.g. `https://auth.example.com` — clients **MUST** try:

| Order | URL |
|---|---|
| 1 | `https://auth.example.com/.well-known/oauth-authorization-server` |
| 2 | `https://auth.example.com/.well-known/openid-configuration` |

> **Validation:** *"the `issuer` value in the document **MUST** be identical to the issuer identifier used
> to construct the well-known URL. If they differ, the client **MUST NOT** use the metadata. For example,
> a document fetched from `https://attacker.example/.well-known/oauth-authorization-server` that contains
> `"issuer": "https://honest.example"` **MUST** be rejected."*

**AS implementation consequence:** if you support multi-tenant issuers with paths, you must serve
metadata at **all three** URL shapes for that tenant, and each must return `"issuer"` equal to the
tenant issuer exactly. Serving only `/{tenant}/.well-known/openid-configuration` means an MCP client
hits your generic root document first — and if that root document exists and returns a *different*
`issuer`, the client rejects it and the flow dies with no useful error.

### Step 4 — Client registration → see C.6

### Step 5–6 — authorize + token → see C.4

## C.3 `resource` parameter — RFC 8707, mandatory for MCP clients

> *"MCP clients **MUST** implement Resource Indicators for OAuth 2.0 as defined in RFC 8707 to explicitly
> specify the target resource for which the token is being requested. The `resource` parameter:
> 1. **MUST** be included in **both authorization requests and token requests**.
> 2. **MUST** identify the MCP server that the client intends to use the token with.
> 3. **MUST** use the canonical URI of the MCP server as defined in RFC 8707 Section 2."*

> *"MCP clients **MUST** send this parameter regardless of whether authorization servers support it."*

RFC 8707 §2, verbatim constraints on the value:

- *"Its value **MUST** be an absolute URI, as specified by Section 4.3 of [RFC3986]."*
- *"The URI **MUST NOT** include a fragment component."*
- *"SHOULD NOT include a query component, but it is recognized that there are cases that make a query
  component a useful and necessary part."*
- *"Multiple `resource` parameters **MAY** be used to indicate that the requested token is intended to be
  used at multiple resources."*

Form-encoded parameter name is exactly **`resource`** (lowercase), appearing possibly more than once:

```
&resource=https%3A%2F%2Fmcp.example.com
```

Canonical URI rules from MCP:

| Valid | Invalid |
|---|---|
| `https://mcp.example.com/mcp` | `mcp.example.com` (missing scheme) |
| `https://mcp.example.com` | `https://mcp.example.com#fragment` (fragment) |
| `https://mcp.example.com:8443` | |
| `https://mcp.example.com/server/mcp` | |

> *"While the canonical form uses lowercase scheme and host components, implementations **SHOULD** accept
> uppercase scheme and host components for robustness and interoperability."*
> *"implementations **SHOULD** consistently use the form without the trailing slash"*

**Error code when the AS rejects the resource — RFC 8707 §2:**

| Error | Verbatim definition | HTTP | Where |
|---|---|---|---|
| **`invalid_target`** | *"The requested resource is invalid, missing, unknown, or malformed."* | 400 (token endpoint JSON) / redirect `error=invalid_target` (authorization endpoint) | Unknown `resource`, fragment present, relative URI |

### The AS's obligation

> RFC 8707 §2: *"The authorization server **SHOULD** audience-restrict issued access tokens to the
> resource(s) indicated by the `resource` parameter. Audience restrictions can be communicated in JSON
> Web Tokens [RFC7519] with the `aud` claim."*

> *"The authorization server determines acceptable resources based on policy and may limit them to
> originally-granted resources or subsets thereof."* (token endpoint: the `resource` at `/token` must be
> within the set granted at `/authorize`)

**Concrete C# rule:** `aud` **must be the exact `resource` string received**, not your API's internal
name, not a GUID, not the client_id. Claude and ChatGPT both compute the expected audience as the MCP
server URL and the resource server compares `aud` against its own `resource` identifier. Any
transformation breaks it.

```csharp
// AS: minting the access token
var aud = validatedResourceIndicators;              // List<string>, exactly as received
var jwt = new JwtSecurityToken(
    issuer:   _issuer,                              // MUST equal AS metadata "issuer" byte-for-byte
    audience: null,                                 // set aud manually to support multi-valued
    claims:   claims.Concat(aud.Select(a => new Claim("aud", a))),
    ...);
// RFC 9068 typ header for JWT access tokens:
jwt.Header["typ"] = "at+jwt";
```

```csharp
// RS: validating
options.TokenValidationParameters = new TokenValidationParameters
{
    ValidateAudience = true,
    ValidAudiences   = new[] { "https://mcp.example.com/mcp" },  // this RS's resource identifier
    ValidateIssuer   = true,
    ValidIssuer      = "https://auth.example.com",
    ValidateLifetime = true,
    ValidTypes       = new[] { "at+jwt", "JWT" },   // reject id_tokens presented as access tokens
};
```

## C.4 Token audience binding + the token-passthrough prohibition

From MCP Authorization → Token Handling (verbatim):

> *"MCP servers, acting in their role as an OAuth 2.1 resource server, **MUST** validate access tokens as
> described in OAuth 2.1 Section 5.2. MCP servers **MUST** validate that access tokens were issued
> specifically for them as the intended audience, according to RFC 8707 Section 2. If validation fails,
> servers **MUST** respond according to OAuth 2.1 Section 5.3 error handling requirements. Invalid or
> expired tokens **MUST** receive a HTTP 401 response."*

> *"MCP clients **MUST NOT** send tokens to the MCP server other than ones issued by the MCP server's
> authorization server."*
> *"MCP servers **MUST** only accept tokens that are valid for use with their own resources."*
> *"MCP servers **MUST NOT** accept or transit any other tokens."*

From Security Considerations → Access Token Privilege Restriction (verbatim):

> *"MCP servers **MUST** validate access tokens before processing the request, ensuring the access token
> is issued specifically for the MCP server, and take all necessary steps to ensure no data is returned
> to unauthorized parties."*
> *"MCP servers **MUST** only accept tokens specifically intended for themselves and **MUST** reject
> tokens that do not include them in the audience claim or otherwise verify that they are the intended
> recipient of the token."*
> *"If the MCP server makes requests to upstream APIs, it may act as an OAuth client to them. The access
> token used at the upstream API is a **separate token**, issued by the upstream authorization server.
> The MCP server **MUST NOT** pass through the token it received from the MCP client."*

From Security Best Practices → Token Passthrough → Mitigation (verbatim, the flat prohibition):

> ### *"MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server."*

Definition, verbatim: *"'Token passthrough' is an anti-pattern where an MCP server accepts tokens from an
MCP client without validating that the tokens were properly issued **to the MCP server** and passes them
through to the downstream API."*

Two named dimensions:
1. **Audience validation failures** — *"When an MCP server doesn't verify that tokens were specifically
   intended for it (for example, via the audience claim, as mentioned in RFC9068), it may accept tokens
   originally issued for other services."*
2. **Token passthrough** — *"If the MCP server not only accepts tokens with incorrect audiences but also
   forwards these unmodified tokens to downstream services, it can potentially cause the 'confused
   deputy' problem."*

Enumerated risks: Security Control Circumvention · Accountability and Audit Trail Issues · Trust
Boundary Issues · Future Compatibility Risk.

**Error code when `aud` doesn't match:** `invalid_token`, HTTP **401**, with `resource_metadata` in the
challenge so the client can re-authorize against the right AS.

## C.5 Error handling — status codes and the insufficient-scope challenge

> *"Servers **MUST** return appropriate HTTP status codes for authorization errors:"*

| Status Code | Description | Usage |
|---|---|---|
| 401 | Unauthorized | Authorization required or token invalid |
| 403 | Forbidden | Invalid scopes or insufficient permissions |
| 400 | Bad Request | Malformed authorization request |

Runtime insufficient scope — the server **SHOULD** respond with 403 plus a `Bearer` challenge carrying
`error="insufficient_scope"`, `scope="…"`, `resource_metadata`, and optional `error_description`.
Exact wire example from the spec:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                         scope="files:write",
                         resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         error_description="File write permission required for this operation"
```

And the 401 with scope guidance:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         scope="files:read"
```

Scope semantics (verbatim highlights):

- *"MCP servers **SHOULD** include a `scope` parameter in the `WWW-Authenticate` header as defined in
  RFC 6750 Section 3 to indicate the scopes required for accessing the resource."*
- *"Clients **MUST NOT** assume any particular set relationship between the challenged scope set and
  `scopes_supported`. Clients **MUST** treat the scopes provided in the challenge as authoritative for
  the current operation."*
- *"servers **SHOULD** include all scopes required for the current operation in a single challenge"*
  (incremental challenging degrades UX)
- *"Servers **MUST** account for scope hierarchies, where a broader scope implies narrower ones, when
  deciding whether a token is sufficient for an operation."*
- Client scope-selection priority: (1) `scope` from the 401 header; (2) else all of `scopes_supported`;
  omit if `scopes_supported` undefined.
- *"**MCP Servers** (Protected Resources) **SHOULD NOT** include `offline_access` in `WWW-Authenticate`
  scope or Protected Resource Metadata `scopes_supported`, as refresh tokens are not a resource
  requirement."* — but the AS **may** list `offline_access` in *its own* `scopes_supported`, and both
  Claude and ChatGPT will then request it to get a refresh token.

## C.6 Client registration (what your AS must support)

Client selection priority (clients supporting all options **SHOULD** use):

| Order | Mechanism | AS advertises via |
|---|---|---|
| 1 | Pre-registered client information | (out of band) |
| 2 | **Client ID Metadata Documents (CIMD)** | `"client_id_metadata_document_supported": true` |
| 3 | Dynamic Client Registration (deprecated fallback) | `"registration_endpoint": "https://…"` |
| 4 | Prompt the user for client information | — |

### CIMD — authorization server obligations (verbatim)

> * *"**SHOULD** fetch metadata documents when encountering URL-formatted client_ids"*
> * *"**MUST** validate that the fetched document's `client_id` matches the URL exactly"*
> * *"**SHOULD** cache metadata respecting HTTP cache headers"*
> * *"**MUST** validate redirect URIs presented in an authorization request against those in the metadata document"*
> * *"**MUST** validate the document structure is valid JSON and contains required fields"*
> * *"**SHOULD** follow the security considerations in Section 6 of Client ID Metadata Document"*

Client-side rules your AS can rely on:

> * *"The `client_id` URL **MUST** use the 'https' scheme and contain a path component, e.g. `https://example.com/client.json`"*
> * *"The metadata document **MUST** include at least the following properties: `client_id`, `client_name`, `redirect_uris`"*
> * *"Clients **MAY** use `private_key_jwt` for client authentication … with appropriate JWKS configuration"*

Exact example document from the spec:

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "client_uri": "https://app.example.com",
  "logo_uri": "https://app.example.com/logo.png",
  "redirect_uris": [
    "http://127.0.0.1:3000/callback",
    "http://localhost:3000/callback"
  ],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Advertise support with exactly:

```json
{ "client_id_metadata_document_supported": true }
```

On CIMD validation failure the AS returns `error=invalid_client` **or** `error=invalid_request`
(per the spec's own flow diagram).

### DCR

> *"MCP clients **MUST** specify an appropriate `application_type` during Dynamic Client Registration.
> Omitting it defaults to `"web"` under OIDC, which can conflict with native-style redirect URIs;
> non-OIDC servers safely ignore the parameter."*
> Native (desktop/mobile/CLI/localhost) **SHOULD** use `application_type: "native"`; remote browser apps
> **SHOULD** use `"web"`.

**AS trap:** if you implement OIDC DCR strictly, `application_type: "web"` forbids `http://localhost`
redirect URIs. Claude Code and other native clients will fail registration. Either accept `native`, or
relax the localhost rule.

### Authorization Server Binding

> *"Clients that use pre-registered credentials, or persist client credentials obtained via Dynamic
> Client Registration, **MUST** associate those credentials with the specific authorization server that
> issued them, keyed by the authorization server's `issuer` identifier … clients **MUST NOT** reuse client
> credentials from a different authorization server and **MUST** re-register with the new authorization
> server."*

## C.7 RFC 9207 `iss` — do this now

> *"MCP authorization servers **SHOULD** include the `iss` parameter in authorization responses,
> **including error responses**, as defined in RFC9207 Section 2. Authorization servers that include the
> `iss` parameter **MUST** advertise this by setting `authorization_response_iss_parameter_supported` to
> `true` in their metadata (RFC9207 Section 2.3)."*

> *"A future revision of this specification is expected to **upgrade authorization server inclusion of
> `iss` from SHOULD to MUST**. Implementers are encouraged to emit and validate `iss` now."*

Client-side comparison table (drives what you must emit):

| `authorization_response_iss_parameter_supported` | `iss` in response | Client action |
|---|---|---|
| `true` | present | Compare to recorded issuer, simple string comparison (RFC 3986 §6.2.1) |
| `true` | absent | **Reject the response** |
| `false` or absent | present | Compare to recorded issuer |
| `false` or absent | absent | Proceed |

> *"clients **MUST NOT** apply scheme or host case folding, default-port elision, trailing-slash, or
> percent-encoding normalization (RFC 3986 §§6.2.2–6.2.3) before comparison."*

→ **The `iss` you put in the redirect must be byte-identical to the `issuer` in your AS metadata.**
Row 2 is a hard failure mode: advertise `true` and then omit `iss` on *any* response (including the
error redirect) and conforming clients abort.

```
HTTP/1.1 302 Found
Location: https://claude.ai/api/mcp/auth_callback?code=SplxlO...&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.example.com
```

## C.8 Other MCP security requirements affecting the AS

| Requirement | Verbatim |
|---|---|
| PKCE | *"MCP clients **MUST** implement PKCE according to OAuth 2.1 §7.5.2 and **MUST** verify PKCE support before proceeding"*; *"**MUST** use the `S256` code challenge method when technically capable"* |
| PKCE discovery | *"If `code_challenge_methods_supported` is absent, the authorization server does not support PKCE and MCP clients **MUST** refuse to proceed."* — **and** *"Authorization servers providing OpenID Connect Discovery 1.0 **MUST** include `code_challenge_methods_supported` in their metadata to ensure MCP compatibility."* |
| Refresh token rotation | *"For public clients, authorization servers **MUST** rotate refresh tokens as described in OAuth 2.1 §4.3.1"* |
| Short-lived tokens | *"Authorization servers **SHOULD** issue short-lived access tokens"* |
| HTTPS | *"1. All authorization server endpoints **MUST** be served over HTTPS. 2. All redirect URIs **MUST** be either `localhost` or use HTTPS."* |
| Redirect URIs | *"MCP clients **MUST** have redirect URIs registered … Authorization servers **MUST** validate exact redirect URIs against pre-registered values"*; and from Best Practices: *"Use **exact string matching** (not pattern matching or wildcards)"* |
| Open redirect | *"Authorization servers **MUST** take precautions to prevent redirecting user agents to untrusted URI's"*; *"**SHOULD** only automatically redirect the user agent if it trusts the redirection URI"* |
| Localhost consent UI | AS **SHOULD** display additional warnings for `localhost`-only redirect URIs; **MAY** require additional attestation; **MUST** clearly display the redirect URI hostname during authorization |
| CIMD trust policy | AS **MAY** implement domain-based trust policies (allowlists / accept-any-HTTPS / reputation / domain age) |
| SSRF at the AS | *"the authorization server takes a URL as input from an unknown client and fetches that URL … The mitigations described above, such as blocking private IP ranges and using egress proxies, apply equally to authorization servers fetching client metadata documents."* |
| Confused deputy | *"MCP proxy servers using static client IDs **MUST** obtain user consent for each dynamically registered client before forwarding to third-party authorization servers"* |
| State handling (proxy) | state **MUST** be crypto-random, stored **only after** consent approval, single-use, short-lived (~10 min), validated exactly at callback; the consent cookie *"**MUST NOT** be set until **after** the user has approved the consent screen"* |
| Consent cookies | *"Use `__Host-` prefix … Set `Secure`, `HttpOnly`, and `SameSite=Lax` … cryptographically signed or use server-side sessions … Bind to the specific `client_id`"* |
| Anti-clickjacking on consent | *"Prevent iframing via `frame-ancestors` CSP directive or `X-Frame-Options: DENY`"* |

---

# PART D — ASP.NET Core 9 build checklist

## D.1 Endpoints the AUTHORIZATION SERVER must expose

| Path | Method | Auth | Content-Type | Notes |
|---|---|---|---|---|
| `/.well-known/oauth-authorization-server` | GET | anon | `application/json` | RFC 8414. `issuer` MUST equal the URL prefix |
| `/.well-known/oauth-authorization-server/{tenant}` | GET | anon | `application/json` | path-inserted variant, probe #1 for path issuers |
| `/.well-known/openid-configuration` | GET | anon | `application/json` | probe #2 |
| `/.well-known/openid-configuration/{tenant}` | GET | anon | `application/json` | probe #2 for path issuers |
| `/{tenant}/.well-known/openid-configuration` | GET | anon | `application/json` | probe #3 for path issuers |
| `/.well-known/jwks.json` | GET | anon | `application/json` | must serve `kid`; support 2 keys during rotation |
| `/authorize` | GET (+POST) | user session | 302 | must emit `iss` on success **and** error redirects |
| `/token` | POST | client auth | **`application/x-www-form-urlencoded` in**, `application/json` out | see D.4 |
| `/register` | POST | anon | **`application/json`** | RFC 7591 §3.1 — different parser from `/token` |
| `/introspect` | POST | client auth | form-urlencoded in | RFC 7662, optional |
| `/revoke` | POST | client auth | form-urlencoded in | RFC 7009 |
| `/userinfo` | GET/POST | bearer | `application/json` | OIDC |

## D.2 Minimum AS metadata document

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://auth.example.com/register",
  "scopes_supported": ["openid", "profile", "email", "offline_access", "mcp:tools"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "subject_types_supported": ["public"],
  "client_id_metadata_document_supported": true,
  "authorization_response_iss_parameter_supported": true,
  "resource_indicators_supported": true,
  "protected_resources": ["https://mcp.example.com/mcp"],
  "revocation_endpoint": "https://auth.example.com/revoke",
  "introspection_endpoint": "https://auth.example.com/introspect"
}
```

Non-negotiable members for Claude + ChatGPT interop, all confirmed against vendor docs:
`code_challenge_methods_supported: ["S256"]`, `client_id_metadata_document_supported: true` **together
with** `"none"` in `token_endpoint_auth_methods_supported`, and either `registration_endpoint` or CIMD.

## D.3 Endpoints the RESOURCE SERVER (MCP) must expose

| Path | Auth | Notes |
|---|---|---|
| `/.well-known/oauth-protected-resource` | **anon** | root form |
| `/.well-known/oauth-protected-resource/{*rest}` | **anon** | path-inserted form — catch-all route required |
| `/mcp` | Bearer | POST only in `2026-07-28`; GET/DELETE → **405 Method Not Allowed** |

## D.4 Token endpoint content-type

Claude's doc, verbatim: *"Your `/token` endpoint must accept `Content-Type:
application/x-www-form-urlencoded` per RFC 6749 §4.1.3. … Some web frameworks default to JSON-only body
parsing — if your endpoint returns `415 Unsupported Media Type`, register a form-urlencoded body parser.
Dynamic client registration (`/register`) uses `application/json` per RFC 7591 §3.1, so don't assume the
same parser works for both."*

In ASP.NET Core Minimal APIs, a `[FromBody]`-bound record silently expects JSON. Bind the token
endpoint from `HttpRequest.Form` (or `[FromForm]`) and the register endpoint from JSON.

## D.5 Latency budgets (Claude, vendor doc)

| Endpoint class | Timeout |
|---|---|
| discovery, registration, token | **10 seconds** |
| refresh token requests | **30 seconds** |

Exceeding these fails the flow *even if the server eventually responds*. Watch cold starts, EF Core
first-query JIT, and any WAF buffering.

## D.6 CORS / anonymous access

- `/.well-known/*` on both AS and RS must be reachable **without** a token. A global
  `builder.Services.AddAuthorization(o => o.FallbackPolicy = ...RequireAuthenticatedUser())` will 401
  them — a documented, common Claude connector failure.
- If a browser-based client is in scope, `/.well-known/*` needs
  `Access-Control-Allow-Origin: *` and the preflight `OPTIONS` must return 204 without auth.
  Claude.ai/ChatGPT fetch server-side, so this is only needed for browser clients — but it costs nothing.
- The `WWW-Authenticate` header must be in `Access-Control-Expose-Headers` for browser clients to read it.

## D.7 SSRF hardening on CIMD fetch (your AS becomes an HTTP client)

Blocklist per RFC 9728 §7.7 + MCP Best Practices:
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `169.254.0.0/16`
(cloud metadata), `fc00::/7`, `fe80::/10`.

> *"Avoid implementing IP validation manually. Attackers exploit encoding tricks (octal, hex,
> IPv4-mapped IPv6) that custom parsers often miss."*

Use `SocketsHttpHandler.ConnectCallback` to check the **resolved** `IPAddress` at connect time — this
closes the DNS-rebinding TOCTOU window that pre-flight `Dns.GetHostAddressesAsync` validation leaves
open. Also disable automatic redirects (`AllowAutoRedirect = false`) and validate each hop, and cap
response size + set a short timeout.

---

# PART E — Interop traps (Claude.ai and ChatGPT), from vendor docs + reported failures

## E.1 Claude (Claude.ai web, Desktop, mobile, Cowork, Claude Code)

| Trap | Detail (vendor doc verbatim where quoted) |
|---|---|
| 401 is mandatory, not 200 | *"The `401` status is required — Claude does not honor a `WWW-Authenticate` header on a `200` response"* |
| PRM host is free | *"the `resource_metadata` URL doesn't have to be on the MCP server's origin; it can be any HTTPS location that serves the JSON document"* — the escape hatch for Cloudflare Workers / Lambda / Supabase Edge that can't serve `/.well-known/*` |
| Only the FIRST AS is used | *"If you list more than one, Claude uses the first entry and does not fall back to later entries — list your primary issuer first"* |
| `resource` must match user input exactly | *"must match your MCP server URL exactly as the user enters it in Claude, including any path component"* |
| CIMD selection is conjunctive | *"Claude selects CIMD only when your authorization server metadata advertises **both** `"client_id_metadata_document_supported": true` **and** `"none"` in `token_endpoint_auth_methods_supported`"*. Missing either → falls back to DCR |
| DCR at scale | *"DCR causes Claude to register a new client on every fresh connection, which can result in very large numbers of registered clients"* → prefer CIMD |
| Redirect URI (hosted surfaces) | `https://claude.ai/api/mcp/auth_callback` — exact string |
| Redirect URI (Claude Code) | RFC 8252 loopback on an **ephemeral port**, e.g. `http://localhost:3118/callback`. Claude Code's CIMD declares `http://localhost/callback` and `http://127.0.0.1/callback`; *"your authorization server must accept both **with the port component ignored**"* |
| Refresh error code | *"Return RFC 6749-compliant error codes (`invalid_grant`, not `invalid_request` or a custom code) when a refresh token is no longer valid"* |
| Refresh rotation | *"If you rotate, return the new refresh token in the same response that invalidates the old one"* |
| `offline_access` | Claude appends it *"when your authorization server metadata lists it in `scopes_supported`"* |
| Egress IPs / WAF | Anthropic egress `160.79.104.0/21`. Discovery to your **AS** comes from the same range — a WAF in front of the IdP breaks the flow even when the MCP server is reachable |
| Entra ID | *"you must also register the MCP server URL as an Application ID URI on your Entra app registration, or the token request fails with `AADSTS9010010`"* — i.e. the AS must know the `resource` value in advance |
| No pure M2M | *"A pure machine-to-machine `client_credentials` grant … is **not supported**. Every connection requires user consent."* |

**Port-agnostic loopback matching — the exact rule to implement:**

```csharp
static bool RedirectUriMatches(Uri registered, Uri presented)
{
    if (IsLoopback(registered) && IsLoopback(presented))
        // RFC 8252 §7.3: ignore the port for loopback. Apply to localhost too, for Claude Code.
        return registered.Scheme == presented.Scheme
            && string.Equals(registered.Host, presented.Host, StringComparison.OrdinalIgnoreCase)
            && registered.AbsolutePath == presented.AbsolutePath;

    return string.Equals(registered.AbsoluteUri, presented.AbsoluteUri, StringComparison.Ordinal); // exact
}
static bool IsLoopback(Uri u) =>
    u.Host is "localhost" or "127.0.0.1" or "[::1]" or "::1";
```

Note `127.0.0.1` and `localhost` are **different** registered values — do not fold one into the other,
match each independently.

## E.2 ChatGPT / OpenAI connectors

| Trap | Detail |
|---|---|
| Redirect URI (current) | `https://chatgpt.com/connector/oauth/{callback_id}` — **dynamic path segment**, so an exact-match allowlist you hardcode will fail. CIMD or DCR is how the URI gets registered |
| Redirect URI (legacy) | `https://chatgpt.com/connector_platform_oauth_redirect` — still works; a very common source of "Invalid redirect_uri" support tickets |
| Exact match | Reported failures are all character-for-character mismatches, including trailing slash |
| `resource` echoed to `aud` | *"ChatGPT appends `resource=https%3A%2F%2Fyour-mcp.example.com` to authorization and token requests. Authorization server must echo this into access token's `aud` claim."* |
| CIMD preferred | `"client_id_metadata_document_supported": true`; token auth `"none"` (public) or `"private_key_jwt"` |
| DCR optional | via `registration_endpoint` |
| PKCE | `S256` required |
| OIDC scopes | *"If authorization server advertises OIDC scopes (`openid`, `email`, `profile`) in `scopes_supported`, ChatGPT requests them by default. Verify advertised scopes are enabled for the OAuth client."* → **do not advertise a scope you will reject** |
| 401 shape | *"Both `error` and `error_description` parameters required to trigger authentication UI"* |

**Combined conclusion:** support **CIMD + DCR + pre-registration** simultaneously, advertise
`"none"` in `token_endpoint_auth_methods_supported`, and never advertise a scope you will refuse.
That configuration satisfies both vendors without branching.

## E.3 MCP transport traps that surface as "auth broken"

Revision `2026-07-28` changed Streamable HTTP; these produce confusing symptoms alongside auth:

- *"The server **MUST** provide a single HTTP endpoint path … that supports POST."* GET/DELETE to the MCP
  endpoint **SHOULD** return `405 Method Not Allowed`. Protocol-level sessions and the GET SSE stream
  were **removed** in this revision.
- *"Servers **MUST** validate the `Origin` header on all incoming connections … If the `Origin` header is
  present and invalid, servers **MUST** respond with HTTP `403 Forbidden`."* Don't let this fire before
  the 401 — a browser-origin 403 hides the auth challenge.
- Every POST **MUST** carry `MCP-Protocol-Version` (e.g. `MCP-Protocol-Version: 2026-07-28`) plus
  `Mcp-Method`, and `Mcp-Name` for `tools/call` / `resources/read` / `prompts/get`. Mismatch with the
  body → `400` + JSON-RPC error **`-32020` (`HeaderMismatch`)`.
- `Mcp-Session-Id` and `Last-Event-ID` are to be **ignored**; do not mint or echo session IDs.
- Auth state must therefore be anchored to the token identity, never to a session.

---

# PART F — Consolidated error-code cheat sheet

| Condition | HTTP | Where | Exact error string |
|---|---|---|---|
| No `Authorization` header on MCP endpoint | 401 | `WWW-Authenticate` | *(none per RFC 6750; emit `invalid_token` for ChatGPT UI)* |
| Token expired / bad signature / unknown kid | 401 | `WWW-Authenticate` | `invalid_token` |
| **`aud` ≠ this resource identifier** | 401 | `WWW-Authenticate` | `invalid_token` |
| Token in query string, or two token-transmission methods | 400 | `WWW-Authenticate` | `invalid_request` |
| Valid token, missing scope | 403 | `WWW-Authenticate` + `scope=` | `insufficient_scope` |
| Unknown / malformed / missing `resource` at AS | 400 or redirect | token JSON / redirect query | `invalid_target` |
| `redirect_uri` not registered / mismatched | 400, **no redirect** | HTML/JSON body | `invalid_request` (never redirect to an unvalidated URI) |
| CIMD document invalid, or `client_id` ≠ URL | 400 | redirect or body | `invalid_client` or `invalid_request` |
| PKCE verifier mismatch / missing | 400 | token JSON | `invalid_grant` |
| Authorization code reused / expired | 400 | token JSON | `invalid_grant` |
| **Refresh token revoked/rotated-away** | 400 | token JSON | `invalid_grant` *(Claude explicitly requires this, not `invalid_request`)* |
| Client auth failed at `/token` | 401 | token JSON + `WWW-Authenticate` | `invalid_client` |
| Grant type not allowed for client | 400 | token JSON | `unauthorized_client` |
| Unsupported grant type | 400 | token JSON | `unsupported_grant_type` |
| Scope not permitted | 400 | token JSON / redirect | `invalid_scope` |
| User denied consent | 302 | redirect query + `iss` | `access_denied` |
| MCP header/body mismatch | 400 | JSON-RPC | code `-32020` `HeaderMismatch` |

---

# PART G — Test matrix (write these as integration tests)

| # | Test | Expected |
|---|---|---|
| 1 | `GET /.well-known/oauth-protected-resource/mcp` with no auth | 200, `application/json`, `resource == "https://host/mcp"` |
| 2 | Same, with a global auth fallback policy configured | still 200 (regression guard for the `.AllowAnonymous()` bug) |
| 3 | `POST /mcp` no token | 401; header parses; `resource_metadata` is a **quoted** absolute https URL |
| 4 | `POST /mcp` token with `aud` = a *different* resource | 401 `invalid_token` (**not** 200 — the passthrough guard) |
| 5 | `POST /mcp` token with correct `aud`, missing scope | 403 `insufficient_scope` + `scope=` + `resource_metadata` |
| 6 | AS metadata fetched from each of the 5 probe URLs | every response's `issuer` byte-equals the constructed issuer |
| 7 | `/authorize` without `resource` | policy decision — document it; if required, `invalid_target` |
| 8 | `/authorize` with `resource` containing `#frag` | `invalid_target` |
| 9 | `/token` with a `resource` not granted at `/authorize` | `invalid_target` |
| 10 | Issued JWT | `aud` string-equals the `resource` sent; `typ` header = `at+jwt`; `iss` byte-equals metadata `issuer` |
| 11 | Success redirect and error redirect | both carry `iss=` matching metadata exactly |
| 12 | `redirect_uri` `http://127.0.0.1:9999/callback` vs registered `http://127.0.0.1/callback` | accepted (port ignored) |
| 13 | `redirect_uri` `http://localhost:9999/callback` vs registered `http://127.0.0.1/callback` | **rejected** (different host) |
| 14 | `redirect_uri` `https://evil.example/cb` unregistered | 400, **no redirect issued** |
| 15 | `/token` with `Content-Type: application/json` | 400 (not 415 crash); with form-urlencoded | 200 |
| 16 | `/register` with form-urlencoded | 400; with JSON | 201 |
| 17 | CIMD `client_id` = `https://169.254.169.254/c.json` | blocked before any socket connect |
| 18 | CIMD doc whose `client_id` ≠ fetch URL | `invalid_client` |
| 19 | CIMD doc served with a 302 to an internal IP | blocked at the redirect hop |
| 20 | Refresh token replay after rotation | `invalid_grant`, and the whole token family revoked |
| 21 | `error_description` containing `"` or `\` | header still parses; `resource_metadata` still present |
| 22 | PRM `resource` vs URL with/without trailing slash | documented and consistent; §3.3 identity holds |
| 23 | Discovery + token endpoints under load | p99 < 10 s (Claude budget) |
| 24 | `GET /mcp` (revision 2026-07-28) | 405 |

---

## Open items to verify against a live client before shipping

1. Whether Claude's PRM fallback probing tolerates `Content-Type: application/json; charset=utf-8`.
   (Not stated in any fetched doc; assume yes but test.)
2. Whether ChatGPT's `{callback_id}` redirect path is stable per connector instance across
   re-authorization. (Vendor doc implies per-connector, not per-session; verify before caching a
   registered redirect URI.)
3. `resource_indicators_supported` is not a field defined by RFC 8707 itself in the fetched text; it is
   widely emitted in practice. Harmless, but not spec-backed — do not rely on clients reading it.
