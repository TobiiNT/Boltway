# Discovery & Metadata — implementer reference

Scope: RFC 8414 (OAuth 2.0 Authorization Server Metadata), OpenID Connect Discovery 1.0,
RFC 9728 (Protected Resource Metadata, for the MCP resource server side), and the MCP
authorization spec's client-side probing order (2025-06-18 and 2025-11-25).

Sources fetched and quoted from: `https://www.rfc-editor.org/rfc/rfc8414.txt`,
`https://openid.net/specs/openid-connect-discovery-1_0.html`,
`https://www.rfc-editor.org/rfc/rfc9728.txt`,
`https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml`,
`https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization`.

---

## 0. Corrections to the brief (read first)

Two premises in the task statement are wrong against the actual text; both matter.

| Premise | Actual |
|---|---|
| "RFC 8414 §3.3 on caching/TLS requirements" | §3.3 is **only** the issuer-match validation rule. **RFC 8414 contains no caching guidance at all** — `grep -i "cach" rfc8414.txt` returns zero hits. TLS is §6.1, impersonation is §6.2. |
| "OIDC Discovery appends `/.well-known/openid-configuration`" | Correct, but incomplete. RFC 8414 §5 explicitly says an AS **may need to publish at both locations** during transition, and MCP clients probe a *third* hybrid form (`/.well-known/openid-configuration/tenant1`) that neither spec defines as canonical. See §4. |

Because no RFC mandates cache headers, caching is a deployment decision. See §8 for what to
actually send.

---

## 1. Well-known URI construction — the core interop trap

### 1.1 Normative text, verbatim

**RFC 8414 §3:**
> "Authorization servers supporting metadata MUST make a JSON document containing metadata as specified in Section 2 available at a path formed by inserting a well-known URI string into the authorization server's issuer identifier **between the host component and the path component**, if any. By default, the well-known URI string used is "/.well-known/oauth-authorization-server". This path MUST use the "https" scheme."

**RFC 8414 §3.1:**
> "An authorization server metadata document MUST be queried using an HTTP "GET" request at the previously specified path."
>
> "If the issuer identifier value contains a path component, any terminating "/" MUST be removed before inserting "/.well-known/" and the well-known URI suffix between the host component and the path component."

**OIDC Discovery §4:**
> "OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by **concatenating the string `/.well-known/openid-configuration` to the Issuer**."
>
> "`openid-configuration` MUST point to a JSON document compliant with this specification and MUST be returned using the `application/json` content type."
>
> "The `openid-configuration` endpoint **SHOULD** support the use of Cross-Origin Resource Sharing (CORS) […] to enable JavaScript Clients and other Browser-Based Clients to access it."

**OIDC Discovery §4.1:**
> "An OpenID Provider's configuration information MUST be retrieved using an HTTP GET request at the previously specified path."
>
> "If the Issuer value contains a path component, any terminating `/` MUST be removed before **appending** `/.well-known/openid-configuration`."

**RFC 8414 §5 (the disagreement, stated by the RFC itself):**
> "The algorithm for transforming the issuer identifier to an authorization server metadata location defined in Section 3 is equivalent to the corresponding transformation defined in Section 4 of "OpenID Connect Discovery 1.0" […] **provided that the issuer identifier contains no path component**. However, they are different when there is a path component, because OpenID Connect Discovery 1.0 specifies that the well-known URI string is **appended** to the issuer identifier (e.g., `https://example.com/issuer1/.well-known/openid-configuration`), whereas this specification specifies that the well-known URI string is **inserted before the path component** of the issuer identifier (e.g., `https://example.com/.well-known/openid-configuration/issuer1`)."
>
> "[…] when deployed in legacy environments in which the OpenID Connect Discovery 1.0 transformation is already used, it may be necessary during a transition period to **publish metadata for issuer identifiers containing a path component at both locations**."

### 1.2 Exact URL matrix — what to serve

**Issuer `https://as.example.com` (no path component)** — serve exactly these two:

| # | URL | Spec | Body |
|---|---|---|---|
| 1 | `https://as.example.com/.well-known/oauth-authorization-server` | RFC 8414 §3 | AS metadata |
| 2 | `https://as.example.com/.well-known/openid-configuration` | OIDC Discovery §4 | OP metadata |

The two transformations coincide here. Both must return `"issuer": "https://as.example.com"`.

**Issuer `https://as.example.com/tenant1` (path component)** — serve **all four**:

| # | URL | Derivation | Required by |
|---|---|---|---|
| 1 | `https://as.example.com/.well-known/oauth-authorization-server/tenant1` | RFC 8414 insertion | RFC 8414 §3 (**MUST**) |
| 2 | `https://as.example.com/.well-known/openid-configuration/tenant1` | RFC 8414 insertion, `openid-configuration` suffix | RFC 8414 §5 + MCP client probe #2 |
| 3 | `https://as.example.com/tenant1/.well-known/openid-configuration` | OIDC append | OIDC Discovery §4 (**MUST**) + MCP client probe #3 |
| 4 | `https://as.example.com/tenant1/.well-known/oauth-authorization-server` | OIDC-style append, OAuth suffix | Not in any spec. Serve anyway — several client libraries and gateways construct it. Cheap insurance. |

All four MUST return `"issuer": "https://as.example.com/tenant1"` — identical string, no
trailing slash, no normalization.

**Recommendation for this AS: use a path-less issuer per tenant** (`https://tenant1.as.example.com`,
or a single issuer with tenancy inside the token) unless multi-tenant-on-one-host is a hard
requirement. Every path-component bug in the wild comes from this table.

### 1.3 MCP client probing order, verbatim

MCP spec 2025-11-25, *Authorization Server Metadata Discovery*:

> "For issuer URLs with path components (e.g., `https://auth.example.com/tenant1`), clients **MUST** try endpoints in the following priority order:
> 1. OAuth 2.0 Authorization Server Metadata with path insertion: `https://auth.example.com/.well-known/oauth-authorization-server/tenant1`
> 2. OpenID Connect Discovery 1.0 with path insertion: `https://auth.example.com/.well-known/openid-configuration/tenant1`
> 3. OpenID Connect Discovery 1.0 path appending: `https://auth.example.com/tenant1/.well-known/openid-configuration`
>
> For issuer URLs without path components (e.g., `https://auth.example.com`), clients **MUST** try:
> 1. OAuth 2.0 Authorization Server Metadata: `https://auth.example.com/.well-known/oauth-authorization-server`
> 2. OpenID Connect Discovery 1.0: `https://auth.example.com/.well-known/openid-configuration`"

> "MCP authorization servers **MUST** provide at least one of the following discovery mechanisms: OAuth 2.0 Authorization Server Metadata (RFC8414); OpenID Connect Discovery 1.0. MCP clients **MUST** support both discovery mechanisms."

**Interop trap:** probing is sequential on 404. If a non-matching path returns **200 with an
HTML error page** or a **302 to a login page**, clients that only check status code will parse
garbage and fail with a confusing JSON error instead of falling through. In ASP.NET Core, map
the well-known routes explicitly and let unmatched `/.well-known/*` fall to a **404 with an
empty body**, never to your SPA fallback or auth middleware challenge.

### 1.4 ASP.NET Core routing sketch

```csharp
// Path-less issuer: two literal routes.
app.MapGet("/.well-known/oauth-authorization-server", GetAsMetadata);
app.MapGet("/.well-known/openid-configuration",        GetAsMetadata);

// Path-ful (multi-tenant) issuer: catch-all segment after the well-known suffix,
// plus the appended forms.
app.MapGet("/.well-known/oauth-authorization-server/{*tenant}", GetAsMetadataForTenant);
app.MapGet("/.well-known/openid-configuration/{*tenant}",       GetAsMetadataForTenant);
app.MapGet("/{tenant}/.well-known/openid-configuration",        GetAsMetadataForTenant);
app.MapGet("/{tenant}/.well-known/oauth-authorization-server",  GetAsMetadataForTenant);
```

Pitfalls specific to ASP.NET Core:
- **`UseAuthentication`/`UseAuthorization` must not challenge these routes.** Mark them
  `.AllowAnonymous()`. A 302 to a login page here breaks every client.
- **`UseHttpsRedirection` + a reverse proxy** — if TLS terminates upstream, configure
  `ForwardedHeaders` (`X-Forwarded-Proto`) or the issuer you compute will be `http://…` and
  §2 validation fails at the client.
- **Do not use `UseStaticFiles` to serve these.** Content negotiation and caching get wrong.
- **Trailing slash**: `/.well-known/openid-configuration/` (trailing slash) is a different
  route. ASP.NET Core matches it by default only if you don't set
  `AppendTrailingSlash`. Accept both; return byte-identical bodies.
- **HEAD**: `MapGet` handles HEAD in ASP.NET Core. Some probes use HEAD first.

---

## 2. Issuer validation — the rule both specs share

**RFC 8414 §3.3, complete text:**
> "The "issuer" value returned MUST be identical to the authorization server's issuer identifier value into which the well-known URI string was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data contained in the response MUST NOT be used."

**OIDC Discovery §4.3:**
> "If any of the validation procedures defined in this specification fail, any operations requiring the information that failed to correctly validate MUST be aborted and the information that failed to validate MUST NOT be used."
>
> "The `issuer` value returned MUST be identical to the Issuer URL that was used as the prefix to `/.well-known/openid-configuration` to retrieve the configuration information. **This MUST also be identical to the `iss` Claim value in ID Tokens issued from this Issuer.**"

**RFC 8414 §6.2:**
> "An attacker may also attempt to impersonate an authorization server by publishing a metadata document that contains an "issuer" claim using the issuer identifier URL of the authorization server being impersonated, but with its own endpoints and signing keys. […] To prevent this, the client MUST ensure that the issuer identifier URL it is using as the prefix for the metadata request exactly matches the value of the "issuer" metadata value in the authorization server metadata document received by the client."

**Comparison is code-point equality, not URL equivalence.** RFC 8414 §4:
> "Comparisons between the two strings MUST be performed as a Unicode code-point-to-code-point equality comparison."
> "Unicode Normalization [USA15] MUST NOT be applied at any point to either the JSON string or the string it is to be compared against."

OIDC Discovery §5 states the identical rule.

### Implementer rules

| Rule | Consequence if violated |
|---|---|
| `issuer` is a **configured constant**, never derived from `Request.Host` | Host-header injection rewrites your issuer; tokens minted under an attacker-chosen `iss` |
| `issuer` MUST use `https`, MUST have no `?query` and no `#fragment` (RFC 8414 §2) | Client rejects metadata |
| No trailing slash (unless the trailing slash is genuinely part of the issuer, in which case it must appear everywhere) | Client's string compare fails; discovery aborts |
| Same `issuer` string in: metadata `issuer`, JWT `iss` claim, ID-token `iss` claim, all four well-known bodies | Token validation fails after successful discovery — very hard to debug |
| Case is significant | `https://AS.example.com` != `https://as.example.com` |

In ASP.NET Core, bind issuer from configuration and assert once at startup:

```csharp
var issuer = new Uri(cfg["Oidc:Issuer"]!);
if (issuer.Scheme != "https") throw new InvalidOperationException("issuer MUST use https");
if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
    throw new InvalidOperationException("issuer MUST have no query or fragment (RFC 8414 §2)");
// Emit the *configured string*, not issuer.ToString() — Uri normalizes and can add a slash.
```

`new Uri("https://as.example.com").ToString()` yields `"https://as.example.com/"` — **with a
trailing slash**. This single line has broken more OIDC deployments than any other. Store and
emit the raw configured string.

---

## 3. Response format

**RFC 8414 §3.2:**
> "A successful response MUST use the 200 OK HTTP status code and return a JSON object using the "application/json" content type that contains a set of claims as its members that are a subset of the metadata values defined in Section 2. **Other claims MAY also be returned.**"
>
> "Claims that return multiple values are represented as JSON arrays. **Claims with zero elements MUST be omitted from the response.**"
>
> "An error response uses the applicable HTTP status code value."

| Aspect | Value |
|---|---|
| Method | `GET` (MUST) |
| Success status | `200` (MUST) |
| Content-Type | `application/json` (MUST) |
| Empty arrays | **MUST be omitted** — never emit `"scopes_supported": []` |
| Unknown members | MAY be present; clients ignore |
| Unknown tenant / no such issuer | `404`, empty body |
| Wrong method | `405` |

ASP.NET Core: configure `JsonSerializerOptions` with
`DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull` **and** a custom check that
drops empty collections. `System.Text.Json` does *not* drop empty arrays by default.

---

## 4. RFC 8414 §2 — complete field list

Verbatim requirement levels from RFC 8414 §2. "Publish" = recommended value for this AS.

| Field | Type | Level | Publish |
|---|---|---|---|
| `issuer` | string (https URL, no query/fragment) | **REQUIRED** | configured issuer, exact string |
| `authorization_endpoint` | string (URL) | **REQUIRED** unless no grant types use it | `{issuer}/authorize` |
| `token_endpoint` | string (URL) | **REQUIRED** unless only implicit is supported | `{issuer}/token` |
| `jwks_uri` | string (https URL) | OPTIONAL *(REQUIRED by OIDC — see §6)* | `{issuer}/.well-known/jwks.json` |
| `registration_endpoint` | string (URL) | OPTIONAL | `{issuer}/register` — **needed for ChatGPT DCR** |
| `scopes_supported` | array of string | RECOMMENDED | `["openid","profile","email","offline_access", …app scopes]` |
| `response_types_supported` | array of string | **REQUIRED** | `["code"]` |
| `response_modes_supported` | array of string | OPTIONAL — default `["query","fragment"]` | `["query","form_post"]` |
| `grant_types_supported` | array of string | OPTIONAL — default `["authorization_code","implicit"]` | `["authorization_code","refresh_token","client_credentials"]` |
| `token_endpoint_auth_methods_supported` | array of string | OPTIONAL — default `["client_secret_basic"]` | `["none","client_secret_basic","client_secret_post","private_key_jwt"]` |
| `token_endpoint_auth_signing_alg_values_supported` | array of string | OPTIONAL — **"MUST be present if either of these authentication methods [`private_key_jwt`, `client_secret_jwt`] are specified"**; "Servers SHOULD support `RS256`"; **"The value `none` MUST NOT be used."** | `["RS256","ES256"]` |
| `service_documentation` | string (URL) | OPTIONAL | your docs page |
| `ui_locales_supported` | array of BCP 47 tags | OPTIONAL | `["en-US","vi-VN"]` |
| `op_policy_uri` | string (URL) | OPTIONAL | privacy policy URL |
| `op_tos_uri` | string (URL) | OPTIONAL | ToS URL |
| `revocation_endpoint` | string (URL) | OPTIONAL | `{issuer}/revoke` |
| `revocation_endpoint_auth_methods_supported` | array of string | OPTIONAL — default `["client_secret_basic"]` | mirror token endpoint |
| `revocation_endpoint_auth_signing_alg_values_supported` | array of string | OPTIONAL — same MUST-be-present rule; **`none` MUST NOT be used** | `["RS256","ES256"]` |
| `introspection_endpoint` | string (URL) | OPTIONAL | `{issuer}/introspect` |
| `introspection_endpoint_auth_methods_supported` | array of string | OPTIONAL — "If omitted, the set of supported authentication methods MUST be determined by other means" | `["client_secret_basic","private_key_jwt"]` |
| `introspection_endpoint_auth_signing_alg_values_supported` | array of string | OPTIONAL — same MUST-be-present rule; **`none` MUST NOT be used** | `["RS256","ES256"]` |
| `code_challenge_methods_supported` | array of string | OPTIONAL — **"If omitted, the authorization server does not support PKCE."** | `["S256"]` |
| `signed_metadata` | string (JWT) | OPTIONAL (§2.1) | omit |

Closing clause, §2:
> "Additional authorization server metadata parameters MAY also be used. Some are defined by other specifications, such as OpenID Connect Discovery 1.0."

**§2.1 signed_metadata**, verbatim:
> "The signed metadata MUST be digitally signed or MACed using JSON Web Signature (JWS) and MUST contain an "iss" (issuer) claim denoting the party attesting to the claims in the signed metadata. Consumers of the metadata MAY ignore the signed metadata if they do not support this feature. If the consumer of the metadata supports signed metadata, metadata values conveyed in the signed metadata MUST take precedence over the corresponding values conveyed using plain JSON elements."
> "A "signed_metadata" metadata value SHOULD NOT appear as a claim in the JWT."

**`jwks_uri` sub-requirement (§2):** "This URL MUST use the "https" scheme. […] When both signing
and encryption keys are made available, a "use" (public key use) parameter value is REQUIRED for
all keys in the referenced JWK Set to indicate each key's intended usage."

### 4.1 Verbatim example response (RFC 8414 §3.2)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
 "issuer":
   "https://server.example.com",
 "authorization_endpoint":
   "https://server.example.com/authorize",
 "token_endpoint":
   "https://server.example.com/token",
 "token_endpoint_auth_methods_supported":
   ["client_secret_basic", "private_key_jwt"],
 "token_endpoint_auth_signing_alg_values_supported":
   ["RS256", "ES256"],
 "userinfo_endpoint":
   "https://server.example.com/userinfo",
 "jwks_uri":
   "https://server.example.com/jwks.json",
 "registration_endpoint":
   "https://server.example.com/register",
 "scopes_supported":
   ["openid", "profile", "email", "address",
    "phone", "offline_access"],
 "response_types_supported":
   ["code", "code token"],
 "service_documentation":
   "http://server.example.com/service_documentation.html",
 "ui_locales_supported":
   ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
}
```

Note the RFC's own example includes `userinfo_endpoint`, which is an **OIDC** field — evidence
that mixing registries in one document is expected and correct.

---

## 5. OIDC Discovery §3 — complete OpenID Provider Metadata field list

Verbatim requirement levels from OIDC Discovery 1.0 §3.

| Field | Type | Level | Notes / publish |
|---|---|---|---|
| `issuer` | https URL, no query/fragment | **REQUIRED** | "MUST be identical to the `iss` Claim value in ID Tokens issued from this Issuer" |
| `authorization_endpoint` | https URL | **REQUIRED** | "MUST use the https scheme and MAY contain port, path, and query parameter components" |
| `token_endpoint` | https URL | **REQUIRED** unless only Implicit Flow used | |
| `userinfo_endpoint` | https URL | RECOMMENDED | `{issuer}/userinfo` |
| `jwks_uri` | https URL | **REQUIRED** | "The JWK Set MUST NOT contain private or symmetric key values." |
| `registration_endpoint` | https URL | RECOMMENDED | required in practice for ChatGPT DCR |
| `scopes_supported` | array | RECOMMENDED | "The server **MUST support the `openid` scope value**" |
| `response_types_supported` | array | **REQUIRED** | "Dynamic OpenID Providers MUST support the `code`, `id_token`, and the `id_token token` Response Type values" |
| `response_modes_supported` | array | OPTIONAL — default `["query","fragment"]` | |
| `grant_types_supported` | array | OPTIONAL — default `["authorization_code","implicit"]` | "Dynamic OpenID Providers MUST support the `authorization_code` and `implicit` Grant Type values" |
| `acr_values_supported` | array | OPTIONAL | |
| `subject_types_supported` | array | **REQUIRED** | "Valid types include `pairwise` and `public`" |
| `id_token_signing_alg_values_supported` | array | **REQUIRED** | "The algorithm **`RS256` MUST be included**." "The value `none` MAY be supported but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint" |
| `id_token_encryption_alg_values_supported` | array | OPTIONAL | omit |
| `id_token_encryption_enc_values_supported` | array | OPTIONAL | omit |
| `userinfo_signing_alg_values_supported` | array | OPTIONAL | "The value `none` MAY be included" |
| `userinfo_encryption_alg_values_supported` | array | OPTIONAL | omit |
| `userinfo_encryption_enc_values_supported` | array | OPTIONAL | omit |
| `request_object_signing_alg_values_supported` | array | OPTIONAL | "Servers SHOULD support `none` and `RS256`" |
| `request_object_encryption_alg_values_supported` | array | OPTIONAL | omit |
| `request_object_encryption_enc_values_supported` | array | OPTIONAL | omit |
| `token_endpoint_auth_methods_supported` | array | OPTIONAL — default `["client_secret_basic"]` | "The options are `client_secret_post`, `client_secret_basic`, `client_secret_jwt`, and `private_key_jwt`" |
| `token_endpoint_auth_signing_alg_values_supported` | array | OPTIONAL | "Servers SHOULD support `RS256`. The value `none` MUST NOT be used." |
| `display_values_supported` | array | OPTIONAL | `["page","popup"]` |
| `claim_types_supported` | array | OPTIONAL — default `["normal"]` | values: `normal`, `aggregated`, `distributed` |
| `claims_supported` | array | RECOMMENDED | "for privacy or other reasons, this might not be an exhaustive list" |
| `service_documentation` | URL | OPTIONAL | |
| `claims_locales_supported` | array of BCP 47 | OPTIONAL | |
| `ui_locales_supported` | array of BCP 47 | OPTIONAL | |
| `claims_parameter_supported` | boolean | OPTIONAL — default `false` | `false` |
| `request_parameter_supported` | boolean | OPTIONAL — default `false` | `false` |
| `request_uri_parameter_supported` | boolean | OPTIONAL — **default `true`** | publish `false` explicitly if unsupported |
| `require_request_uri_registration` | boolean | OPTIONAL — default `false` | |
| `op_policy_uri` | URL | OPTIONAL | |
| `op_tos_uri` | URL | OPTIONAL | |

**CORS (OIDC §3 closing paragraph):**
> "The Token Endpoint, UserInfo Endpoint, `jwks_uri` endpoint, Dynamic Client Registration Endpoint, and any other endpoints directly accessed by Clients SHOULD support the use of Cross-Origin Resource Sharing (CORS) […]. The use of CORS at the Authorization Endpoint is NOT RECOMMENDED as it is redirected to by the client and not directly accessed."

**Closing clause:** "Additional OpenID Provider Metadata parameters MAY also be used."

**§6 Implementation Considerations:** "All of these Relying Parties and OpenID Providers MUST
implement the features that are listed in this specification as being "REQUIRED" or are described
with a "MUST"."

---

## 6. Where the two documents disagree — exact deltas

### 6.1 Requirement-level conflicts on shared fields

| Field | RFC 8414 | OIDC Discovery | Resolution for this AS |
|---|---|---|---|
| `jwks_uri` | **OPTIONAL** | **REQUIRED** | **Always publish.** Omitting it breaks every OIDC RP and most JWT-validating resource servers. |
| `registration_endpoint` | OPTIONAL | RECOMMENDED | Publish — ChatGPT connectors historically require DCR. |
| `response_types_supported` | REQUIRED, no mandated values | REQUIRED, "Dynamic OPs **MUST support** `code`, `id_token`, `id_token token`" | Publish `["code"]` only. OAuth 2.1 forbids implicit; the OIDC "dynamic OP" MUST conflicts with OAuth 2.1 §. Accept the deviation deliberately — no MCP client needs `id_token token`. |
| `grant_types_supported` | OPTIONAL, default includes `implicit` | "Dynamic OPs MUST support `authorization_code` and `implicit`" | Publish explicitly `["authorization_code","refresh_token","client_credentials"]`. **Always publish this field** so the `implicit`-containing default never applies. |
| `scopes_supported` | RECOMMENDED, no mandated value | RECOMMENDED, "**MUST support the `openid` scope value**" | Include `openid`. |
| `code_challenge_methods_supported` | OPTIONAL; "If omitted, the authorization server does not support PKCE" | **Not defined at all** | **MUST publish `["S256"]` in BOTH documents.** See §6.3. |
| Well-known path with issuer path component | insert before path | append after path | Serve both (§1.2). |

### 6.2 Fields OIDC requires that RFC 8414 does not define at all

These have no RFC 8414 counterpart. If you serve `/.well-known/openid-configuration` they are
**REQUIRED**:

| Field | Level | Minimum viable value |
|---|---|---|
| `jwks_uri` | REQUIRED in OIDC, OPTIONAL in 8414 | `{issuer}/.well-known/jwks.json` |
| `subject_types_supported` | **REQUIRED** | `["public"]` |
| `id_token_signing_alg_values_supported` | **REQUIRED**, must include `RS256` | `["RS256"]` (add `ES256` if you sign with EC — but `RS256` must still be listed) |

`userinfo_endpoint` is RECOMMENDED in OIDC and absent from RFC 8414 §2, yet appears in RFC 8414's
own §3.2 example.

### 6.3 The PKCE discovery trap — hard requirement for MCP

MCP spec 2025-11-25, *Authorization Code Protection*:

> "**OAuth 2.0 Authorization Server Metadata**: If `code_challenge_methods_supported` is absent, the authorization server does not support PKCE and MCP clients **MUST refuse to proceed**."
>
> "**OpenID Connect Discovery 1.0**: While the OpenID Provider Metadata does not define `code_challenge_methods_supported`, this field is commonly included by OpenID providers. MCP clients **MUST** verify the presence of `code_challenge_methods_supported` in the provider metadata response. If the field is absent, MCP clients **MUST refuse to proceed**."
>
> "**Authorization servers providing OpenID Connect Discovery 1.0 MUST include `code_challenge_methods_supported` in their metadata to ensure MCP compatibility.**"

> "MCP clients **MUST** use the `S256` code challenge method when technically capable."

**Concretely:** emit `"code_challenge_methods_supported": ["S256"]` in **all four** documents. Do
not emit `"plain"` — OAuth 2.1 removed it. This is the single most common cause of "Claude/ChatGPT
refuses to connect" with an otherwise-correct AS.

### 6.4 Additional field required by the current MCP spec

| Field | Type | Source | Value |
|---|---|---|---|
| `client_id_metadata_document_supported` | boolean | draft-ietf-oauth-client-id-metadata-document-00; MCP 2025-11-25 *Discovery* | `true` if you support CIMD |

MCP client registration priority order, verbatim:
> "1. Use pre-registered client information for the server if the client has it available
> 2. Use Client ID Metadata Documents if the Authorization Server indicates if the server supports it (via `client_id_metadata_document_supported` in OAuth Authorization Server Metadata)
> 3. Use Dynamic Client Registration as a fallback if the Authorization Server supports it (via `registration_endpoint` in OAuth Authorization Server Metadata)
> 4. Prompt the user to enter the client information if no other option is available"

Support **both** CIMD and DCR: Claude's route on the deployment measured here is CIMD; ChatGPT
historically requires DCR.

---

## 7. IANA "OAuth Authorization Server Metadata" registry — full value list

Anything you emit outside this list is a private extension. Complete registry as fetched:

| Metadata Name | Reference |
|---|---|
| `issuer` | RFC 8414 §2 |
| `authorization_endpoint` | RFC 8414 §2 |
| `token_endpoint` | RFC 8414 §2 |
| `jwks_uri` | RFC 8414 §2 |
| `registration_endpoint` | RFC 8414 §2 |
| `scopes_supported` | RFC 8414 §2 |
| `response_types_supported` | RFC 8414 §2 |
| `response_modes_supported` | RFC 8414 §2 |
| `grant_types_supported` | RFC 8414 §2 |
| `token_endpoint_auth_methods_supported` | RFC 8414 §2 |
| `token_endpoint_auth_signing_alg_values_supported` | RFC 8414 §2 |
| `service_documentation` | RFC 8414 §2 |
| `ui_locales_supported` | RFC 8414 §2 |
| `op_policy_uri` | RFC 8414 §2 |
| `op_tos_uri` | RFC 8414 §2 |
| `revocation_endpoint` | RFC 8414 §2 |
| `revocation_endpoint_auth_methods_supported` | RFC 8414 §2 |
| `revocation_endpoint_auth_signing_alg_values_supported` | RFC 8414 §2 |
| `introspection_endpoint` | RFC 8414 §2 |
| `introspection_endpoint_auth_methods_supported` | RFC 8414 §2 |
| `introspection_endpoint_auth_signing_alg_values_supported` | RFC 8414 §2 |
| `code_challenge_methods_supported` | RFC 8414 §2 |
| `signed_metadata` | RFC 8414 §2.1 |
| `device_authorization_endpoint` | RFC 8628 §4 |
| `tls_client_certificate_bound_access_tokens` | RFC 8705 §3.3 |
| `mtls_endpoint_aliases` | RFC 8705 §5 |
| `require_signed_request_object` | RFC 9101 §10.5 |
| `pushed_authorization_request_endpoint` | RFC 9126 §5 |
| `require_pushed_authorization_requests` | RFC 9126 §5 |
| `authorization_response_iss_parameter_supported` | RFC 9207 §3 |
| `authorization_details_types_supported` | RFC 9396 §10 |
| `dpop_signing_alg_values_supported` | RFC 9449 §5.1 |
| `introspection_signing_alg_values_supported` | RFC 9701 §7 |
| `introspection_encryption_alg_values_supported` | RFC 9701 §7 |
| `introspection_encryption_enc_values_supported` | RFC 9701 §7 |
| `protected_resources` | RFC 9728 §4 |
| `userinfo_endpoint` | OIDC Discovery §3 |
| `acr_values_supported` | OIDC Discovery §3 |
| `subject_types_supported` | OIDC Discovery §3 |
| `id_token_signing_alg_values_supported` | OIDC Discovery §3 |
| `id_token_encryption_alg_values_supported` | OIDC Discovery §3 |
| `id_token_encryption_enc_values_supported` | OIDC Discovery §3 |
| `userinfo_signing_alg_values_supported` | OIDC Discovery §3 |
| `userinfo_encryption_alg_values_supported` | OIDC Discovery §3 |
| `userinfo_encryption_enc_values_supported` | OIDC Discovery §3 |
| `request_object_signing_alg_values_supported` | OIDC Discovery §3 |
| `request_object_encryption_alg_values_supported` | OIDC Discovery §3 |
| `request_object_encryption_enc_values_supported` | OIDC Discovery §3 |
| `display_values_supported` | OIDC Discovery §3 |
| `claim_types_supported` | OIDC Discovery §3 |
| `claims_supported` | OIDC Discovery §3 |
| `claims_locales_supported` | OIDC Discovery §3 |
| `claims_parameter_supported` | OIDC Discovery §3 |
| `request_parameter_supported` | OIDC Discovery §3 |
| `request_uri_parameter_supported` | OIDC Discovery §3 |
| `require_request_uri_registration` | OIDC Discovery §3 |
| `check_session_iframe` | OIDC Session Management 1.0 §3.3 |
| `end_session_endpoint` | OIDC RP-Initiated Logout 1.0 §2.1 |
| `frontchannel_logout_supported` | OIDC Front-Channel Logout 1.0 §3 |
| `backchannel_logout_supported` | OIDC Back-Channel Logout 1.0 §2 |
| `backchannel_logout_session_supported` | OIDC Back-Channel Logout 1.0 §2 |
| `backchannel_token_delivery_modes_supported` | OIDC CIBA Core 1.0 §4 |
| `backchannel_authentication_endpoint` | OIDC CIBA Core 1.0 §4 |
| `backchannel_authentication_request_signing_alg_values_supported` | OIDC CIBA Core 1.0 §4 |
| `backchannel_user_code_parameter_supported` | OIDC CIBA Core 1.0 §4 |
| `client_registration_types_supported` | OpenID Federation 1.0 §5.1.3 |
| `federation_registration_endpoint` | OpenID Federation 1.0 §5.1.3 |
| `signed_jwks_uri` | OpenID Federation 1.0 §5.2.1 |
| `jwks` | OpenID Federation 1.0 §5.2.1 |
| `organization_name`, `display_name`, `description`, `keywords`, `contacts`, `logo_uri`, `information_uri`, `organization_uri` | OpenID Federation 1.0 §5.2.2 |
| `nfv_token_signing_alg_values_supported`, `nfv_token_encryption_alg_values_supported`, `nfv_token_encryption_enc_values_supported` | ETSI GS NFV-SEC 022 V2.7.1 |
| `status_list_aggregation_endpoint` | draft-ietf-oauth-status-list-21 §9 |
| `identity_chaining_requested_token_types_supported` | draft-ietf-oauth-identity-chaining-16 §3 |

**Not yet registered but required by MCP 2025-11-25:** `client_id_metadata_document_supported`.

---

## 8. TLS and caching

### 8.1 TLS — RFC 8414 §6.1, verbatim

> "Implementations MUST support TLS. Which version(s) ought to be implemented will vary over time […] The authorization server **MUST support TLS version 1.2** [RFC5246] and MAY support additional TLS mechanisms meeting its security requirements. When using TLS, the client MUST perform a TLS/SSL server certificate check, per RFC 6125 [RFC6125]."
>
> "To protect against information disclosure and tampering, confidentiality protection MUST be applied using TLS with a ciphersuite that provides confidentiality and integrity protection."

**RFC 8414 §6.2:**
> "TLS certificate checking MUST be performed by the client, as described in Section 6.1, when making an authorization server metadata request."

**OIDC Discovery §7.1** states the same, but points at the newer BCP: "Implementations SHOULD
follow the guidance in BCP 195 [RFC8996] [RFC9325]" — i.e. TLS 1.0/1.1 deprecated.

**MCP spec:** "All authorization server endpoints **MUST** be served over HTTPS." and
"All redirect URIs **MUST** be either `localhost` or use HTTPS."

Kestrel: set `SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13`. Do not enable TLS 1.0/1.1.

### 8.2 Caching — no RFC requirement; here is what to send anyway

RFC 8414 says nothing about caching. OIDC Discovery says nothing about caching the
configuration document. So this is your call. Recommended:

| Endpoint | Header | Rationale |
|---|---|---|
| `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` | `Cache-Control: public, max-age=3600` + `ETag` | Metadata is near-static; clients re-fetch on every connect. Keep TTL short enough that adding a field propagates within an hour. |
| `jwks_uri` | `Cache-Control: public, max-age=300` (shorter) + `ETag` | Key rotation must propagate fast. Publish the new key **before** signing with it, and keep the old key in the set for at least one max-age window past rotation. |
| Any error (404) | `Cache-Control: no-store` | A cached 404 on a probe path poisons discovery. |

`ETag` + `If-None-Match` → `304` is safe and cheap in ASP.NET Core. Do **not** set `Vary: Origin`
with a wildcard CORS policy on cached responses; it fragments caches and some proxies drop it.

CORS: OIDC §4 says the `openid-configuration` endpoint SHOULD support CORS. Send
`Access-Control-Allow-Origin: *` on the metadata and JWKS endpoints — they contain only public
data and no credentials. Never combine `*` with `Access-Control-Allow-Credentials: true`.

---

## 9. RFC 9728 — Protected Resource Metadata (the MCP server side)

Included because MCP makes it mandatory and its well-known rule is a *third* variant.

**Fields (§2):**

| Field | Level |
|---|---|
| `resource` | **REQUIRED** |
| `scopes_supported` | RECOMMENDED |
| `resource_name` | RECOMMENDED |
| `authorization_servers` | OPTIONAL in RFC 9728 — **REQUIRED by MCP**, "MUST include the `authorization_servers` field containing at least one authorization server" |
| `jwks_uri` | OPTIONAL |
| `bearer_methods_supported` | OPTIONAL |
| `resource_signing_alg_values_supported` | OPTIONAL |
| `resource_documentation` | OPTIONAL |
| `resource_policy_uri` | OPTIONAL |
| `resource_tos_uri` | OPTIONAL |
| `tls_client_certificate_bound_access_tokens` | OPTIONAL |
| `authorization_details_types_supported` | OPTIONAL |
| `dpop_signing_alg_values_supported` | OPTIONAL |
| `dpop_bound_access_tokens_required` | OPTIONAL |
| `signed_metadata` | OPTIONAL |

**Well-known construction (§3.1)** — **insertion**, same as RFC 8414, *not* OIDC-style append:

| Resource identifier | Metadata URL |
|---|---|
| `https://resource.example.com` | `https://resource.example.com/.well-known/oauth-protected-resource` |
| `https://resource.example.com/resource1` | `https://resource.example.com/.well-known/oauth-protected-resource/resource1` |

> "If the resource identifier value contains a path or query component, any terminating slash (`/`) following the host component MUST be removed before inserting."

**Validation (§3.3):**
> "The `resource` value returned MUST be identical to the protected resource's resource identifier value into which the well-known URI path suffix was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data contained in the response MUST NOT be used."

**§5.1 WWW-Authenticate — exact wire format:**

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"
```

MCP 2025-11-25 adds a `scope` parameter (SHOULD) and defines the insufficient-scope case:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         scope="files:read"
```

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                         scope="files:read files:write user:profile",
                         resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         error_description="Additional file write permission required"
```

**MCP status code table (normative):**

| Status | Usage |
|---|---|
| `401` | Authorization required or token invalid |
| `403` | Invalid scopes or insufficient permissions |
| `400` | Malformed authorization request |

---

## 10. Error codes to return

Discovery endpoints are unauthenticated `GET`s and do **not** use OAuth error codes — those
belong to `/authorize` and `/token`. Table given so the AS is consistent end to end.

| Condition | Where | Status | Body / header |
|---|---|---|---|
| Metadata fetched OK | discovery | `200` | `application/json` |
| Unknown tenant / issuer | discovery | `404` | empty, `Cache-Control: no-store` |
| Non-GET on discovery | discovery | `405` | `Allow: GET, HEAD` |
| No token at MCP resource | resource server | `401` | `WWW-Authenticate: Bearer resource_metadata="…"` |
| Token audience mismatch / expired | resource server | `401` | `WWW-Authenticate: Bearer error="invalid_token"` |
| Token valid, scope insufficient | resource server | `403` | `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` |
| Missing/bad `response_type`, `redirect_uri`, malformed request | `/authorize` | `400` or redirect | `error=invalid_request` |
| `response_type` not in `response_types_supported` | `/authorize` | redirect | `error=unsupported_response_type` |
| Scope not in `scopes_supported` | `/authorize` | redirect | `error=invalid_scope` |
| Unknown/unresolvable `client_id` (incl. CIMD fetch failure, `client_id` != document URL) | `/authorize` | `400`, **do not redirect** | `error=invalid_client` |
| `redirect_uri` not exactly matching a registered value | `/authorize` | `400`, **do not redirect** | `error=invalid_request` — never redirect to an unvalidated URI |
| Bad client auth at token endpoint | `/token` | `401` | `error=invalid_client`, `WWW-Authenticate: Basic` if Basic was attempted |
| Bad/expired/replayed code, PKCE verifier mismatch | `/token` | `400` | `error=invalid_grant` |
| `grant_type` not supported | `/token` | `400` | `error=unsupported_grant_type` |
| `resource` (RFC 8707) names an unknown resource | `/token` | `400` | `error=invalid_target` |

---

## 11. Reference documents to emit

### `/.well-known/oauth-authorization-server` — issuer `https://as.example.com`

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "jwks_uri": "https://as.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://as.example.com/register",
  "revocation_endpoint": "https://as.example.com/revoke",
  "introspection_endpoint": "https://as.example.com/introspect",
  "userinfo_endpoint": "https://as.example.com/userinfo",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "form_post"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,
  "service_documentation": "https://as.example.com/docs",
  "op_policy_uri": "https://as.example.com/privacy",
  "op_tos_uri": "https://as.example.com/terms"
}
```

### `/.well-known/openid-configuration` — same issuer

Everything above, **plus** the three OIDC-REQUIRED fields:

```json
{
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                       "name", "given_name", "family_name", "email", "email_verified"],
  "claim_types_supported": ["normal"],
  "claims_parameter_supported": false,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "require_request_uri_registration": false
}
```

Simplest correct implementation: build **one** metadata object and serve it from all routes.
`jwks_uri`, `subject_types_supported` and `id_token_signing_alg_values_supported` are legal in
the RFC 8414 document (§2: "Additional authorization server metadata parameters MAY also be
used"; "Other claims MAY also be returned"), so a single superset document satisfies both specs
and eliminates drift between the two files.

---

## 12. Pre-ship checklist

- [ ] `issuer` is a configured string, `https`, no query, no fragment, no trailing slash; identical in metadata, JWT `iss`, ID-token `iss`, and all well-known bodies. Assert at startup.
- [ ] Never build `issuer` from `Request.Host` / `Request.Scheme`.
- [ ] `new Uri(issuer).ToString()` is not used anywhere on the emit path (adds a trailing slash).
- [ ] `code_challenge_methods_supported: ["S256"]` present in **every** document. Without it MCP clients MUST abort.
- [ ] `jwks_uri`, `subject_types_supported`, `id_token_signing_alg_values_supported` present (OIDC REQUIRED, 8414 does not require them).
- [ ] `RS256` listed in `id_token_signing_alg_values_supported` even if you prefer `ES256`.
- [ ] `openid` present in `scopes_supported`.
- [ ] `grant_types_supported` explicitly published so the `implicit`-containing default never applies.
- [ ] Zero-element arrays omitted, not emitted as `[]`.
- [ ] `Content-Type: application/json`, status `200`.
- [ ] Discovery routes `.AllowAnonymous()`; auth middleware cannot 302 them.
- [ ] Unmatched `/.well-known/*` returns a bare `404`, never HTML, never a SPA fallback, never a redirect.
- [ ] `ForwardedHeaders` configured if TLS terminates at a proxy.
- [ ] TLS 1.2 minimum; TLS 1.0/1.1 disabled.
- [ ] CORS `Access-Control-Allow-Origin: *` on metadata + JWKS, without `Allow-Credentials`.
- [ ] If the issuer has a path component, all four URLs in §1.2 are live and byte-identical.
- [ ] JWKS contains no private or symmetric key material; `use` present on every key when both signing and encryption keys are published.
- [ ] Both `client_id_metadata_document_supported: true` (Claude) and a working `registration_endpoint` (ChatGPT) — the two vendors take different registration routes.
- [ ] End-to-end probe: `curl` each of the well-known URLs and diff the `issuer` field against the configured constant with `cmp`, not a URL parser.
