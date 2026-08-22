# OAuth 2.1 Core — Implementer's Distillation

**Primary source fetched:** `draft-ietf-oauth-v2-1-15`, 2 March 2026, expires 3 September 2026.
Text: <https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt>
Datatracker: <https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/> — WG state "I-D Exists",
**not yet in IESG processing**; WG milestone "Submit to IESG" = December 2026. There is no RFC number yet.
Secondary: RFC 6749 (<https://www.rfc-editor.org/rfc/rfc6749.txt>) for the IANA registries 2.1 inherits
(§11.2 Parameters, §11.3 Response Types, §11.4 Extensions Error) and for the redirect_uri back-compat rule.

> All section numbers written `§N` below refer to **draft-ietf-oauth-v2-1-15** unless prefixed `6749 §N`.
> Quoted lines are verbatim from the fetched draft text.

---

## 0. Ten-second summary for the build

| # | Rule | Where |
|---|---|---|
| 1 | PKCE `code_challenge`/`code_verifier` is **mandatory for all clients**, confidential included. AS **MUST** enforce. | §4.1.1, §4.1.2.1, §7.5.1.1 |
| 2 | `redirect_uri` matched by **Simple String Comparison** (RFC 3986 §6.2.1). Only exception: loopback port. | §2.3.1, §4.1.1, §8.4.2 |
| 3 | Authorization code is **one-time use**. Second valid redemption ⇒ deny **and** revoke all tokens from that code. | §4.1.3, §7.5.2 |
| 4 | Refresh tokens for public clients **MUST** be sender-constrained **or** rotated. | §4.3.1 |
| 5 | Implicit grant, ROPC, and bearer-token-in-query-string are **gone**. | §10, §5.1 |

---

## 1. What OAuth 2.1 REMOVES vs OAuth 2.0

§10 gives the non-normative change list; the normative removals live in the sections cited.

| Removed | Normative statement | Section | Concrete ASP.NET Core action |
|---|---|---|---|
| **Implicit grant** (`response_type=token`) | "The Implicit grant (`response_type=token`) is omitted from this specification as per Section 2.1.2 of [RFC9700]"; "This value for the `response_type` parameter is no longer defined in OAuth 2.1." | §10, §10.1 | `/authorize` accepts only `response_type=code` (plus registered extension types e.g. OIDC `id_token`). Anything else ⇒ redirect with `error=unsupported_response_type`. |
| **Resource Owner Password Credentials** (`grant_type=password`) | "The Resource Owner Password Credentials grant is omitted from this specification as per Section 2.4 of [RFC9700]" | §10 | `/token` with `grant_type=password` ⇒ `400` + `{"error":"unsupported_grant_type"}`. Do **not** implement it even behind a flag. |
| **Bearer token in URI query string** | "clients **MUST NOT** send the access token in a URI query parameter, and resource servers **MUST ignore** access tokens in a URI query parameter." | §5.1 | RS middleware reads `Authorization: Bearer` only (plus optional form param). Never bind `?access_token=`. |
| **Bearer token in page URLs** | "Bearer tokens **MUST NOT** be passed in page URLs (for example, as query string parameters)." | §7.1.3.7 | — |
| **`redirect_uri` in the token request** | "In OAuth 2.1 … it has been removed." | §10.2 | See trap in §7 below — you must still *accept* it for OAuth 2.0 clients. |
| **HTTP 307 for the credential-carrying redirect** | "An authorization server which redirects a request that potentially contains user credentials **MUST NOT** use the 307 status code"; "AS **SHOULD** use the status code 303 ("See Other")." | §7.5.3, §1.6 | `Results.Redirect(url)` in ASP.NET Core emits **302**, which is allowed. Use `Results.SeeOther`/`303` on the POST-login → redirect leg. Never `307`/`Redirect(preserveMethod: true)`. |
| **`Pragma: no-cache`** | 2.1 requires only `Cache-Control: no-store`; RFC 6749 §5.1 additionally required `Pragma: no-cache`. | §3.2.3 vs 6749 §5.1 | Emit `Cache-Control: no-store`. Emitting `Pragma: no-cache` too is harmless and helps ancient clients. |

**Trap:** removing implicit does *not* remove other authorization-endpoint response types.
"Removal of `response_type=token` does not have an effect on other extension response types
returning other artifacts from the authorization endpoint, for example, `response_type=id_token`
defined by [OpenID.Connect]." (§10.1) — so your response_type validator must be a **registry
lookup**, not a hardcoded `== "code"`, if you intend to serve OIDC hybrid/`id_token` flows.

---

## 2. What OAuth 2.1 makes MANDATORY

### 2.1 PKCE — for every client type

| Normative statement | Section |
|---|---|
| "`code_challenge`: **REQUIRED** unless the specific requirements of Section 7.5.1 are met." | §4.1.1 |
| "Authorization servers **MUST support** the `code_challenge` and `code_verifier` parameters." | §4.1.1 |
| "Clients **MUST** use `code_challenge` and `code_verifier` and authorization servers **MUST enforce** their use except under the conditions described in Section 7.5.1." | §4.1.1 |
| "An authorization server **MUST reject** requests without a `code_challenge` from public clients, and **MUST reject** such requests from other clients unless there is reasonable assurance that the client mitigates authorization code injection in other ways." | §4.1.2.1 |
| "If the client is capable of using `S256`, it **MUST** use `S256`, as **S256 is Mandatory To Implement (MTI) on the server**." | §4.1.1 |
| "`code_challenge_method`: **OPTIONAL, defaults to `plain` if not present** in the request. Code verifier transformation method is `S256` or `plain`." | §4.1.1 |

The only carve-out (§7.5.1.1) requires **both**:
1. the client is a confidential client, **and**
2. "there is reasonable assurance by the authorization server that the client implements the
   OpenID Connect `nonce` mechanism properly."
Even then: "using and enforcing `code_challenge` and `code_verifier` is still **RECOMMENDED**."

**Build decision: do not implement the carve-out.** Beyond it being weaker, §4.1.3 makes a code
issued without a challenge unredeemable anyway (see the spec-tension trap in §7).

**Transformations (§4.1.1), exact:**
```
S256    code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
plain   code_challenge = code_verifier
```

**ABNF (§4.1.1, Appendix A.17/A.18) — both verifier and challenge:**
```
code-verifier  = 43*128unreserved
code-challenge = 43*128unreserved
unreserved     = ALPHA / DIGIT / "-" / "." / "_" / "~"
ALPHA          = %x41-5A / %x61-7A
DIGIT          = %x30-39
```
Entropy guidance (§4.1.1): "It is **RECOMMENDED** that the output of a suitable random number
generator be used to create a **32-octet sequence**. The octet sequence is then base64url-encoded
to produce a **43-octet** URL-safe string."

C# verification (constant-time, no padding):
```csharp
// stored: challenge (string), method ("S256" | "plain")
static bool Verify(string verifier, string challenge, string method)
{
    if (verifier.Length is < 43 or > 128) return false;
    if (!verifier.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~')) return false;
    var computed = method switch
    {
        "S256"  => Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
        "plain" => verifier,
        _       => null
    };
    return computed is not null && CryptographicOperations.FixedTimeEquals(
        Encoding.ASCII.GetBytes(computed), Encoding.ASCII.GetBytes(challenge));
}
```
`System.Buffers.Text.Base64Url` exists in .NET 9 and produces unpadded base64url — correct here.
On .NET 8 and earlier you must hand-roll (`Convert.ToBase64String` → `+`→`-`, `/`→`_`, strip `=`).

**PKCE interop traps**

| Trap | Consequence |
|---|---|
| Treating a missing `code_challenge_method` as an error. | Spec says it **defaults to `plain`** (§4.1.1). Legal request. If your policy is S256-only, reject with `error=invalid_request` per the §4.1.2.1 unsupported-transform rule — but reject it *as an unsupported method*, not as a malformed request, and advertise `"code_challenge_methods_supported":["S256"]` in RFC 8414 metadata so clients know before they start. |
| Base64**+padding** or standard base64 alphabet in the S256 challenge. | Comparison always fails. Challenge is base64url, **unpadded**, 43 chars for SHA-256. |
| Hashing the verifier as UTF-8 bytes with a BOM, or hashing the base64 rather than the ASCII. | Spec is explicit: `SHA256(ASCII(code_verifier))`. |
| `==` string compare on the challenge. | Timing oracle. Use `CryptographicOperations.FixedTimeEquals`. |
| Accepting `code_verifier` when no challenge was sent. | §3.2.4 explicitly makes this `invalid_request`: "contains a `code_verifier` although no `code_challenge` was sent in the authorization request". |
| Storing the challenge in a client-readable place. | "the server **MUST NOT** include the `code_challenge` value in a response parameter in a form that entities other than the AS can extract." (§4.1.2) |

### 2.2 Exact-string redirect URI matching

| Normative statement | Section |
|---|---|
| "Authorization servers **MUST require** clients to register their **complete** redirect URI (including the path component)." | §2.3.1 |
| "Authorization servers **MUST reject** authorization requests that specify a redirect URI that doesn't **exactly match** one that was registered, with an exception for loopback redirects, where an exact match is required except for the port URI component" | §2.3.1 |
| "the authorization server **MUST ensure that the two URIs are equal**, see Section 6.2.1 of [RFC3986], **Simple String Comparison**, for details." | §4.1.1 |
| "The redirect URI **MUST be an absolute URI** … **MUST NOT include a fragment component**." | §2.3 |
| "The authorization server **MUST allow any port** to be specified at the time of the request for **loopback IP** redirect URIs" | §8.4.2 |
| "If multiple redirect URIs have been registered to a client, the client **MUST include** a redirect URI with the authorization request … If only a single redirect URI has been registered, the `redirect_uri` request parameter is **optional**." | §2.3.2 |
| "All the OAuth protocol URLs … **MUST use the `https` scheme** except for **loopback interface redirect URIs**, which **MAY** use the `http` scheme." | §1.5 |

Loopback forms (§8.4.2), exactly: `http://127.0.0.1:{port}/{path}` and `http://[::1]:{port}/{path}`.
`http://localhost:{port}/{path}` is **NOT RECOMMENDED** ("avoids inadvertently listening on network
interfaces other than the loopback interface").

Private-use scheme (§2.3.1, §8.4.3): "apps **MUST** use a URI scheme based on a domain name under
their control, expressed in reverse order"; AS **SHOULD** enforce this, and "**At a minimum, any
private-use URI scheme that doesn't contain a period character (.) SHOULD be rejected.**"
Form is single-slash: `com.example.app:/oauth2redirect/example-provider` (RFC 3986 §3.2 — no authority).

**Redirect-URI interop traps**

| Trap | Why it bites |
|---|---|
| Using `new Uri(a) == new Uri(b)` or `Uri.Compare` with normalization. | .NET `Uri` normalizes case, default ports, dot-segments, and **percent-decodes**. That is *not* Simple String Comparison. Compare the **raw registered string** to the **raw received string** with `StringComparison.Ordinal`. |
| Reading `Request.Query["redirect_uri"]` and re-serializing. | ASP.NET Core decodes query values. Round-tripping changes `%2F` → `/` etc. Keep the decoded value for comparison against the decoded registered value — pick one canonical side and be consistent; never mix decoded-vs-raw. |
| Allowing prefix/wildcard/subdomain matching "for dev convenience". | Direct violation of §2.3.1; also the classic redirect-URI-manipulation exfil. |
| Forgetting the loopback port carve-out. | Native/desktop clients bind an ephemeral port. Registered `http://127.0.0.1/cb` must match request `http://127.0.0.1:51004/cb`. Compare scheme + host + path + query exactly, ignore **only** the port. |
| Allowing a fragment. | §2.3: "MUST NOT include a fragment component." |
| Dropping the registered query string when appending `code`/`state`. | §2.3: the redirect URI "**MAY include a query string component** … which **MUST be retained** when adding additional query parameters." Same rule for the authorization endpoint URL itself (§3.1) and token endpoint URL (§3.2). |

### 2.3 Refresh token protection for public clients

| Normative statement | Section |
|---|---|
| "Authorization servers **MUST utilize one of these methods** to detect refresh token replay by malicious actors **for public clients**: *Sender-constrained refresh tokens* … e.g., by utilizing DPoP [RFC9449] or mTLS [RFC8705]. *Refresh token rotation*: the authorization server issues a new refresh token with every access token refresh response." | §4.3.1 |
| "When client authentication is not possible, the authorization server **SHOULD** issue sender-constrained refresh tokens or use refresh token rotation" | §4.3 |
| "The authorization server **MUST maintain the binding** between a refresh token and the client to whom it was issued." | §4.3 |
| "The authorization server **MUST verify the binding** between the refresh token and client identity whenever the client identity can be authenticated." | §4.3 |
| "The authorization server **MUST ensure that refresh tokens cannot be generated, modified, or guessed** to produce valid refresh tokens by unauthorized parties." | §4.3 |
| "If refresh tokens are issued, those refresh tokens **MUST be bound to the scope and resource servers** as consented by the resource owner." | §3.2.3 |

Rotation replay semantics, verbatim (§4.3.1): "The previous refresh token is invalidated but
**information about the relationship is retained** by the authorization server. If a refresh token
is compromised and subsequently used by both the attacker and the legitimate client, one of them
will present an invalidated refresh token, which will inform the authorization server of the breach.
The authorization server cannot determine which party submitted the invalid refresh token, but it
**will revoke the active refresh token as well as the access authorization grant** associated with it."

⇒ Data model: a refresh token row must carry a `GrantId` (family id) plus `PreviousTokenId`.
Presenting a token whose `RevokedAt is not null` and whose family is still active ⇒ **revoke the
entire family and the grant**, then return `400 {"error":"invalid_grant"}`.

### 2.4 Client authentication and registration

| Normative statement | Section |
|---|---|
| "Confidential clients **MUST authenticate** with the authorization server … when making requests to the token endpoint." | §3.2.1, §3.2.2 |
| "the authorization server **MUST support the client including the client credentials in the request body content**" (`client_secret_post`) | §2.4.1 |
| "The authorization server **MAY support the HTTP Basic authentication scheme**" (`client_secret_basic`) | §2.4.1 |
| "The parameters can only be transmitted in the request content and **MUST NOT be included in the request URI**." | §2.4.1 |
| "The client **MUST NOT use more than one authentication method** in each request" | §2.4 |
| "the authorization server **MUST protect any endpoint utilizing it against brute force attacks**." | §2.4.1 |
| "The client credentials grant type **MUST only be used by confidential clients**." | §4.2 |
| "A single `client_id` **SHOULD NOT** be treated as more than one type of client." | §2.1 |
| "It is **RECOMMENDED** to use asymmetric (public-key based) methods for client authentication such as mTLS [RFC8705] or … `private_key_jwt`" | §2.4 |

**The Basic-auth encoding trap** — the draft calls it out by name (§2.4.1): the client id is
`application/x-www-form-urlencoded`-encoded, *then* used as the Basic username; same for the secret
as password. Verbatim: "This method … **has led to many interoperability problems in the past**.
Some implementations have missed the encoding step, or decided to only encode certain characters,
or ignored the encoding requirement when validating the credentials". Practical AS behaviour:
when validating Basic, try both the form-decoded and the raw value. When issuing secrets, **restrict
the generated alphabet to `[A-Za-z0-9-._~]`** so the encoding step is an identity function and the
whole class of bugs disappears.

Registered `token_endpoint_auth_method` values (IANA "OAuth Token Endpoint Authentication Methods"):
`none`, `client_secret_post`, `client_secret_basic`, `client_secret_jwt`, `private_key_jwt`,
`tls_client_auth`, `self_signed_tls_client_auth`.

Client types (§2.1) — only two: **`confidential`** (has credentials with the AS) and **`public`**
(no credentials). Profiles named in the spec: `web application`, `browser-based application`,
`native application`.

---

## 3. `/authorize` — request contract

`GET` **MUST** be supported; `POST` **MAY** be (§3.1). Request parameters (§4.1.1):

| Parameter | Presence | Notes |
|---|---|---|
| `response_type` | REQUIRED | `code`. Missing or not understood ⇒ error per §4.1.2.1. |
| `client_id` | REQUIRED | §2.2. |
| `code_challenge` | REQUIRED (unless §7.5.1 carve-out) | 43–128 unreserved chars. |
| `code_challenge_method` | OPTIONAL | `S256` \| `plain`; **defaults to `plain`**. |
| `redirect_uri` | OPTIONAL if exactly one registered; **REQUIRED if multiple** | §2.3.2. |
| `scope` | OPTIONAL | space-delimited, case-sensitive. |
| `state` | OPTIONAL | opaque; echoed verbatim. |

Endpoint-level rules (§3.1):
- "The authorization server **MUST ignore unrecognized request parameters**."
- "Request and response parameters defined by this specification **MUST NOT be included more than once**." ⇒ duplicate `client_id` etc. is `invalid_request`.
- "**Parameters sent without a value MUST be treated as if they were omitted** from the request." ⇒ `&scope=&` is *absent* scope, not empty scope. In ASP.NET Core, `Request.Query["scope"]` returns `StringValues` — check `.Count > 1` for duplicates and treat `""` as missing.
- "The authorization endpoint URL **MUST NOT include a fragment component**."
- "**Cross-Origin Resource Sharing [WHATWG.CORS] MUST NOT be supported at the Authorization Endpoint**" — do not apply your global CORS policy here.
- "The authorization server **MUST first authenticate the resource owner**."

Scope rules (§1.4.1):
- "The authorization server **MAY** fully or partially ignore the scope requested by the client".
- "If the issued access token scope is different from the one requested by the client, the authorization server **MUST include the `scope` response parameter** in the token response".
- "If the client omits the `scope` parameter …, the authorization server **MUST either** process the request using a pre-defined default value **or** fail the request indicating an invalid scope."

---

## 4. `/authorize` — success response (§4.1.2)

Parameters appended to the **query component** of the redirect URI (Query String Serialization, App. C.1):

| Parameter | Presence |
|---|---|
| `code` | REQUIRED |
| `state` | **REQUIRED if** `state` was present in the request — "The exact value received from the client." |
| `iss` | OPTIONAL — the AS issuer identifier, RFC 9207 mix-up defence |

```http
HTTP/1.1 302 Found
Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
          &state=xyz&iss=https%3A%2F%2Fauthorization-server.example.com
```

- "The authorization code **MUST expire shortly** after it is issued … A **maximum authorization code lifetime of 10 minutes is RECOMMENDED**." (§4.1.2)
- "The authorization code is **bound to the client identifier, code challenge and redirect URI**." (§4.1.2)
- "The authorization server **MUST associate the `code_challenge` and `code_challenge_method` values with the issued authorization code**" (§4.1.2)

**Emit `iss` unconditionally.** Both Claude.ai and ChatGPT connect users to many authorization
servers from one client; §2.3.4 makes mix-up defence a client MUST, and RFC 9207 `iss` is the
defence the AS can actually provide. Cost is one query parameter.

---

## 5. `/authorize` — error response and the NO-REDIRECT rule

### 5.1 When you MUST NOT redirect

> "If the request fails due to a **missing, invalid, or mismatching redirect URI**, **or if the
> client identifier is missing or invalid**, the authorization server **MUST NOT redirect the user
> agent to the invalid redirect URI** and **SHOULD inform the resource owner** of the error, for
> example by displaying a message to the user in their browser." — §4.1.2.1

> "If an authorization request fails validation due to a missing, invalid, or mismatching redirect
> URI, the authorization server **SHOULD inform the resource owner** of the error and **MUST NOT
> automatically redirect** the user agent to the invalid redirect URI." — §2.3.5

> "Section 4.1.2.1 already prevents open redirects by stating that the authorization server MUST
> NOT automatically redirect the user agent in case of an **invalid combination of `client_id` and
> `redirect_uri`**." — §7.12.2

**Therefore the validation order at `/authorize` is not negotiable:**

```
1. client_id present?           no → RENDER ERROR PAGE (no redirect)
2. client_id known/enabled?     no → RENDER ERROR PAGE (no redirect)
3. redirect_uri resolvable?
     - absent + exactly 1 registered   → use it
     - absent + 0 or >1 registered     → RENDER ERROR PAGE (no redirect)
     - present + exact match (loopback: port-insensitive) → use it
     - present + no match              → RENDER ERROR PAGE (no redirect)
   ---- redirect_uri is now TRUSTED. Only past this line may you redirect. ----
4. response_type / code_challenge / scope / consent → REDIRECT with error=...
```

The error page is your own HTML. The spec prescribes no status code for it; **400 Bad Request** with
a human-readable body is the sane choice. Never put the untrusted `redirect_uri` in a `Location`
header, and do not reflect it unencoded into the page (§7.11: "The authorization server and client
MUST treat parameters received as potentially malicious external input … in particular, the values
of the `state` and `redirect_uri` parameters.").

Additional AS-as-open-redirector duty (§7.12.2): "The authorization server **MUST always
authenticate the user first** and, with the exception of the silent authentication use case, prompt
the user for credentials when needed, **before redirecting** the user." And: "The authorization
server **SHOULD only automatically redirect** the user agent **if it trusts the redirect URI**."
This matters when you enable RFC 7591 dynamic client registration for MCP — an attacker can self-register
a client with an attacker-controlled `redirect_uri`. Mitigation: never redirect before authentication,
and consider a warn-interstitial for first-time/low-reputation dynamically registered clients.

### 5.2 Authorization endpoint error codes (§4.1.2.1) — complete list

Delivered as **query parameters on the redirect**, with an HTTP **302** (or 303) `Location`.
There is no JSON body and no 4xx status for these — the redirect itself is the transport.

| `error` value | Meaning (verbatim) | HTTP status | Trigger in your handler |
|---|---|---|---|
| `invalid_request` | "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed." | 302 redirect | Missing `code_challenge`; unsupported `code_challenge_method`; duplicated parameter; missing `response_type` |
| `unauthorized_client` | "The client is not authorized to request an authorization code using this method." | 302 redirect | Client known but `authorization_code` not in its allowed grant types |
| `access_denied` | "The resource owner or authorization server denied the request." | 302 redirect | User clicked Deny; policy/ACL refusal |
| `unsupported_response_type` | "The authorization server does not support obtaining an authorization code using this method." | 302 redirect | `response_type` not `code`/not a registered type |
| `invalid_scope` | "The requested scope is invalid, unknown, or malformed." | 302 redirect | Unknown scope token; scope not allowed for client |
| `server_error` | "The authorization server encountered an unexpected condition… (This error code is needed because a **500** Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect.)" | 302 redirect | Unhandled exception **after** the redirect_uri is trusted |
| `temporarily_unavailable` | "…temporary overloading or maintenance of the server. (This error code is needed because a **503** Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)" | 302 redirect | Dependency down, shedding load |

Accompanying parameters: `error_description` (OPTIONAL), `error_uri` (OPTIONAL),
`state` (**REQUIRED if** present in the request — "The exact value received from the client."),
`iss` (OPTIONAL).

Two specific named cases:
- Unsupported transform: "If the server does not support the requested `code_challenge_method` transformation, the authorization endpoint **MUST return the authorization error response with error value set to `invalid_request`**." (§4.1.2.1)
- Missing/unknown `response_type`: "If an authorization request is missing the `response_type` parameter, **or if the response type is not understood**, the authorization server **MUST return an error response** as described in Section 4.1.2.1." (§4.1.1)

```http
HTTP/1.1 302 Found
Location: https://client.example.com/cb?error=access_denied
          &state=xyz&iss=https%3A%2F%2Fauthorization-server.example.com
```

**Traps:**
- `invalid_client` is **not** in the §4.1.2.1 list, and can't be — an unknown client is exactly the case where you may not redirect. (The IANA registry lists it at the authorization endpoint because OIDC-adjacent specs use it; core 2.1 does not.)
- Returning `500` from `/authorize` after the redirect URI has been validated is a spec violation *in spirit* — the client will see a browser error page instead of a machine-readable `server_error`. Wrap everything downstream of step 3 in a try/catch that redirects with `server_error`.
- Dropping `state` on the error path. It's REQUIRED whenever the request carried it, on **both** success and error. This is the single most common cause of "client hangs forever" — many clients key their pending-request table on `state`.

### 5.3 Character sets for error values (§4.1.2.1, §3.2.4, Appendix A.7–A.9)

```
error             = 1*NQSCHAR      NQSCHAR = %x20-21 / %x23-5B / %x5D-7E
error_description = 1*NQSCHAR      (i.e. no " and no \ , no control chars, ASCII only)
error_uri         = URI-reference  NQCHAR  = %x21 / %x23-5B / %x5D-7E   (also excludes space)
```
**Trap:** localised or user-supplied `error_description` containing non-ASCII, a `"`, or a `\` is a
protocol violation and breaks naive client parsers. Sanitise to the NQSCHAR set before emitting.

---

## 6. `/token` — request contract

- "The client **MUST use the HTTP POST method** when making requests to the token endpoint." (§3.2)
- Body is form-encoded, **UTF-8**, `Content-Type: application/x-www-form-urlencoded` (§3.2.2, App. C.2).
- "The authorization server **MUST ignore unrecognized request parameters**." (§3.2)
- "**Parameters sent without a value MUST be treated as if they were omitted**… Request and response parameters … **MUST NOT be included more than once**." (§3.2)
- "The token endpoint URL **MUST NOT include a fragment component**." (§3.2)
- CORS: §3.2 — browser-based apps "**will need** to ensure the token endpoint supports the necessary CORS headers". Same for "metadata URLs, dynamic client registration, revocation, introspection, discovery or user info endpoints". ⇒ CORS **on** at `/token` and metadata, **off** at `/authorize`.

Common parameters (§3.2.2):

| Parameter | Presence |
|---|---|
| `grant_type` | REQUIRED — `authorization_code` \| `refresh_token` \| `client_credentials` \| extension absolute URI |
| `client_id` | OPTIONAL — "needed when a form of client authentication that relies on the parameter is used, or the `grant_type` requires identification of public clients" |

Per-grant additions:

| `grant_type` | Parameter | Presence | Section |
|---|---|---|---|
| `authorization_code` | `code` | REQUIRED | §4.1.3 |
| | `code_verifier` | **REQUIRED if** `code_challenge` was in the authorization request; **MUST NOT be used otherwise** | §4.1.3 |
| | `client_id` | **REQUIRED if** the client is not authenticating | §4.1.3 |
| `refresh_token` | `refresh_token` | REQUIRED | §4.3.1 |
| | `scope` | OPTIONAL — "**MUST NOT include any scope not originally granted**…, and if omitted is treated as equal to the scope originally granted" | §4.3.1 |
| `client_credentials` | `scope` | OPTIONAL | §4.2.1 |

Extension grants (§4.4) use an absolute URI, e.g.
`grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code`.

ABNF (App. A.10): `grant-type = grant-name / URI-reference`, `grant-name = 1*("-"/"."/"_"/DIGIT/ALPHA)`.

---

## 7. `authorization_code` grant — server-side checks (§4.1.3)

Verbatim MUST-list, in addition to §3.2.2 processing:

> * ensure that the authorization code was issued to the **authenticated confidential client**, or if the client is public, ensure that the code was **issued to `client_id` in the request**,
> * verify that the authorization code is **valid**,
> * verify that the `code_verifier` parameter is present **if and only if** a `code_challenge` parameter was present in the authorization request,
> * if a `code_verifier` is present, verify the `code_verifier` by calculating the code challenge from the received `code_verifier` and comparing it with the previously associated `code_challenge`, after first transforming it according to the `code_challenge_method` method specified by the client, and
> * **If there was no `code_challenge` in the authorization request associated with the authorization code in the token request, the authorization server MUST reject the token request.**

And, one-time use:

> "The authorization server **MUST return an access token only once for a given authorization code**." — §4.1.3

**Spec-tension worth knowing.** The last bullet of §4.1.3 says a code with no associated
`code_challenge` **MUST** be rejected at `/token` — unconditionally, with no §7.5.1 carve-out. So a
code issued under the §7.5.1.1 confidential-client/OIDC-`nonce` exemption at `/authorize` is
un-redeemable under §4.1.3 as written. Draft-15 does not reconcile these. **Resolution for this
build: require PKCE at `/authorize` for every client, always.** You then satisfy both readings, and
you match what Claude.ai and ChatGPT actually send (S256).

Reference request (§4.1.3) — note **no `redirect_uri`**:
```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&code_verifier=3641a2d12d66101249cdf7a79c000c1f8c05d2aafcf14bf146497bed
```

**Back-compat trap (§10.2), a hard MUST:**
> "For backwards compatibility of an authorization server wishing to support both OAuth 2.0 and
> OAuth 2.1 clients, the authorization server **MUST allow clients to send the `redirect_uri`
> parameter in the token request** (Section 4.1.3), and **MUST enforce the parameter as described
> in [RFC6749]**."

⇒ Accept `redirect_uri` at `/token`; if present, it **must** equal the one used at `/authorize`,
else `invalid_grant` ("does not match the redirect URI used in the authorization request", §3.2.4).
If absent, do not error. §10.2 also notes you may key this off `client_id`. Do **not** make it
required — "A client following only the OAuth 2.1 recommendations will not send the `redirect_uri`
in the token request, and therefore will not be compatible with an authorization server that expects
the parameter in the token request."

### 7.1 Code replay — exactly what to do

> "If a second valid token request is made with the same authorization code as a previously
> successful token request, the authorization server **MUST deny the request** and **SHOULD revoke
> (when possible) all access tokens and refresh tokens previously issued based on that authorization
> code**." — §4.1.3

> "However, the authorization server should only revoke issued tokens **if the request containing
> the authorization code is also valid**, including any other parameters such as the `code_verifier`
> and client authentication. The authorization server **SHOULD NOT revoke any issued tokens when
> receiving a replayed authorization code that contains invalid parameters**. If it were to do so,
> this would create a **denial of service opportunity** for an attacker who is able to obtain an
> authorization code but unable to obtain the client authentication or `code_verifier`…" — §7.5.2

**This is the single most-often-botched rule.** The naive "code seen twice ⇒ nuke the grant"
implementation is a DoS: an attacker who sniffs a code but has neither the verifier nor the client
secret replays it with garbage and kills the legitimate client's tokens.

Correct order for a replayed code:

```
1. Look up the code. Not found / expired  → 400 invalid_grant.  DO NOT revoke.
2. Code found but already redeemed:
     a. Run the FULL validation anyway: client auth, client_id binding,
        code_verifier ↔ code_challenge, redirect_uri (if sent).
     b. Any check fails  → 400 invalid_grant.  DO NOT revoke.   ← DoS guard
     c. All checks pass  → 400 invalid_grant  AND revoke every access token
                           and refresh token descended from this code.
```
Implementation: retain redeemed codes (with their challenge + client binding) until at least their
original expiry so step 2a is possible; a redeemed code must not simply be deleted.

Rationale, verbatim (§7.5.2): "If an attacker is able to exfiltrate an authorization code and use
it before the legitimate client, the attacker will obtain the access token and the legitimate client
will not. Revoking any issued tokens means the attacker's tokens will then be revoked, stopping the
attack from proceeding any further."

---

## 8. `refresh_token` grant (§4.3)

Verbatim MUST-list (§4.3.1), in addition to §3.2.2:

> * if client authentication is included in the request, ensure that the refresh token was issued to the **authenticated client**, OR if a `client_id` is included in the request, ensure the refresh token was **issued to the matching client**
> * validate that the **grant** corresponding to this refresh token is **still active**
> * validate the refresh token

Plus: "Confidential clients **MUST authenticate** with the authorization server as described in Section 3.2.1." (§4.3.1)

Response (§4.3.2, §4.3.3):
- "If valid and authorized, the authorization server issues an access token as described in Section 3.2.3."
- "The authorization server **MAY** issue a new refresh token, in which case the client **MUST discard the old** refresh token".
- "The authorization server **MAY revoke the old refresh token** after issuing a new refresh token to the client. **If a new refresh token is issued, the refresh token scope MUST be identical to that of the refresh token included by the client in the request.**"

**Trap:** narrowing scope on the *access* token (allowed, §4.3.1) must **not** narrow the *refresh*
token's scope (forbidden, §4.3.3). Otherwise a client that requests a narrow scope once is
permanently downgraded — a real, frequently-shipped bug. Keep the rotated refresh token's scope
pinned to the grant's scope.

Automatic revocation triggers, "MAY" (§4.3.3): password change, logout at the authorization server.
Inactivity: "Refresh tokens **SHOULD expire if the client has been inactive** for some time".

---

## 9. `/token` — success response (§3.2.3)

`application/json` (RFC 8259), **HTTP 200**, `Cache-Control: no-store`.

| JSON field | Presence | Type / notes |
|---|---|---|
| `access_token` | **REQUIRED** | string |
| `token_type` | **REQUIRED** | string; "**Value is case insensitive**" — emit `Bearer` |
| `expires_in` | RECOMMENDED | **JSON number**, seconds. ABNF `expires-in = 1*DIGIT` |
| `scope` | "RECOMMENDED, if identical to the scope requested by the client; otherwise, **REQUIRED**" | space-delimited |
| `refresh_token` | OPTIONAL | string |

> "The authorization server **MUST include** the HTTP `Cache-Control` response header field … with a
> value of **`no-store`** in **any response containing tokens, credentials, or other sensitive
> information**." — §3.2.3

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter": "example_value"
}
```

**Traps:**
- `expires_in` as a **string** (`"3600"`). Spec says "A JSON number". `System.Text.Json` will do the right thing for an `int` property; it will not if you type it `string`.
- Omitting `Cache-Control: no-store`. Applies to the token response **and** to introspection, userinfo, DCR responses — anything with credentials in it. In ASP.NET Core set it explicitly per-endpoint; the default `ResponseCaching`/output-cache middleware will not add it for you, and a reverse proxy may cache a 200 without it.
- Omitting `scope` when you downscoped. It is REQUIRED whenever granted ≠ requested (§3.2.3, §1.4.1).
- `System.Text.Json` default camelCase policy would rename `access_token` → `accessToken`. Use explicit `[JsonPropertyName]` on every field, or a snake_case naming policy scoped to these DTOs.

---

## 10. `/token` — error response (§3.2.4)

> "The authorization server responds with an **HTTP 400 (Bad Request)** status code (**unless
> specified otherwise**) and includes the following parameters with the response"

Body is `application/json` (§3.2.4 — note this differs from RFC 6749's looser wording).

| `error` value | HTTP status | Meaning (verbatim) |
|---|---|---|
| `invalid_request` | **400** | "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, **contains a `code_verifier` although no `code_challenge` was sent in the authorization request**, or is otherwise malformed." |
| `invalid_client` | **401** if the client used the `Authorization` header, else 400 (401 MAY be used) | "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)." |
| `invalid_grant` | **400** | "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is **invalid, expired, revoked, does not match the redirect URI** used in the authorization request, **or was issued to another client**." |
| `unauthorized_client` | **400** | "The authenticated client is not authorized to use this authorization grant type." |
| `unsupported_grant_type` | **400** | "The authorization grant type is not supported by the authorization server." |
| `invalid_scope` | **400** | "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner." |

**These six are the entire core token-endpoint set.** `access_denied`, `unsupported_response_type`,
`server_error`, `temporarily_unavailable` are **authorization-endpoint only** — do not return them
from `/token`.

The `invalid_client` status rule, verbatim (§3.2.4, identical to 6749 §5.2):
> "The authorization server **MAY** return an HTTP 401 (Unauthorized) status code to indicate which
> HTTP authentication schemes are supported. **If the client attempted to authenticate via the
> `Authorization` request header field, the authorization server MUST respond with an HTTP 401
> (Unauthorized) status code and include the `WWW-Authenticate` response header field matching the
> authentication scheme used by the client.**"

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
 "error": "invalid_request"
}
```
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Cache-Control: no-store
WWW-Authenticate: Basic realm="token"

{
 "error": "invalid_client"
}
```

**Traps:**
- **Blanket 401 for `invalid_client`.** Only mandatory when the client used the `Authorization`
  header. If it used `client_secret_post`, return 400 — and if you return 401 anyway, **you must
  still not omit `WWW-Authenticate`** when you do use 401 with a header-authenticating client.
  Several client libraries treat a 401 without `WWW-Authenticate` as a transport failure and retry-loop.
- **`invalid_grant` vs `invalid_request` for a bad `code_verifier`.** A *mismatching* verifier is a
  bad grant ⇒ `invalid_grant`. A verifier sent when no challenge existed is malformed ⇒
  `invalid_request` (§3.2.4 names this case explicitly). Getting this backwards makes client
  error-handling misfire, since many clients treat `invalid_grant` as "restart the auth flow" and
  `invalid_request` as "my code is broken".
- **Unknown `grant_type` ⇒ `unsupported_grant_type`**, not `invalid_request`. §3.2.4's
  `invalid_request` text explicitly excludes grant type: "includes an unsupported parameter value
  (**other than grant type**)".
- **Returning `500` on an internal fault at `/token`.** Permitted (`server_error` isn't a token-endpoint
  code), but emit a JSON body and `Cache-Control: no-store` anyway so clients don't parse an HTML error page.
- **ASP.NET Core model-binding 400s.** The default `[ApiController]` `ValidationProblemDetails`
  response (`{"type":..., "title":"One or more validation errors occurred.", ...}`) is **not** an
  OAuth error object. Suppress it (`ApiBehaviorOptions.SuppressModelStateInvalidFilter = true`) or
  hand-parse the form on these endpoints. Same for the built-in `ProblemDetails` exception handler.

---

## 11. Resource server side (§5) — for the MCP server that trusts this AS

Two transports only (§5.1): `Authorization: Bearer <token>` (RS **MUST** support) and the
`access_token` form parameter (RS **MAY** support). "Clients **MUST** use one of the two methods …
and **MUST NOT use more than one** method to transmit the token in each request."

- "the string `bearer` is **case-insensitive**" (§5.1.1) — `Bearer`, `bearer`, `BEARER`, `bEaReR` all valid. Do not `StartsWith("Bearer ", Ordinal)`.
- `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="` (§5.1.1)
- Form-encoded method: `Content-Type` must be `application/x-www-form-urlencoded`, single-part, all-ASCII, and "**the GET method MUST NOT be used**" (§5.1.2). "**SHOULD NOT** be used except in application contexts where participating clients do not have access to the `Authorization` request header field."

Validation duty (§5.2): "the resource server **MUST check that the access token is not yet expired,
is authorized to access the requested resource, was issued with the appropriate scope**, and meets
other policy requirements".

`WWW-Authenticate` (§5.3.1): "the resource server **MUST include the HTTP `WWW-Authenticate`
response header field**" when credentials are missing or insufficient. "All challenges for this
token type **MUST use the auth-scheme value `Bearer`**. This scheme **MUST be followed by one or
more auth-param values.**" auth-params: `realm` (MAY), `scope` (OPTIONAL), `error`, `error_description`,
`error_uri` — each "MUST NOT appear more than once".

### Resource-server error codes (§5.3.2) — a separate registry slice

| `error` | HTTP status | Meaning |
|---|---|---|
| `invalid_request` | **400** ("SHOULD") | missing/unsupported/repeated parameter, more than one token transport, otherwise malformed |
| `invalid_token` | **401** ("SHOULD") | "expired, revoked, malformed, or invalid for other reasons"; "The client MAY request a new access token and retry" |
| `insufficient_scope` | **403** ("SHOULD") | "requires higher privileges (scopes) than provided"; "**MAY include the `scope` attribute** with the scope necessary" |

> "If the request lacks any authentication information …, the resource server **SHOULD NOT include
> an error code** or other error information." — §5.3.2

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example"
```
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  error="invalid_token",
                  error_description="The access token expired"
```

**Trap:** a bare `401` with **no** `WWW-Authenticate` is the most common MCP-connector failure mode —
Claude.ai and ChatGPT drive discovery off that challenge (with RFC 9728 `resource_metadata`). §5.3.1
already makes the header a MUST; treat the missing-credentials 401 as your discovery entry point.

**Trap:** the RS error set (`invalid_token`, `insufficient_scope`) and the AS token-endpoint set
(`invalid_grant`, `invalid_client`, …) are disjoint. `invalid_token` from `/token` or `invalid_grant`
from a protected resource are both wrong.

---

## 12. Lifetimes and token-shape recommendations

| Item | Statement | Section |
|---|---|---|
| Authorization code | "**MUST expire shortly** after it is issued"; "**maximum … lifetime of 10 minutes is RECOMMENDED**" | §4.1.2 |
| Authorization code use count | exactly **once** ("MUST return an access token only once for a given authorization code") | §4.1.3 |
| Access token | "Authorization servers **SHOULD issue short-lived bearer tokens**, particularly when issuing tokens to clients that run within a web browser" | §7.1.3.5 |
| Access token audience | "**SHOULD** issue bearer tokens that contain an **audience restriction**"; "access tokens **SHOULD** be restricted to certain resource servers (audience restriction), **preferably to a single resource server**" | §7.1.3.6, §7.1.4 |
| Access token privilege | "**SHOULD** be restricted to the **minimum required**" | §7.1.4 |
| `expires_in` semantics | "the authorization server **may prematurely expire** an access token and clients **MUST NOT expect** an access token to be valid for the provided lifetime" | §3.2.3 |
| Refresh token | lifetime "at the discretion of the authorization server"; "**SHOULD expire if the client has been inactive** for some time" | §1.3.2, §4.3.3 |
| Refresh token binding | "**MUST be bound to the scope and resource servers** as consented by the resource owner" | §3.2.3 |
| Whether to issue refresh tokens at all | "Authorization servers **SHOULD determine, based on a risk assessment and their own policies**, whether to issue refresh tokens to a certain client." | §3.2.3 |

Suggested defaults for this build (policy, not spec): code 60 s single-use; access token 5–15 min;
refresh token 30 d absolute / 14 d inactivity for confidential, 8 h–7 d rotated for public clients.

Audience mechanics (§7.1.4): "the authorization server associates the access token with certain
resource servers and **every resource server is obliged to verify, for every request**, whether the
access token sent with that request was meant to be used for that particular resource server.
**If not, the resource server MUST refuse to serve the respective request.**" Clients and AS "**MAY**
utilize the parameters `scope` or **`resource` as specified in … [RFC8707]**". For MCP, `resource`
(RFC 8707) is the mechanism both Claude and ChatGPT use — audience-restrict on it.

---

## 13. Transport, TLS, and redirect mechanics

| Statement | Section |
|---|---|
| "Implementations **MUST use a mechanism to provide communication authentication, integrity and confidentiality** such as Transport-Layer Security [RFC8446]" | §1.5 |
| "All the OAuth protocol URLs (URLs exposed by the AS, RS and Client) **MUST use the `https` scheme** except for loopback interface redirect URIs, which **MAY** use the `http` scheme." | §1.5 |
| "When using https, **TLS certificates MUST be checked** according to Section 4.3.4 of [RFC9110]." | §1.5 |
| "any other method available via the user agent to accomplish this redirection, **with the exception of HTTP 307**, is allowed" | §1.6 |
| "**MUST NOT use the 307 status code** … AS **SHOULD** use the status code **303** ("See Other")." | §7.5.3 |
| "The authorization server and client **MUST treat parameters received as potentially malicious external input** … in particular, the values of the `state` and `redirect_uri` parameters." | §7.11 |

Why 303 specifically (§7.5.3): "In HTTP [RFC9110], **only the status code 303 unambiguously enforces
rewriting the HTTP POST request to an HTTP GET request**. For all other status codes, including the
popular 302, user agents can opt not to rewrite POST to GET requests and therefore **reveal the user
credentials to the client**."

ASP.NET Core: behind a reverse proxy / Cloudflare you must configure `ForwardedHeadersOptions`
(`XForwardedProto`, `XForwardedHost`) or every absolute URL you mint — issuer, metadata,
`Location` — comes out `http://` and clients reject the flow. This is the most common
"works locally, fails in prod" failure for an AS.

---

## 14. Extensibility and IANA registries

| Registry | Governing procedure | Values relevant here |
|---|---|---|
| OAuth Parameters | RFC 6749 §11.2 | `client_id`, `client_secret`, `response_type`, `redirect_uri`, `scope`, `state`, `code`, `error`, `error_description`, `error_uri`, `grant_type`, `access_token`, `token_type`, `expires_in`, `username`, `password`, `refresh_token`, + registered extensions (`code_challenge`, `code_challenge_method`, `code_verifier`, `resource`, `iss`, `nonce`, `dpop_jkt`, …) |
| OAuth Authorization Endpoint Response Types | RFC 6749 §11.3 | `code`, `token` (— `token` is registered but **not defined by 2.1**) |
| OAuth Extensions Error | RFC 6749 §11.4 — Specification Required, two-week review on `oauth-ext-review@ietf.org` | see below |
| OAuth Token Endpoint Authentication Methods | — | `none`, `client_secret_post`, `client_secret_basic`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` |

**IANA OAuth Extensions Error registry**, fetched from
<https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml> — errors you may encounter
or need to emit beyond core, with their registered usage location:

| Error | Usage location |
|---|---|
| `invalid_request` | authorization endpoint, token endpoint, resource access error response |
| `unauthorized_client` | authorization endpoint, token endpoint |
| `access_denied` | authorization endpoint |
| `unsupported_response_type` | authorization endpoint |
| `invalid_scope` | authorization endpoint, token endpoint |
| `server_error` | authorization endpoint |
| `temporarily_unavailable` | authorization endpoint |
| `invalid_client` | token endpoint, authorization endpoint |
| `invalid_grant` | token endpoint |
| `unsupported_grant_type` | token endpoint |
| `invalid_token` | resource access error response |
| `insufficient_scope` | resource access error response |
| `unsupported_token_type` | revocation endpoint error response (RFC 7009) |
| `interaction_required`, `login_required`, `account_selection_required`, `consent_required` | authorization endpoint (OIDC) |
| `invalid_request_uri`, `invalid_request_object`, `request_not_supported`, `request_uri_not_supported`, `registration_not_supported` | authorization endpoint (OIDC) |
| `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement` | registration endpoint (RFC 7591) |
| `authorization_pending`, `slow_down`, `expired_token` | token endpoint response (RFC 8628 device grant) |
| `invalid_target` | token error response (RFC 8707 `resource`) |
| `invalid_dpop_proof`, `use_dpop_nonce` | token error response, resource access error response (RFC 9449) |
| `insufficient_user_authentication` | resource access error response (RFC 9470 step-up) |
| `invalid_authorization_details` | token endpoint, authorization endpoint (RFC 9396) |
| `unsupported_pop_key`, `incompatible_ace_profiles`, `need_info`, `request_denied`, `request_submitted`, `invalid_issuer`, `invalid_subject`, `invalid_trust_anchor`, `invalid_trust_chain`, `invalid_metadata`, `not_found`, `unsupported_parameter`, `vp_formats_not_supported`, `invalid_request_uri_method`, `wallet_unavailable` | various extensions |

Naming your own (§6.5): "Error codes **MUST conform to the error ABNF** and **SHOULD be prefixed by
an identifying name** when possible. For example, an error identifying an invalid value set to the
extension parameter `example` SHOULD be named `example_invalid`."

New parameters (§6.2): `param-name = 1*("-" / "." / "_" / DIGIT / ALPHA)`; unregistered
vendor-specific extensions "**SHOULD** utilize a vendor-specific prefix … (e.g., begin with
`companyname_`)".

---

## 15. Full ABNF reference (Appendix A)

```
VSCHAR  = %x20-7E
NQCHAR  = %x21 / %x23-5B / %x5D-7E
NQSCHAR = %x20-21 / %x23-5B / %x5D-7E

client-id         = *VSCHAR
client-secret     = *VSCHAR
response-type     = response-name *( SP response-name )
response-name     = 1*( "_" / DIGIT / ALPHA )
scope             = scope-token *( SP scope-token )
scope-token       = 1*NQCHAR
state             = 1*VSCHAR
redirect-uri      = URI-reference
error             = 1*NQSCHAR
error-description = 1*NQSCHAR
error-uri         = URI-reference
grant-type        = grant-name / URI-reference
grant-name        = 1*( "-" / "." / "_" / DIGIT / ALPHA )
code              = 1*VSCHAR
access-token      = 1*VSCHAR
token-type        = type-name / URI-reference
type-name         = 1*( "-" / "." / "_" / DIGIT / ALPHA )
expires-in        = 1*DIGIT
refresh-token     = 1*VSCHAR
param-name        = 1*( "-" / "." / "_" / DIGIT / ALPHA )
code-verifier     = 43*128unreserved
code-challenge    = 43*128unreserved
unreserved        = ALPHA / DIGIT / "-" / "." / "_" / "~"
```

Serializations (Appendix C):
- **C.1 Query String** — `application/x-www-form-urlencoded` in the URL query component. Used for `/authorize` request and response.
- **C.2 Form-Encoded** — `application/x-www-form-urlencoded` in the request body. Used for `/token` request.
- **C.3 JSON** — "Omitted parameters and parameters with no value **SHOULD be omitted from the object and not represented by a JSON `null` value**." Used for `/token` response. ⇒ set `JsonIgnoreCondition.WhenWritingNull`.

---

## 16. Beyond core 2.1 — what Claude.ai and ChatGPT additionally need

Core OAuth 2.1 deliberately leaves discovery and registration undefined (§1.7: "This specification
leaves a few required components partially or fully undefined (e.g., client registration,
authorization server capabilities, endpoint discovery)"). It names the extensions that fill the gaps:
**RFC 8414** (AS Metadata), **RFC 7591** (Dynamic Client Registration), **RFC 7592** (DCR Management),
**RFC 7662** (Introspection), **RFC 9068** (JWT access token profile), **RFC 9126** (PAR),
**RFC 8707** (`resource`), **RFC 9449** (DPoP), **RFC 8705** (mTLS), **RFC 9207** (`iss`),
**RFC 9396** (RAR), **RFC 9700** (Security BCP — the source of most 2.1 restrictions).

For MCP connector interop you additionally need **RFC 9728** (Protected Resource Metadata) on the
resource server, surfaced via the `WWW-Authenticate: Bearer resource_metadata="…"` challenge — that
is *not* in this draft; it belongs to a sibling research note. Note also §9 "Browser-Based Apps"
is still a **TODO** stub in draft-15 ("Bring in the normative text of the browser-based apps BCP when
it is finalized") — do not expect normative SPA guidance from this document.

---

## 17. Implementer's checklist

**`/authorize`**
- [ ] `GET` supported; `POST` optional. CORS **disabled**.
- [ ] Unrecognised params ignored; duplicate params ⇒ `invalid_request`; empty-valued params treated as absent.
- [ ] Order: `client_id` → `redirect_uri` → *(only now may you redirect)* → everything else.
- [ ] Redirect URI compared with `StringComparison.Ordinal` against the raw registered value; loopback port ignored; fragment rejected.
- [ ] `code_challenge` required for every client; `code_challenge_method` defaults to `plain`; unsupported method ⇒ redirect `invalid_request`.
- [ ] `state` echoed verbatim on success **and** error whenever it was sent.
- [ ] `iss` emitted on success and error.
- [ ] Redirect uses 302 or 303, **never 307**; the post-login leg uses 303.
- [ ] Post-redirect-URI-validation exceptions become `error=server_error`, not HTTP 500.
- [ ] Code: ≤10 min, single-use, bound to `client_id` + `code_challenge` + `redirect_uri`.

**`/token`**
- [ ] `POST` only; form-encoded; CORS **enabled**.
- [ ] `client_secret_post` supported (MUST); `client_secret_basic` optional but must handle the form-encoding quirk; reject more than one auth method with `invalid_request`.
- [ ] Confidential clients authenticated on every grant; brute-force protection on secret checks.
- [ ] `code_verifier` present **iff** `code_challenge` was; verified with `FixedTimeEquals`.
- [ ] `redirect_uri` accepted-but-not-required; enforced per RFC 6749 when present.
- [ ] Code replay: full validation **before** deciding to revoke; invalid replay ⇒ `invalid_grant` with **no** revocation.
- [ ] Refresh: client binding verified; grant-still-active checked; rotation or sender-constraining for public clients; rotated token keeps the **original** scope.
- [ ] 200 + `Cache-Control: no-store`; `expires_in` a JSON number; `scope` present when downscoped; snake_case field names.
- [ ] Errors: 400 by default; 401 + `WWW-Authenticate` for `invalid_client` when the client used the `Authorization` header; only the six core codes; ASP.NET `ProblemDetails` suppressed.

**Resource server**
- [ ] `Authorization: Bearer` scheme matched **case-insensitively**; `?access_token=` ignored.
- [ ] Audience checked per request; refuse if the token was not minted for this RS.
- [ ] `WWW-Authenticate: Bearer …` on every 401; `invalid_token`/401, `insufficient_scope`/403, `invalid_request`/400; no error code when credentials were entirely absent.

**Transport**
- [ ] `https` everywhere except loopback redirect URIs.
- [ ] `ForwardedHeaders` configured so issuer/metadata/`Location` are `https` behind the proxy.
