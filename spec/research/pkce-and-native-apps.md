# PKCE (RFC 7636) + Native Apps (RFC 8252) — implementer's reference

Target: from-scratch OAuth 2.1 / OIDC AS in ASP.NET Core 9 that Claude.ai, Claude Code and
ChatGPT connectors can both talk to.

Primary sources fetched and quoted verbatim below:
`RFC 7636`, `RFC 8252`, `RFC 9700` (OAuth 2.0 Security BCP, Jan 2025), `draft-ietf-oauth-v2-1-15`,
`RFC 6749`, `RFC 8414`, MCP Authorization spec (2025-11-25), Claude connector auth docs,
Claude Code's live Client ID Metadata Document.

---

## 0. TL;DR — the five things that break interop

| # | Requirement | Source | Failure mode if wrong |
|---|---|---|---|
| 1 | Loopback redirect match **ignores the port on both sides** — registered `http://localhost/callback` (implicit :80) must match requested `http://localhost:3118/callback` | RFC 8252 §7.3, §8.4 | Claude Code cannot connect at all |
| 2 | `localhost` by name must get the same port-agnostic treatment as `127.0.0.1`, despite RFC 8252 §8.3 calling it NOT RECOMMENDED | Claude docs; RFC 8252 §8.3 | Claude Code CIMD lists `http://localhost/callback` first — half its redirects rejected |
| 3 | Token endpoint must verify `code_verifier` is present **if and only if** a `code_challenge` was stored with the code | RFC 9700 §4.8.2, OAuth 2.1 §4.1.3 | PKCE downgrade attack → full account takeover |
| 4 | Publish `"code_challenge_methods_supported": ["S256"]` in **both** `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` | MCP auth spec; RFC 8414 §2 | MCP clients "MUST refuse to proceed" — connection aborts before `/authorize` |
| 5 | Everything that is not loopback is **byte-exact** ordinal string match, no normalization, no prefix match, no wildcards | RFC 9700 §2.1, OAuth 2.1 §2.3.1 | Open redirector → code exfiltration |

---

# PART 1 — RFC 7636 (PKCE)

## 1.1 `code_verifier` — charset and length (§4.1)

> **RFC 7636 §4.1:** "code_verifier = high-entropy cryptographic random STRING using the
> unreserved characters `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"` from Section 2.3 of
> [RFC3986], with a minimum length of 43 characters and a maximum length of 128 characters."

```abnf
code-verifier = 43*128unreserved
unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
ALPHA         = %x41-5A / %x61-7A
DIGIT         = %x30-39
```

> **RFC 7636 §4.1 (NOTE):** "The code verifier SHOULD have enough entropy to make it impractical
> to guess the value. It is RECOMMENDED that the output of a suitable random number generator be
> used to create a 32-octet sequence. The octet sequence is then base64url-encoded to produce a
> 43-octet URL safe string to use as the code verifier."

> **RFC 7636 §7.1:** "The client SHOULD create a `code_verifier` with a minimum of 256 bits of
> entropy."

OAuth 2.1 §4.1.1 repeats the same charset and the same 43/128 bounds verbatim.

**ASP.NET Core validation (do this at the token endpoint, before hashing):**

```csharp
// Compiled once. Ordinal by construction — no culture, no Unicode classes.
[GeneratedRegex(@"\A[A-Za-z0-9\-._~]{43,128}\z", RegexOptions.CultureInvariant)]
private static partial Regex CodeVerifierPattern();
```

| Trap | Detail |
|---|---|
| `RegexOptions.None` + `$` | `$` matches before a trailing `\n`. Use `\z`, not `$`. A verifier of `…\n` would slip through. |
| `\w` / `\d` | Match Unicode categories by default in .NET. `\d` matches Arabic-Indic digits. Use explicit `0-9`. |
| Length in chars vs bytes | Charset is ASCII-only, so `string.Length` == byte count **after** the regex passes. Check the regex first, then it is safe to use `Encoding.ASCII`. |
| `Encoding.ASCII.GetBytes` | Silently substitutes `?` for non-ASCII. Harmless only because the charset check ran first. If you reorder these, you create a hash collision surface. |

## 1.2 `code_challenge` and the two transforms (§4.2)

> **RFC 7636 §4.2:**
> ```
> plain
>    code_challenge = code_verifier
>
> S256
>    code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
> ```
> "If the client is capable of using `S256`, it MUST use `S256`, as `S256` is Mandatory To
> Implement (MTI) on the server. Clients are permitted to use `plain` only if they cannot support
> `S256` for some technical reason and know via out-of-band configuration that the server
> supports `plain`."

```abnf
code-challenge = 43*128unreserved
```

> **RFC 7636 §3 (Terminology), base64url:** "Base64 encoding using the URL- and filename-safe
> character set defined in Section 5 of [RFC4648], with all trailing '=' characters omitted (as
> permitted by Section 3.2 of [RFC4648]) and without the inclusion of any line breaks,
> whitespace, or other additional characters."

**Exact S256 computation, .NET 9:**

```csharp
using System.Buffers.Text;   // .NET 9: System.Buffers.Text.Base64Url
using System.Security.Cryptography;
using System.Text;

static string ComputeS256Challenge(string codeVerifier)
{
    // Caller MUST have validated codeVerifier against CodeVerifierPattern() first.
    Span<byte> hash = stackalloc byte[32];
    SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier), hash);
    return Base64Url.EncodeToString(hash);   // no padding, '-' and '_', no line breaks
}
```

Alternatives if not on .NET 9: `Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(byte[])`
or `Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(byte[])`. Do **not** hand-roll
`Convert.ToBase64String(...).TrimEnd('=').Replace('+','-').Replace('/','_')` unless you also strip
`\r\n` — `Convert.ToBase64String` with `Base64FormattingOptions.InsertLineBreaks` would poison it,
and the `.Replace` chain allocates three strings per call on a hot path.

**RFC 7636 Appendix A** ships this exact C# reference (note it is the naive version):

```csharp
static string base64urlencode(byte [] arg)
{
  string s = Convert.ToBase64String(arg); // Regular base64 encoder
  s = s.Split('=')[0]; // Remove any trailing '='s
  s = s.Replace('+', '-'); // 62nd char of encoding
  s = s.Replace('/', '_'); // 63rd char of encoding
  return s;
}
```

### Conformance test vector (RFC 7636 Appendix B) — put this in a unit test

| Field | Value |
|---|---|
| verifier octets (32) | `116 24 223 180 151 153 224 37 79 250 96 125 216 173 187 186 22 212 37 77 105 214 191 240 91 88 5 88 83 132 141 121` |
| `code_verifier` | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` |
| SHA-256 octets (32) | `19 211 30 150 26 26 216 236 47 22 177 12 76 152 46 8 118 168 120 173 109 241 68 86 110 225 137 74 203 112 249 195` |
| `code_challenge` | `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` |

Appendix A's smaller round-trip vector: octets `3 236 255 224 193` ⇄ `A-z_4ME`.

### Interop traps on the challenge

| Trap | Why it bites | What to do |
|---|---|---|
| Hashing the **decoded** verifier | The verifier is itself usually base64url of 32 random bytes. Implementers base64url-*decode* it and hash the 32 bytes. Wrong — `SHA256(ASCII(code_verifier))` hashes the 43 **characters**. | Hash the string bytes. The Appendix B vector catches this immediately. |
| Padded challenge (`…=` / `…==`) | 44 or 45 chars, and `=` is not in `unreserved`. Some SDKs pad. | Reject at `/authorize` with `invalid_request`. Do **not** silently strip: a padded challenge stored as-is never matches the computed unpadded one, and you get a confusing `invalid_grant` at token time instead of a clear error at authorize time. |
| Standard base64 (`+`, `/`) | Same class of bug, same detection. | Same: reject at `/authorize`. |
| `code-challenge = 43*128unreserved` applied to S256 | S256 output is **always exactly 43 chars**. The 43..128 range only has meaning for `plain`. | If you reject `plain` (recommended), enforce `length == 43` for `S256`. Extra defense-in-depth, costs nothing. |
| Comparing with `==` / `string.Equals` | Timing side channel on a server-held secret comparison. | `CryptographicOperations.FixedTimeEquals(computedBytes, storedBytes)` over the ASCII bytes. |

## 1.3 Wire parameters

**Authorization request** (RFC 7636 §4.3) — query params on `GET /authorize`:

| Parameter | Presence | Values |
|---|---|---|
| `code_challenge` | REQUIRED (§4.3) | `43*128unreserved` |
| `code_challenge_method` | **OPTIONAL, defaults to `plain` if not present** (§4.3) | `S256` \| `plain` |

**Token request** (RFC 7636 §4.5) — `Content-Type: application/x-www-form-urlencoded`:

| Parameter | Presence |
|---|---|
| `code_verifier` | REQUIRED (§4.5) |

> **RFC 7636 §4.5:** "The `code_challenge_method` is bound to the Authorization Code when the
> Authorization Code is issued. That is the method that the token endpoint MUST use to verify the
> `code_verifier`."

**Registry values** (RFC 7636 §6.2.2, "PKCE Code Challenge Method Registry") — the initial and,
to date, complete contents:

| Code Challenge Method Parameter Name | Change Controller | Spec |
|---|---|---|
| `plain` | IESG | RFC 7636 §4.2 |
| `S256` | IESG | RFC 7636 §4.2 |

Case matters: it is `S256`, capital S. Reject `s256`, `sha256`, `SHA-256`.

Complete authorization request as Claude sends it:

```http
GET /authorize?response_type=code
  &client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fclaude-code-client-metadata
  &redirect_uri=http%3A%2F%2Flocalhost%3A3118%2Fcallback
  &scope=offline_access%20files%3Aread
  &state=<opaque>
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &resource=https%3A%2F%2Fmcp.example.com%2Fmcp HTTP/1.1
Host: auth.example.com
```

Token exchange:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=http%3A%2F%2Flocalhost%3A3118%2Fcallback
&client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fclaude-code-client-metadata
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&resource=https%3A%2F%2Fmcp.example.com%2Fmcp
```

> Claude docs: "Your `/token` endpoint must accept `Content-Type: application/x-www-form-urlencoded`
> per RFC 6749 section 4.1.3. … if your endpoint returns `415 Unsupported Media Type`, register a
> form-urlencoded body parser." (`/register` for DCR uses `application/json` — different parser.)

## 1.4 Server storage duty (§4.4)

> **RFC 7636 §4.4:** "When the server issues the authorization code in the authorization
> response, it MUST associate the `code_challenge` and `code_challenge_method` values with the
> authorization code so it can be verified later."
>
> "The server MUST NOT include the `code_challenge` value in client requests in a form that other
> entities can extract."

> **RFC 7636 §7.2:** "If the code challenge method is `plain` and the code challenge is to be
> returned inside authorization `code` to achieve a stateless server, it MUST be encrypted in such
> a manner that only the server can decrypt and extract it."

Concretely, the authorization-code record needs **three** fields, and the third is the one people
forget:

```csharp
public sealed record AuthorizationCodeGrant
{
    public required string  ClientId              { get; init; }
    public required string  RedirectUri           { get; init; }   // as sent, for §4.1.3 rebinding
    public required bool    PkceWasRequested      { get; init; }   // ← the downgrade-attack flag
    public          string? CodeChallenge         { get; init; }   // null iff !PkceWasRequested
    public          string? CodeChallengeMethod   { get; init; }   // "S256" | "plain"
    // …sub, scope, resource, nonce, auth_time, expiry, single-use marker
}
```

`PkceWasRequested` must be a stored boolean, not `CodeChallenge is not null` inferred at request
time from what the *token request* contains. See §1.6.

## 1.5 Error table — exact strings to return

### Authorization endpoint (`/authorize`)

| Condition | Normative source | HTTP | `error` |
|---|---|---|---|
| `code_challenge` absent and server requires PKCE | RFC 7636 §4.4.1 | 302 to `redirect_uri` | `invalid_request` |
| `code_challenge_method` value the server does not support (incl. `plain` when you only do S256, **and** the omitted-method case, which defaults to `plain`) | RFC 7636 §4.4.1 | 302 to `redirect_uri` | `invalid_request` |
| `code_challenge` violates `43*128unreserved` (padding, `+`/`/`, wrong length) | RFC 7636 §4.2 ABNF + RFC 6749 §4.1.2.1 ("invalid value") | 302 to `redirect_uri` | `invalid_request` |
| `redirect_uri` missing / invalid / does not match a registered one | **RFC 6749 §4.1.2.1** | 400 **HTML error page — MUST NOT redirect** | n/a |
| `client_id` unknown | RFC 6749 §4.1.2.1 | 400 HTML error page — MUST NOT redirect | n/a |

> **RFC 7636 §4.4.1:** "If the server requires Proof Key for Code Exchange (PKCE) by OAuth public
> clients and the client does not send the `code_challenge` in the request, the authorization
> endpoint MUST return the authorization error response with the `error` value set to
> `invalid_request`. The `error_description` or the response of `error_uri` SHOULD explain the
> nature of error, e.g., code challenge required.
>
> If the server supporting PKCE does not support the requested transformation, the authorization
> endpoint MUST return the authorization error response with `error` value set to
> `invalid_request`. The `error_description` or the response of `error_uri` SHOULD explain the
> nature of error, e.g., transform algorithm not supported."

> **RFC 6749 §4.1.2.1:** when the request "fails due to a missing, invalid, or mismatching
> redirection URI, or if the client identifier is missing or invalid, the authorization server
> SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent
> to the invalid redirection URI."

**Ordering is load-bearing.** Validate in this order in your `/authorize` handler:

1. `client_id` → resolve client (or fetch CIMD). Fail ⇒ render page, never redirect.
2. `redirect_uri` → match (§2.4 algorithm). Fail ⇒ render page, never redirect.
3. **Only now** is it safe to emit `error=` via a 302. Everything after this point redirects.
4. `response_type`, `code_challenge`, `code_challenge_method`, `scope`, `resource`.

Getting 1–2 after 3–4 turns your AS into an open redirector that leaks `state`.

The authorization error redirect looks like:

```http
HTTP/1.1 302 Found
Location: http://localhost:3118/callback?error=invalid_request&error_description=transform%20algorithm%20not%20supported&state=<echoed>
Cache-Control: no-store
```

`state` is REQUIRED in the error response if it was present in the request (RFC 6749 §4.1.2.1).
Full authorization-endpoint `error` registry (RFC 6749 §4.1.2.1): `invalid_request`,
`unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`,
`server_error`, `temporarily_unavailable`.

### Token endpoint (`/token`)

| Condition | Normative source | HTTP | `error` |
|---|---|---|---|
| `code_verifier` present, transform applied, values **not equal** | RFC 7636 §4.6 | 400 | `invalid_grant` |
| `code_verifier` **missing** but a `code_challenge` was stored with the code | OAuth 2.1 §4.1.3 ("present if and only if"); RFC 7636 §4.6 by implication | 400 | `invalid_grant` |
| `code_verifier` **present** but **no** `code_challenge` was stored with the code | **RFC 9700 §4.8.2** — the downgrade attack | 400 | `invalid_grant` |
| `code_verifier` violates `43*128unreserved` | RFC 7636 §4.1 ABNF | 400 | `invalid_grant` (see note) |
| `redirect_uri` differs from the one in the authorization request | RFC 6749 §4.1.3 / §5.2 | 400 | `invalid_grant` |
| refresh token revoked/expired | RFC 6749 §5.2 | 400 | `invalid_grant` |

> **RFC 7636 §4.6:** "If the values are equal, the token endpoint MUST continue processing as
> normal (as defined by OAuth 2.0 [RFC6749]). If the values are not equal, an error response
> indicating `invalid_grant` as described in Section 5.2 of [RFC6749] MUST be returned."

> **OAuth 2.1 §4.1.3 (Token Endpoint Extension):** the authorization server MUST "verify that the
> `code_verifier` parameter is present if and only if a `code_challenge` parameter was present in
> the authorization request" … "If there was no `code_challenge` in the authorization request
> associated with the authorization code in the token request, the authorization server MUST
> reject the token request." On failure: error code `invalid_grant`.

**Note on the malformed-verifier row.** RFC 7636 does not name a code for a syntactically invalid
`code_verifier`. `invalid_request` is defensible (RFC 6749 §5.2: "including an unsupported
parameter value"), but return **`invalid_grant`** and a generic `error_description`: a malformed
verifier is functionally an attacker probing, and distinguishing "malformed" from "wrong" hands
them an oracle. Claude specifically warns about non-standard codes:

> Claude docs: "Return RFC 6749-compliant error codes (`invalid_grant`, not `invalid_request` or a
> custom code) when a refresh token is no longer valid."

Full token-endpoint `error` registry (RFC 6749 §5.2): `invalid_request`, `invalid_client`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_grant`, `invalid_scope`. HTTP 400 for
all of them except `invalid_client`, which MAY be 401 with a `WWW-Authenticate` header.

Error body shape:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{"error":"invalid_grant","error_description":"PKCE verification failed"}
```

## 1.6 The downgrade attack — strip `code_challenge_method` / strip `code_challenge`

**RFC 9700 §4.8 "PKCE Downgrade Attack"**, §4.8.1 Attack Description:

Prerequisites are (a) an attacker-controllable flag that enables/disables PKCE — which is exactly
what "presence or absence of `code_challenge`" is — and (b) a client that does not check `state`
adequately.

1. Attacker starts a flow **on their own device** against the honest AS, and simply **omits
   `code_challenge`** from the authorization request.
2. AS (if it tolerates PKCE-less flows) issues an authorization code that is bound to **no** code
   challenge.
3. Attacker injects that code into the victim's client — redirects the victim's browser to the
   client's redirect URI carrying the attacker's `code`.
4. Victim's client, which *did* generate PKCE material, redeems it with its own
   `code_verifier=abc`.
5. > RFC 9700 §4.8.1: "the authorization server sees that this code is not bound to any PKCE code
   > challenge, it will not check" the verifier — and issues an access token for the **attacker's**
   > resources into the victim's client. (Or, in the mirrored variant, the victim's authorization
   > lands in the attacker's client.)

**Countermeasure, RFC 9700 §4.8.2 — the exact sentence to implement:**

> "Authorization servers MUST ensure that if there was no `code_challenge` in the authorization
> request, a request to the token endpoint containing a `code_verifier` is rejected."

Note the *stripping `code_challenge_method`* variant is a different, milder bug and RFC 7636
already handles it by defaulting: omitting `code_challenge_method` silently means `plain`
(§4.3), and with `plain` the challenge *is* the verifier — so an attacker who can read the
authorization request now has everything. That is why §7.2 says:

> **RFC 7636 §7.2:** "Clients MUST NOT downgrade to `plain` after trying the `S256` method. …
> Because of this, an error when `S256` is presented can only mean that the server is faulty or
> that a MITM attacker is trying a downgrade attack."
>
> "Because of this, `plain` SHOULD NOT be used and exists only for compatibility with deployed
> implementations where the request path is already protected. The `plain` method SHOULD NOT be
> used in new implementations, unless they cannot support `S256` for some technical reason."
>
> "The `S256` code challenge method or other cryptographically secure code challenge method
> extension SHOULD be used."

> **RFC 9700 §2.1.1:** "clients SHOULD use PKCE code challenge methods that do not expose the PKCE
> verifier in the authorization request. Otherwise, attackers that can read the authorization
> request … can break the security provided by PKCE. Currently, `S256` is the only such method."

### Implementation — the whole defense in one method

```csharp
// Called after the authorization code has been looked up and marked single-use-consumed.
static PkceResult VerifyPkce(AuthorizationCodeGrant grant, string? codeVerifier)
{
    // RFC 9700 §4.8.2 / OAuth 2.1 §4.1.3: "present if and only if".
    // XOR, not two independent ifs — the whole point is that BOTH asymmetries are errors.
    if (grant.PkceWasRequested != (codeVerifier is not null))
        return PkceResult.Fail("invalid_grant");          // covers BOTH downgrade directions

    if (!grant.PkceWasRequested)
        return PkceResult.Ok();                            // only reachable if you allow non-PKCE clients at all

    if (!CodeVerifierPattern().IsMatch(codeVerifier!))
        return PkceResult.Fail("invalid_grant");

    var computed = grant.CodeChallengeMethod switch
    {
        "S256"  => ComputeS256Challenge(codeVerifier!),
        "plain" => codeVerifier!,                          // only if you ever registered plain
        _       => null
    };
    if (computed is null) return PkceResult.Fail("invalid_grant");

    return CryptographicOperations.FixedTimeEquals(
               Encoding.ASCII.GetBytes(computed),
               Encoding.ASCII.GetBytes(grant.CodeChallenge!))
           ? PkceResult.Ok()
           : PkceResult.Fail("invalid_grant");
}
```

**The stronger move: remove the flag entirely.** OAuth 2.1 §4.1.1 makes `code_challenge`
"REQUIRED unless the specific requirements of Section 7.5.1 are met", and:

> **OAuth 2.1 §4.1.1:** "Clients MUST use `code_challenge` and `code_verifier` and authorization
> servers MUST enforce their use except under the conditions described in Section 7.5.1." An
> authorization server "MUST reject requests without a `code_challenge` from public clients, and
> MUST reject such requests from other clients unless there is reasonable assurance that the
> client mitigates authorization code injection in other ways."

> **RFC 9700 §2.1.1:** "Public clients MUST use PKCE [RFC7636]" … "For confidential clients, the
> use of PKCE [RFC7636] is RECOMMENDED" … "Authorization servers MUST support PKCE [RFC7636]" …
> "If a client sends a valid PKCE `code_challenge` parameter in the authorization request, the
> authorization server MUST enforce the correct usage of `code_verifier` at the token endpoint."

> **RFC 8252 §6:** "Public native app clients MUST implement the Proof Key for Code Exchange
> (PKCE [RFC7636]) extension to OAuth, and authorization servers MUST support PKCE for such
> clients."

> **RFC 8252 §8.1:** "Authorization servers SHOULD reject authorization requests from native apps
> that don't use PKCE by returning an error message, as defined in Section 4.4.1 of PKCE
> [RFC7636]."

For an Auth0 replacement targeting MCP: make `code_challenge` **unconditionally required** for
every client, and support only `S256`. Then `PkceWasRequested` is always `true`, the
attacker-controllable flag from §4.8.1 does not exist, and the XOR above degenerates to "verifier
must be present". Keep the XOR anyway — it is the invariant, and someone will later add a
legacy-client escape hatch.

### `plain`: reject it, and be consistent about it

| Decision | Consequence |
|---|---|
| Advertise `"code_challenge_methods_supported": ["S256"]` | Clients that only do `plain` fail fast at discovery — the correct outcome per RFC 7636 §4.2 ("know via out-of-band configuration that the server supports `plain`"). |
| Reject `code_challenge_method=plain` at `/authorize` | `invalid_request`, `error_description=transform algorithm not supported` (RFC 7636 §4.4.1). |
| Reject **omitted** `code_challenge_method` | Per §4.3 the default is `plain`, and you do not support `plain`, so this is the same error. **Do not silently upgrade a missing method to `S256`.** Upgrading means a `plain` client's verifier will never match, producing a bewildering `invalid_grant` at token time instead of a clear `invalid_request` at authorize time — and it lets a `plain`-only client believe it is protected when the server treats its plaintext challenge as a hash. |

Claude and ChatGPT both always send `code_challenge_method=S256`, so this costs nothing:

> Claude docs: "Claude includes a PKCE `code_challenge` with `code_challenge_method=S256` on every
> authorization request, regardless of which registration mechanism it uses. Your authorization
> server must support S256 PKCE."

## 1.7 Discovery metadata

> **RFC 8414 §2:** "`code_challenge_methods_supported` — OPTIONAL. JSON array containing a list of
> Proof Key for Code Exchange (PKCE) [RFC7636] code challenge methods supported by this
> authorization server."

RFC 8414 says OPTIONAL; MCP makes it effectively mandatory:

> **MCP Authorization spec, "Authorization Code Protection":** "**OAuth 2.0 Authorization Server
> Metadata**: If `code_challenge_methods_supported` is absent, the authorization server does not
> support PKCE and MCP clients **MUST** refuse to proceed."
>
> "**OpenID Connect Discovery 1.0**: While the OpenID Provider Metadata does not define
> `code_challenge_methods_supported`, this field is commonly included by OpenID providers. MCP
> clients **MUST** verify the presence of `code_challenge_methods_supported` in the provider
> metadata response. If the field is absent, MCP clients **MUST** refuse to proceed."
>
> "Authorization servers providing OpenID Connect Discovery 1.0 **MUST** include
> `code_challenge_methods_supported` in their metadata to ensure MCP compatibility."

> **RFC 9700 §2.1.1:** "It is RECOMMENDED for authorization servers to publish the element
> `code_challenge_methods_supported` in their Authorization Server Metadata [RFC8414]."

**Trap:** OIDC Discovery's canonical field list does not include it, so OIDC-first libraries
(including hand-rolled `/.well-known/openid-configuration` handlers) omit it. Emit the same
document body from both paths, or at minimum add the field to both.

Minimum metadata for MCP interop:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
  "client_id_metadata_document_supported": true,
  "scopes_supported": ["offline_access", "..."]
}
```

> Claude docs: "Claude selects CIMD only when your authorization server metadata advertises
> **both** `"client_id_metadata_document_supported": true` **and** `"none"` in
> `token_endpoint_auth_methods_supported` — the second is required because Claude's CIMD client
> authenticates as a public client at your token endpoint. If either is missing, Claude falls back
> to DCR."

## 1.8 Backwards compatibility (§5) — read this as a warning, not a permission

> **RFC 7636 §5:** "Server implementations of this specification MAY accept OAuth2.0 clients that
> do not implement this extension. If the `code_verifier` is not received from the client in the
> Authorization Request, servers supporting backwards compatibility revert to the OAuth 2.0
> [RFC6749] protocol without this extension."

This MAY is precisely the attacker-controllable flag that RFC 9700 §4.8.1 exploits. RFC 9700 and
OAuth 2.1 both post-date RFC 7636 and override it in practice. Do not take this MAY.

---

# PART 2 — RFC 8252 (OAuth 2.0 for Native Apps)

## 2.1 The three redirect URI options an AS MUST offer

> **RFC 8252 §7:** "To fully support this best practice, authorization servers MUST offer at least
> the three redirect URI options described in the following subsections to native apps. Native
> apps MAY use whichever redirect option suits their needs best, taking into account
> platform-specific implementation details."

> **RFC 8252 Appendix A (Server Support Checklist):** OAuth servers that support native apps must:
> 1. Support private-use URI scheme redirect URIs (§7.1) — required for mobile OSes.
> 2. Support "https" scheme redirect URIs for public native app clients (§7.2).
> 3. Support loopback IP redirect URIs (§7.3) — required for desktop OSes.
> 4. Not assume that native app clients can keep a secret (§8.5).
> 5. Support PKCE [RFC7636] (§8.1).

| Option | Form | Who uses it |
|---|---|---|
| Loopback IP (§7.3) | `http://127.0.0.1:{port}/{path}`, `http://[::1]:{port}/{path}` | **Claude Code**, most CLI/desktop MCP clients |
| Claimed `https` (§7.2) | `https://app.example.com/oauth2redirect/example-provider` | **Claude.ai hosted**, **ChatGPT**, mobile apps with universal/app links |
| Private-use scheme (§7.1) | `com.example.app:/oauth2redirect/example-provider` | Native mobile apps; not used by Claude or ChatGPT |

## 2.2 §7.3 Loopback interface redirection — the critical MUST

> **RFC 8252 §7.3:** "Loopback redirect URIs use the "http" scheme and are constructed with the
> loopback IP literal and whatever port the client is listening on. That is,
> `http://127.0.0.1:{port}/{path}` for IPv4, and `http://[::1]:{port}/{path}` for IPv6."
>
> Examples given:
> ```
> http://127.0.0.1:51004/oauth2redirect/example-provider
> http://[::1]:61023/oauth2redirect/example-provider
> ```
>
> "**The authorization server MUST allow any port to be specified at the time of the request for
> loopback IP redirect URIs**, to accommodate clients that obtain an available ephemeral port from
> the operating system at the time of the request."
>
> "Clients SHOULD NOT assume that the device supports a particular version of the Internet
> Protocol. It is RECOMMENDED that clients attempt to bind to the loopback interface using both
> IPv4 and IPv6 and use whichever is available."

That last sentence is why you must support **both** `127.0.0.1` and `[::1]` — a client may register
one and, at runtime, discover only the other is bindable.

> **RFC 8252 §8.3:** "Loopback interface redirect URIs use the "http" scheme (i.e., without
> Transport Layer Security (TLS)). This is acceptable for loopback interface redirect URIs as the
> HTTP request never leaves the device."
>
> "While redirect URIs using localhost (i.e., `http://localhost:{port}/{path}`) function similarly
> to loopback IP redirects described in Section 7.3, **the use of localhost is NOT RECOMMENDED**.
> Specifying a redirect URI with the loopback IP literal rather than localhost avoids
> inadvertently listening on network interfaces other than the loopback interface. It is also less
> susceptible to client-side firewalls and misconfigured host name resolution on the user's
> device."

## 2.3 …and Claude Code declares `localhost` anyway

Live document at `https://claude.ai/oauth/claude-code-client-metadata` (fetched 2026-08-03):

```json
{
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "client_name": "Claude Code",
  "client_uri": "https://claude.ai",
  "redirect_uris": [
    "http://localhost/callback",
    "http://127.0.0.1/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

> Claude docs, "Callback URLs": "**Claude Code** is a native client and uses an RFC 8252 loopback
> redirect on an ephemeral port — for example: `http://localhost:3118/callback`. The port varies
> per session. Claude Code declares `http://localhost/callback` and `http://127.0.0.1/callback` in
> its Client ID Metadata Document, so your authorization server must accept both **with the port
> component ignored**. RFC 8252 section 7.3 requires this for the IP-literal form (`127.0.0.1`);
> **apply the same port-agnostic match to `localhost` so Claude Code works, even though RFC 8252
> section 8.3 discourages `localhost`.**"

**Two things follow, and both are easy to miss:**

1. The *registered* value has **no port at all** (`http://localhost/callback`, implicit :80). The
   *requested* value has an explicit ephemeral port. A naive "strip the port from the request and
   compare to the registered string" works here, but a "compare `Uri.Port` for equality unless
   both are loopback" does not. **The port must be excluded from the comparison on both sides.**
2. RFC 8252 §7.3's MUST is scoped to "loopback IP redirect URIs" — `localhost` is a *name*, not an
   IP literal, so §7.3 does not strictly cover it and §8.3 discourages it. You must extend the
   exception to `localhost` on interop grounds. Note this deliberately in code; a future reader
   comparing against RFC 8252 will otherwise "fix" it and break Claude Code.

**Other known client redirect URIs:**

| Client | Redirect URI | Matching |
|---|---|---|
| Claude.ai web / Desktop / mobile / Cowork | `https://claude.ai/api/mcp/auth_callback` | exact, no exception |
| Claude Code | `http://localhost/callback`, `http://127.0.0.1/callback` (registered); `http://localhost:{ephemeral}/callback` (requested) | loopback, port ignored |
| ChatGPT connectors | `https://chatgpt.com/connector_platform_oauth_redirect` (widely reported; ChatGPT may also surface a per-connector callback) | exact, no exception |
| ChatGPT GPT Actions | `https://chatgpt.com/aip/{g-...}/oauth/callback` | exact, no exception |

Do not hardcode the ChatGPT value from this document — it is vendor-reported, not from an RFC.
Read it from the CIMD/DCR registration the client actually presents, and log rejected
`redirect_uri` values so a change surfaces as data rather than as a support ticket.

## 2.4 The redirect URI comparison algorithm

### Normative basis

> **RFC 8252 §8.4:** "Authorization servers MUST require clients to register their complete
> redirect URI (including the path component) and reject authorization requests that specify a
> redirect URI that doesn't exactly match the one that was registered; **the exception is loopback
> redirects, where an exact match is required except for the port URI component**."

> **RFC 9700 §2.1:** authorization servers "MUST utilize exact string matching except for port
> numbers in localhost redirection URIs of native apps" (see §4.1.3).
>
> **RFC 9700 §4.1.3:** the authorization server "MUST ensure that the two URIs are equal" through
> exact matching, with one exception: "In this case, the authorization server MUST allow variable
> port numbers as described in Section 7.3 of [RFC8252]."

> **OAuth 2.1 §2.3.1:** "Authorization servers MUST require clients to register their complete
> redirect URI (including the path component). Authorization servers MUST reject authorization
> requests that specify a redirect URI that doesn't exactly match one that was registered, with an
> exception for loopback redirects, where an exact match is required except for the port URI
> component."
>
> **OAuth 2.1 (Authorization Request):** "When comparing the two URIs the authorization server
> MUST ensure that the two URIs are equal, see Section 6.2.1 of RFC3986, Simple String Comparison,
> for details. The only exception is native apps using a localhost URI: In this case, the
> authorization server MUST allow variable port numbers as described in [loopback-interface-redirection]."

> **RFC 6749 §3.1.2:** "The redirection endpoint URI MUST be an absolute URI as defined by
> [RFC3986] Section 4.3." … "The endpoint URI MAY include an 'application/x-www-form-urlencoded'
> formatted … query component …, which MUST be retained when adding additional query parameters."
> … "**The endpoint URI MUST NOT include a fragment component.**"

> **RFC 6749 §3.1.2.3:** "the authorization server MUST compare and match the value received
> against at least one of the registered redirection URIs … using simple string comparison as
> defined in [RFC3986] Section 6.2.1."

> **MCP Authorization spec, "Open Redirection":** "MCP clients **MUST** have redirect URIs
> registered with the authorization server. Authorization servers **MUST** validate exact redirect
> URIs against pre-registered values to prevent redirection attacks."

> **MCP Authorization spec, "Communication Security":** "All redirect URIs **MUST** be either
> `localhost` or use HTTPS."

### The algorithm — exact string match, with loopback as a separate code path

Structure it as **two** functions. The exception must be a visibly distinct branch, not a set of
conditionals woven through the general path, because the general path must stay auditable as
"pure ordinal equality".

```csharp
public sealed class RedirectUriMatcher
{
    // Only these three hosts get the port exception. 127.0.0.1 and ::1 are RFC 8252 §7.3.
    // "localhost" is RFC 8252 §8.3 NOT RECOMMENDED, included solely because Claude Code's
    // Client ID Metadata Document declares http://localhost/callback. Do not "clean this up".
    private static readonly FrozenSet<string> LoopbackHosts =
        new[] { "127.0.0.1", "::1", "localhost" }.ToFrozenSet(StringComparer.Ordinal);

    /// <returns>true iff `requested` is an allowed redirect for this client.</returns>
    public bool IsAllowed(string requested, IReadOnlyList<string> registered)
    {
        // ---- Step 0: syntactic gate on the REQUESTED value ---------------------------
        // RFC 6749 §3.1.2: MUST be absolute; MUST NOT include a fragment.
        if (!Uri.TryCreate(requested, UriKind.Absolute, out var reqUri)) return false;
        if (requested.Contains('#', StringComparison.Ordinal))        return false;
        if (!string.IsNullOrEmpty(reqUri.UserInfo))                   return false; // no http://user@127.0.0.1:…
        // MCP: all redirect URIs MUST be localhost or HTTPS. Keep private-use schemes only if
        // you also serve native mobile apps that are not MCP clients.
        // if (reqUri.Scheme is not ("https" or "http")) { /* private-use scheme path, §2.5 */ }

        // ---- Step 1: exact string match — the ONLY path for 99% of clients ------------
        // RFC 3986 §6.2.1 Simple String Comparison. Ordinal. No normalization. No IdnHost.
        // No case folding. No trailing-slash tolerance. No percent-decoding.
        foreach (var r in registered)
            if (string.Equals(requested, r, StringComparison.Ordinal))
                return true;

        // ---- Step 2: loopback port exception — RFC 8252 §7.3 + §8.4 ------------------
        if (!IsLoopback(reqUri)) return false;

        foreach (var r in registered)
        {
            if (!Uri.TryCreate(r, UriKind.Absolute, out var regUri)) continue;
            if (!IsLoopback(regUri)) continue;
            if (LoopbackEqualIgnoringPort(reqUri, regUri)) return true;
        }
        return false;
    }

    private static bool IsLoopback(Uri u) =>
        // Scheme comparison is ordinal on Uri.Scheme, which .NET already lowercases.
        string.Equals(u.Scheme, "http", StringComparison.Ordinal)
        && LoopbackHosts.Contains(u.Host);   // Uri.Host strips the [] from [::1] → "::1"

    private static bool LoopbackEqualIgnoringPort(Uri a, Uri b) =>
        // Host: exact literal equality. 127.0.0.1 does NOT match localhost, does NOT match ::1.
        string.Equals(a.Host, b.Host, StringComparison.Ordinal)
        // Path and query: compare in escaped form so %2F vs / is not silently unified.
     && string.Equals(a.GetComponents(UriComponents.Path,  UriFormat.UriEscaped),
                      b.GetComponents(UriComponents.Path,  UriFormat.UriEscaped), StringComparison.Ordinal)
     && string.Equals(a.GetComponents(UriComponents.Query, UriFormat.UriEscaped),
                      b.GetComponents(UriComponents.Query, UriFormat.UriEscaped), StringComparison.Ordinal);
        // Port: deliberately absent. RFC 8252 §7.3 "MUST allow any port to be specified".
}
```

Then, everywhere downstream, redirect to the **requested** URI (which carries the real ephemeral
port), never the registered one. And store the requested URI on the authorization code so the
token endpoint can enforce RFC 6749 §4.1.3's `redirect_uri` rebinding check against the same
value.

### Traps in this algorithm, ranked by how often they are gotten wrong

| # | Trap | Consequence |
|---|---|---|
| 1 | Comparing `Uri.AbsoluteUri` or `Uri.ToString()` instead of the raw strings in Step 1 | .NET **drops default ports** (`http://127.0.0.1:80/cb` → `http://127.0.0.1/cb`), unescapes some percent-triples, and lowercases the host. Two different registered URIs can collapse to one. Do the exact match on **raw strings**; parse only inside the loopback branch. |
| 2 | `StartsWith` / prefix matching | `https://claude.ai/api/mcp/auth_callback` also "matches" `https://claude.ai/api/mcp/auth_callback.attacker.com/x`. Classic open redirector; leaks `code` and `state`. |
| 3 | Applying the port exception to non-loopback hosts | `https://claude.ai:1337/api/mcp/auth_callback` becomes acceptable. Restrict the branch by host **before** you drop the port. |
| 4 | Treating `127.0.0.1` ≡ `localhost` ≡ `::1` as interchangeable | Widens the match surface for no benefit. Claude Code registers all the forms it uses. Compare host literals exactly. |
| 5 | Accepting the whole `127.0.0.0/8`, or `127.1`, `0x7f.0.0.1`, `2130706433`, `0.0.0.0`, `[::ffff:127.0.0.1]` | All resolve to loopback on some stacks. RFC 8252 §7.3 names exactly two literals. Allowlist strings; never call `IPAddress.IsLoopback` on parsed input to decide this. |
| 6 | Dropping the path in the loopback branch | `http://127.0.0.1:9/anything` would match a registration for `/callback`. Any local process could then harvest codes. Path and query stay exact. |
| 7 | `Uri.Host` vs the registered `[::1]` literal | `new Uri("http://[::1]:5000/cb").Host` returns `::1` **without** brackets. If you compare `Uri.Host` to the raw registered string `[::1]` it never matches. Compare `Uri.Host` to `Uri.Host`, as above. |
| 8 | `Uri.IdnHost` / `Uri.DnsSafeHost` | Applies IDN/punycode normalization. Unicode-confusable hostnames become equal. Use `Uri.Host`. |
| 9 | `Uri.AbsolutePath` for the path compare | Percent-decodes some sequences. `%2e%2e%2f` and `../` can converge. Use `GetComponents(UriComponents.Path, UriFormat.UriEscaped)`. |
| 10 | Allowing `redirect_uri` to be omitted when exactly one is registered | RFC 6749 §3.1.2.3 permits it; OAuth 2.1 and MCP do not. Require it always — an omitted value means you cannot tell which registered URI the client meant when there are two, which is Claude Code's exact situation. |
| 11 | Port `0`, or a port outside 1–65535 | `http://127.0.0.1:0/callback` parses. Reject `Port <= 0` explicitly in `IsLoopback`. |
| 12 | Emitting `error=` to an unvalidated `redirect_uri` | RFC 6749 §4.1.2.1: MUST NOT redirect on a bad redirect URI. See §1.5 ordering. |
| 13 | Case-normalizing the scheme or host "to be helpful" | Simple String Comparison is case-**sensitive**. Normalize at *registration* time (lowercase scheme and host, reject anything else), then compare ordinally at request time. Normalizing at request time is what turns an exact matcher into a fuzzy one. |

### Test matrix (write these as xUnit theory rows)

Registered for Claude Code: `["http://localhost/callback", "http://127.0.0.1/callback"]`

| Requested | Expect | Why |
|---|---|---|
| `http://localhost:3118/callback` | ✅ | loopback, port ignored (§7.3) |
| `http://127.0.0.1:51004/callback` | ✅ | loopback, port ignored |
| `http://localhost/callback` | ✅ | exact match, Step 1 |
| `http://127.0.0.1:65535/callback` | ✅ | any port |
| `http://[::1]:61023/callback` | ❌ | `::1` not registered by this client — but you MUST support it for clients that do register it |
| `http://localhost:3118/callback/` | ❌ | trailing slash → different path |
| `http://localhost:3118/Callback` | ❌ | path is case-sensitive |
| `http://localhost:3118/callback?x=1` | ❌ | query differs |
| `https://localhost:3118/callback` | ❌ | scheme differs |
| `http://localhost.attacker.com:3118/callback` | ❌ | host is not a loopback literal |
| `http://127.0.0.2:3118/callback` | ❌ | not one of the two named literals |
| `http://127.1:3118/callback` | ❌ | alternate IPv4 spelling |
| `http://2130706433:3118/callback` | ❌ | integer form |
| `http://user@localhost:3118/callback` | ❌ | userinfo present |
| `http://localhost:3118/callback#x` | ❌ | fragment (RFC 6749 §3.1.2) |
| `http://localhost:0/callback` | ❌ | port 0 |

Registered for Claude.ai: `["https://claude.ai/api/mcp/auth_callback"]`

| Requested | Expect |
|---|---|
| `https://claude.ai/api/mcp/auth_callback` | ✅ |
| `https://claude.ai:443/api/mcp/auth_callback` | ❌ (explicit default port ≠ registered string) |
| `https://claude.ai/api/mcp/auth_callback/` | ❌ |
| `https://claude.ai/api/mcp/auth_callback?x=1` | ❌ |
| `https://claude.ai.attacker.com/api/mcp/auth_callback` | ❌ |
| `https://Claude.ai/api/mcp/auth_callback` | ❌ (normalize at registration, not here) |

Row 2 is worth a decision: strict Simple String Comparison rejects `:443`. Real clients do not send
it. Reject, and let the log tell you if that ever changes.

## 2.5 §7.1 Private-use URI schemes (`myapp://`)

> **RFC 8252 §7.1:** "When choosing a URI scheme to associate with the app, apps MUST use a URI
> scheme based on a domain name under their control, expressed in reverse order, as recommended by
> Section 3.8 of [RFC7595] for private-use URI schemes."
>
> "For example, an app that controls the domain name `app.example.com` can use `com.example.app`
> as their scheme. … **A scheme such as `myapp`, however, would not meet this requirement**, as it
> is not based on a domain name."
>
> "Following the requirements of Section 3.2 of [RFC3986], as there is no naming authority for
> private-use URI scheme redirects, **only a single slash ("/") appears after the scheme
> component**. A complete example … is:
> ```
> com.example.app:/oauth2redirect/example-provider
> ```
> "

> **RFC 8252 §8.4:** "For private-use URI scheme-based redirects, authorization servers SHOULD
> enforce the requirement in Section 7.1 that clients use schemes that are reverse domain name
> based. **At a minimum, any private-use URI scheme that doesn't contain a period character (".")
> SHOULD be rejected.**"

Registration-time validation:

```csharp
// Reject "myapp://…". Require at least one '.' in the scheme.
static bool IsAcceptablePrivateUseScheme(string scheme) =>
    scheme.Contains('.', StringComparison.Ordinal)
    && scheme.Length > 0
    && char.IsAsciiLetterLower(scheme[0])
    && scheme.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '+' or '-' or '.');
```

| Trap | Detail |
|---|---|
| `com.example.app:/path` vs `com.example.app://path` | One slash is correct per §7.1; two is what many SDKs actually emit (and what `Uri` will happily parse with an empty authority). Exact string match means the two forms never match each other. Store what was registered, compare ordinally, and document which form you require in your integration guide. |
| Parsing with `System.Uri` | For unregistered schemes .NET uses "generic" parsing whose `AbsolutePath`/`Host` behavior is surprising. **Do not parse private-use scheme URIs.** They never get the loopback exception, so pure ordinal `string.Equals` on the raw strings is complete. |
| Scheme case | RFC 3986 says schemes are case-insensitive; Simple String Comparison is not. Lowercase at registration; reject non-lowercase at request time. |
| Collision | Any app on the device can register the same scheme (§8.1). This is *why* PKCE is mandatory here — see §8.1 quote below. |

## 2.6 §7.2 Claimed `https` scheme URIs

> **RFC 8252 §7.2:** "Some operating systems allow apps to claim "https" scheme [RFC7230] URIs in
> the domains they control. … Such URIs can be used as redirect URIs by native apps. **They are
> indistinguishable to the authorization server from a regular web-based client redirect URI.**"
>
> "As the redirect URI alone is not enough to distinguish public native app clients from
> confidential web clients, **it is REQUIRED in Section 8.4 that the client type be recorded during
> client registration** to enable the server to determine the client type and act accordingly."
>
> "App-claimed "https" scheme redirect URIs have some advantages … in that the identity of the
> destination app is guaranteed to the authorization server by the operating system. For this
> reason, native apps SHOULD use them over the other options where possible."

**Concrete consequence:** your client record needs an explicit `ClientType { Public, Confidential }`
column. You cannot infer it from the redirect URI, and `https://claude.ai/api/mcp/auth_callback` is
a *public* client despite looking exactly like a server-side web app's callback.

## 2.7 Remaining §8 duties that land on the AS

> **§8.1 Protecting the Authorization Code:** "A limitation of using private-use URI schemes for
> redirect URIs is that multiple apps can typically register the same scheme, which makes it
> indeterminate as to which app will receive the authorization code." … "**Loopback IP-based
> redirect URIs may be susceptible to interception by other apps accessing the same loopback
> interface on some operating systems.**" … "Section 6 requires that both clients and servers use
> PKCE for public native app clients. Authorization servers SHOULD reject authorization requests
> from native apps that don't use PKCE by returning an error message, as defined in Section 4.4.1
> of PKCE [RFC7636]."

> **§8.2:** "as the implicit flow cannot be protected by PKCE [RFC7636] (which is required in
> Section 8.1), the use of the Implicit Flow with native apps is NOT RECOMMENDED." → do not
> implement `response_type=token` at all; OAuth 2.1 removes it.

> **§8.4:** "native apps are classified as public clients … they MUST be registered with the
> authorization server as such. Authorization servers MUST record the client type in the client
> registration details in order to identify and process requests accordingly."

> **§8.5 Client Authentication:** "it is NOT RECOMMENDED for authorization servers to require
> client authentication of public native apps clients using a shared secret, as this serves little
> value beyond client identification which is already provided by the `client_id` request
> parameter."
>
> "**Authorization servers that still require a statically included shared secret for native app
> clients MUST treat the client as a public client** (as defined by Section 2.1 of OAuth 2.0
> [RFC6749]), and not accept the secret as proof of the client's identity."

→ Claude Code presents `token_endpoint_auth_method: "none"`. Your token endpoint must accept a
`POST /token` with `client_id` in the body and **no** client authentication for public clients, and
must not treat that as `invalid_client`.

> **§8.6 Client Impersonation:** "the authorization server SHOULD NOT process authorization
> requests automatically without user consent or interaction, except when the identity of the
> client can be assured." … "This includes the case where the user has previously approved an
> authorization request for a given client id — unless the identity of the client can be proven,
> the request SHOULD be processed as if no previous request had been approved."

→ **Do not skip the consent screen on repeat authorizations for public/loopback clients.** This is
the single most common "we made it faster" regression.

> **§8.12 Embedded User-Agents:** "This best current practice requires that "native apps MUST NOT
> use embedded user-agents to perform authorization requests" and allows that authorization
> endpoints MAY take steps to detect and block authorization requests in embedded user-agents."

### MCP's addition: loopback consent-screen requirements

> **MCP Authorization spec, "Localhost Redirect URI Risks":** "Client ID Metadata Documents cannot
> prevent `localhost` URL impersonation by themselves. An attacker can claim to be any client by:
> 1. Providing the legitimate client's metadata URL as their `client_id`
> 2. Binding to any `localhost` port, and providing that address as the redirect_uri
> 3. Receiving the authorization code via the redirect when the user approves
>
> The server will see the legitimate client's metadata document and the user will see the
> legitimate client's name, making attack detection difficult.
>
> Authorization servers:
> * **SHOULD** display additional warnings for `localhost`-only redirect URIs
> * **MAY** require additional attestation mechanisms for enhanced security
> * **MUST** clearly display the redirect URI hostname during authorization"

That MUST is a consent-page requirement, not a protocol one — it is easy to ship a Razor consent
page that omits it. Render the full requested `redirect_uri` (host at minimum) and, when every
registered URI for the client is loopback, an explicit "any program on this computer could be
making this request" warning.

Related CIMD duties the same spec imposes on the AS:

> "**MUST** validate that the fetched document's `client_id` matches the URL exactly"
> "**MUST** validate redirect URIs presented in an authorization request against those in the metadata document"
> "**SHOULD** cache metadata respecting HTTP cache headers"
> "Authorization servers fetching metadata documents **SHOULD** consider Server-Side Request Forgery (SSRF) risks"

SSRF matters concretely: `client_id` is an attacker-supplied URL your server fetches. Block private
IP ranges, link-local `169.254.0.0/16` (cloud metadata), and redirects into them, on the
`HttpClient` used for CIMD fetches.

---

## 3. Implementation checklist

**PKCE**

- [ ] `code_challenge` required on every `/authorize`; no per-client opt-out.
- [ ] Only `S256` accepted. Omitted `code_challenge_method` → `invalid_request` (defaults to `plain` per §4.3).
- [ ] `code_challenge` validated against `^[A-Za-z0-9\-._~]{43}$` at `/authorize`.
- [ ] `code_verifier` validated against `\A[A-Za-z0-9\-._~]{43,128}\z` at `/token`.
- [ ] `SHA256(ASCII(verifier))` → base64url **no padding**. Appendix B vector in a test.
- [ ] `CryptographicOperations.FixedTimeEquals` for the comparison.
- [ ] XOR check: verifier present ⟺ challenge stored. Both directions → `invalid_grant`. (RFC 9700 §4.8.2)
- [ ] Challenge + method + `PkceWasRequested` persisted with the code; encrypted if the code is a self-contained token.
- [ ] Authorization code is single-use and short-lived; consumed before PKCE verification so a failed verify still burns it.
- [ ] `code_challenge_methods_supported: ["S256"]` in **both** well-known documents.

**Redirect URIs**

- [ ] Step 1 = raw ordinal `string.Equals` on unparsed strings, for every scheme.
- [ ] Step 2 = loopback branch, gated on `scheme == "http"` and host ∈ {`127.0.0.1`, `::1`, `localhost`}, comparing host + escaped path + escaped query, **ignoring port on both sides**.
- [ ] Registered loopback URIs with no explicit port match requested URIs with any port.
- [ ] Fragment, userinfo, port 0 rejected.
- [ ] `redirect_uri` required in every authorization request.
- [ ] Redirect-URI and client-id validation happen **before** any `302` carrying `error=`.
- [ ] Private-use schemes: never parsed, `.`-in-scheme enforced at registration (§8.4).
- [ ] Registration-time normalization (lowercase scheme/host); request-time comparison is exact.
- [ ] `ClientType` recorded explicitly (§8.4); `https` redirect ≠ confidential.
- [ ] `token_endpoint_auth_method: none` accepted for public clients.
- [ ] Consent screen shows the requested redirect URI hostname; extra warning for loopback-only clients.
- [ ] Consent not auto-approved on repeat for public clients (§8.6).
- [ ] CIMD fetcher is SSRF-hardened.

---

## 4. Source index

| Spec | URL | Sections used |
|---|---|---|
| RFC 7636 (PKCE) | `https://www.rfc-editor.org/rfc/rfc7636.txt` | 3, 4.1–4.6, 4.4.1, 5, 6.2.2, 7.1, 7.2, App. A, App. B |
| RFC 8252 (Native Apps) | `https://www.rfc-editor.org/rfc/rfc8252.txt` | 6, 7, 7.1, 7.2, 7.3, 8.1–8.6, 8.12, App. A |
| RFC 9700 (OAuth Security BCP) | `https://www.rfc-editor.org/rfc/rfc9700.txt` | 2.1, 2.1.1, 4.1.3, 4.8, 4.8.1, 4.8.2 |
| OAuth 2.1 draft-15 | `https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.html` | 2.3.1, 4.1.1, 4.1.3, 7.5.1 |
| RFC 6749 (OAuth 2.0) | `https://www.rfc-editor.org/rfc/rfc6749.txt` | 3.1.2, 3.1.2.2, 3.1.2.3, 4.1.2.1, 5.2 |
| RFC 8414 (AS Metadata) | `https://www.rfc-editor.org/rfc/rfc8414.txt` | 2 |
| MCP Authorization 2025-11-25 | `https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization` | Authorization Code Protection; Open Redirection; Localhost Redirect URI Risks; CIMD |
| Claude connector auth | `https://claude.com/docs/connectors/building/authentication` | Callback URLs; DCR and CIMD details; Token refresh |
| Claude Code CIMD (live) | `https://claude.ai/oauth/claude-code-client-metadata` | full document, fetched 2026-08-03 |
