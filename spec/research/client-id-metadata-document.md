# OAuth Client ID Metadata Document (CIMD) — implementer's distillation

**Primary source fetched:** `draft-ietf-oauth-client-id-metadata-document-02`, 6 July 2026,
Parecki (Okta) + Smith. Expires 7 January 2027. Intended status: Standards Track.
Raw text: <https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.txt>
(pinned in this repository: [`spec/draft-ietf-oauth-client-id-metadata-document-02.txt`](../draft-ietf-oauth-client-id-metadata-document-02.txt) — checked to be this revision, 6 July 2026)

**Section numbers below are from -02.** ⚠️ The MCP `2026-07-28` authorization spec still cites
**-00**, whose numbering differs. Mapping for anyone following MCP's links:

| Topic | -00 / -01 § | **-02 §** |
|---|---|---|
| Client Identifier URL rules | 3 | **3** |
| Metadata document contents | 4.1 | **4** |
| Credential/key restrictions | 4.1 (inline) | **4.1** |
| Redirect URL registration | 4.5 | **4.2** |
| Fetching / discovery | 4 | **5** |
| Discovery errors | 4.3 | **5.1** |
| Caching | 4.4 | **5.2** |
| AS metadata flag | 5 | **6** |
| Security Considerations | 6 | **8** |
| SSRF | 6.5 | **8.6** |
| Max response size | 6.6 | **8.7** |

Draft revision history (per §Document History): -00 initial; -01 added 200-OK requirement,
metadata-change and SSRF considerations; -02 renamed "client identifier" → "Client Identifier URL",
clarified the loopback SSRF exception is dev/test only, moved dev "CIMD Services" to a
non-normative appendix, strengthened the client-authentication recommendation.

---

## 0. One-paragraph model

The client's `client_id` **is** an `https` URL. The AS `GET`s that URL, gets back an RFC 7591
client-metadata JSON blob, and treats it as the client's registration — no `/register` call, no
stored client record required. Because there is no shared secret, CIMD clients are public clients
(`none`) unless they publish a public key and use `private_key_jwt`. The whole security burden
moves onto (a) validating the document, (b) not being SSRF'd while fetching it, and (c) not
letting a random domain impersonate a well-known app on the consent screen.

---

## 1. Client Identifier URL — validation rules (§3)

Normative list, verbatim from §3. A Client Identifier URL:

| # | Normative text (§3) | Level | Concrete check |
|---|---|---|---|
| 1 | "MUST use the https URL scheme" | MUST | `uri.Scheme == "https"` (ordinal, lowercase) |
| 2 | "MUST NOT contain a userinfo component defined by [RFC3986]" | MUST | `uri.UserInfo.Length == 0` |
| 3 | "MAY contain a port" | MAY | allow explicit port; do **not** strip `:443` |
| 4 | "MUST contain a path component" | MUST | `uri.AbsolutePath.Length > 1` (i.e. not `""` and not `/`) |
| 5 | "MUST NOT contain single-dot or double-dot path components" | MUST | reject any segment `==` `.` or `..`, **including percent-encoded `%2e`/`%2E`** |
| 6 | "SHOULD NOT contain a query component" | SHOULD | tolerate on input; do not add one |
| 7 | "MUST NOT contain a fragment component" | MUST | `uri.Fragment.Length == 0` |

**Comparison rule (§3), quoted:**

> "Client Identifier URLs MUST be compared using simple string comparison, as defined in
> Section 6.2.1 of [RFC3986]. For example, `https://example.com/client` and
> `https://example.com:443/client` are not equivalent even though 443 is the default port
> for the https scheme."

⚠️ **This is the single most-failed rule.** `System.Uri` normalizes aggressively: it lowercases
scheme+host, **elides the default port**, collapses `/./` and `/../`, and decodes some
percent-escapes. If you round-trip the client's string through `new Uri(s).ToString()` /
`.AbsoluteUri` and then string-compare against the document's `client_id`, you will produce false
matches and false mismatches. **Keep the raw request string** for all comparisons; use `Uri` only
for the structural checks above.

```csharp
// Parse for validation, compare on the ORIGINAL string.
if (!Uri.TryCreate(raw, UriKind.Absolute, out var u)) return Invalid;
if (!string.Equals(u.Scheme, "https", StringComparison.Ordinal)) return Invalid;
if (u.UserInfo.Length != 0 || u.Fragment.Length != 0)            return Invalid;
if (u.AbsolutePath.Length <= 1)                                  return Invalid;
foreach (var seg in raw_path_segments_from_the_raw_string)       // NOT u.Segments
    if (seg is "." or ".." || seg.Contains("%2e", StringComparison.OrdinalIgnoreCase)) return Invalid;
// later: string.Equals(raw, doc.client_id, StringComparison.Ordinal)
```

Non-normative but load-bearing guidance in §3:

- Short URL is **RECOMMENDED** (it gets shown to the end user).
- Stable URL is **RECOMMENDED**; changing it = a brand-new client (see §8.3).
- "URL shortening services are generally not suitable as Client Identifier URLs, since they
  typically operate using HTTP redirects, which conflicts with the requirement in Section 5."
- Path of `/` is **NOT RECOMMENDED**.

---

## 2. The document itself (§4)

> "The Client ID Metadata Document MUST contain a `client_id` property whose value MUST match the
> Client Identifier URL, which MUST also match the URL that the authorization server used to fetch
> the document; comparisons MUST be made using simple string comparison as defined in Section 6.2.1
> of [RFC3986]. The authorization server is responsible for validating this match as part of
> processing the fetched document." (§4)

Three strings must be ordinal-equal: **request `client_id` param == URL actually fetched ==
`client_id` field inside the body.** The middle term matters — it is what makes redirect-following
a violation, and it is what stops a "fetch A, get content of B" confusion.

> "The Client ID Metadata Document MUST be served with a 200 OK HTTP status code. The Client ID
> Metadata Document MAY also be served with more specific content types as long as the response is
> JSON and conforms to `application/<AS-defined>+json`." (§4)

Content-type is deliberately loose — **do not require exact `application/json`**. Parse the media
type and accept `application/json` and anything `+json`; ignore the `charset` parameter. (Observed
in the wild: `application/json` from claude.ai, `application/json; charset=utf-8` from chatgpt.com.)

Field vocabulary (§4): "The client metadata values are the values defined in the OAuth Dynamic
Client Registration Metadata OAuth Parameters registry … as established by [RFC7591]."
"The client metadata document MAY define additional properties" — so **unknown fields MUST be
ignored, not rejected**.

There is an open `TBD` in §4 for a future `client_id_expires_at`. Don't implement it yet; don't
choke on it if it appears.

### 2.1 RFC 7591 §2 field map (what to bind to a C# record)

| JSON field | Type | CIMD relevance |
|---|---|---|
| `client_id` | string | **REQUIRED by CIMD §4**; must equal the fetch URL |
| `redirect_uris` | string[] | the registered redirect set (§4.2) |
| `token_endpoint_auth_method` | string | constrained by §4.1 — see §3 below |
| `grant_types` | string[] | default `["authorization_code"]` |
| `response_types` | string[] | default `["code"]` |
| `client_name` | string | consent screen |
| `client_uri` | string | consent screen; candidate for same-origin policy |
| `logo_uri` | string | consent screen — prefetch + cache (§8.8) |
| `scope` | string | space-separated |
| `contacts` | string[] | |
| `tos_uri`, `policy_uri` | string | consent screen links |
| `jwks_uri` | string | public keys; **mutually exclusive with `jwks`** |
| `jwks` | object | inline JWK Set; **mutually exclusive with `jwks_uri`** |
| `software_id`, `software_version` | string | |
| `software_statement` | JWT string | §4.3 — MAY be present inside the document |

RFC 7591 §2.2: human-readable fields may carry BCP 47 language tags delimited by `#`, e.g.
`client_name#en`, `client_name#ja-Jpan-JP`. Your JSON binder must not blow up on a property name
containing `#`. "If any human-readable field is sent without a language tag, parties using it
MUST NOT make any assumptions about the language."

RFC 7591 §2.1 `token_endpoint_auth_method` registry values: `none`, `client_secret_post`,
`client_secret_basic` (RFC 7591 default when omitted), plus `client_secret_jwt` and
`private_key_jwt` from OIDC Registration, and `tls_client_auth` /
`self_signed_tls_client_auth` from RFC 8705.

### 2.2 Credential and key material restrictions (§4.1) — verbatim

> "As there is no way to establish a shared secret to be used with client metadata documents, the
> following restrictions apply to the contents of the Client ID Metadata Document:
> - the `token_endpoint_auth_method` property MUST NOT include `client_secret_post`,
>   `client_secret_basic`, `client_secret_jwt`, or any other method based around a shared
>   symmetric secret
> - the `client_secret` and `client_secret_expires_at` properties MUST NOT be used
> - private key material MUST NOT be included in the Client ID Metadata Document; only public
>   keys, such as those published via the `jwks` or `jwks_uri` properties, are permitted"

⚠️ **The default-value trap.** RFC 7591 §2 says `token_endpoint_auth_method` defaults to
`client_secret_basic` when absent — and §4.1 forbids exactly that. A literal implementation
("apply RFC 7591 defaults, then enforce §4.1") rejects every document that omits the field.
**For CIMD, the effective default MUST be `none`.**

Reject the document if `jwks` and `jwks_uri` are both present (RFC 7591 §2 says mutually
exclusive), and reject any JWK carrying private parameters (`d`, `p`, `q`, `dp`, `dq`, `qi`, or a
symmetric `k`) — that is the §4.1 "private key material" rule made concrete.

### 2.3 Redirect URL registration (§4.2) — verbatim

> "According to [RFC9700], the authorization server MUST require registration of redirect URLs,
> and MUST ensure that the redirect URL in an authorization request is an exact match, using simple
> string comparison, of a registered redirect URL.
>
> This method of client information discovery establishes registered redirect URL(s) when the
> authorization server fetches the contents of the Client ID Metadata Document."

So: the fetched `redirect_uris` array **is** the registration. Exact ordinal string match, no
prefix matching, no wildcards, no trailing-slash tolerance, no port wildcarding.

§4.2 also carves out non-redirect grants: "For grant types that do not involve a redirect URL, such
as the Client Credentials Grant, or extension grants such as Token Exchange, the requirements of
this section do not apply … The other mechanisms described in this specification, namely client
identification and client metadata discovery, apply regardless of which grant type is used."

### 2.4 `software_statement` (§4.3)

MAY be included as a property of the document. Operational warning worth heeding: the statement is
"no longer presented inline by the client during the authorization request; instead, it is
retrieved by the authorization server as part of fetching the Client ID Metadata Document," so its
trustworthiness now also depends on the integrity of the fetch (i.e. on your §8.6 defenses).

---

## 3. Fetching the document (§5)

| Normative text | Level | ASP.NET Core action |
|---|---|---|
| "Authorization servers SHOULD automatically fetch the Client ID Metadata Document at the Client Identifier URL to retrieve the client metadata." | SHOULD | `GET` via a dedicated hardened `HttpClient` |
| "Authorization servers SHOULD periodically re-fetch the Client ID Metadata Document as the contents may change over time." | SHOULD | background refresh / TTL expiry |
| "An authorization server MAY instead associate a Client Identifier URL with client metadata through other means, such as by pre-registering the URL" | MAY | admin-pinned clients skip the fetch |
| "The Client ID Metadata Document MUST be served with a 200 OK HTTP status code. The authorization server MUST treat all other HTTP status codes as an error response" | MUST | **only** `200` is success. `201`, `203`, `204`, `301`, `302`, `304` → error |
| "The authorization server MUST NOT automatically follow HTTP redirects when fetching the Client ID Metadata Document." | MUST | `AllowAutoRedirect = false` |

⚠️ **`AllowAutoRedirect` defaults to `true` in .NET.** A stock `HttpClient` silently violates the
MUST NOT and simultaneously opens the classic SSRF bypass (public hostname → `302` →
`http://169.254.169.254/…`). This is the single highest-value one-line fix in the whole feature.

⚠️ `304 Not Modified` is "all other HTTP status codes" → an error. If you send
`If-None-Match`/`If-Modified-Since` on a revalidation, you must handle `304` as *"reuse the cached
entry"* in your cache layer **before** the document validator sees it — never as a fresh fetch
result. Simplest correct choice: don't send conditional requests at all.

### 3.1 Errors (§5.1)

> "If the authorization server attempts to fetch the Client ID Metadata Document, and fetching the
> metadata document fails, the authorization server SHOULD abort the authorization request." (§5.1)

"Abort" for a client_id-class failure means **render an error page, do not redirect** — see §6.

### 3.2 Caching (§5.2) — verbatim

> "The authorization server MAY cache the client metadata it discovers at the Client ID Metadata
> Document URL.
>
> The authorization server SHOULD respect HTTP cache headers [RFC9111] when caching client
> metadata, but MAY define its own upper and/or lower bounds on an acceptable cache lifetime as well.
>
> The authorization server MUST NOT cache error responses. The authorization server also MUST NOT
> cache documents which are invalid or malformed."

Practical policy that satisfies all of the above:

| Case | TTL |
|---|---|
| `Cache-Control: max-age=N` present | `Clamp(N, floor: 300s, ceiling: 86400s)` |
| no cache headers | default 3600s |
| `no-store` / `no-cache` | floor (300s) — the SHOULD is overridden by your MAY-defined lower bound, and this is what prevents §9.1 fetch-per-request side-channel |
| non-200, timeout, DNS failure, oversize, JSON parse error, `client_id` mismatch | **MUST NOT cache** |

⚠️ Both Claude and ChatGPT publish `Cache-Control: public, max-age=300`. Honoring that literally
means a refetch every 5 minutes per client — fine, but it makes your outbound fetch path a hot,
user-triggered code path. Rate-limit it and add a negative-result **circuit breaker in memory only**
(you must not *cache the error document*, but you may throttle repeat fetch attempts to the same
host — that is a different thing, and it is what stops CIMD being an outbound DoS amplifier).

---

## 4. AS metadata flag (§6) — verbatim

> "Authorization servers that publish Authorization Server Metadata [RFC8414] MUST include the
> following property to signal support for Client ID Metadata Documents as described in this
> specification.
>
> `client_id_metadata_document_supported`: OPTIONAL. Boolean value specifying whether the
> authorization server supports retrieving client metadata from a `client_id` URL as described in
> this specification."

IANA registration (§10.1): name `client_id_metadata_document_supported`, description "JSON boolean
value specifying whether the authorization server supports retrieving client metadata from a
client_id URL", change controller IETF, registry "OAuth Authorization Server Metadata" (RFC 8414).

Add to **both** `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`:

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "client_id_metadata_document_supported": true
}
```

⚠️ **This flag is the #1 cause of "Claude/ChatGPT won't connect."** Per MCP's client-registration
priority order, clients only attempt CIMD *if this boolean is present and true*; otherwise they
fall straight through to DCR (or fail). It must be a JSON **boolean** `true`, not the string
`"true"`. Note also `code_challenge_methods_supported` is separately mandatory for MCP clients —
its absence makes MCP clients "refuse to proceed" regardless of CIMD.

---

## 5. Client authentication (§8.2) — CIMD clients are *usually* public, not *always*

Common misreading: "CIMD ⇒ public client." §4.1 forbids only **symmetric** secrets. Asymmetric
auth is explicitly supported and, as of -02, encouraged:

> "Clients that are capable of maintaining private key material and performing client
> authentication SHOULD do so with an acceptable method, such as a method in the OAuth Token
> Endpoint Authentication Methods registry." (§8.2)

> "When a client declares `token_endpoint_auth_method` as `private_key_jwt`, the authorization
> server MUST require client authentication according to Section 2.2 of [RFC7523] using the
> corresponding key discovered from the client's metadata document." (§8.2)

Document example from §8.2:

```json
{
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://client.example.com/jwks.json"
}
```

> "This establishes this client as a confidential client, and any communication with the
> authorization server MUST include client authentication of the registered type." (§8.2)

Implementation consequences:

| Declared method | Token endpoint behavior |
|---|---|
| absent, or `"none"` | public client. `client_id` in the form body. **No** `Authorization` header. PKCE `S256` is the only proof. |
| `"private_key_jwt"` | **MUST** require `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + `client_assertion=<JWT>`, verified against the key from `jwks`/`jwks_uri`. Missing/invalid ⇒ `invalid_client`. |
| any `client_secret_*` | **reject the document** (§4.1) |

`jwks_uri` is a second attacker-supplied URL. §8.6 covers it explicitly ("or any URLs contained
within a Client ID Metadata Document") — run the *same* SSRF guard, size cap, and no-redirect rule
on the JWKS fetch. Do not reuse a general-purpose `HttpClient` for it.

Exact form parameters for `private_key_jwt` at `POST /token`:

```
grant_type=authorization_code
&code=...
&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2Fmcp
&code_verifier=...
&client_id=https%3A%2F%2Fchatgpt.com%2Foauth%2Fmcp%2Fclient.json
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6ImNpbWQtMjAyNjA0MjgwMzAxMTkifQ...
&resource=https%3A%2F%2Fmcp.example.com%2Fmcp
```

Assertion claims per RFC 7523 §3: `iss` = `sub` = the client_id URL, `aud` = the token endpoint URL
(accept the issuer identifier too), plus `exp`, and `jti` with replay caching.

---

## 6. Error handling — exact codes and the redirect decision

The governing rule is **RFC 6749 §4.1.2.1**, quoted:

> "the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically
> redirect the user-agent to the invalid redirection URI."

Every CIMD failure is a `client_id`-class or `redirect_uri`-class failure, therefore **none of them
may be returned via redirect.** They render on the AS's own error page. Only *after* `client_id`
and `redirect_uri` are both validated do you switch to the redirect-the-error mode.

| Failure | Redirect? | HTTP | `error` | `error_description` (suggested) |
|---|---|---|---|---|
| `client_id` not `https`, has fragment/userinfo, no path, has `.`/`..` | **no** | 400 | `invalid_request` | `client_id is not a valid Client Identifier URL` |
| `client_id` looks like a URL but CIMD unsupported/disabled | **no** | 400 | `invalid_client` | |
| Fetch: DNS fail, TCP refused, TLS fail, timeout | **no** | 400 | `invalid_client` | `unable to retrieve client metadata` |
| Fetch: status ≠ 200 (incl. 3xx, 304, 404, 500) | **no** | 400 | `invalid_client` | |
| Fetch: redirect encountered (`AllowAutoRedirect=false` ⇒ 3xx surfaces) | **no** | 400 | `invalid_client` | `client metadata URL must not redirect` |
| Fetch: response exceeded byte cap | **no** | 400 | `invalid_client` | |
| Fetch: resolved to special-use IP (§8.6) | **no** | 400 | `invalid_client` | do **not** leak the resolved IP |
| Body not JSON / not an object | **no** | 400 | `invalid_client` | |
| `client_id` field missing, or ≠ fetch URL (ordinal) | **no** | 400 | `invalid_client` | `client_id mismatch` |
| `token_endpoint_auth_method` is a `client_secret_*` variant, or `client_secret` present | **no** | 400 | `invalid_client` | |
| `jwks` **and** `jwks_uri` both present, or private key material present | **no** | 400 | `invalid_client` | |
| `redirect_uris` missing/empty, or request `redirect_uri` not an exact member | **no** | 400 | `invalid_request` | `redirect_uri not registered` |
| Requested `response_type` not in doc's `response_types` | yes | 302 | `unauthorized_client` | |
| Requested `grant_type` not in doc's `grant_types` | yes | 302 | `unauthorized_client` | |
| Requested scope not permitted | yes | 302 | `invalid_scope` | |
| User declines consent | yes | 302 | `access_denied` | |
| Fetch failed transiently and you'd rather retry | yes | 302 | `temporarily_unavailable` | only after `redirect_uri` validated |

MCP's own flow diagram confirms the pair: "Error response `error=invalid_client` or
`error=invalid_request`."

At `POST /token`, per RFC 6749 §5.2, an unresolvable/mismatched CIMD `client_id` ⇒ HTTP **400** with
`{"error":"invalid_client"}`; use **401** with a `WWW-Authenticate` header only if the client
attempted to authenticate via the `Authorization` header. Response `Content-Type: application/json`,
`Cache-Control: no-store`, `Pragma: no-cache`.

Authorization-endpoint error codes (RFC 6749 §4.1.2.1 registry): `invalid_request`,
`unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`,
`temporarily_unavailable`.
Token-endpoint error codes (RFC 6749 §5.2): `invalid_request`, `invalid_client`, `invalid_grant`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`.

---

## 7. SSRF defenses (§8.6) — the part that gets you owned

Verbatim:

> "Authorization servers fetching the Client ID Metadata Document and resolving URLs contained
> within it should be aware of possible SSRF attacks. Authorization servers **MUST NOT** fetch a
> Client ID Metadata Document URL or any URLs contained within a Client ID Metadata Document that
> resolve to special-use IP addresses as defined in [RFC6890]."

> "Authorization servers deployed for development or testing purposes MAY relax this restriction to
> allow fetching from loopback addresses when the authorization server itself is also running on a
> loopback address and the resolved address matches the same loopback interface. Authorization
> servers **MUST NOT** apply this exception in production deployments, since doing so would allow an
> attacker-controlled Client Identifier URL to cause the authorization server to make requests
> against itself or other services on the loopback interface or special-use IP addresses."

> "Authorization servers SHOULD consider network policies or other measures to prevent making
> requests to special-use addresses. Authorization servers which support non-http-based URI schemes
> are at additional risk of SSRF attacks."

> "Authorization servers SHOULD ensure they only fetch or parse URLs with known and supported URI
> schemes. This can help avoid leading to compromises if a client uses a URI scheme such as
> `javascript:` in a metadata property."

Size cap, §8.7:

> "authorization servers SHOULD limit the amount of data they read and process when fetching a
> Client ID Metadata Document, for example by stopping after a maximum number of bytes and treating
> the response as an error if that limit is reached before the document has been fully read. The
> recommended maximum size to read is **5 kilobytes**."

Note the -02 rewording: the cap is on **bytes you read**, not on `Content-Length`. A lying or absent
`Content-Length` must not be able to bypass it.

### 7.1 RFC 6890 special-use blocklist (complete, from the RFC's own tables)

**IPv4:** `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`,
`172.16.0.0/12`, `192.0.0.0/24`, `192.0.0.0/29`, `192.0.2.0/24`, `192.88.99.0/24`,
`192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`,
`255.255.255.255/32`

**IPv6:** `::/128`, `::1/128`, `64:ff9b::/96`, `::ffff:0:0/96`, `100::/64`, `2001::/23`,
`2001::/32`, `2001:2::/48`, `2001:db8::/32`, `2001:10::/28`, `2002::/16`, `fc00::/7`, `fe80::/10`

Also block, though not in RFC 6890: `224.0.0.0/4` (multicast), `ff00::/8` (v6 multicast).
`169.254.169.254` (AWS/GCP/Azure IMDS) is already inside `169.254.0.0/16` — but check it explicitly
in tests so a regression is loud.

⚠️ `::ffff:0:0/96` and `64:ff9b::/96` are the *bypass* entries: `http://[::ffff:127.0.0.1]/` and
`http://[::ffff:a9fe:a9fe]/` reach loopback and IMDS respectively through an IPv6 literal. In .NET,
`IPAddress.IsIPv4MappedToIPv6` → `MapToIPv4()` before range-checking, or you will miss these.
Decimal/octal/hex IPv4 literals (`http://2130706433/`, `http://0177.0.0.1/`) are another family —
`IPAddress.TryParse` in .NET does *not* accept most of these, but the OS resolver might, so validate
the **resolved `IPAddress` objects**, never the hostname string.

### 7.2 DNS rebinding — the only correct .NET shape

Resolve-then-validate-then-`HttpClient.GetAsync(url)` is a **TOCTOU hole**: the resolver is consulted
a second time inside the handler and can return a different (internal) address. The fix in .NET is
`SocketsHttpHandler.ConnectCallback`, which lets you validate and connect to the *same* `IPAddress`:

```csharp
var handler = new SocketsHttpHandler
{
    AllowAutoRedirect       = false,                       // §5 MUST NOT follow redirects
    MaxAutomaticRedirections = 0,
    AutomaticDecompression  = DecompressionMethods.None,   // no decompression bomb
    ConnectTimeout          = TimeSpan.FromSeconds(3),
    PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    UseCookies              = false,
    Credentials             = null,
    UseProxy                = false,                       // a proxy would bypass ConnectCallback

    ConnectCallback = async (ctx, ct) =>
    {
        var addrs = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
        var ip = addrs.Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
                      .FirstOrDefault(a => !SpecialUse.Contains(a))
                 ?? throw new HttpRequestException("blocked: special-use address");

        var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        await sock.ConnectAsync(new IPEndPoint(ip, ctx.DnsEndPoint.Port), ct); // pinned IP
        return new NetworkStream(sock, ownsSocket: true);
    }
};

var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
http.MaxResponseContentBufferSize = 5 * 1024;   // belt; braces below
```

Byte-capped read (the `MaxResponseContentBufferSize` belt is not enough on its own — enforce the
5 KB cap yourself so you can distinguish "too big" from "transport error"):

```csharp
using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
if (resp.StatusCode != HttpStatusCode.OK) return Fail(CimdError.NotOk);   // ONLY 200
await using var s = await resp.Content.ReadAsStreamAsync(ct);
var buf = new byte[5 * 1024 + 1];
int n = 0, r;
while (n < buf.Length && (r = await s.ReadAsync(buf.AsMemory(n), ct)) > 0) n += r;
if (n > 5 * 1024) return Fail(CimdError.TooLarge);
```

### 7.3 Defense checklist

| Defense | Setting | Source |
|---|---|---|
| scheme allowlist (`https` only) | reject before any DNS | §3, §8.6 |
| special-use IP block on **every** resolved address | RFC 6890 table above | §8.6 MUST |
| IPv4-mapped-IPv6 unwrap before range check | `MapToIPv4()` | §8.6 (bypass) |
| connect to the validated IP (anti-rebinding) | `ConnectCallback` | §8.6 intent |
| no redirects | `AllowAutoRedirect = false` | §5 MUST NOT |
| read cap | 5 KB, on bytes read | §8.7 SHOULD |
| connect + total timeout | 3 s / 5 s | operational |
| no decompression | `DecompressionMethods.None` | operational |
| no proxy, no cookies, no creds, no client cert | as above | operational |
| egress network policy / dedicated egress identity | infra | §8.6 SHOULD |
| same guard applied to `jwks_uri` and `logo_uri` | reuse the handler | §8.6 "any URLs contained within" |
| per-host outbound rate limit + breaker | app | §9.1 |

---

## 8. Consent-screen and trust obligations (§8.5, §8.9, §8.1)

> "Authorization servers SHOULD fetch the client_id metadata document provided in the authorization
> request in order to provide users with additional information about the request, such as the
> application name and logo." (§8.5)

> "The authorization server SHOULD display the hostname of the client_id on the authorization
> interface, in addition to displaying the fetched client information if any." (§8.5)

> "If fetching the Client ID Metadata Document fails for any reason, the client_id URL is the only
> piece of information the user has as an indication of which application they are authorizing."

⚠️ `client_name` is **attacker-controlled**. Anyone can publish `{"client_name": "Claude"}` at
`https://evil.example/c.json`. The hostname display requirement is the whole mitigation — render
the **origin of the `client_id`** prominently and never let `client_name` be the only identity cue.
HTML-encode `client_name`; validate `logo_uri` is `https` and prefetch it (§8.8) rather than
hotlinking (which is also a cross-domain tracking vector per §9.2).

§8.1 — the highest-leverage optional policy:

> "An authorization server may impose restrictions or relationships between the `redirect_uris` and
> the `client_id` or `client_uri` properties, for example to restrict the `redirect_uri` to the
> same-origin as the Client ID Metadata Document. Without restrictions like these, there are
> potential trust and safety issues where the client attempts to impersonate a more well-known
> client or otherwise act in a way which is malicious or puts the end-user at risk."

**Good news: both Claude and ChatGPT satisfy a strict same-origin rule** (see §10). Same-origin is
therefore a shippable default. §8.1 notes the no-restriction case exists only for Solid-OIDC
backwards compatibility. If you enforce it, Appendix A **RECOMMENDS** you also run at least one
exempt "CIMD Service" for developers — or, more simply, ship an admin allowlist escape hatch.

§8.9 gives the trust-policy menu: first-N-users warning interstitial, domain-age/reputation checks,
and "allowlists of trusted domain patterns, such as treating any Client Identifier URL under
`*.example.com` as belonging to a known and trusted operator, and apply reduced friction."

MCP adds a requirement the IETF draft does not state, worth honoring:
- **SHOULD** display additional warnings for `localhost`-only redirect URIs
- **MUST** clearly display the redirect URI hostname during authorization
("Client ID Metadata Documents cannot prevent `localhost` URL impersonation by themselves.")

---

## 9. Coexisting with your own client_ids (§7.1)

> "If an authorization server wishes to support clients using Client ID Metadata Documents as well
> as clients where the authorization server generates the `client_id`, it SHOULD ensure that the
> `client_id` strings it generates do not start with `https://`."

> "The determining factor for whether a `client_id` is subject to this specification is whether the
> authorization server fetches, or otherwise associates, a Client ID Metadata Document for that
> `client_id`. Authorization servers that support both approaches need a reliable way, internal to
> their own implementation, to distinguish clients registered via this specification from those
> registered by other means."

Concretely: store a `ClientKind` discriminator (`Cimd | Dynamic | PreRegistered`) on the client
record. **Do not** re-derive "is this CIMD?" by `client_id.StartsWith("https://")` at each call
site — §7.1 says the prefix is not a reliable signal (an AS may issue vanity `https://` ids).
Resolution order at `/authorize`: look up pre-registered/DCR store first; only on a miss, and only
if the string passes the §3 URL rules, go to the CIMD path. §7.2 permits pre-registering a Client
Identifier URL, in which case it behaves as a normal pre-registered client and you skip the fetch.

Also relevant to a multi-tenant reusable AS: per MCP, "Client IDs based on Client ID Metadata
Documents are portable across authorization servers" — the client will present the *same*
`client_id` to every customer deployment. Your consent/grant records must be keyed by
`(tenant, client_id URL, user)`, and the `client_id` string contains `:` and `/`, so encode it
before using it in a route, cache key, or filename.

---

## 10. What Claude and ChatGPT actually publish (fetched 2026-08-03)

### 10.1 Claude — `https://claude.ai/oauth/mcp-oauth-client-metadata`

Response headers (relevant): `HTTP/2 200`, `content-type: application/json`,
`cache-control: public, max-age=300`.

**Body, verbatim, byte-for-byte as served (single line, no trailing newline):**

```json
{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

Pretty-printed:

```json
{
  "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
  "client_name": "Claude",
  "client_uri": "https://claude.ai",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer"
  ],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

### 10.2 ChatGPT — `https://chatgpt.com/oauth/client.json`

Headers: `HTTP/2 200`, `content-type: application/json; charset=utf-8`,
`cache-control: public, max-age=300`, `x-content-type-options: nosniff`.

**Body, verbatim:**

```json
{"client_id":"https://chatgpt.com/oauth/client.json","client_uri":"https://chatgpt.com/","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_methods_supported":["none","private_key_jwt"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"ChatGPT","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png","token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://chatgpt.com/oauth/jwks.json"}
```

### 10.3 ChatGPT — `https://chatgpt.com/oauth/mcp/client.json` (second, MCP-specific document)

**Body, verbatim:**

```json
{"client_id":"https://chatgpt.com/oauth/mcp/client.json","client_uri":"https://chatgpt.com/","redirect_uris":["https://chatgpt.com/connector/oauth/mcp"],"token_endpoint_auth_methods_supported":["none","private_key_jwt"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"ChatGPT","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png","token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://chatgpt.com/oauth/jwks.json"}
```

`https://chatgpt.com/oauth/jwks.json` (live, RS256, for `private_key_jwt`):

```json
{"keys":[{"kty":"RSA","kid":"cimd-20260428030119","use":"sig","alg":"RS256","n":"y09nMyYX6LhSgS3YmbLOZrFoR8SffxG0kM5gQ5PKpHVMzbAu__-7rf0_Q_pwhVa9vxJzv3cRkGnXKNWKOHDdEXp8YFPVUql4NcDjDdS_0w0uos8gazoa7Td47qVquxOsG3861l8oKEh-E4r5C_6w6Sx0Rl2WEEs2-dmvn3fwH9PkLCQOo4tsNAEnrW_ge2vQE-pFo-kJp5QRRiX2w0YvaMFtIfEvNbdPSJ3xd7NbGrvRt279HrxgDLGUvpbeWrCsp3D7HdR2QZn-9MZp7CHPlMGtFgN9aIB4Guf7qYlRiC3Ja0ZI22jSMct6xrI-90XX4AK2FhiWmYOmjV_2d3vEVw","e":"AQAB"}]}
```

The `kid` (`cimd-20260428030119`) is date-stamped — expect rotation, so cache the JWKS by
`jwks_uri` with a TTL and refetch on unknown `kid` (with a rate limit). §8.4.1: "If the
authorization server notices that the `jwks`, `jwks_uri` or the contents at the `jwks_uri` have
changed compared to the last time it fetched the metadata, the authorization server may take
actions such as revoking any tokens issued to this client" — that is a MAY; do not auto-revoke on
routine rotation.

OpenAI's stated position (developers.openai.com MCP docs): *"We recommend using OAuth with Client ID
Metadata Documents (CIMD) for client registration when your authorization server supports CIMD…
ChatGPT supports CIMD with public-client token exchange (`none`) or signed client assertion token
exchange (`private_key_jwt`). Dynamic client registration remains supported when configured."*

### 10.4 ⚠️⚠️ The interop trap that will break ChatGPT on a spec-literal AS

**ChatGPT publishes `token_endpoint_auth_methods_supported` (plural, array). That is an
*authorization server* metadata field name (RFC 8414), not an RFC 7591 *client* metadata field.
The correct client-side field is `token_endpoint_auth_method` (singular, string).**

A strictly-spec implementation reads `token_endpoint_auth_method`, finds it absent, applies the
RFC 7591 default `client_secret_basic`, and then §4.1 forbids `client_secret_basic` → **every
ChatGPT connection is rejected at document validation.** Required tolerance:

```csharp
static string ResolveAuthMethod(CimdDocument d) =>
    d.TokenEndpointAuthMethod                                   // RFC 7591, correct
    ?? d.TokenEndpointAuthMethodsSupported?.FirstOrDefault(m =>  // ChatGPT's spelling
           m is "none" or "private_key_jwt" or "self_signed_tls_client_auth" or "tls_client_auth")
    ?? "none";                                                   // CIMD default, NOT client_secret_basic
```

Prefer `private_key_jwt` when the client offers both `none` and `private_key_jwt` *and* publishes a
usable `jwks_uri` — but you must then require the assertion consistently, and you must accept that
if the JWKS fetch fails the client cannot authenticate at all. Safer default for v1: pick `none`
(both vendors support it), and make `private_key_jwt` an opt-in per-tenant policy.

### 10.5 Other Claude/ChatGPT interop notes

| Observation | Consequence |
|---|---|
| Claude's client_id has **no file extension and no trailing slash** (`…/mcp-oauth-client-metadata`) | never "helpfully" append `.json` or `/`; never normalize |
| Claude declares `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types` | must not reject a document for containing a grant type you don't support — only reject the *request* that uses one |
| Claude publishes **no `logo_uri`** | consent UI must render with name+hostname only |
| ChatGPT publishes `client_uri` as `https://chatgpt.com/` (**trailing slash**) while `client_id` host is `chatgpt.com` | a same-origin `redirect_uri` policy must compare **origins** (scheme+host+port), not string prefixes |
| Both use `max-age=300` | apply a cache floor; don't fetch per-request (§9.1 side channel) |
| Both serve `200` directly, no redirect | your `AllowAutoRedirect=false` will not break either — so a redirect is always a red flag |
| ChatGPT ships **two** documents with different `redirect_uris` | client_id is per-surface; never key state on hostname alone |
| Both redirect_uris are same-origin with their client_id | a strict §8.1 same-origin policy is safe to ship |

---

## 11. Minimal wire example (end to end)

```http
GET /authorize?response_type=code
 &client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata
 &redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback
 &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
 &code_challenge_method=S256
 &scope=stories%3Aread
 &resource=https%3A%2F%2Fmcp.example.com%2Fmcp
 &state=af0ifjsldkj HTTP/1.1
Host: as.example.com
```

AS-side sequence:
1. §3 URL checks on the **raw** decoded `client_id` string.
2. Cache lookup by that exact string. Miss ⇒ hardened `GET` (§7.2 handler).
3. Require `200`; read ≤ 5 KB; parse JSON; require `client_id` field `==` the fetched URL (ordinal).
4. §4.1 credential restrictions; resolve auth method per §10.4.
5. Exact-match `redirect_uri` against `redirect_uris`. Failure at steps 1–5 ⇒ **error page, no redirect.**
6. Cache with clamped TTL (never cache a failure).
7. Consent screen showing `claude.ai` (hostname of client_id) + `Claude` + redirect hostname.
8. Redirect with `code`, `state`, and `iss` (RFC 9207 — MCP SHOULD, and advertise
   `authorization_response_iss_parameter_supported: true`).

```http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQ&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata&resource=https%3A%2F%2Fmcp.example.com%2Fmcp
```

No `Authorization` header (`token_endpoint_auth_method: none`). Re-resolve the client from cache;
bind `redirect_uri` and PKCE to the code; set `aud` of the issued token from `resource`.

---

## 12. Test vectors to encode as unit tests

| Input `client_id` | Expected |
|---|---|
| `https://claude.ai/oauth/mcp-oauth-client-metadata` | accept |
| `https://chatgpt.com/oauth/mcp/client.json` | accept |
| `http://example.com/c.json` | reject — scheme |
| `https://example.com` / `https://example.com/` | reject — no path component |
| `https://example.com/c.json#x` | reject — fragment |
| `https://user:pw@example.com/c.json` | reject — userinfo |
| `https://example.com/a/../c.json` | reject — dot segment |
| `https://example.com/a/%2e%2e/c.json` | reject — encoded dot segment |
| `https://example.com:443/c` vs doc `https://example.com/c` | reject — mismatch (no port normalization) |
| doc served with `301`→`200` elsewhere | reject — redirect |
| doc served `200` but body `client_id` differs by one char | reject — mismatch |
| doc 6 KB | reject — size |
| host resolves `127.0.0.1` | reject — special-use |
| host resolves `::ffff:169.254.169.254` | reject — v4-mapped IMDS |
| host resolves public IP, second lookup returns `10.0.0.1` | reject — pinned-IP connect prevents rebinding |
| doc `{"token_endpoint_auth_method":"client_secret_basic"}` | reject — §4.1 |
| doc omitting `token_endpoint_auth_method` | accept as `none` (**not** `client_secret_basic`) |
| doc with only `token_endpoint_auth_methods_supported:["none","private_key_jwt"]` | accept — §10.4 tolerance |
| doc with `jwks` **and** `jwks_uri` | reject |
| doc with a JWK containing `"d"` | reject — private key material |
| doc with unknown field `"x_custom":1` | accept — ignore |
| `redirect_uri` differing only by trailing `/` | reject — exact match |

---

## 13. Sources

- <https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/>
- <https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.txt> (revision -02, 6 Jul 2026)
- <https://www.rfc-editor.org/rfc/rfc7591.txt> (client metadata field registry, §2, §3.2.2 errors)
- <https://www.rfc-editor.org/rfc/rfc6749.txt> (§4.1.2.1 authz errors, §5.2 token errors)
- <https://www.rfc-editor.org/rfc/rfc6890.txt> (special-use address blocks)
- <https://www.rfc-editor.org/rfc/rfc8414> (AS metadata registry), <https://www.rfc-editor.org/rfc/rfc9700> (OAuth 2.0 BCP), <https://www.rfc-editor.org/rfc/rfc7523> (private_key_jwt)
- <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration>
- <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations>
- <https://claude.ai/oauth/mcp-oauth-client-metadata> (fetched 2026-08-03)
- <https://chatgpt.com/oauth/client.json>, <https://chatgpt.com/oauth/mcp/client.json>, <https://chatgpt.com/oauth/jwks.json> (fetched 2026-08-03)
- <https://developers.openai.com/api/docs/mcp>
