# OAuth 2.0 Security BCP + Hardening Checklist for a C# / ASP.NET Core 9 Authorization Server

Primary sources fetched and quoted verbatim from the RFC text (not from memory):

| RFC | Title | Local copy |
|---|---|---|
| RFC 9700 | Best Current Practice for OAuth 2.0 Security | `scratchpad/rfc/rfc9700.txt` |
| RFC 6819 | OAuth 2.0 Threat Model and Security Considerations | `scratchpad/rfc/rfc6819.txt` |
| RFC 9207 | OAuth 2.0 Authorization Server Issuer Identification | fetched |
| RFC 9126 | OAuth 2.0 Pushed Authorization Requests (PAR) | `scratchpad/rfc/rfc9126.txt` |
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | `scratchpad/rfc/rfc9449.txt` |
| RFC 6750 | OAuth 2.0 Bearer Token Usage | fetched |
| RFC 8707 | Resource Indicators for OAuth 2.0 | `scratchpad/rfc/rfc8707.txt` |
| RFC 6749 | The OAuth 2.0 Authorization Framework (error registries) | `scratchpad/rfc/rfc6749.txt` |
| MCP spec (draft) | Model Context Protocol — Authorization | fetched |

> **Reading note.** RFC 9700 is normative *for this AS*. Section 2 is the "do this" list; Section 4 is the "why". Where 9700 says "as described in [RFC6819]", RFC 6819 supplies the concrete control (this is true for clickjacking and for `state`).

---

# Part 1 — Hardening Checklist

Each item: **attack → normative statement → ASP.NET Core implementation → error code string → interop trap.**

---

## H-01 — Redirect URI validation: exact string match

**Attack.** RFC 9700 §4.1: pattern-matched redirect URIs (`https://*.client.example/*`, prefix matches, sub-path matches) let an attacker who controls *any* matching origin receive the authorization code or access token.

**Normative.**
> "When comparing client redirection URIs against pre-registered URIs, authorization servers **MUST** utilize exact string matching except for port numbers in localhost redirection URIs of native apps" — RFC 9700 §2.1
>
> "the authorization server **MUST** ensure that the two URIs are equal; see Section 6.2.1 of [RFC3986], Simple String Comparison, for details. The only exception is native apps using a localhost URI: In this case, the authorization server **MUST** allow variable port numbers as described in Section 7.3 of [RFC8252]." — RFC 9700 §4.1.3
>
> "every actual redirect URI sent with the respective `client_id` to the end-user authorization endpoint must match the registered redirect URI. Where it does not match, the authorization server should assume that the inbound GET request has been sent by an attacker and refuse it. Note: The authorization server should **not** redirect the user agent back to the redirect URI of such an authorization request." — RFC 6819 §5.2.3.5

**ASP.NET Core.**

```csharp
// Authorization endpoint. Runs BEFORE anything else, before authentication.
static bool RedirectUriMatches(string registered, string presented)
    => string.Equals(registered, presented, StringComparison.Ordinal);   // RFC 3986 §6.2.1

// localhost exception for native apps (RFC 8252 §7.3): host+scheme+path must match
// ordinally; ONLY the port may vary.
static bool LoopbackMatches(Uri registered, Uri presented) =>
    registered.Scheme == "http"
    && (presented.Host is "127.0.0.1" or "[::1]" or "localhost")
    && registered.Host == presented.Host
    && string.Equals(registered.AbsolutePath, presented.AbsolutePath, StringComparison.Ordinal);
```

On mismatch or unknown `client_id`: **do not redirect**. Render an error page on the AS's own origin with `400 Bad Request`. This is RFC 6749 §4.1.2.1 behaviour and it is what stops the AS becoming an open redirector (H-02).

**Error code.** No `error=` redirect is emitted at all. Response body: `400` + AS-hosted HTML/JSON. If you emit a machine-readable body use `"error": "invalid_request"`.

**Interop trap (.NET-specific, high severity).** Do **not** compare with `System.Uri`. `new Uri(a) == new Uri(b)` and `Uri.Equals` apply .NET normalization: lowercasing scheme and host, eliding default ports, resolving `.`/`..` dot segments, and unescaping "unreserved" percent-encodings. That is *not* RFC 3986 §6.2.1 Simple String Comparison, and each normalization is an exploitable widening of the match set. Store the registered URI as the exact registered string and compare with `StringComparison.Ordinal` on raw strings. Likewise never use `Uri.AbsoluteUri` as the comparison input — it is already normalized.

**Second trap.** Validate the redirect URI *before* authenticating the user, and never echo an unvalidated `redirect_uri` into an error page link, `Location` header, or `<a href>`.

---

## H-02 — The AS as an open redirector

**Attack.** RFC 9700 §4.11.2: attacker registers a client (trivially, if DCR is on) with a redirect URI pointing at a phishing site, then (1) sends a deliberately broken authorization request so the AS redirects the error to them, or (2) sends a valid request so that even a user who clicks **Deny** is redirected to the phishing site, or (3) sends `prompt=none` so the redirect happens with no user interaction at all. In every case the user is bounced to the phishing site *from a URL on your trusted AS domain*.

**Normative.**
> "Clients and authorization servers **MUST NOT** expose URLs that forward the user's browser to arbitrary URIs obtained from a query parameter (open redirectors)" — RFC 9700 §2.1
>
> "The authorization server **MUST** take precautions to prevent these threats. The authorization server **MUST** always authenticate the user first and, with the exception of the silent authentication use case, prompt the user for credentials when needed, before redirecting the user. … The authorization server **SHOULD** only automatically redirect the user agent if it trusts the redirection URI. If the URI is not trusted, the authorization server **MAY** inform the user and rely on the user to make the correct decision." — RFC 9700 §4.11.2

**ASP.NET Core.**

Order of operations at `GET /authorize` is itself the control:

1. Resolve `client_id`. Unknown → `400`, no redirect.
2. Exact-match `redirect_uri` (H-01). Mismatch → `400`, no redirect.
3. **Authenticate the user** (`HttpContext.User` / challenge the login scheme).
4. Only now validate `scope`, `response_type`, `resource`, `code_challenge` — and only now may you redirect with `error=`.

Any general-purpose `?returnUrl=` on your login/logout/error pages is an open redirector on the AS origin. Allowlist it against local paths only:

```csharp
if (!Url.IsLocalUrl(returnUrl)) returnUrl = "/";
```

`Url.IsLocalUrl` rejects absolute URLs and protocol-relative `//evil.com`. Do not hand-roll it.

**Error codes.** Steps 1–2: none (no redirect). Steps 4+: redirect with `error=invalid_request` / `unsupported_response_type` / `invalid_scope` / `access_denied` / `invalid_target`.

**Interop trap.** `prompt=none` is the sharpest edge: it produces a redirect with zero user interaction. For clients not on a trust allowlist, treat `prompt=none` on an unrecognized/low-trust redirect URI as a candidate for an interstitial rather than an automatic bounce. Also: `access_denied` (the user clicked Deny) still redirects to the client by spec — that is exactly attack variant (2), and the only real mitigation is trusting the registered redirect URI, which for DCR-registered clients you do not.

---

## H-03 — Authorization code injection → PKCE

**Attack.** RFC 9700 §4.5: attacker obtains a *legitimate* authorization code issued for the victim (via referrer leak, browser history, a mis-scoped redirect, or an open redirector), then injects it into their own session at the client. The client exchanges it and the attacker ends up logged in as the victim (or the victim's resources bound into the attacker's account).

**Normative.**
> "Public clients **MUST** use PKCE [RFC7636] to this end" — RFC 9700 §2.1.1
>
> "For confidential clients, the use of PKCE [RFC7636] is **RECOMMENDED**" — RFC 9700 §2.1.1
>
> "Authorization servers **MUST** support PKCE [RFC7636]." — RFC 9700 §2.1.1
>
> "If a client sends a valid PKCE `code_challenge` parameter in the authorization request, the authorization server **MUST** enforce the correct usage of `code_verifier` at the token endpoint." — RFC 9700 §2.1.1
>
> "the PKCE challenge or OpenID Connect nonce **MUST** be transaction-specific and securely bound to the client and the user agent in which the transaction was started. Authorization servers are encouraged to make a reasonable effort at detecting and preventing the use of constant values" — RFC 9700 §2.1.1
>
> "When using PKCE, clients **SHOULD** use PKCE code challenge methods that do not expose the PKCE verifier in the authorization request. … Currently, `S256` is the only such method." — RFC 9700 §2.1.1
>
> "Authorization servers **MUST** provide a way to detect their support for PKCE. It is **RECOMMENDED** for authorization servers to publish the element `code_challenge_methods_supported` in their Authorization Server Metadata" — RFC 9700 §2.1.1

**Wire format.**

Authorization request: `code_challenge`, `code_challenge_method=S256`
Token request: `code_verifier`

**ASP.NET Core.**

```csharp
// Verification at POST /token.  RFC 7636: ASCII, SHA-256, base64url, no padding.
static bool VerifyS256(string codeVerifier, string storedChallenge)
{
    Span<byte> hash = stackalloc byte[32];
    SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier), hash);
    var computed = Base64Url.EncodeToString(hash);           // .NET 9 System.Buffers.Text.Base64Url
    return CryptographicOperations.FixedTimeEquals(
        Encoding.ASCII.GetBytes(computed),
        Encoding.ASCII.GetBytes(storedChallenge));
}
```

Persist `code_challenge` + `code_challenge_method` on the authorization-code record. Reject `plain` outright: advertise only `"code_challenge_methods_supported": ["S256"]` and return `invalid_request` for `code_challenge_method=plain`.

Also enforce the RFC 7636 verifier grammar before hashing: 43–128 chars, `[A-Za-z0-9-._~]` only.

**Error codes.**

| Condition | HTTP | `error` |
|---|---|---|
| `code_challenge` missing when required | 302 to redirect_uri | `invalid_request` |
| `code_challenge_method` unsupported (e.g. `plain`) | 302 to redirect_uri | `invalid_request` |
| `code_verifier` missing at token endpoint but challenge stored | 400 | `invalid_grant` |
| `code_verifier` present but does not verify | 400 | `invalid_grant` |
| `code_verifier` malformed (length/charset) | 400 | `invalid_request` |

**Interop trap.** The verifier is hashed as **ASCII**, not UTF-8, and the base64url output has **no `=` padding**. `Convert.ToBase64String` + manual `-`/`_` replacement while forgetting to strip `=` is the single most common PKCE bug; every conforming client will then fail with `invalid_grant` and the cause is invisible from the outside. Use `Base64Url.EncodeToString` (.NET 9) and add a unit test against the RFC 7636 Appendix B test vector.

**Second trap.** Compare in constant time (`CryptographicOperations.FixedTimeEquals`), not with `==`.

---

## H-04 — PKCE downgrade attack

**Attack.** RFC 9700 §4.8: attacker strips `code_challenge` from the authorization request (or replays a code minted from a challenge-less request), then supplies *any* `code_verifier` at the token endpoint. A naive AS reasons "no stored challenge → nothing to check → accept", and PKCE has been silently downgraded to nothing.

**Normative.**
> "Authorization servers **MUST** mitigate PKCE downgrade attacks by ensuring that a token request containing a `code_verifier` parameter is accepted only if a `code_challenge` parameter was present in the authorization request" — RFC 9700 §2.1.1
>
> "Therefore, authorization servers **MUST** mitigate this attack. … to prevent PKCE downgrade attacks, the authorization server **MUST** ensure that if there was no `code_challenge` in the authorization request, a request to the token endpoint containing a `code_verifier` is rejected. Authorization servers that mandate the use of PKCE (in general or for particular clients) implicitly implement this security measure." — RFC 9700 §4.8.2

**ASP.NET Core.** Both directions must be checked — this is a strict XNOR on the code record:

```csharp
var hadChallenge = code.CodeChallenge is not null;
var hasVerifier  = !string.IsNullOrEmpty(req.CodeVerifier);

if (hadChallenge != hasVerifier)
    return TokenError("invalid_grant", "PKCE parameter mismatch");
if (hadChallenge && !VerifyS256(req.CodeVerifier!, code.CodeChallenge!))
    return TokenError("invalid_grant", "PKCE verification failed");
```

**Error code.** `invalid_grant`, HTTP `400`.

**Recommendation for this AS.** Take the escape hatch the RFC offers: **mandate PKCE for every client and every authorization-code flow**, public and confidential. `hadChallenge` is then always `true`, the downgrade branch is unreachable by construction, and you satisfy both the OAuth 2.1 draft and the MCP spec at once. Reject an authorization request with no `code_challenge` at the authorization endpoint with `error=invalid_request`.

---

## H-05 — Authorization code single use + revocation of derived tokens

**Attack.** A code that leaked via referrer (H-10) or browser history (H-11) is replayed by the attacker. If the AS accepts it twice, the attacker gets a parallel token set.

**Normative.**
> "As described in Section 4.1.2 of [RFC6749], authorization codes **MUST** be invalidated by the authorization server after their first use at the token endpoint. … Therefore, [RFC6749] further recommends that, when an attempt is made to redeem a code twice, the authorization server **SHOULD** revoke all tokens issued previously based on that code." — RFC 9700 §4.2.4
>
> "If an authorization server observes multiple attempts to redeem an authorization grant (e.g., such as an authorization `code`), the authorization server may want to revoke all tokens granted based on the authorization grant." — RFC 6819 §5.2.1.1

**ASP.NET Core.** The redemption must be an atomic compare-and-swap, not read-then-write — two concurrent redemptions of the same code must not both succeed.

```sql
-- EF Core: ExecuteUpdateAsync, or raw. Rows-affected is the authority.
UPDATE auth_codes SET redeemed_at = @now
 WHERE code_hash = @hash AND redeemed_at IS NULL;
```

`rowsAffected == 0` → either unknown or already-redeemed. If already redeemed, **revoke the whole grant**: every access token, refresh token, and consent derived from that code (same mechanism as H-13 family revocation).

Store only a hash of the code (`SHA-256`), never the code itself. Lifetime: ≤ 60 seconds. Bind the code to `client_id`, `redirect_uri`, `code_challenge`, `resource`, and the authenticated subject; verify all of them at redemption (RFC 6749 §5.2 `invalid_grant` covers "does not match the redirection URI used in the authorization request, or was issued to another client").

**Error code.** `invalid_grant`, HTTP `400`.

**Interop trap.** Return `invalid_grant` uniformly for unknown / expired / already-redeemed / wrong-client / wrong-redirect_uri. Distinguishing them in `error_description` is an oracle. Also: do **not** return `invalid_client` when the code belongs to another client — that leaks code existence.

---

## H-06 — CSRF and the `state` parameter

**Attack.** RFC 6819 §4.4.1.8 / RFC 9700 §4.7: an attacker feeds their own authorization code to the victim's client redirect endpoint. The victim's client binds the attacker's account to the victim's session (or vice versa).

**Normative.**
> "Clients **MUST** prevent Cross-Site Request Forgery (CSRF). … Clients that have ensured that the authorization server supports Proof Key for Code Exchange (PKCE) [RFC7636] **MAY** rely on the CSRF protection provided by PKCE. In OpenID Connect flows, the `nonce` parameter provides CSRF protection. Otherwise, one-time use CSRF tokens carried in the `state` parameter that are securely bound to the user agent **MUST** be used for CSRF protection" — RFC 9700 §2.1
>
> "The authorization server therefore **MUST** provide a way to detect their support for PKCE. Using Authorization Server Metadata according to [RFC8414] is **RECOMMENDED**" — RFC 9700 §4.7.1
>
> "The client should utilize the `state` request parameter to send the authorization server a value that binds the request to the user agent's authenticated state" — RFC 6819 §5.3.5

**ASP.NET Core.** Most of this is a *client* obligation. The AS's three duties:

1. Echo `state` back **verbatim, unmodified**, in both success and error redirects, whenever it was present. Never synthesize one; never re-encode it.
2. Publish `code_challenge_methods_supported` so clients may legitimately rely on PKCE for CSRF (RFC 9700 §4.7.1 makes this the AS's obligation).
3. Accept an arbitrary-length opaque `state` (clients put signed JWTs in there). Do not impose a short cap; ~2 KB minimum, and document the ceiling.

**Distinct, and frequently missed:** the AS's *own consent form* is a normal HTML form POST and needs normal ASP.NET Core antiforgery protection. `state` protects the client; it does nothing for your consent page.

```csharp
// Program.cs — the consent POST is a state-changing form on the AS origin.
builder.Services.AddAntiforgery(o => {
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite     = SameSiteMode.Strict;
});
// Minimal APIs validate antiforgery by default for form-bound endpoints in .NET 8+;
// do NOT call .DisableAntiforgery() on the consent endpoint.
```

Set the AS session/login cookie to `SameSite=Lax` at minimum (`Strict` if your flows never arrive cross-site with a cookie requirement), `Secure`, `HttpOnly`.

**Error code.** N/A on the AS side (this is client-side detection). A malformed/oversized `state` → `invalid_request`.

**Interop trap.** Do not URL-decode-then-re-encode `state`. Round-tripping through `Uri.EscapeDataString` after `Uri.UnescapeDataString` mangles values containing `%2B`, `+`, or `=` and breaks strict clients. Carry the raw percent-encoded token through untouched.

---

## H-07 — Mix-up attacks and the `iss` authorization response parameter (RFC 9207)

**Attack.** RFC 9700 §4.4: a client that talks to more than one AS is tricked into sending the code it received from AS-A to the token endpoint of attacker-controlled AS-B (or vice versa) — the attacker harvests the code and/or the client credentials. Storing only the *authorization endpoint* URL is not enough: "An attacker might declare an uncompromised authorization server's authorization endpoint URL as 'their' authorization server URL, but declare a token endpoint under their own control." (RFC 9700 §4.4.2)

**Normative.**
> "When an OAuth client can interact with more than one authorization server, a defense against mix-up attacks (see Section 4.4) is **REQUIRED**. To this end, clients **SHOULD** use the `iss` parameter as a countermeasure according to [RFC9207]" — RFC 9700 §2.1
>
> "In authorization responses to the client, including error responses, an authorization server supporting this specification **MUST** indicate its identity by including the `iss` parameter in the response." — RFC 9207 §2
>
> "The `iss` parameter value is the issuer identifier of the authorization server that created the authorization response, as defined in [RFC8414]. Its value **MUST** be a URL that uses the `https` scheme without any query or fragment components." — RFC 9207 §2
>
> "The server **MUST** indicate its support for the `iss` parameter by setting the metadata parameter `authorization_response_iss_parameter_supported` … to `true`." — RFC 9207 §3
>
> "In OpenID Connect flows where an ID Token is returned from the authorization endpoint, the value in the `iss` parameter **MUST** always be identical to the `iss` claim in the ID Token." — RFC 9207 §2.4

MCP spec adds:
> "MCP authorization servers **SHOULD** include the `iss` parameter in authorization responses, including error responses… Authorization servers that include the `iss` parameter **MUST** advertise this by setting `authorization_response_iss_parameter_supported` to `true`." — MCP draft, Authorization Response Validation. A future revision is expected to upgrade this **SHOULD** to **MUST**.

**Wire format.**

Success:
```
HTTP/1.1 302 Found
Location: https://client.example/cb?code=x1848ZT64p4IirMPT0R-X3141MFPTuBX-VFL_cvaplMH58
  &state=ZWVlNDBlYzA1NjdkMDNhYjg3ZjUxZjAyNGQzMTM2NzI
  &iss=https%3A%2F%2Fhonest.as.example
```

Error — **note `iss` is present here too**:
```
HTTP/1.1 302 Found
Location: https://client.example/cb?error=access_denied
  &state=N2JjNGJhY2JiZjRhYzA3MGJkMzNmMDE5OWJhZmJhZjA
  &iss=https%3A%2F%2Fhonest.as.example
```

**ASP.NET Core.** Emit `iss` from a *single* constant — the same string served as `issuer` in `/.well-known/oauth-authorization-server` and as the `iss` claim in ID Tokens and JWT access tokens.

```csharp
// One source of truth. No trailing slash. No port unless non-default. https only.
public sealed record AsIdentity(string Issuer);   // e.g. "https://auth.example.com"

// Build EVERY authorization response — success and error — through one helper:
static IResult AuthorizeRedirect(string redirectUri, IEnumerable<KeyValuePair<string,string?>> p, string issuer)
{
    var qs = QueryHelpers.AddQueryString(redirectUri,
        p.Append(new("iss", issuer)));
    return SeeOther(qs);            // 303 — see H-08
}
```

Metadata: `"authorization_response_iss_parameter_supported": true`.

**Error code.** N/A — `iss` is additive; there is no failure mode on the AS side.

**Interop trap 1.** Forgetting `iss` on the **error** redirect. RFC 9207 §2 says "including error responses", and the MCP spec says a client that sees `authorization_response_iss_parameter_supported: true` and no `iss` **MUST reject the response** — including the error one. Half-implementing this makes your error paths look like attacks.

**Interop trap 2.** Issuer string drift. Clients compare with RFC 3986 §6.2.1 Simple String Comparison and the MCP spec explicitly forbids them from normalizing: "clients **MUST NOT** apply scheme or host case folding, default-port elision, trailing-slash, or percent-encoding normalization … before comparison." So `https://auth.example.com` and `https://auth.example.com/` are *different issuers*. Pin one exact byte string in configuration and assert at startup that the metadata `issuer`, the `iss` response parameter, and the `iss` token claim are `Ordinal`-equal.

**Interop trap 3.** Behind a reverse proxy, do not derive the issuer from `HttpContext.Request` (`Scheme`/`Host`). A spoofed `X-Forwarded-Host` then rewrites your issuer. Use the configured constant. (See H-16.)

---

## H-08 — 307 vs 303 after the credential form POST

**Attack.** RFC 9700 §4.12, the highest-value low-effort bug on this list. The login form is submitted by `POST` to the AS. If the AS answers that POST with a **307**, the browser re-sends the request body — *the user's username and password* — to the redirect target, i.e. to the client. A malicious client harvests them and can then impersonate the user at the AS directly.

**Normative (§4.12, complete).**
> "In [RFC6749], the HTTP status code 302 (Found) is used for this purpose, but 'any other method available via the user-agent to accomplish this redirection is allowed'. When the status code 307 is used for redirection instead, the user agent will send the user's credentials via HTTP POST to the client.
>
> This discloses the sensitive credentials to the client. If the client is malicious, it can use the credentials to impersonate the user at the authorization server.
>
> The behavior might be unexpected for developers but is defined in Section 15.4.8 of [RFC9110]. This status code (307) does not require the user agent to rewrite the POST request to a GET request and thereby drop the form data in the POST request body.
>
> In the HTTP standard [RFC9110], only the status code **303** unambiguously enforces rewriting the HTTP POST request to an HTTP GET request. For all other status codes, including the popular 302, user agents can opt not to rewrite POST to GET requests, thereby causing the user's credentials to be revealed to the client. (In practice, however, most user agents will only show this behavior for 307 redirects.)
>
> Authorization servers that redirect a request that potentially contains the user's credentials therefore **MUST NOT** use the HTTP 307 status code for redirection. If an HTTP redirection (and not, for example, JavaScript) is used for such a request, the authorization server **SHOULD** use HTTP status code 303 (See Other)."

Also RFC 9700 §2.1: "An authorization server that redirects a request potentially containing user credentials **MUST** avoid forwarding these user credentials accidentally."

**ASP.NET Core — the exact trap.** ASP.NET Core has no `Results.SeeOther`. It has:

| Call | Status emitted | Verdict |
|---|---|---|
| `Results.Redirect(url)` | **302** | tolerated, not ideal |
| `Results.Redirect(url, permanent: false, preserveMethod: true)` | **307** | ❌ **BANNED** |
| `Results.Redirect(url, permanent: true, preserveMethod: true)` | **308** | ❌ **BANNED** |
| `Results.RedirectToRoute(...)` | 302 | n/a for external URIs |
| manual | **303** | ✅ required |

`preserveMethod: true` is *precisely* the flag that produces the credential leak. It must never appear on any path that can terminate an authorization request.

```csharp
// The only redirect helper the authorize/consent/login pipeline may use.
static IResult SeeOther(string location) => Results.Extensions.SeeOther(location);

public static IResult SeeOther(this IResultExtensions _, string location) =>
    new SeeOtherResult(location);

file sealed class SeeOtherResult(string location) : IResult
{
    public Task ExecuteAsync(HttpContext ctx)
    {
        ctx.Response.StatusCode = StatusCodes.Status303SeeOther;   // 303
        ctx.Response.Headers.Location = location;
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";
        ctx.Response.Headers.RefererPolicy = "no-referrer";        // see H-10
        return Task.CompletedTask;
    }
}
```

Enforce it mechanically — an architecture test is cheap and this bug is silent:

```csharp
// Fails the build if preserveMethod:true or a 307/308 literal appears in the AS project.
[Fact] public void No307Redirects() { /* Roslyn or grep over src/**/*.cs */ }
```

**Error code.** N/A — status-code choice, not an error.

**Related trap.** ASP.NET Core Identity's `SignInManager` and the cookie handler emit 302s on their own. That is acceptable per the RFC's parenthetical, but the *final* hop that carries the authorization response to the client's `redirect_uri` — the one that immediately follows the credential POST — must be 303.

---

## H-09 — Clickjacking of the login / consent page

**Attack.** RFC 9700 §4.16: "an attacker embeds the authorization endpoint user interface in an innocuous context. A user believing to interact with that context, for example, by clicking on buttons, inadvertently interacts with the authorization endpoint user interface instead. The opposite can be achieved as well: A user believing to interact with the authorization endpoint might inadvertently type a password into an attacker-provided input field overlaid over the original user interface." Impact per RFC 6819 §4.4.1.9: "An attacker can steal a user's authentication credentials and access their resources."

**Normative.**
> "Authorization servers **MUST** prevent clickjacking attacks. Multiple countermeasures are described in [RFC6819], including the use of the `X-Frame-Options` HTTP response header field and frame-busting JavaScript. In addition to those, authorization servers **SHOULD** also use Content Security Policy (CSP) level 2 [W3C.CSP-2] or greater." — RFC 9700 §4.16
>
> "To be effective, CSP must be used on the authorization endpoint and, if applicable, other endpoints used to authenticate the user and authorize the client (e.g., the device authorization endpoint, login pages, error pages, etc.)." — RFC 9700 §4.16
>
> "authorization servers **SHOULD** allow administrators to configure allowed origins for particular clients and/or for clients to register these dynamically." — RFC 9700 §4.16
>
> "Because some user agents do not support [W3C.CSP-2], this technique **SHOULD** be combined with others, including those described in [RFC6819], unless such legacy user agents are explicitly unsupported by the authorization server. Even in such cases, additional countermeasures **SHOULD** still be employed." — RFC 9700 §4.16
>
> RFC 6819 §5.2.2.6: "avoidance of iFrames can be enforced on the server side by using the `X-FRAME-OPTIONS` header … This header can have two values, `DENY` and `SAMEORIGIN` … The value `ALLOW-FROM` specifies a list of trusted origins."

Non-normative example from RFC 9700 §4.16:
```
HTTP/1.1 200 OK
Content-Security-Policy: frame-ancestors https://ext.example.org:8000
Content-Security-Policy: script-src 'self'
X-Frame-Options: ALLOW-FROM https://ext.example.org:8000
```

**ASP.NET Core.** Middleware applied to every user-facing AS endpoint — `/authorize`, `/login`, `/consent`, `/logout`, `/device`, and **error pages**:

```csharp
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        var h = ctx.Response.Headers;
        // Default: deny all framing. Per-client allowed origins override frame-ancestors.
        var allowed = ctx.Features.Get<IFrameAncestorsFeature>()?.Origins;
        h["Content-Security-Policy"] = string.Join("; ",
            allowed is { Count: > 0 }
                ? $"frame-ancestors {string.Join(' ', allowed)}"
                : "frame-ancestors 'none'",
            "script-src 'self'",
            "default-src 'self'",
            "form-action 'self'",
            "base-uri 'none'",
            "object-src 'none'");
        h["X-Frame-Options"]        = "DENY";      // legacy fallback
        h["Referrer-Policy"]        = "no-referrer";   // H-10
        h["X-Content-Type-Options"] = "nosniff";
        h["Cache-Control"]          = "no-store";
        return Task.CompletedTask;
    });
    await next();
});
```

`IFrameAncestorsFeature` is populated from the resolved client's registered `frame_ancestors` (the "allow administrators to configure allowed origins for particular clients" SHOULD). Default to `'none'` — a connector like Claude or ChatGPT opens the authorization endpoint in a top-level browser window/tab, never an iframe, so `'none'` is correct for the target deployment.

**Error code.** N/A — response headers.

**Interop trap.** `X-Frame-Options: ALLOW-FROM` — which the RFC's own example shows — **is dead**. Chrome never implemented it and Firefox removed it. If you need per-client framing you must use CSP `frame-ancestors`; `X-Frame-Options` can only be `DENY` or `SAMEORIGIN`. Emitting `ALLOW-FROM` in modern browsers is parsed as an invalid value and, depending on the browser, either ignored (no protection) or treated as `DENY` (breaking your allowlisted client). Emit `X-Frame-Options: DENY` as the legacy fallback and express any allowlist **only** in `frame-ancestors`.

**Second trap.** Set these headers in `OnStarting`, not eagerly — otherwise a downstream handler (Razor Pages, Identity UI) that writes headers later can clobber them, and `Headers["..."] = v` on an already-started response throws.

---

## H-10 — Credential leakage via the `Referer` header

**Attack.** RFC 9700 §4.2. Two directions:
- *From the client:* the page rendered after the authorization response contains a link or third-party resource (ad iframe, image, analytics beacon). The browser sends the full authorization-response URL — containing `code` and `state` — in `Referer` to the third party.
- *From the AS:* the authorization endpoint page contains links or third-party content, leaking `state` (and the whole authorization request) from the AS side. That one is **your** bug.

**Normative.**
> "The page rendered as a result of the OAuth authorization response and the authorization endpoint **SHOULD NOT** include third-party resources or links to external sites." — RFC 9700 §4.2.4
>
> "Suppress the `Referer` header by applying an appropriate Referrer Policy … For example, the header `Referrer-Policy: no-referrer` in the response completely suppresses the `Referer` header in all requests originating from the resulting document." — RFC 9700 §4.2.4
>
> "The `state` value **SHOULD** be invalidated by the client after its first use at the redirection endpoint." — RFC 9700 §4.2.4

**ASP.NET Core.**

1. `Referrer-Policy: no-referrer` on `/authorize`, `/login`, `/consent`, error pages (already in the H-09 middleware).
2. **No third-party origins in the consent/login pages at all.** No CDN fonts, no CDN scripts, no analytics, no external logo hotlinking. Enforce with the CSP from H-09 (`default-src 'self'`) — CSP turns the SHOULD into a mechanical guarantee.
3. Client logos on the consent screen: proxy/cache them on the AS origin, do not `<img src="https://attacker.example/logo.png">`. A remote logo URL supplied via DCR is both a referrer leak and an SSRF vector.

**Error code.** N/A.

**Interop trap.** `Referrer-Policy: no-referrer` on the *client's* callback page is what actually stops code leakage, and you do not control that. What you can control: keep the code short-lived (≤60s), single-use (H-05), and PKCE-bound (H-03) so a leaked code is inert. RFC 9700 §4.2.4 lists exactly this: "Bind the authorization code to a confidential client or PKCE challenge. In this case, the attacker lacks the secret to request the code exchange."

---

## H-11 — Credential leakage via browser history

**Attack.** RFC 9700 §4.3.1: `client.example/redirection_endpoint?code=abcd` lands in the browser's URL history; anyone with device access can read and replay it. §4.3.2: access tokens in query strings do the same, permanently.

**Normative.**
> "Clients **MUST NOT** pass access tokens in a URI query parameter in the way described in Section 2.3 of [RFC6750]. The authorization code grant or alternative OAuth response modes like the form post response mode [OAuth.Post] can be used to this end." — RFC 9700 §4.3.2
>
> Countermeasures for the code case: "Authorization code replay prevention as described in Section 4.4.1.1 of [RFC6819], and Section 4.5. Use the form post response mode instead of redirect for the authorization response (see [OAuth.Post])." — RFC 9700 §4.3.1

**ASP.NET Core.** The code-in-history exposure is intrinsic to the redirect response mode; the mitigation is the code's own weakness budget:

- ≤ 60 second lifetime.
- Single use with atomic CAS + family revocation on reuse (H-05).
- PKCE-bound (H-03) — history gives the attacker the code but not the verifier.
- Support `response_mode=form_post` as an option for clients that want it (the code arrives in a POST body, never in a URL).

**Error code.** N/A on the AS; `invalid_grant` on replay.

**Interop trap.** Do not "fix" this by lengthening code lifetime for slow clients. A 10-minute code plus browser history plus a shared machine is a real account takeover. If clients time out, fix the client.

---

## H-12 — Ban bearer tokens in query strings

**Attack.** Tokens in URLs are logged by every reverse proxy, CDN, load balancer, and application server on the path; they land in browser history; and they leak via `Referer`. RFC 9700 §4.3.2 notes the reality: "[RFC6750] discourages this practice and advises transferring tokens via a header, but in practice websites often pass access tokens in query parameters."

**Normative.**
> "Clients **MUST NOT** pass access tokens in a URI query parameter" — RFC 9700 §4.3.2
>
> RFC 6750 §2.3 (URI Query Parameter) — this method "**SHOULD NOT** be used unless it is impossible to transport the access token in the `Authorization` request header field or the HTTP request entity-body." Clients must send `Cache-Control: no-store`; servers should respond with `Cache-Control: private`.
>
> MCP spec: "MCP client **MUST** use the Authorization request header field … Access tokens **MUST NOT** be included in the URI query string."

**ASP.NET Core.** For the AS itself: never accept a token in a query parameter on any endpoint (introspection, revocation, userinfo).

```csharp
// Reject the RFC 6750 §2.3 form outright, everywhere.
app.Use(async (ctx, next) => {
    if (ctx.Request.Query.ContainsKey("access_token"))
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        ctx.Response.Headers.WWWAuthenticate =
            "Bearer error=\"invalid_request\", error_description=\"Access token must be sent in the Authorization header\"";
        await ctx.Response.WriteAsJsonAsync(new { error = "invalid_request" });
        return;
    }
    await next();
});
```

Also: turn tokens off in logs. ASP.NET Core's `W3CLogger`/HTTP logging can capture query strings and the `Authorization` header — configure `HttpLoggingFields` to exclude `RequestHeaders`/`RequestQuery`, or add a redacting `IHttpLoggingInterceptor`.

**Error code.** `invalid_request`, HTTP `400` (RFC 6750 §3.1).

**RFC 6750 §3.1 status mapping — memorize this table:**

| `error` | HTTP | When |
|---|---|---|
| `invalid_request` | **400** | Missing/repeated parameter, malformed, or *multiple token transmission methods used at once* |
| `invalid_token` | **401** | Expired, revoked, malformed, or otherwise invalid token |
| `insufficient_scope` | **403** | Token valid but lacks required scope; **SHOULD** include a `scope` attribute |

> "When the request lacks any authentication information, the resource server **SHOULD NOT** include an error code or other error information" — i.e. bare `WWW-Authenticate: Bearer realm="example"` with 401, no `error=`.

**Interop trap.** Sending a token in *both* the `Authorization` header and the body/query is `invalid_request` (400), **not** `invalid_token` (401). Getting this backwards makes clients retry-loop on token refresh forever.

---

## H-13 — Refresh token replay: rotation with family revocation

**Attack.** RFC 9700 §4.14: a refresh token stolen from a public client is long-lived and bearer. Without rotation there is no detection signal at all.

**Normative.**
> "Refresh tokens for public clients **MUST** be sender-constrained or use refresh token rotation as described in Section 4.14." — RFC 9700 §2.2.2
>
> "Authorization servers **MUST** determine, based on a risk assessment, whether to issue refresh tokens to a certain client." — RFC 9700 §4.14.2
>
> "If refresh tokens are issued, those refresh tokens **MUST** be bound to the scope and resource servers as consented by the resource owner." — RFC 9700 §4.14.2
>
> "Authorization servers **MUST** utilize one of these methods to detect refresh token replay by malicious actors for public clients:
> * **Sender-constrained refresh tokens:** the authorization server cryptographically binds the refresh token to a certain client instance, e.g., by utilizing [RFC8705] or [RFC9449].
> * **Refresh token rotation:** the authorization server issues a new refresh token with every access token refresh response. The previous refresh token is invalidated, but information about the relationship is retained by the authorization server. If a refresh token is compromised and subsequently used by both the attacker and the legitimate client, one of them will present an invalidated refresh token, which will inform the authorization server of the breach. The authorization server cannot determine which party submitted the invalid refresh token, but **it will revoke the active refresh token**. This stops the attack at the cost of forcing the legitimate client to obtain a fresh authorization grant." — RFC 9700 §4.14.2
>
> "Implementation note: The grant to which a refresh token belongs may be encoded into the refresh token itself. … Authorization servers **MUST** ensure the integrity of the refresh token value in this case, for example, using signatures." — RFC 9700 §4.14.2
>
> "Authorization servers **MAY** revoke refresh tokens automatically in case of a security event, such as: password change or logout at the authorization server." — RFC 9700 §4.14.2
>
> "Refresh tokens **SHOULD** expire if the client has been inactive for some time" — RFC 9700 §4.14.2
>
> RFC 6819 §5.2.2.3: "in case of such an access attempt the valid refresh token **and the access authorization associated with it** are both revoked."

**ASP.NET Core — data model.**

```csharp
public sealed class GrantFamily              // one per authorization code redemption
{
    public Guid   Id { get; init; }
    public string ClientId { get; init; }
    public string Subject { get; init; }
    public string Scope { get; init; }        // consented scope — refresh MUST NOT exceed
    public string[] Resources { get; init; }  // consented audiences — RFC 9700 §4.14.2
    public bool   Revoked { get; set; }
    public DateTimeOffset LastUsedAt { get; set; }   // inactivity expiry
}

public sealed class RefreshToken
{
    public Guid   Id { get; init; }
    public Guid   FamilyId { get; init; }
    public byte[] TokenHash { get; init; }    // SHA-256, never the raw value
    public Guid?  ReplacedById { get; set; }  // rotation chain
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; init; }
}
```

**Rotation, atomically:**

```sql
UPDATE refresh_tokens SET consumed_at = @now
 WHERE token_hash = @hash AND consumed_at IS NULL;
```

- `rowsAffected == 1` → issue a new access token + a **new** refresh token in the same family; bump `LastUsedAt`.
- `rowsAffected == 0` **and the token exists** → **replay detected**. Revoke the entire family: set `GrantFamily.Revoked = true`, delete/consume every refresh token with that `FamilyId`, and revoke all access tokens derived from the family (for JWTs: add `FamilyId` to a denylist checked by introspection, or keep access-token lifetimes short enough — ≤ 5–15 min — that the window is acceptable).
- `rowsAffected == 0` and unknown token → `invalid_grant`.

Run the rotation inside a serializable transaction (or rely on the single-statement CAS) — two concurrent refreshes from a legitimate client that raced must not both succeed and must not both be treated as an attack.

**Error code.** `invalid_grant`, HTTP `400`, in all failure cases (unknown, expired, consumed, family-revoked, wrong client). Never distinguish "replayed" from "unknown" in the response — that is an oracle telling the attacker their token was real.

**Refresh request scope rule (RFC 6749 §6):** the requested `scope` **MUST NOT** exceed the scope of the original grant. Narrower is allowed; wider → `invalid_scope`.

**Interop trap 1 — the mobile/flaky-network false positive.** The legitimate client sends a refresh, the AS rotates and responds, the response is lost in transit. The client retries with the old token → family nuked → user forcibly logged out. Two accepted mitigations: (a) a short **grace window** (e.g. 10–30 s) during which the immediately-preceding token in the chain returns the *same* newly-issued pair idempotently rather than triggering revocation; (b) reuse detection only when the presented token is more than one hop back in the chain. Pick one and document it; without it you will get bug reports that look like security incidents.

**Interop trap 2.** Claude and ChatGPT both hold refresh tokens for long-lived connectors. Family revocation is user-visible as "reconnect your connector". Make sure the resulting error is a clean `invalid_grant` so the client re-runs the authorization flow rather than hard-failing.

---

## H-14 — Access token audience restriction

**Attack.** RFC 9700 §4.9.1 (access token phishing by counterfeit resource server) and §4.10: a token issued for RS-A is replayed at RS-B. Without an audience, every RS that trusts your issuer accepts every token you mint. In an MCP deployment this is the **confused deputy**: a token minted for one MCP server used against another.

**Normative.**
> "access tokens **SHOULD** be audience-restricted to a specific resource server or, if that is not feasible, to a small set of resource servers. … every resource server is obliged to verify, for every request, whether the access token sent with that request was meant to be used for that particular resource server. If it was not, the resource server **MUST** refuse to serve the respective request. The `aud` claim as defined in [RFC9068] **MAY** be used to audience-restrict access tokens. Clients and authorization servers **MAY** utilize the parameters `scope` or `resource` as specified in [RFC6749] and [RFC8707]" — RFC 9700 §2.3
>
> "The privileges associated with an access token **SHOULD** be restricted to the minimum required" — RFC 9700 §2.3
>
> "Authorization servers therefore **SHOULD** ensure that access tokens are sender-constrained and audience-restricted" — RFC 9700 §4.10
>
> "To prevent phishing, it is necessary to use **the actual URL the client will send requests to**." — RFC 9700 §4.10.2
>
> "In deployments where the authorization server knows the URLs of all resource servers, the authorization server may just refuse to issue access tokens for unknown resource server URLs." — RFC 9700 §4.10.2
>
> RFC 8707 §2: "The authorization server **SHOULD** audience-restrict issued access tokens to the resource(s) indicated by the `resource` parameter." Error code: **`invalid_target`** — "The requested resource is invalid, missing, unknown, or malformed."

**MCP makes this mandatory, not optional:**
> "MCP clients **MUST** implement Resource Indicators for OAuth 2.0 as defined in RFC 8707… The `resource` parameter **MUST** be included in both authorization requests and token requests… **MUST** identify the MCP server that the client intends to use the token with."
>
> "MCP servers … **MUST** validate that access tokens were issued specifically for them as the intended audience."
>
> "MCP clients **MUST** send this parameter regardless of whether authorization servers support it."

**ASP.NET Core.**

```csharp
// Accept `resource` (RFC 8707) at BOTH /authorize and /token. May repeat.
// Validate against a registry of known resource identifiers.
var requested = req.Resource;                       // string[] — parameter may appear >1 time
if (requested.Length == 0)
    return TokenError("invalid_target", "resource parameter is required");

foreach (var r in requested)
{
    if (!Uri.TryCreate(r, UriKind.Absolute, out var u)
        || u.Scheme != "https"
        || !string.IsNullOrEmpty(u.Fragment))            // RFC 8707: absolute URI, no fragment
        return TokenError("invalid_target", "malformed resource");

    if (!_resourceRegistry.IsKnown(r))                    // RFC 9700 §4.10.2
        return TokenError("invalid_target", "unknown resource");
}

// Mint a JWT access token per RFC 9068.
var claims = new JwtPayload {
    ["iss"] = _issuer,                                   // exact issuer string (H-07)
    ["aud"] = requested,                                 // the *actual URL* the client calls
    ["sub"] = subject,
    ["client_id"] = clientId,
    ["scope"] = grantedScope,
    ["jti"] = jti, ["iat"] = now, ["exp"] = now + 900,
};
// RFC 9068 REQUIRES this JOSE header — it stops JWT type confusion with ID Tokens:
//   typ: "at+jwt"
```

The `resource` value must survive the whole flow: capture it on the authorization code record, re-check it at `/token`, and require the token-request `resource` (if present) to be a subset of the authorized set.

**Error code.** `invalid_target`, HTTP `400` at the token endpoint; at the authorization endpoint, redirect with `error=invalid_target`.

**Interop trap 1.** The canonical URI rules bite here. MCP requires no fragment and prefers no trailing slash, and both `https://mcp.example.com` and `https://mcp.example.com/` are "technically valid" but must be treated consistently. Normalize on **registration** (store the canonical form once) and compare `Ordinal` at request time. Do not normalize at request time — an AS that quietly rewrites `resource` will mint a token whose `aud` the RS then rejects, and the failure surfaces as an unexplained 401 loop at the MCP server.

**Interop trap 2.** `aud` is `string | string[]` in JWT. Serialize a single audience as a **string**, not a one-element array, unless you have verified the RS's validator handles both. `Microsoft.IdentityModel.Tokens` handles both; many non-.NET validators do not.

**Interop trap 3.** Set the `typ` JOSE header to `at+jwt` (RFC 9068). Without it a resource server can be tricked into accepting an ID Token as an access token.

---

## H-15 — TLS

**Normative.**
> "Authorization responses **MUST NOT** be transmitted over unencrypted network connections. To this end, authorization servers **MUST NOT** allow redirection URIs that use the `http` scheme except for native clients that use loopback interface redirection as described in Section 7.3 of [RFC8252]." — RFC 9700 §2.6
>
> "It is **RECOMMENDED** to use end-to-end TLS according to [BCP195] between the client and the resource server." — RFC 9700 §2.6
>
> RFC 6750 §5: "Clients **MUST** always use TLS (https) or equivalent transport security when making requests with bearer tokens." Clients "**MUST** validate the TLS certificate chain when making requests to protected resources."
>
> RFC 6819 §5.1.2 (countermeasure against "Phishing by counterfeit servers"): "HTTPS server authentication or similar means can be used to authenticate the identity of a server. The goal is to reliably bind the fully qualified domain name of the server to the public key presented by the server."

**ASP.NET Core.**

```csharp
app.UseHsts();                       // Strict-Transport-Security; production only
app.UseHttpsRedirection();
builder.Services.AddHsts(o => {
    o.MaxAge = TimeSpan.FromDays(365);
    o.IncludeSubDomains = true;
    o.Preload = true;
});
```

Redirect URI scheme validation at registration time:

```csharp
static bool IsAllowedRedirectScheme(Uri u, ClientType type) =>
    u.Scheme == "https"
    || (type == ClientType.Native && u.Scheme == "http" && IsLoopback(u))   // RFC 8252 §7.3
    || (type == ClientType.Native && u.Scheme is not "http" and not "https"); // private-use URI scheme

static bool IsLoopback(Uri u) => u.Host is "127.0.0.1" or "[::1]";
```

**Error code.** At DCR: `invalid_redirect_uri` (RFC 7591). At `/authorize`: `400`, no redirect.

**Interop trap.** `localhost` as a *hostname* resolves through DNS and can be hijacked; RFC 8252 §7.3 prefers the literal IPs `127.0.0.1` and `[::1]`. Accept `localhost` for compatibility if you must, but never accept `http://` for anything that is not loopback — including "internal" or "staging" hosts.

---

## H-16 — TLS-terminating reverse proxy header spoofing

**Attack.** RFC 9700 §4.13: "If the reverse proxy passes through any header sent from the outside, an attacker could try to directly send the faked header values through the proxy to the application server in order to circumvent security controls. … it is standard practice of reverse proxies to accept `X-Forwarded-For` headers and just add the origin of the inbound request (making it a list). Depending on the logic performed in the application server, the attacker could simply add an allowed IP address to the header and render the protection useless."

**Normative.**
> "A reverse proxy **MUST** therefore sanitize any inbound requests to ensure the authenticity and integrity of all header values relevant for the security of the application servers." — RFC 9700 §4.13
>
> "the communication link between the reverse proxy and application server **MUST** be protected against eavesdropping, injection, and replay of messages." — RFC 9700 §4.13

**ASP.NET Core.**

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor
                       | ForwardedHeaders.XForwardedProto
                       | ForwardedHeaders.XForwardedHost;
    o.ForwardLimit = 1;                       // exactly one trusted hop
    o.KnownProxies.Clear();
    o.KnownNetworks.Clear();
    o.KnownProxies.Add(IPAddress.Parse("10.0.1.7"));   // your ingress, explicitly
});
app.UseForwardedHeaders();                    // FIRST in the pipeline
```

**Interop trap — the classic.** Every "my app behind nginx/Traefik/Azure Front Door doesn't see HTTPS" StackOverflow answer says to clear `KnownProxies` and `KnownNetworks` *and stop there*. Clearing them without adding your proxy back makes the middleware trust `X-Forwarded-*` from **anyone**, and an attacker can then forge `X-Forwarded-Proto: https` (defeating `UseHttpsRedirection`), forge `X-Forwarded-For` (defeating IP allowlists and rate limiting, H-18), and forge `X-Forwarded-Host` (rewriting your issuer if you derive it from the request — see H-07 trap 3). Always re-add the specific proxy address. Note the defaults are loopback-only, which is why it "doesn't work" in containers — the fix is the explicit address, not the empty allowlist.

**Second trap.** Never derive `issuer`, `iss`, metadata endpoint URLs, or the JWT `aud` from `HttpContext.Request.Host` / `.Scheme`. Use configured constants. This holds even with `UseForwardedHeaders` configured correctly — defence in depth against a proxy misconfiguration.

---

## H-17 — Ban the Resource Owner Password Credentials grant

**Normative.**
> "The resource owner password credentials grant [RFC6749] **MUST NOT** be used. This grant type insecurely exposes the credentials of the resource owner to the client. Even if the client is benign, usage of this grant results in an increased attack surface (i.e., credentials can leak in more places than just the authorization server) and in training users to enter their credentials in places other than the authorization server. Furthermore, the resource owner password credentials grant is not designed to work with two-factor authentication and authentication processes that require multiple user interaction steps." — RFC 9700 §2.4

**ASP.NET Core.** Do not implement `grant_type=password`. Do not list it in `grant_types_supported`. Reject at DCR if a client requests it.

**Error code.** `unsupported_grant_type`, HTTP `400`.

**Related — implicit grant.** RFC 9700 §2.1.2: "clients **SHOULD NOT** use the implicit grant (response type `token`) or other response types issuing access tokens in the authorization response". Do not implement `response_type=token` or `response_type=id_token token`. Advertise `"response_types_supported": ["code"]`. Return `unsupported_response_type` for anything else.

---

## H-18 — Client authentication

**Normative.**
> "Authorization servers **SHOULD** enforce client authentication if it is feasible, in the particular deployment, to establish a process for issuance/registration of credentials for clients and ensuring the confidentiality of those credentials." — RFC 9700 §2.5
>
> "It is **RECOMMENDED** to use asymmetric cryptography for client authentication, such as mutual TLS for OAuth 2.0 [RFC8705] or signed JWTs ('Private Key JWT') in accordance with [RFC7521] and [RFC7523]. … When asymmetric cryptography for client authentication is used, authorization servers do not need to store sensitive symmetric keys, making these methods more robust against leakage of keys." — RFC 9700 §2.5

**ASP.NET Core.** Support, in priority order:

| Method | `token_endpoint_auth_method` | Notes |
|---|---|---|
| Private key JWT | `private_key_jwt` | RECOMMENDED. Validate `iss`=`sub`=`client_id`, `aud`, `exp`, `jti` replay cache |
| mTLS | `tls_client_auth` / `self_signed_tls_client_auth` | RFC 8705 |
| Client secret POST | `client_secret_post` | store secrets **hashed** (PBKDF2/Argon2), compare `FixedTimeEquals` |
| Client secret Basic | `client_secret_basic` | same; note the RFC 6749 §2.3.1 `x-www-form-urlencoded` escaping rule |
| None | `none` | public clients only — **PKCE mandatory** |

Claude and ChatGPT connectors register as **public clients** (`none` + PKCE) or receive a secret via DCR/pre-registration. Support `none` properly; do not require a secret.

**Error code.** `invalid_client`. Status per RFC 6749 §5.2: "The authorization server **MAY** return an HTTP 401 (Unauthorized) status code… If the client attempted to authenticate via the `Authorization` request header field, the authorization server **MUST** respond with an HTTP 401 (Unauthorized) status code and include the `WWW-Authenticate` response header field matching the authentication scheme used by the client."

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="token_endpoint"
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_client"}
```

Otherwise (secret in the body) → `400` + `{"error":"invalid_client"}`.

**Interop trap.** `client_secret_basic` requires the client id and secret to be `application/x-www-form-urlencoded`-encoded *before* base64 (RFC 6749 §2.3.1). Many clients skip this. Accept both the encoded and raw forms on decode, but emit encoded. Also: a request may present credentials **both** in the header and the body — that is `invalid_request`, not `invalid_client`.

---

## H-19 — CORS: allowed on some endpoints, forbidden on `/authorize`

**Normative.**
> "To support browser-based clients, endpoints directly accessed by such clients including the Token Endpoint, Authorization Server Metadata Endpoint, `jwks_uri` Endpoint, and Dynamic Client Registration Endpoint **MAY** support the use of Cross-Origin Resource Sharing (CORS). However, **CORS MUST NOT be supported at the authorization endpoint**, as the client does not access this endpoint directly; instead, the client redirects the user agent to it." — RFC 9700 §2.6

**ASP.NET Core.**

```csharp
builder.Services.AddCors(o => o.AddPolicy("oauth-public", p => p
    .AllowAnyOrigin()          // public, unauthenticated endpoints only
    .WithMethods("GET", "POST")
    .WithHeaders("Content-Type", "Authorization", "DPoP")));

app.MapPost("/token",    Token).RequireCors("oauth-public");
app.MapGet("/jwks",      Jwks).RequireCors("oauth-public");
app.MapGet("/.well-known/oauth-authorization-server", Meta).RequireCors("oauth-public");
app.MapPost("/register", Register).RequireCors("oauth-public");

app.MapGet("/authorize", Authorize);        // NO .RequireCors — and no global CORS policy
```

**Interop trap.** Do not register a *global* CORS policy via `app.UseCors(policy)` — it applies to `/authorize` too and violates the MUST NOT. Use per-endpoint `RequireCors`. Also: `AllowAnyOrigin()` cannot be combined with `AllowCredentials()`; these endpoints are cookie-free by design, so that is correct — but if you add `AllowCredentials` you have created a cross-origin credential leak.

---

## H-20 — Client impersonating a resource owner (`client_id` / `sub` collision)

**Attack.** RFC 9700 §4.15: with `client_credentials`, RFC 9068 puts the `client_id` in `sub`. If client IDs and user IDs share a namespace, a client registering `client_id` = an existing user's identifier gets a token that a resource server reads as that user.

**Normative.**
> "Authorization servers **SHOULD NOT** allow clients to influence their `client_id` or any other claim that could cause confusion with a genuine resource owner if a common namespace for client IDs and user identifiers exists… Where this cannot be avoided, authorization servers **MUST** provide other means for the resource server to distinguish between the two types of access tokens." — RFC 9700 §4.15.1 / §2.6

**ASP.NET Core.**

```csharp
// DCR: the AS generates the client_id. The client NEVER supplies it.
var clientId = "c_" + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(24));
```

Prefix-separate the namespaces (`c_` for clients, `u_` for users) **and** emit a distinguishing claim on client-credentials tokens so an RS can tell them apart regardless:

```json
{ "sub": "c_9f3...", "client_id": "c_9f3...", "act_type": "client" }
```

RFC 9068 also lets you rely on the absence of user-only claims, but an explicit marker is more robust.

**Error code.** DCR: `invalid_client_metadata` (RFC 7591) if a client tries to specify `client_id`.

**Note — Client ID Metadata Documents (CIMD).** Both Claude and ChatGPT now support CIMD, where `client_id` is an **HTTPS URL** supplied by the client. That deliberately lets the client choose its own `client_id`. The §4.15.1 requirement still applies: since CIMD client IDs are URLs and user identifiers are not, the namespaces are naturally disjoint — but you must *enforce* that user identifiers can never be URL-shaped, and validate the CIMD URL (https, no fragment, fetched over TLS, size-capped, SSRF-guarded — no redirects to internal addresses).

---

## H-21 — Authorization server phishing

**Attack.** RFC 6819 §4.2.1: "Wide deployment of OAuth and similar protocols may cause users to become inured to the practice of being redirected to web sites where they are asked to enter their passwords. If users are not careful to verify the authenticity of these web sites before entering their credentials, it will be possible for attackers to exploit this practice to steal users' passwords."

Compounding it: RFC 9700 §4.11.2 (H-02) turns your *own* trusted domain into the launch pad, and RFC 9700 §4.16 (H-09) lets an attacker overlay a fake password field on your real page.

**Normative.**
> "Authorization servers should consider such attacks when developing services based on OAuth and should require the use of transport-layer security for any requests where the authenticity of the authorization server or of request responses is an issue (see Section 5.1.2)." — RFC 6819 §4.2.1
>
> "Authorization servers should attempt to educate users about the risks posed by phishing attacks and should provide mechanisms that make it easy for users to confirm the authenticity of their sites." — RFC 6819 §4.2.1
>
> RFC 6819 §5.1.3: "The user should always be in control of the authorization processes and get the necessary information to make informed decisions." Note the warning: "notifications can be a phishing vector. Messages should be such that look-alike phishing messages cannot be derived from them."

**ASP.NET Core — concrete controls.**

1. **Stable, short, memorable AS origin.** One hostname, never per-tenant subdomains that users cannot distinguish. HSTS preload (H-15).
2. **Never render a password field inside an iframe** — H-09's `frame-ancestors 'none'` is the enforcement.
3. **Kill the phishing value of passwords entirely.** Passkeys / WebAuthn are origin-bound: a phishing site on another origin cannot produce a valid assertion. This is the only countermeasure that actually solves §4.2.1 rather than mitigating it. `Fido2NetLib` on ASP.NET Core 9; make WebAuthn the primary factor, password the fallback.
4. **Consent screen must show what is verifiable**, not what the client claims. Display the exact registered `redirect_uri` origin and the client's registration provenance (pre-registered / CIMD URL / dynamically registered). For DCR clients, label them: "This application registered itself automatically and has not been verified."
5. **No third-party content on login/consent** (H-10) — an injected script is a credential harvester.
6. `autocomplete="current-password"`, `autocomplete="username"` so password managers bind to your origin; a password manager that refuses to autofill is a real phishing signal for users.

**Error code.** N/A — design controls.

**Interop trap.** For an MCP connector AS, the DCR/CIMD path means *anyone* can become a registered client. Do not let the consent screen render attacker-supplied `client_name` or `logo_uri` as if it were trustworthy. HTML-encode all client metadata (Razor does this by default — do **not** use `@Html.Raw`), cap lengths, proxy logos, and visually separate "what the client told us" from "what we verified."

---

## H-22 — Miscellaneous mandatory behaviours

| # | Requirement | Source | Implementation |
|---|---|---|---|
| a | Publish AS metadata | RFC 9700 §2.6 (**RECOMMENDED**); MCP (**MUST** provide RFC 8414 *or* OIDC Discovery) | `GET /.well-known/oauth-authorization-server` **and** `/.well-known/openid-configuration` |
| b | `Cache-Control: no-store` on token/PAR/introspection responses | RFC 6749 §5.1, RFC 9126 §2.2 | `ctx.Response.Headers.CacheControl = "no-store"` |
| c | Codes ≤ 60 s, single use | RFC 6749 §4.1.2, RFC 9700 §4.2.4 | H-05 |
| d | Access tokens short-lived | RFC 6750 §5.1 ("one hour or less") | 5–15 min |
| e | Sender-constrain access tokens | RFC 9700 §2.2.1 (**SHOULD**) | mTLS (RFC 8705) or DPoP (RFC 9449) — see Part 3 |
| f | High-entropy tokens | RFC 6819 §5.1.4.2.2 | `RandomNumberGenerator.GetBytes(32)` — never `Random`/`Guid.NewGuid()` |
| g | Store only hashes of codes/refresh tokens | RFC 6819 §5.1.4.1.3 | SHA-256 at rest |
| h | Sign self-contained tokens | RFC 6819 §5.1.5.9 | ES256 or RS256; publish `jwks_uri`; rotate keys |
| i | Rate-limit token/PAR/DCR endpoints | RFC 9126 §2.3 (429) | `builder.Services.AddRateLimiter(...)` — key on `client_id` **and** validated remote IP (H-16) |

---

## Error code registry (complete, with status codes)

### Authorization endpoint — RFC 6749 §4.1.2.1 (delivered as a redirect with `error=`)

| `error` | Meaning |
|---|---|
| `invalid_request` | Missing/duplicated/malformed parameter |
| `unauthorized_client` | Client not permitted this `response_type` |
| `access_denied` | Resource owner or AS denied the request |
| `unsupported_response_type` | AS does not support obtaining a code this way |
| `invalid_scope` | Scope invalid, unknown, or malformed |
| `server_error` | "because a 500 Internal Server Error HTTP status code cannot be returned to the client via an HTTP redirect" |
| `temporarily_unavailable` | "because a 503 Service Unavailable HTTP status code cannot be returned to the client via an HTTP redirect" |
| `invalid_target` | RFC 8707 — resource invalid/missing/unknown/malformed |
| `login_required`, `consent_required`, `interaction_required`, `account_selection_required` | OIDC Core, for `prompt=none` |

**Every one of these redirects MUST also carry `state` (if supplied) and `iss` (RFC 9207).**

### Token endpoint — RFC 6749 §5.2

| `error` | HTTP |
|---|---|
| `invalid_request` | 400 |
| `invalid_client` | **401** if the client used the `Authorization` header (with matching `WWW-Authenticate`), else 400 |
| `invalid_grant` | 400 |
| `unauthorized_client` | 400 |
| `unsupported_grant_type` | 400 |
| `invalid_scope` | 400 |
| `invalid_target` (RFC 8707) | 400 |
| `invalid_dpop_proof` (RFC 9449) | 400 |
| `use_dpop_nonce` (RFC 9449) | 400 + `DPoP-Nonce` header |

### Resource server — RFC 6750 §3.1

| `error` | HTTP |
|---|---|
| `invalid_request` | 400 |
| `invalid_token` | 401 |
| `insufficient_scope` | 403 |

### PAR endpoint — RFC 9126 §2.3

| Condition | HTTP | `error` |
|---|---|---|
| Bad/missing/mismatched `redirect_uri` (no redirect permitted) | 400 | `invalid_request` (the specified default) |
| `request_uri` present in the pushed request | 400 | `invalid_request` |
| Client auth failed | 401/400 | `invalid_client` |
| Non-POST method | **405** | — |
| Body over the size limit | **413** | — |
| Rate limit exceeded | **429** | — |

> "Since initial processing of the pushed authorization request does not involve resource owner interaction, error codes related to user interaction, such as `consent_required` defined by [OIDC], are never returned." — RFC 9126 §2.3

### DCR — RFC 7591 §3.2.2

`invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement` — all HTTP `400`.

---

## Discovery metadata — fields this AS must emit

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "jwks_uri": "https://auth.example.com/jwks",
  "registration_endpoint": "https://auth.example.com/register",
  "revocation_endpoint": "https://auth.example.com/revoke",
  "introspection_endpoint": "https://auth.example.com/introspect",
  "scopes_supported": ["openid", "profile", "offline_access"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "token_endpoint_auth_methods_supported":
    ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,

  "pushed_authorization_request_endpoint": "https://auth.example.com/par",
  "require_pushed_authorization_requests": false,

  "dpop_signing_alg_values_supported": ["ES256", "RS256"]
}
```

| Field | Defined in | Required by |
|---|---|---|
| `code_challenge_methods_supported` | RFC 7636 / RFC 8414 | RFC 9700 §2.1.1 + §4.7.1 (**MUST** provide *a* way to detect PKCE support; metadata is RECOMMENDED) |
| `authorization_response_iss_parameter_supported` | RFC 9207 §3 | **MUST** be `true` if you emit `iss` |
| `pushed_authorization_request_endpoint` | RFC 9126 §5 | SHOULD, if PAR supported |
| `require_pushed_authorization_requests` | RFC 9126 §5 | default `false` |
| `dpop_signing_alg_values_supported` | RFC 9449 §5.1 | if DPoP supported |

---

# Part 2 — RFC 9126: Pushed Authorization Requests (PAR)

## What it adds

The client POSTs the authorization request parameters **directly to the AS, back-channel and authenticated**, and receives an opaque one-time `request_uri`. The browser-visible authorization URL then contains only `client_id` and `request_uri`. Consequences:

- Request parameters never traverse the browser → no tampering, no leakage via `Referer`/history, no URL length limits.
- The AS validates the request **before** any user interaction (fail fast, before the login screen).
- The AS knows the request is authentic, which unlocks a relaxation: RFC 9700 §4.1.3 — "If the origin and integrity of the authorization request containing the redirection URI can be verified, for example, when using [RFC9101] or [RFC9126] **with client authentication**, the authorization server **MAY** trust the redirection URI without further checks."

## Endpoint and parameters

**Request** — RFC 9126 §2.1:

```
POST /as/par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code&state=af0ifjsldkj&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
&code_challenge=K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U
&code_challenge_method=S256&scope=account-information
```

- Method: **POST only** (405 otherwise). Content type: `application/x-www-form-urlencoded`, UTF-8. Endpoint URL **MUST** use `https`.
- Carries every parameter the authorization endpoint would take, **plus** `client_id` (required — "as a required authorization request parameter, it is similarly required in a pushed authorization request").
- Client authentication: "The rules for client authentication as defined in [RFC6749] for token endpoint requests, including the applicable authentication methods, apply for the PAR endpoint as well."
- **`request_uri` MUST NOT be provided** in the pushed request.

**Processing — RFC 9126 §2.1, verbatim:**
> "The authorization server **MUST** process the request as follows:
> 1. Authenticate the client in the same way as at the token endpoint (Section 2.3 of [RFC6749]).
> 2. Reject the request if the `request_uri` authorization request parameter is provided.
> 3. Validate the pushed request as it would an authorization request sent to the authorization endpoint. … The authorization server **MAY** omit validation steps that it is unable to perform when processing the pushed request; however, such checks **MUST** then be performed when processing the authorization request at the authorization endpoint."

**Success — RFC 9126 §2.2:**
> "If the verification is successful, the server **MUST** generate a request URI and provide it in the response with a `201` HTTP status code."

```
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-cache, no-store

{
 "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
 "expires_in": 60
}
```

| Field | Type | Rule |
|---|---|---|
| `request_uri` | string | "single-use reference"; "**MUST** contain some part generated using a cryptographically strong pseudorandom algorithm such that it is computationally infeasible to predict or guess a valid value"; "**MUST** be bound to the client that posted the authorization request"; AS **MAY** use the form `urn:ietf:params:oauth:request_uri:<reference-value>` |
| `expires_in` | number | "lifetime of the request URI in seconds as a positive integer… typically be relatively short (e.g., between 5 and 600 seconds)" |

**Subsequent authorization request — RFC 9126 §4:**

```
GET /authorize?client_id=s6BhdRkqt3
  &request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A6esc_11ACC5bwc014ltc14eY22c HTTP/1.1
Host: as.example.com
```

> "the client **MUST** only use a `request_uri` value once."
> "Authorization servers **SHOULD** treat `request_uri` values as one-time use but **MAY** allow for duplicate requests due to a user reloading/refreshing their user agent."
> "An expired `request_uri` **MUST** be rejected as invalid."
> "The authorization server **MUST** validate authorization requests arising from a pushed request as it would any other authorization request."

**Security — RFC 9126 §7:**
> §7.1: "The authorization server **MUST** account for the considerations given in JAR [RFC9101], Section 10.2, clause (d) on request URI entropy."
> §7.2: "The authorization server **MUST** only accept new redirect URIs in the pushed authorization request from authenticated clients."
> §7.3: "the authorization server **SHOULD** make the request URIs one-time use."

**Client-assertion audience — RFC 9126 §2:**
> "the issuer identifier URL of the authorization server according to [RFC8414] **SHOULD** be used as the value of the audience", and "the authorization server **MUST** accept its issuer identifier, token endpoint URL, or pushed authorization request endpoint URL as values that identify it as an intended audience."

## Metadata

| Parameter | Where | Type | Default |
|---|---|---|---|
| `pushed_authorization_request_endpoint` | AS metadata (RFC 8414) | URI | — |
| `require_pushed_authorization_requests` | AS metadata | boolean | `false` |
| `require_pushed_authorization_requests` | Client metadata (RFC 7591) | boolean | `false` |

> "the presence of `pushed_authorization_request_endpoint` is sufficient for a client to determine that it may use the PAR flow."

If `require_pushed_authorization_requests` is `true`, the AS "will refuse, using the `invalid_request` error code, to process any request to the authorization endpoint that does not have a `request_uri` parameter with a value obtained from the PAR endpoint."

## ASP.NET Core sketch

```csharp
app.MapPost("/par", async (HttpContext ctx, IParStore store, IClientAuth auth) =>
{
    // 405 handled by routing: only MapPost is registered for /par.
    var form = await ctx.Request.ReadFormAsync();

    var client = await auth.AuthenticateAsync(ctx, form);          // step 1
    if (client is null) return ParError(401, "invalid_client");

    if (form.ContainsKey("request_uri"))                            // step 2
        return ParError(400, "invalid_request", "request_uri must not be provided");

    var v = ValidateAuthorizationRequest(form, client);             // step 3 (reuse /authorize logic)
    if (!v.Ok) return ParError(400, v.Error!, v.Description);

    var reference = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));  // §7.1 entropy
    var requestUri = $"urn:ietf:params:oauth:request_uri:{reference}";
    await store.SaveAsync(requestUri, client.ClientId, form, TimeSpan.FromSeconds(60));

    ctx.Response.Headers.CacheControl = "no-cache, no-store";
    return Results.Json(new { request_uri = requestUri, expires_in = 60 },
                        statusCode: StatusCodes.Status201Created);
})
.RequireCors("oauth-public")
.WithMetadata(new RequestSizeLimitAttribute(64 * 1024))   // → 413 beyond this
.RequireRateLimiting("par");                              // → 429
```

At `/authorize`, when `request_uri` is present: look it up, verify **not expired**, verify **bound to the presented `client_id`**, atomically consume it, and treat the stored form as the authorization request — ignoring every other query parameter the browser supplied.

## Interop traps

1. **201, not 200.** Strict clients check the status code.
2. **Bind `request_uri` to the client.** Without that check, client A can consume client B's pushed request.
3. **Consume atomically** — the same CAS pattern as authorization codes (H-05).
4. **`request_uri` in a PAR request must be rejected**, or you have built an SSRF/parameter-confusion primitive.
5. **The `request_uri` in the browser URL is attacker-visible.** 32 bytes of CSPRNG entropy minimum; §7.1 makes this a MUST.

---

# Part 3 — RFC 9449: DPoP (Demonstrating Proof of Possession)

## What it adds

Application-layer **sender-constraining**. The client generates a key pair, sends the public key in a per-request signed JWT (the "DPoP proof"), and the AS binds the issued access token to the JWK thumbprint. A stolen token is then useless without the private key. It is the RFC 9700 §2.2.1 "SHOULD" countermeasure that does not require mTLS infrastructure.

## The DPoP proof JWT — RFC 9449 §4.2

**JOSE header:**

| Field | Rule |
|---|---|
| `typ` | "A field with the value `dpop+jwt`" |
| `alg` | "an identifier for a JWS asymmetric digital signature algorithm… It **MUST NOT** be `none` or an identifier for a symmetric algorithm" |
| `jwk` | "the public key chosen by the client, in JSON Web Key (JWK) format… It **MUST NOT** contain a private key" |

**Payload claims:**

| Claim | Rule |
|---|---|
| `jti` | "Unique identifier for the DPoP proof JWT. The value **MUST** be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof" |
| `htm` | "The value of the HTTP method… of the request to which the JWT is attached" |
| `htu` | "The HTTP target URI… of the request to which the JWT is attached, **without query and fragment parts**" |
| `iat` | "Creation timestamp of the JWT" |
| `ath` | Required when presenting an access token: "the result of a base64url encoding the SHA-256 hash of the ASCII encoding of the associated access token's value" |
| `nonce` | "A recent nonce provided via the `DPoP-Nonce` HTTP header" — required when the server has issued one |

```json
{ "jti":"-BwC3ESc6acc2lTc", "htm":"POST",
  "htu":"https://server.example.com/token", "iat":1562262616 }
```

## Wire format

Token request:
```
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwiandr...

grant_type=authorization_code&client_id=s6BhdRkqt&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb&code_verifier=bEaL42izcC-...
```

Token response — RFC 9449 §5: "A `token_type` of `DPoP` **MUST** be included in the access token response":
```json
{ "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
  "token_type": "DPoP", "expires_in": 2677,
  "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g" }
```

Resource request — RFC 9449 §7.1 (note the **`DPoP` auth scheme**, not `Bearer`):
```
Authorization: DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Ii...
```

Confirmation claim — RFC 9449 §6.1: "The `jkt` member **MUST** be the base64url encoding of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key":
```json
{ "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } }
```
Introspection response carries "the same `cnf` content with `jkt` member structure" (§6.2).

## Server-side validation — RFC 9449 §4.3 (all MUST; "may be performed in any order")

1. There is not more than one `DPoP` HTTP request header field.
2. The header value is a single and well-formed JWT.
3. All required claims per §4.2 are present.
4. `typ` has the value `dpop+jwt`.
5. `alg` indicates a registered asymmetric digital signature algorithm, is not `none`, is supported, and is acceptable per local policy.
6. The JWT signature verifies with the public key in the `jwk` header.
7. The `jwk` header does not contain a private key.
8. `htm` matches the HTTP method of the current request.
9. `htu` matches the request URI, **ignoring query and fragment**.
10. If the server provided a nonce, `nonce` matches it.
11. `iat` (or a server-managed timestamp via the nonce) is within an acceptable window.
12. If presented with an access token: `ath` equals the hash of that access token, **and** the public key bound to the access token matches the DPoP proof's key.

## Nonce — RFC 9449 §8

> "An authorization server **MAY** supply a nonce value… the authorization server responds to requests that do not include a nonce with an HTTP **400** (Bad Request) error response… using `use_dpop_nonce` as the error code value. The authorization server includes a `DPoP-Nonce` HTTP header in the response supplying a nonce value… **Nonce values MUST be unpredictable.** … there **MUST NOT** be more than one `DPoP-Nonce` header."

```
HTTP/1.1 400 Bad Request
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v

{ "error": "use_dpop_nonce",
  "error_description": "Authorization server requires nonce in DPoP proof" }
```

More efficiently (§8.2), a fresh nonce may ride along on a `200`:
```
HTTP/1.1 200 OK
Cache-Control: no-store
DPoP-Nonce: eyJ7S_zG.eyJbYu3.xQmBj-1
```

## `WWW-Authenticate` challenges (resource server) — RFC 9449 §7.1

Scheme name is `DPoP`. `realm` MAY be included, `scope` MAY be included, `error` SHOULD be included, and "an `algs` parameter **SHOULD** be included to signal acceptable JWS algorithms".

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP algs="ES256 PS256"
```
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"
```
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
```

## Status codes and error strings

| Code | HTTP | Emitted by | When |
|---|---|---|---|
| `invalid_dpop_proof` | **400** (AS) / 401 (RS) | AS token endpoint per RFC 6749 §5.2 | "If the DPoP proof is invalid" |
| `use_dpop_nonce` | **400** (AS) / **401** (RS) | with `DPoP-Nonce` header | nonce missing or mismatched |
| `invalid_token` | 401 | RS | DPoP key binding failure |

## Code binding and refresh tokens

**`dpop_jkt` authorization request parameter — RFC 9449 §10:**
> "The value of the `dpop_jkt` authorization request parameter is the JWK Thumbprint [RFC7638] of the proof-of-possession public key using the SHA-256 hash function, which is the same value as used for the `jkt` confirmation method."
>
> "When a token request is received, the authorization server computes the JWK Thumbprint of the proof-of-possession public key in the DPoP proof and verifies that it matches the `dpop_jkt` parameter value in the authorization request. If they do not match, it **MUST** reject the request."
>
> "Use of the `dpop_jkt` authorization request parameter is **OPTIONAL**."

**Refresh tokens — RFC 9449 §5:**
> "When an authorization server supporting DPoP issues a refresh token to a **public client** that presents a valid DPoP proof at the token endpoint, the refresh token **MUST** be bound to the respective public key. The binding **MUST** be validated when the refresh token is later presented to get new access tokens."

This is one of the two ways to satisfy RFC 9700 §2.2.2 (H-13) — sender-constraining instead of rotation.

## Metadata

| Parameter | Where | Meaning |
|---|---|---|
| `dpop_signing_alg_values_supported` | AS metadata (§5.1) | JSON array of supported JWS `alg` values for DPoP proofs |
| `dpop_bound_access_tokens` | Client metadata (§5.2), boolean, default `false` | "If the value is true, the authorization server **MUST** reject token requests from the client that do not contain the DPoP header." |

## ASP.NET Core notes

- `Microsoft.IdentityModel.JsonWebTokens` (`JsonWebTokenHandler`) parses the proof; validate `typ` yourself — the standard validation parameters do not check `typ`.
- Compute the RFC 7638 thumbprint from the **canonical** JWK: for EC, the members `crv`, `kty`, `x`, `y` in lexicographic order, no whitespace; for RSA, `e`, `kty`, `n`. `JsonWebKey.ComputeJwkThumbprint()` does this in `Microsoft.IdentityModel.Tokens`.
- `htu` comparison: strip query and fragment, then compare `Ordinal`. Behind a proxy, build the expected `htu` from the **configured** public base URL, not `Request.GetDisplayUrl()` (H-16).
- `jti` replay cache: `IDistributedCache` keyed `dpop:{jkt}:{jti}` with TTL equal to your `iat` acceptance window.
- Reject `alg` values not on an explicit allowlist (`ES256`, `ES384`, `PS256`, `RS256`); explicitly reject `none` and all HMAC (`HS*`) algorithms.

## Interop traps

1. **`token_type` is `DPoP`, not `Bearer`** — in both the token response and the `Authorization` header. A client that sends `Authorization: Bearer <dpop-token>` must be rejected.
2. **`htu` excludes query and fragment.** Including the query string is the most common DPoP bug.
3. **`ath` is over the ASCII bytes of the access token string**, base64url, unpadded — the same encoding discipline as PKCE (H-03).
4. **Nonce is a two-round-trip protocol.** If you require nonces, every client's first request gets a 400. Clients that do not implement the retry break outright. Do not enable nonce requirement unless you have verified client support.
5. **Never accept a `jwk` containing private key material** (§4.3 step 7) — a client that leaks its own `d` parameter must be rejected, not silently accepted.

---

# Recommendation for v1

## Summary

| Spec | v1? | Reasoning |
|---|---|---|
| PKCE S256, mandatory for all clients | ✅ **Required** | RFC 9700 §2.1.1 MUST; OAuth 2.1 MUST; MCP requires it. Mandating universally also eliminates the H-04 downgrade class by construction. |
| `iss` in every authorization response (RFC 9207) | ✅ **Required** | RFC 9700 §2.1; MCP SHOULD, explicitly slated to become MUST. Roughly 20 lines of code. Cheap now, breaking later. |
| Exact redirect URI matching | ✅ **Required** | RFC 9700 §2.1 MUST. |
| 303 after the credential POST | ✅ **Required** | RFC 9700 §4.12 MUST NOT use 307. |
| CSP `frame-ancestors` + `X-Frame-Options: DENY` | ✅ **Required** | RFC 9700 §4.16: "Authorization servers MUST prevent clickjacking attacks." |
| Refresh token rotation + family revocation | ✅ **Required** | RFC 9700 §2.2.2 MUST for public clients — and Claude/ChatGPT connectors are public clients. |
| `resource` (RFC 8707) + `aud` restriction | ✅ **Required** | MCP: clients **MUST** send `resource`; MCP servers **MUST** validate audience. This is the confused-deputy defence. |
| RFC 8414 + RFC 9728 metadata | ✅ **Required** | MCP: AS **MUST** provide RFC 8414 *or* OIDC Discovery. Provide both. |
| DCR (RFC 7591) + CIMD | ✅ **Required** | See below. |
| **PAR (RFC 9126)** | ⚠️ **Defer — but build the seam** | See below. |
| **DPoP (RFC 9449)** | ❌ **Defer** | See below. |
| mTLS client auth (RFC 8705) | ❌ Defer | No consumer-connector demand. |

## PAR: defer to v1.1, but do not architect it out

**What Claude and ChatGPT require today: neither requires PAR.** The MCP authorization specification does not mention RFC 9126 anywhere in its list of standards, its flow diagram, or its normative requirements. Neither vendor's connector client sends a `request_uri`. Advertising `pushed_authorization_request_endpoint` is harmless — but advertising `require_pushed_authorization_requests: true` would **break both clients immediately**.

Why implement it in v1.1 rather than never:

- It is the smallest of the three specs — one endpoint, one store, ~150 lines given that step 3 reuses the `/authorize` validation you already wrote.
- The "Auth0 replacement, reusable across customer projects" goal is where it pays: FAPI 2.0 **requires** PAR, and any regulated customer (open banking, health, gov) will ask for it. Shipping it later into an AS that was not designed for it means retrofitting the authorization endpoint's parameter-source abstraction.
- **Architect for it now:** make `/authorize` read its parameters through an `IAuthorizationRequestSource` abstraction with a `QueryStringSource` implementation in v1. Adding `ParRequestUriSource` in v1.1 is then additive, not surgical. This is the one place where deferring PAR can cost you real rework, and the mitigation is a single interface.

## DPoP: defer

**What Claude and ChatGPT require today: neither requires DPoP.** RFC 9449 does not appear in the MCP specification's standards list. Both clients send `Authorization: Bearer <token>`; the MCP spec mandates exactly that ("MCP client **MUST** use the Authorization request header field… `Authorization: Bearer <access-token>`"). An AS that issued `token_type: DPoP` to these clients would break them — they would not attach a proof, and the resource server would reject every call.

RFC 9700 §2.2.1 makes sender-constraining a **SHOULD**, not a MUST, and §2.2.2's MUST for public-client refresh tokens offers rotation as the fully compliant alternative. **Refresh token rotation with family revocation (H-13) discharges the only hard obligation.**

DPoP is also the largest of the three by implementation cost: proof parsing, thumbprint canonicalization, a distributed `jti` replay cache, nonce issuance and rotation, `ath` binding, `dpop_jkt` code binding, refresh-token key binding, and a parallel `DPoP` auth scheme on every resource server that trusts you. That is a meaningful fraction of the AS budget spent on something no target client will exercise.

Defer, and revisit when a customer's threat model actually calls for it — a browser-based SPA holding tokens in JS, or a regulated deployment. Two cheap things to do now so that later is not painful:

1. Keep the access-token minting path pluggable so a `cnf`/`jkt` claim can be injected without restructuring.
2. Advertise nothing DPoP-related in metadata until it is real — an advertised `dpop_signing_alg_values_supported` invites clients to try DPoP against an AS that will reject their proofs.

## One nuance on client registration

The MCP draft has moved: DCR is now "**MAY** support… Note that Dynamic Client Registration is **deprecated** and retained for backwards compatibility with authorization servers that do not support Client ID Metadata Documents", while CIMD is "**SHOULD** support". ChatGPT supports CIMD, DCR, pre-registered clients, and PKCE. Implement **both** CIMD and DCR for v1 — CIMD as the preferred path, DCR for compatibility. CIMD also sidesteps the RFC 9700 §4.11.2 open-redirector-via-DCR problem somewhat, because the `client_id` is a URL you can fetch, attribute, and reputation-check.

CIMD security requirements when fetching the `client_id` URL: `https` only, no fragment, response size cap, timeout, **no redirects to private/link-local addresses** (SSRF), cache with a TTL, and validate that every `redirect_uri` in the fetched document shares the registrable domain of the `client_id` URL.

---

## Source URLs

- RFC 9700 — https://www.rfc-editor.org/rfc/rfc9700.txt
- RFC 6819 — https://www.rfc-editor.org/rfc/rfc6819.txt
- RFC 9207 — https://www.rfc-editor.org/rfc/rfc9207.txt
- RFC 9126 — https://www.rfc-editor.org/rfc/rfc9126.txt
- RFC 9449 — https://www.rfc-editor.org/rfc/rfc9449.txt
- RFC 6750 — https://www.rfc-editor.org/rfc/rfc6750.txt
- RFC 8707 — https://www.rfc-editor.org/rfc/rfc8707.txt
- RFC 6749 — https://www.rfc-editor.org/rfc/rfc6749.txt
- MCP Authorization (draft) — https://modelcontextprotocol.io/specification/draft/basic/authorization
