# Proposal A — Security-First Architecture

**Boltway Authorization Server** · OAuth 2.1 + OIDC, from scratch, `net10.0`
Target repo: `/home/user/Boltway/auth/` (ground already pinned in `Directory.Build.props`,
`Directory.Packages.props`, `global.json`, `.editorconfig` — commit `83feebf`).

Requirement IDs cite `research/REQUIREMENTS.md`. §10 of that document wins on conflict with §6/§9.

---

## 0. The thesis, stated once

The sixteen `N-nn` rows are the ones where being wrong is a vulnerability. Every one of them is
currently phrased as *"do X"* — a rule a person must remember. This architecture converts as many as
possible into *"¬X does not compile"* or *"¬X does not link"*.

Three mechanisms, in descending order of strength:

| Strength | Mechanism | Can a junior developer defeat it by accident? | Can a hostile developer defeat it deliberately? |
|---|---|---|---|
| 1 | **No code path exists** — the dangerous operation has no reachable API, because the type it would need cannot be constructed | No | Only by adding a new type |
| 2 | **Build fails** — Cecil architecture test over the compiled IL, run in CI as a test | No | Only by editing the rule file (visible in review) |
| 3 | **Compile fails** — `BannedApiAnalyzers` + `TreatWarningsAsErrors` | No | Yes, `#pragma warning disable` (visible in review; and mechanism 2 backstops it) |

The mapping is deliberate: analyzers are for *ergonomics* (you learn at keystroke time), Cecil is the
*authority* (a `#pragma` cannot reach it). Where both are available I use both.

Coverage of the sixteen:

| N | Enforced by | Mechanism |
|---|---|---|
| N-01 `aud` bound to validated resource | `AccessTokenDescriptor.Audience` is a non-nullable `ResourceIdentifier`, obtainable **only** from `IResourceRegistry` | 1 |
| N-02 PKCE S256 mandatory, XOR check | `AuthorizationCodeRecord` has no nullable challenge; the XOR is the only comparison API | 1 + test |
| N-03 ordinal redirect match, no `System.Uri` | Matcher type contains zero references to `System.Uri` — the parse happens in the value object's factory | 1 + 2 + 3 |
| N-04 loopback port exception | Separate code branch, three host **string** literals, no `IPAddress` involved | 1 + test matrix |
| N-05 SSRF-hardened fetcher | `System.Net.Http` is unreferenceable outside `Boltway.Oidc.Net` | 2 |
| N-06 advertised == actual | Metadata keys and route registration come from the **same** `IServerCapability` object; startup walks `EndpointDataSource` and asserts | 1 + startup assert |
| N-07 code replay: validate-then-revoke | `IAuthorizationCodeStore.TryRedeemAsync` returns rows-affected; validation order is a typed stage pipeline | 1 + test |
| N-08 refresh rotation + grace | `RedeemAsync` returns a closed 4-case result; the decision lives *inside* the store where the atomicity is | 1 + test |
| N-09 `typ`/`alg` pinned | `newobj TokenValidationParameters` banned outside one factory | 2 |
| N-10 ID-token `aud` ≠ access-token `aud` | Different C# types (`ClientId` vs `ResourceIdentifier`) | 1 |
| N-11 `/authorize` ordering | `AuthorizeRedirectError.Create` **requires** a `ValidatedRedirect`, which only stage 3 can mint | 1 |
| N-12 303 not 307/308 | `Results.Redirect*` banned; literals 307/308 banned in `Server`/`Server.Ui` | 2 + 3 |
| N-13 one immutable issuer | `HttpRequest.get_Host`/`get_Scheme`/`GetDisplayUrl` banned in `Server`; all URLs from `EndpointUrls(Issuer)` | 2 + 3 |
| N-14 consent shows `client_id` host | `ConsentViewModel` has no field for a self-asserted name *without* its origin host | 1 + test |
| N-15 clickjacking headers | `Response.OnStarting` middleware; test over all user-facing routes | test |
| N-16 hashed secrets, FixedTimeEquals | No entity has a `string` secret property (asserted over `IModel`); `SecretHash.Matches` is the only comparison API | 1 + 2 |

Everything below serves that table.

---

## 1. Assembly split

### 1.1 The graph

```
                       Boltway.Oidc.Primitives          (no deps beyond BCL)
                        │            │            │
        ┌───────────────┘            │            └────────────────┐
        ▼                            ▼                             ▼
Boltway.Oidc.Net      Boltway.Oidc.Abstractions   Boltway.Oidc.ResourceServer
        │  (SSRF fetcher)             │  (seams, records)          │  (bearer + PRM middleware)
        │                             │                            │
        │        ┌────────────────────┴──────────────┐             │
        │        ▼                                   ▼             │
        └──►  Boltway.Oidc.Server   Boltway.Oidc.Storage.EntityFrameworkCore
                 │        │                     │              │
                 │        │                     ▼              ▼
                 │        │            …EntityFrameworkCore.Sqlite   …PostgreSql
                 │        │
                 │        └──► Boltway.Oidc.Server.Ui   (RCL: Razor login/consent/error/logout)
                 │
                 └──► Boltway.Oidc.Federation.Google
                      Boltway.Oidc.Storage.InMemory
```

`Boltway.Oidc.ResourceServer` deliberately does **not** reference `Abstractions` or `Server`.
That is the reuse boundary the Boltway playbook needs: it is the C# analogue of
`mcp-server/core/` in FictStoryEngine, and the same one-directional rule applies.

### 1.2 Every project

| Project | Contains | References | Why the boundary is here |
|---|---|---|---|
| **`Boltway.Oidc.Primitives`** | Value objects (`Issuer`, `ClientId`, `RegisteredRedirectUri`, `RequestedRedirectUri`, `ScopeName`, `ScopeSet`, `ResourceIdentifier`, `SubjectId`, `GrantId`, `SecretHash`, `OpaqueSecret`), the redirect matcher, the error table, `Base64Url`, `MediaType` | BCL only | **The `BannedApiAnalyzers` ban list is per-project.** Putting the matcher here means `Uri.AbsoluteUri`/`Uri.AbsolutePath`/`Uri.Equals`/`Uri.ToString`/`Uri.IdnHost`/`Uri.DnsSafeHost`/`Uri.op_Equality` can be banned *project-wide* without collateral damage — no other file here has a legitimate reason to call them. This is the N-03 enforcement scope, not a taste decision. It is also the only assembly both the AS and the RS need, so it must have zero framework deps. |
| **`Boltway.Oidc.Net`** | `ISafeHttpFetcher`, `SafeHttpFetcher`, `SpecialUseAddressTable` (RFC 6890, S-29), `AbsoluteHttpsUrl` | Primitives | **N-05 is an assembly-scoped claim.** A Cecil rule bans any reference to `System.Net.Http.*` / `System.Net.WebRequest` from every other Boltway assembly. That claim is only checkable if there is exactly one assembly it is allowed in. The exception list is **empty** — Google federation and RS `jwks_uri` fetching both route through this fetcher. |
| **`Boltway.Oidc.Abstractions`** | Every seam interface, every DTO/record they exchange, `ClientRecord`/`GrantRecord`/etc. as POCOs | Primitives | **Deliberately has no ASP.NET Core reference.** The client-authentication seam takes a transport-neutral `ClientAuthenticationContext` (dictionaries) rather than `HttpContext`, so a customer can unit-test a `private_key_jwt` variant without a web host, and so `Storage.*` never drags in the web stack. |
| **`Boltway.Oidc.Server`** | Endpoints, the two pipelines, CIMD resolution, token minting, metadata generation, capabilities, options, admin schema | Primitives, Net, Abstractions, ASP.NET Core, `Microsoft.IdentityModel.*` | The AS proper. Ban scope for N-12 (307/308), N-13 (`Request.Host`), and `[FromBody]`. |
| **`Boltway.Oidc.Server.Ui`** | Razor Class Library: `/login`, `/consent`, `/error`, `/logout` + their view models | Server | Separate assembly so a customer can `RemoveAll<IUiProvider>()` and ship their own brand without forking. Also a second ban scope for 307/308 — Razor `RedirectToPage` is exactly where a 302/307 sneaks back in. |
| **`Boltway.Oidc.Storage.EntityFrameworkCore`** | `OidcDbContext`, entity configurations, store implementations, the conditional-`UPDATE` redemption logic | Abstractions, `EFCore.Relational` | Provider-agnostic. Contains no provider package reference — that is what keeps "runs on SQLite and PostgreSQL" true rather than aspirational. |
| **`…EntityFrameworkCore.Sqlite`** / **`…PostgreSql`** | Migrations assembly + `IProviderModelCustomization` (collation, column types) | the above + one provider package | EF migrations bake provider SQL; two assemblies is forced. The collation fix (§3.6) also lives here. |
| **`Boltway.Oidc.Storage.InMemory`** | Non-persistent store, same test suite | Abstractions | Ships in the box — customers need it for their own tests, and the shared store conformance suite (§7.3) is what proves the three implementations agree. |
| **`Boltway.Oidc.Federation.Google`** | `GoogleOidcProvider : IExternalIdentityProvider` | Abstractions, Net, `Authentication.OpenIdConnect` | The reference implementation of the federation seam (D-10). Adding Facebook/GitHub is a copy of this project. Kept out of `Server` so "Google is not special" is structurally true. |
| **`Boltway.Oidc.ResourceServer`** | Bearer middleware, `TokenValidationParametersFactory` (the only one, N-09), `WwwAuthenticateBuilder` (S-31), PRM publication (E-22/E-23) | Primitives, Net, ASP.NET Core, `Microsoft.IdentityModel.*` | **The reuse deliverable.** See §1.3. |
| `tools/Boltway.Oidc.Analyzers` | Roslyn analyzers CK1001–CK1006 | `Microsoft.CodeAnalysis.CSharp` | Optional ergonomics layer; Cecil is the authority. |
| `samples/Boltway.Oidc.Sample.Host` | Runnable AS + a toy MCP resource server | everything | The target of `scripts/preflight.sh` (§7.6). |

### 1.3 The customer who only wants the resource-server middleware

They take **three** packages:

```xml
<PackageReference Include="Boltway.Oidc.ResourceServer" />
<!-- transitively: Boltway.Oidc.Primitives, Boltway.Oidc.Net -->
```

and write:

```csharp
builder.Services.AddBoltwayResourceServer(o =>
{
    o.Resource   = "https://mcp.example.com/mcp";       // RFC 9728 §2, A-22 — a path is fine
    o.Authority  = "https://auth.example.com";          // first entry of authorization_servers, C-27
    o.Scopes     = ["mcp:tools", "story:read", "story:write"];   // NO offline_access — C-22
    o.ResourceName = "FictStory MCP";
});
app.UseBoltwayResourceServer();   // maps E-22, E-23; installs bearer validation
```

They get: `at+jwt` validation with `ValidTypes`/`ValidAlgorithms` pinned (N-09), `aud` compared to
`o.Resource` byte-exactly (N-01, A-22), both PRM well-known shapes (C-26/U-01), and the
`WWW-Authenticate` builder that quotes correctly and always emits `error`+`error_description`
(X-32..X-35, C-25). No EF Core, no Razor, no `Abstractions`, no AS.

Rejected alternative: one fat `Boltway.Oidc` package with everything. It would make the
RS customer take EF Core and Razor, and — decisively — it would destroy the per-project ban scopes
that N-03 and N-05 depend on.

---

## 2. Folder and namespace layout

Namespace tracks folder exactly. `file_scoped` namespaces are already an error in `.editorconfig`.

```
auth/
├── Boltway.Auth.slnx
├── Directory.Build.props            (pinned)
├── Directory.Packages.props         (pinned — see §9.1 for additions)
├── global.json                      (pinned: SDK 10.0.302)
├── spec/
│   ├── draft-ietf-oauth-v2-1-15.txt                     (pinned, U-15)
│   ├── draft-ietf-oauth-client-id-metadata-document-02.txt (pinned, U-16)
│   ├── REQUIREMENTS.md              ← copied in; the coverage test parses this file
│   └── cimd-live-2026-08-03.json    ← the four live documents; replayed as tests
│
├── src/
│   ├── Boltway.Oidc.Primitives/
│   │   ├── BannedSymbols.txt                    ← N-03 ban list, project-scoped
│   │   ├── Issuer.cs
│   │   ├── ClientId.cs                          ← A-18: UrlSafeToken, ClientIdKind
│   │   ├── SubjectId.cs   GrantId.cs
│   │   ├── Redirects/
│   │   │   ├── RegisteredRedirectUri.cs         ← normalize-at-registration (N-03)
│   │   │   ├── RequestedRedirectUri.cs          ← parse-at-request, freeze to strings
│   │   │   ├── RedirectUriMatcher.cs            ← ZERO System.Uri references (N-03, N-04)
│   │   │   └── RedirectMatch.cs
│   │   ├── Scopes/  ScopeName.cs  ScopeSet.cs                (A-13)
│   │   ├── Resources/ ResourceIdentifier.cs  ResourceKey.cs   (N-01, §2 "compare loosely")
│   │   ├── Secrets/ OpaqueSecret.cs  SecretHash.cs  TokenPurpose.cs   (N-16)
│   │   ├── Errors/
│   │   │   ├── OAuthErrorCode.cs                ← closed enum, 25 members
│   │   │   ├── OAuthSurface.cs                  ← 7 members
│   │   │   └── OAuthErrors.cs                   ← THE table: (Surface,Code) → wire/status/delivery/X-nn
│   │   └── Encoding/ Base64Url.cs  MediaType.cs
│   │
│   ├── Boltway.Oidc.Net/
│   │   ├── AbsoluteHttpsUrl.cs
│   │   ├── ISafeHttpFetcher.cs   FetchOutcome.cs   FetchPurpose.cs
│   │   ├── SafeHttpFetcher.cs                   ← the ONE HttpClient (N-05)
│   │   ├── SpecialUseAddressTable.cs            ← RFC 6890 v4+v6 + multicast (S-29)
│   │   └── Internal/ PinnedConnectCallback.cs   IAddressResolver.cs
│   │
│   ├── Boltway.Oidc.Abstractions/
│   │   ├── Clients/    IClientStore.cs  IClientResolver.cs  ClientRecord.cs
│   │   ├── Auth/       IClientAuthenticator.cs  ClientAuthenticationContext.cs
│   │   ├── Identity/   IExternalIdentityProvider.cs  ISubjectIdentifierService.cs
│   │   │               IUserStore.cs  IPasswordHasher.cs
│   │   ├── Tokens/     IAccessTokenFormat.cs  IIdentityTokenFormat.cs
│   │   │               IRefreshTokenStore.cs  IAuthorizationCodeStore.cs
│   │   │               IGrantStore.cs  IRevocationList.cs  IClaimsMapper.cs  ClaimSink.cs
│   │   ├── Consent/    IConsentStore.cs  IConsentPolicy.cs
│   │   ├── Requests/   IAuthorizationRequestSource.cs        (D-01 seam)
│   │   ├── Resources/  IResourceRegistry.cs
│   │   └── Keys/       ISigningKeyStore.cs  SigningKey.cs
│   │
│   ├── Boltway.Oidc.Server/
│   │   ├── BannedSymbols.txt                    ← N-12, N-13, [FromBody]
│   │   ├── BoltwayServerBuilderExtensions.cs
│   │   ├── Capabilities/
│   │   │   ├── IServerCapability.cs
│   │   │   ├── CoreCapability.cs   CimdCapability.cs   DcrCapability.cs
│   │   │   ├── OidcCapability.cs   LogoutCapability.cs  JwtBearerGrantCapability.cs
│   │   │   └── CapabilityConflictException.cs   ← N-06 boot failure
│   │   ├── Metadata/
│   │   │   ├── MetadataBuilder.cs               ← no API that can emit [] (S-34)
│   │   │   ├── AuthorizationServerMetadata.cs
│   │   │   ├── MetadataEndpoints.cs             ← E-01..E-06, byte-identical bodies (A-21)
│   │   │   ├── JwksEndpoint.cs                  ← E-07, public params only (S-24, N-16)
│   │   │   └── EndpointUrls.cs                  ← the only place a URL is built (N-13)
│   │   ├── Authorize/
│   │   │   ├── AuthorizeEndpoint.cs             ← E-08; maps GET+POST, no CORS
│   │   │   ├── AuthorizePipeline.cs             ← the ordered stage list (N-11)
│   │   │   ├── AuthorizeContext.cs
│   │   │   ├── ValidatedRedirect.cs             ← the capability token
│   │   │   ├── AuthorizeHtmlError.cs            ← X-01, X-02, X-03
│   │   │   ├── AuthorizeRedirectError.cs        ← X-04..X-16; ctor REQUIRES ValidatedRedirect
│   │   │   └── Stages/
│   │   │       ├── S01_MethodAndParameters.cs   ├── S07_Resource.cs
│   │   │       ├── S02_ClientResolution.cs      ├── S08_OidcParameters.cs
│   │   │       ├── S03_RedirectValidation.cs    ├── S09_Authentication.cs
│   │   │       ├── S04_ResponseType.cs          ├── S10_Consent.cs
│   │   │       ├── S05_Pkce.cs                  ├── S11_CodeIssuance.cs
│   │   │       ├── S06_Scope.cs                 └── S12_Response.cs
│   │   ├── Token/
│   │   │   ├── TokenEndpoint.cs                 ← E-10; Request.Form only
│   │   │   ├── TokenPipeline.cs
│   │   │   ├── GrantRequest.cs                  ← sealed hierarchy (CS8509 exhaustiveness)
│   │   │   ├── GrantTypeTable.cs                ← string → enum, table-driven (D-04)
│   │   │   ├── TokenEndpointResult.cs           ← always writes Cache-Control: no-store
│   │   │   ├── Handlers/ AuthorizationCodeGrantHandler.cs  RefreshTokenGrantHandler.cs
│   │   │   │             ClientCredentialsGrantHandler.cs  JwtBearerGrantHandler.cs
│   │   │   └── Authentication/ NoneAuthenticator.cs  ClientSecretBasicAuthenticator.cs
│   │   │                       ClientSecretPostAuthenticator.cs  PrivateKeyJwtAuthenticator.cs
│   │   │                       ClientAuthenticationDispatcher.cs   ← "exactly one" rule (X-17)
│   │   ├── Cimd/
│   │   │   ├── CimdClientResolver.cs            ← S-16, A-07
│   │   │   ├── CimdDocument.cs                  ← reads BOTH auth-method spellings (C-04)
│   │   │   ├── CimdValidator.cs                 ← §4.1/§4.2 rules, U-17 same-origin+loopback-exempt
│   │   │   └── CimdCache.cs                     ← S-30 clamp 300..86400, never cache errors
│   │   ├── Registration/  RegisterEndpoint.cs  RegistrationManagementEndpoints.cs  (E-11..E-14)
│   │   ├── Introspection/ IntrospectEndpoint.cs  RevokeEndpoint.cs                 (E-15, E-16)
│   │   ├── UserInfo/      UserInfoEndpoint.cs                                      (E-17)
│   │   ├── Tokens/
│   │   │   ├── JwtAccessTokenFormat.cs          ← typ: at+jwt (N-09), aud from ResourceIdentifier
│   │   │   ├── JwtIdentityTokenFormat.cs        ← typ: JWT, aud = ClientId (N-10)
│   │   │   ├── OpaqueSecretGenerator.cs         ← RandomNumberGenerator, ≥256 bits (N-16)
│   │   │   └── SigningKeyRing.cs
│   │   ├── Security/ SecurityHeadersMiddleware.cs  Antiforgery.cs  SeeOtherResult.cs  (N-15, N-12)
│   │   ├── Options/  ServerOptions.cs  CimdOptions.cs  TokenLifetimeOptions.cs
│   │   │              ConfigSchema/ ConfigKeyAttribute.cs  ConfigSchemaBuilder.cs   (A-17)
│   │   └── Admin/    ConfigSchemaEndpoint.cs                                        (E-21)
│   │
│   ├── Boltway.Oidc.Server.Ui/            (BannedSymbols.txt: RedirectToPage*, 307/308)
│   ├── Boltway.Oidc.Storage.EntityFrameworkCore/
│   ├── Boltway.Oidc.Storage.EntityFrameworkCore.Sqlite/
│   ├── Boltway.Oidc.Storage.EntityFrameworkCore.PostgreSql/
│   ├── Boltway.Oidc.Storage.InMemory/
│   ├── Boltway.Oidc.Federation.Google/
│   └── Boltway.Oidc.ResourceServer/
│
├── tests/
│   ├── Boltway.Oidc.Architecture.Tests/   ← Mono.Cecil; N-03, N-05, N-09, N-12, N-13, N-16
│   ├── Boltway.Oidc.Primitives.Tests/     ← the 16-row redirect matrix, PKCE App. B vector
│   ├── Boltway.Oidc.Net.Tests/            ← SSRF matrix
│   ├── Boltway.Oidc.Storage.Tests/        ← one suite × 3 providers
│   ├── Boltway.Oidc.Conformance.Tests/    ← 170 binding IDs, WebApplicationFactory
│   ├── Boltway.Oidc.Interop.Tests/        ← replays cimd-live-2026-08-03.json
│   └── Boltway.Oidc.Traceability.Tests/   ← spec ↔ [Covers] reconciliation
│
├── tools/Boltway.Oidc.Analyzers/
├── samples/Boltway.Oidc.Sample.Host/
└── scripts/preflight.sh                        ← the five Appendix commands
```

---

## 3. The domain model

### 3.1 Value objects (the load-bearing part)

**`RegisteredRedirectUri` / `RequestedRedirectUri` — N-03 and N-04.**

The research sketch (`pkce-and-native-apps.md` §2.4) parses `Uri` *inside* the matcher. I reject
that: it leaves `System.Uri` reachable from the comparison function, so the only available guard is
"don't call the wrong member". Instead, both value types parse **once at construction** and freeze
the results into `string` fields. The matcher then has no reason to reference `System.Uri` at all,
and a Cecil rule can assert that as an absolute.

```csharp
namespace Boltway.Oidc.Primitives.Redirects;

/// <summary>A redirect URI as stored against a client. Normalized at registration (N-03).</summary>
public readonly struct RegisteredRedirectUri : IEquatable<RegisteredRedirectUri>
{
    /// <summary>The canonical raw string. This — and only this — is the comparison input.</summary>
    public string Value { get; }

    // Frozen at construction so the matcher never parses.
    internal bool   IsLoopback   { get; }   // scheme=="http" && host ∈ {127.0.0.1, ::1, localhost}
    internal string Host         { get; }   // Uri.Host form: "::1" without brackets
    internal string EscapedPath  { get; }   // GetComponents(Path,  UriEscaped)
    internal string EscapedQuery { get; }   // GetComponents(Query, UriEscaped)

    private RegisteredRedirectUri(string v, bool lb, string h, string p, string q) { … }

    /// <summary>The only constructor. Lowercases scheme and host; rejects everything else.</summary>
    public static bool TryRegister(string raw, out RegisteredRedirectUri result,
                                   out RedirectRegistrationError error);

    public bool Equals(RegisteredRedirectUri other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);
}
```

`TryRegister` rejects: non-absolute; fragment present (RFC 6749 §3.1.2); userinfo present; scheme
not in {`https`, `http`-with-loopback-host, a configured private-use scheme with a `.` per RFC 8252
§7.1}; port `0` or out of 1–65535; length over cap. It *rewrites* scheme and host to lowercase and
stores the rewritten string — normalize on write, compare exactly on read (A-13/A-19/A-22).

`RequestedRedirectUri.TryParse` is the mirror, and does **not** rewrite: a request that arrives with
`https://Claude.ai/...` fails to match a registration for `https://claude.ai/...`, which is correct
Simple String Comparison (`pkce…md` §2.4 trap 13).

```csharp
public static class RedirectUriMatcher
{
    private static readonly FrozenSet<string> LoopbackHosts =
        FrozenSet.ToFrozenSet(["127.0.0.1", "::1", "localhost"], StringComparer.Ordinal);

    public static RedirectMatch Match(in RequestedRedirectUri requested,
                                      IReadOnlyList<RegisteredRedirectUri> registered)
    {
        // Step 1 — RFC 3986 §6.2.1 Simple String Comparison. The only path for HTTPS clients.
        for (var i = 0; i < registered.Count; i++)
            if (string.Equals(requested.Value, registered[i].Value, StringComparison.Ordinal))
                return RedirectMatch.Exact(registered[i]);

        // Step 2 — RFC 8252 §7.3 loopback port exception. Visibly separate branch (N-04).
        if (!requested.IsLoopback) return RedirectMatch.None;
        for (var i = 0; i < registered.Count; i++)
        {
            ref readonly var r = ref …;
            if (!r.IsLoopback) continue;
            if (string.Equals(requested.Host,         r.Host,         StringComparison.Ordinal)
             && string.Equals(requested.EscapedPath,  r.EscapedPath,  StringComparison.Ordinal)
             && string.Equals(requested.EscapedQuery, r.EscapedQuery, StringComparison.Ordinal))
                return RedirectMatch.LoopbackPortIgnored(r);
        }
        return RedirectMatch.None;
    }
}
```

Every identifier in that file is a `string` or a `bool`. `BannedSymbols.txt` in `Primitives` covers
the value-object factories; the Cecil rule covers the matcher absolutely (§7.4).

**`ClientId` — A-18, C-01.**

```csharp
public readonly struct ClientId : IEquatable<ClientId>
{
    public string        Value        { get; }  // "https://claude.ai/oauth/mcp-oauth-client-metadata"
    public ClientIdKind  Kind         { get; }  // Cimd | Dynamic | PreRegistered — STORED, never re-derived (C-01)
    public string        StorageKey   { get; }  // == Value; the DB primary key, COLLATE "C"
    /// <summary>base64url(SHA-256(Value)). The only form permitted in a route, cache key,
    /// filename or log-file path (A-18: CIMD ids contain ':' and '/').</summary>
    public string        UrlSafeToken { get; }

    public static ClientId ForCimd(AbsoluteHttpsUrl url);
    public static ClientId ForDynamic(string generated);
    public static ClientId ForPreRegistered(string configured);
    public static bool TryParseFromRequest(string raw, out ClientId id, out OAuthErrorCode err);
}
```

There is no `ClientId(string)` constructor: you must state the kind. `RegistrationManagementEndpoints`
routes on `{urlSafeToken}`, never on `{clientId}` — so A-18 has no path traversal to defend.

**`ResourceIdentifier` — N-01, "compare loosely, emit strictly".**

```csharp
public sealed class ResourceIdentifier
{
    /// <summary>Exactly the registered string. This is what goes in `aud`. Never Uri.ToString().</summary>
    public string     Canonical { get; }
    internal ResourceKey Key    { get; }   // internal: cannot be emitted from another assembly

    private ResourceIdentifier(string canonical, ResourceKey key) { … }
    /// <summary>Only callable by IResourceRegistry implementations.</summary>
    public static ResourceIdentifier Register(string canonical, out ResourceRegistrationError e);
}

public readonly record struct ResourceKey   // lookup only; `Value` is internal
{
    internal string Value { get; }
    /// <summary>RFC 3986 §6.2.2–6.2.3 syntax normalization. Returns false on fragment,
    /// non-https, unparseable. Trailing slash tolerated on input, never invented on output.</summary>
    public static bool TryFromRequest(string raw, out ResourceKey key);
}
```

The chain `raw string → ResourceKey → IResourceRegistry.Resolve → ResourceIdentifier? → aud` is the
whole of N-01. `Resolve` returning `null` is `invalid_target` (X-09/X-23), and there is no other
way to get a `ResourceIdentifier`, so "accept and ignore" and "stamp a house default" are both
unreachable. The configured default (A-02) is itself resolved through the registry at startup and is
consulted **only** on the `resource`-absent branch, with a warning log.

**`OpaqueSecret` / `SecretHash` — N-16.**

```csharp
public enum TokenPurpose { AuthorizationCode, RefreshToken, RegistrationAccessToken, ClientSecret }

public readonly struct OpaqueSecret
{
    public TokenPurpose Purpose { get; }
    public string Wire { get; }        // "ck_ac_…" | "ck_rt_…" | "ck_rat_…" | "ck_cs_…"
    /// <summary>256 bits from RandomNumberGenerator. CA5394 makes Random an error.</summary>
    public static OpaqueSecret Generate(TokenPurpose purpose);
    /// <summary>Rejects a wire value whose prefix does not match `expected` BEFORE hashing.</summary>
    public static bool TryParse(string wire, TokenPurpose expected, out OpaqueSecret s);
}

public readonly struct SecretHash
{
    public byte[] Value { get; }                       // SHA-256; the only thing persisted
    public static SecretHash Of(in OpaqueSecret s);
    public bool Matches(in OpaqueSecret s) =>          // the ONLY comparison API
        CryptographicOperations.FixedTimeEquals(Value, SHA256.HashData(…));
}
```

The prefix-before-hash check is why a registration access token can never be valid at `/token`:
`IRefreshTokenStore.RedeemAsync` takes an `OpaqueSecret` that `TryParse(..., TokenPurpose.RefreshToken, ...)`
produced, and a `ck_rat_` value never gets that far.

**Rejected:** making the plaintext a `ref struct` so the compiler forbids storing it in a field. It
is the strongest possible guarantee and it does not survive `await` — the mint path must carry the
plaintext into a JSON response across at least one async boundary. See §8.1.

### 3.2 Entities

Instants are `DateTimeOffset` in the model, `long` (Unix ms, UTC) in every database. See §3.5.

```
users                 id (SubjectId) · email · email_verified · password_hash(bytea/BLOB, Argon2id)
                      · password_updated_at · status · created_at · updated_at
external_identities   upstream_issuer · upstream_subject · user_id     -- PK(issuer, subject); D-10
                      -- exists from day one with one row per user; local `sub` is never passed through

clients               client_id(PK, COLLATE "C") · kind(int: Cimd|Dynamic|PreRegistered) · client_type(Public|Confidential)
                      · client_name · client_uri · logo_uri · logo_blob(bytea)   -- N-14: proxied, never hotlinked
                      · grant_types(int flags) · response_types(int flags)
                      · token_endpoint_auth_method(int) · jwks_uri · jwks_json(text)
                      · registration_access_token_hash(bytea) · created_at · last_seen_at
                      · cimd_fetched_at · cimd_etag        -- CIMD rows are cache, not registration (A-08)
client_redirect_uris  client_id · value(COLLATE "C") · is_loopback   -- PK(client_id, value)
client_scopes         client_id · scope
resources             canonical(PK, COLLATE "C") · lookup_key(UNIQUE, COLLATE "C") · name · created_at
resource_scopes       resource_canonical · scope · description        -- A-14: verbatim consent text

grants                grant_id(PK) · client_id · subject · scopes(text, space-delimited wire form)
                      · auth_time · acr · amr · status(int) · revoked_reason(int?)
                      · created_at · last_used_at · absolute_expires_at
grant_resources       grant_id · resource_canonical                   -- the RFC 8707 grant set

authorization_codes   code_hash(PK, bytea) · grant_id · client_id · redirect_uri_used
                      · code_challenge · code_challenge_method(int) · pkce_was_requested(bool)   -- N-02
                      · nonce · scopes · resources · issued_at · expires_at · redeemed_at(nullable)
                      -- rows are RETAINED past redemption until expires_at, so N-07 step 2a is possible

refresh_tokens        token_hash(PK, bytea) · grant_id · generation(int) · predecessor_hash(bytea?)
                      · issued_at · expires_at · consumed_at(nullable)  -- never deleted while grant alive
revoked_grants        grant_id(PK) · revoked_at · reason               -- the access-token denylist (N-08 cascade)
consents              subject · client_id · scopes · resources · granted_at · updated_at  -- PK(subject, client_id)
signing_keys          kid(PK) · alg(int) · public_jwk(text) · private_key(bytea, DataProtection-wrapped)
                      · state(int: Pending|Active|Retiring|Retired) · not_before · not_after
jti_replay            jti(PK) · client_id · expires_at                 -- private_key_jwt replay (X-18)
```

Notably absent: any `string` column named `*_token`, `*_secret`, `*_password`. Asserted over
EF's `IModel` in the architecture tests, not by grepping source.

### 3.3 Grant/response type sets without arrays

```csharp
[Flags] public enum GrantTypeFlags { None=0, AuthorizationCode=1, RefreshToken=2,
                                     ClientCredentials=4, JwtBearer=8 }
[Flags] public enum ResponseTypeFlags { None=0, Code=1 }
```

Stored as `int`. Portable, indexable, no array support required, and C-14 ("never reject a document
for declaring a grant we haven't enabled — validate per request") falls out: the CIMD parser maps
unknown grant strings to nothing and the per-request check is `client.GrantTypes.HasFlag(...)`.

### 3.4 Scopes as their own wire format

`grants.scopes` and `consents.scopes` store `ScopeSet.ToWireString()` — the space-delimited,
sorted, validated form. The database column and the `scope` claim (RFC 9068 §2.2.3, a **string**)
are the same bytes. No JSON, no array, no join, no serializer.

### 3.5 The DateTimeOffset problem

SQLite has no native `DateTimeOffset`; EF's SQLite provider stores it as TEXT and the ordering is
lexicographic-on-a-formatted-string, which silently misbehaves across offsets. PostgreSQL has
`timestamptz` with different semantics again. Rather than paper over the difference:

```csharp
// Boltway.Oidc.Storage.EntityFrameworkCore/OidcDbContext.cs
protected override void ConfigureConventions(ModelConfigurationBuilder b)
{
    b.Properties<DateTimeOffset>().HaveConversion<UnixMillisecondsConverter>();
    b.Properties<DateTimeOffset?>().HaveConversion<NullableUnixMillisecondsConverter>();
}

public sealed class UnixMillisecondsConverter()
    : ValueConverter<DateTimeOffset, long>(
        v => v.ToUnixTimeMilliseconds(),
        v => DateTimeOffset.FromUnixTimeMilliseconds(v));
```

Every instant is a `bigint`/`INTEGER` on both providers. Comparison and ordering are integer
operations with identical semantics; `WHERE expires_at < @now` translates and indexes on both. It
also matches RFC 7519 NumericDate, so the token minter and the database agree on what "now" is.

Cost: no server-side date functions. We need none. Rejected: `HasColumnType("timestamptz")` with a
SQLite-specific override — it makes the two providers behave differently under exactly the
conditions (clock skew, DST) where you least want a surprise.

### 3.6 Collation — the cross-provider trap worth naming

PostgreSQL's default collation may be non-deterministic (ICU). Under a non-deterministic collation,
`=` is **not** byte equality: `'straße' = 'strasse'` can be true. Every identifier comparison in this
system is required by RFC 3986 §6.2.1 to be byte-exact — and a widened `client_id` or
`redirect_uri` lookup is precisely N-03's failure mode arriving through the database instead of
through C#.

```csharp
// Boltway.Oidc.Storage.EntityFrameworkCore.PostgreSql/PostgreSqlModelCustomization.cs
foreach (var p in IdentifierColumns)          // client_id, redirect value, resource canonical/key, kid, jti
    p.SetCollation("C");                       // byte-exact, deterministic
```

SQLite's default `BINARY` collation is already byte-exact — the rule is *never* declare
`COLLATE NOCASE`, and `EF.Functions.Like`/`StartsWith` are banned in the storage project because
SQLite's `LIKE` is ASCII-case-insensitive by default.

A test in `Storage.Tests` runs `WHERE client_id = 'ABC'` against a row `'abc'` on every provider and
asserts zero rows. Rejected alternative: store a `SHA-256` lookup column and never compare text at
all. Fully collation-proof, and real ceremony on every read path — one `SetCollation` line plus one
test buys the same guarantee.

### 3.7 Atomicity — N-07 and N-08

Both redemptions are conditional `UPDATE`s whose rows-affected is the authority. `ExecuteUpdateAsync`
translates on both providers and bypasses the change tracker, so the check cannot be lost in a
`SaveChanges` batch.

```csharp
// Authorization code — N-07. Full validation has ALREADY passed before this is called.
var rows = await db.AuthorizationCodes
    .Where(c => c.CodeHash == hash && c.RedeemedAt == null)
    .ExecuteUpdateAsync(s => s.SetProperty(c => c.RedeemedAt, now), ct);
return rows == 1;   // false ⇒ replay ⇒ caller revokes the grant (only now)

// Refresh token — N-08, inside an explicit transaction.
await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
var rows = await db.RefreshTokens
    .Where(t => t.TokenHash == hash && t.ConsumedAt == null)
    .ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, now), ct);
if (rows == 0) { /* someone else won, or genuine reuse — grace-window branch, §5.2 */ }
else           { db.RefreshTokens.Add(successor); await db.SaveChangesAsync(ct); }
await tx.CommitAsync(ct);
```

Exactly one successor per parent, ever (the CVE class in `token-formats…md` §7.4). SQLite runs in
WAL mode with a busy timeout; PostgreSQL takes the row lock at the conditional `UPDATE`.

---

## 4. Extensibility seams

All in `Boltway.Oidc.Abstractions` unless noted. Signatures are the real ones.

### 4.1 Client authentication

```csharp
public enum ClientAuthMethod { None, ClientSecretBasic, ClientSecretPost, PrivateKeyJwt /*, TlsClientAuth D-03 */ }

public sealed record ClientAuthenticationContext(
    IReadOnlyDictionary<string, string>                     Headers,
    IReadOnlyDictionary<string, IReadOnlyList<string>>      Form,
    Issuer                                                  Issuer,
    string                                                  EndpointUrl,   // U-08: accept issuer OR this
    OAuthSurface                                            Surface);      // Token | Introspection | Revocation

public interface IClientAuthenticator
{
    ClientAuthMethod Method { get; }
    /// <summary>True iff THIS mechanism's credentials are present. Must not validate them.</summary>
    bool Presents(ClientAuthenticationContext ctx);
    ValueTask<ClientAuthenticationResult> AuthenticateAsync(ClientAuthenticationContext ctx, CancellationToken ct);
}

public abstract record ClientAuthenticationResult
{
    private ClientAuthenticationResult() { }
    public sealed record Success(ClientRecord Client, ClientAuthMethod Method, bool UsedAuthorizationHeader)
        : ClientAuthenticationResult;
    public sealed record Failure(OAuthErrorCode Code, string Description, bool UsedAuthorizationHeader)
        : ClientAuthenticationResult;
}
```

The **"exactly one mechanism"** rule (X-17) lives in `ClientAuthenticationDispatcher`, not in the
authenticators: it calls `Presents` on all registered strategies and returns `invalid_request` if the
count is ≠ 1. Adding a fifth mechanism therefore cannot break the rule. `UsedAuthorizationHeader`
propagates to the response writer so X-18's 401-vs-400 split is decided from evidence, not guessed.

The context is transport-neutral on purpose: `Abstractions` has no ASP.NET Core reference, and a
customer's `TlsClientAuthAuthenticator` is unit-testable with two dictionaries.

*Ships in v1:* `None`, `ClientSecretBasic`, `ClientSecretPost`, `PrivateKeyJwt` (verified against the
CIMD `jwks_uri`, RS256+ES256, `jti` replay table, `aud` ∈ {issuer, token endpoint URL} per U-08).
*Customer writes:* one class + one DI registration.

### 4.2 External identity provider

```csharp
public interface IExternalIdentityProvider
{
    string Scheme      { get; }     // route-safe; e.g. "google"
    string DisplayName { get; }
    /// <summary>A-11: a configured-but-unavailable method renders DISABLED WITH A REASON.
    /// There is no return value meaning "hide me".</summary>
    ProviderAvailability Availability(ClientRecord client);
    Task<ChallengeDescriptor>  BeginAsync(ExternalLoginContext ctx, CancellationToken ct);
    Task<ExternalLoginResult>  CompleteAsync(ExternalCallbackContext ctx, CancellationToken ct);
}

public readonly record struct ProviderAvailability(bool Enabled, string? DisabledReason)
{
    public static ProviderAvailability Available => new(true, null);
    public static ProviderAvailability Disabled(string reason) => new(false, reason);   // reason REQUIRED
}

public sealed record ExternalPrincipal(
    string UpstreamIssuer, string UpstreamSubject, IReadOnlyDictionary<string, string> Claims);
```

`ExternalPrincipal` carries the upstream `sub` and nothing else identity-shaped; the local `SubjectId`
is minted by us and joined through `external_identities` (D-10). *Ships:* `LocalPasswordProvider`
(Argon2id via Konscious), `GoogleOidcProvider`. *Customer writes:* `FacebookProvider` — same shape.

### 4.3 Token format and minting

```csharp
public sealed record AccessTokenDescriptor(
    Issuer Issuer, GrantId GrantId, SubjectId Subject, ClientId Client,
    ResourceIdentifier Audience,                 // NON-NULLABLE — N-01 has no bypass
    ScopeSet Scope, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string JwtId,
    AuthenticationContextInfo Auth,
    IReadOnlyDictionary<string, object?> Extra); // the D-02 seam: a `cnf`/`jkt` claim goes here

public sealed record IdTokenDescriptor(
    Issuer Issuer, ClientId Audience,            // N-10: DIFFERENT TYPE. Cannot be confused.
    SubjectId Subject, string? Nonce, DateTimeOffset AuthTime, string? AtHash, …);

public interface IAccessTokenFormat
{
    string TokenTypeHint { get; }                        // "at+jwt"
    ValueTask<MintedToken> MintAsync(AccessTokenDescriptor d, CancellationToken ct);
}
public interface IIdentityTokenFormat
{
    ValueTask<MintedToken> MintAsync(IdTokenDescriptor d, CancellationToken ct);
}
public sealed record MintedToken(string Wire, DateTimeOffset ExpiresAt, string? Kid);
```

N-10 is enforced by the type system: you cannot pass a `ResourceIdentifier` where a `ClientId` is
expected. *Ships:* `JwtAccessTokenFormat` (`typ: at+jwt`, RFC 9068's seven required claims, `scope`
as a space-delimited **string**, `aud` as a bare string for the single-audience case per S-22),
`JwtIdentityTokenFormat`. *Customer writes:* an opaque-token format, or a DPoP-bound variant that
injects `cnf` via `Extra`.

### 4.4 Claim mapping

```csharp
public interface IClaimsMapper
{
    ValueTask MapAsync(ClaimMappingContext ctx, ClaimSink sink, CancellationToken ct);
}

public sealed class ClaimSink
{
    private static readonly FrozenSet<string> Reserved = FrozenSet.ToFrozenSet(
        ["iss","sub","aud","exp","nbf","iat","jti","typ","scope","client_id","cnf","nonce","at_hash","azp"],
        StringComparer.Ordinal);

    /// <summary>Throws ReservedClaimException on a protocol claim. A customer mapper
    /// cannot overwrite `aud` (N-01) or `iss` (N-13).</summary>
    public void Add(string name, object? value);
}
```

*Ships:* `StandardOidcClaimsMapper` (the OIDC Core §5.4 scope→claim table, gated on `openid` — S-10,
C-13). *Customer writes:* a tenant-claim mapper.

### 4.5 Store

Thin where thin is safe; **not** thin where the atomicity is the requirement.

```csharp
public interface IAuthorizationCodeStore
{
    Task StoreAsync(AuthorizationCodeRecord r, CancellationToken ct);
    Task<AuthorizationCodeRecord?> FindAsync(SecretHash h, CancellationToken ct);   // returns REDEEMED rows too — N-07
    /// <summary>Atomic. True iff THIS call performed the redemption (rows-affected == 1).</summary>
    Task<bool> TryRedeemAsync(SecretHash h, DateTimeOffset now, CancellationToken ct);
}

public interface IRefreshTokenStore
{
    /// <summary>The whole rotation decision, because the atomicity is provider-specific (N-08).</summary>
    Task<RefreshRedemption> RedeemAsync(SecretHash presented, RefreshTokenSeed successor,
                                        DateTimeOffset now, TimeSpan graceWindow, CancellationToken ct);
}

public abstract record RefreshRedemption
{
    private RefreshRedemption() { }
    public sealed record Rotated(RefreshTokenRecord Successor)            : RefreshRedemption;
    public sealed record ReplayedWithinGrace(RefreshTokenRecord Existing) : RefreshRedemption;  // idempotent
    public sealed record ReuseDetected(GrantId Grant)                     : RefreshRedemption;  // revoke family
    public sealed record NotFound                                         : RefreshRedemption;
}
```

**Judgement call, stated:** the conventional "thin store" would expose `Find`/`Update` and put the
rotation logic in a service. I reject it. Every store implementation would then have to be trusted to
be raced correctly, and the CVE class here (family forking, GHSA-392p-2q2v-4372) is *exactly* a race.
Putting the decision behind a four-case closed result means a customer's store must answer the
question the protocol asks, and the caller's `switch` over four cases with no default arm is
exhaustive (CS8509 → error).

Also: `IClientStore`, `IGrantStore`, `IConsentStore`, `IUserStore`, `IRevocationList`,
`ISigningKeyStore`, `IJtiReplayStore`. *Ships:* EF Core (SQLite + PostgreSQL) and InMemory.
*Customer writes:* a Dapper or Mongo store — and the shared store conformance suite (§7.3) is
published as a package so they can run our tests against it.

### 4.6 Authorization request source — the D-01 / PAR seam

```csharp
public interface IAuthorizationRequestSource
{
    string Name { get; }
    bool CanHandle(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters);
    ValueTask<AuthorizationRequestResolution> ResolveAsync(
        AuthorizationRequestInput input, CancellationToken ct);
}

public abstract record AuthorizationRequestResolution
{
    private AuthorizationRequestResolution() { }
    public sealed record Resolved(IReadOnlyDictionary<string, IReadOnlyList<string>> Parameters)
        : AuthorizationRequestResolution;
    public sealed record Rejected(OAuthErrorCode Code, string Description)
        : AuthorizationRequestResolution;
}
```

Stage 1 of `/authorize` runs this **before** anything reads a parameter, so every downstream stage
sees a flat dictionary and does not know or care where it came from. *Ships:* `QueryStringSource`
(the only one). *Adding PAR later:* a `ParRequestUriSource` plus one endpoint plus one metadata key
in a `ParCapability` — no change to the twelve stages. This is the one deferral flagged as costing
real rework (D-01); this seam is what makes it not.

### 4.7 Subject identifier — D-11

```csharp
public interface ISubjectIdentifierService
{
    SubjectId ForClient(UserAccount user, ClientRecord client);
}
```

*Ships:* `PublicSubjectIdentifierService` (ignores `client`). Used by token minting **and**
`/userinfo` — the requirement's own consistency condition. *Adding pairwise:* one class plus a
`sector_identifier_uri` fetch through `ISafeHttpFetcher`, plus flipping
`subject_types_supported` — which the capability model (§6) makes a single edit.

### 4.8 Consent

```csharp
public interface IConsentStore
{
    Task<ConsentRecord?> FindAsync(SubjectId s, ClientId c, CancellationToken ct);
    /// <summary>Widening merge: adds scopes/resources without revoking existing ones (C-24).</summary>
    Task<ConsentRecord> GrantAsync(ConsentGrant g, CancellationToken ct);
    Task RevokeAsync(SubjectId s, ClientId c, CancellationToken ct);
}

public interface IConsentPolicy { ConsentDecision Decide(ConsentContext ctx); }
public enum ConsentDecision { Required, AlreadyGranted, Denied }
```

N-14's "never auto-approve on repeat for public clients" is enforced by a non-removable decorator
registered by `CoreCapability` (not by the DI extension method a customer calls):

```csharp
internal sealed class PublicClientReconsentGuard(IConsentPolicy inner) : IConsentPolicy
{
    public ConsentDecision Decide(ConsentContext ctx) =>
        ctx.Client.ClientType == ClientType.Public && inner.Decide(ctx) == ConsentDecision.AlreadyGranted
            ? ConsentDecision.Required            // RFC 8252 §8.6
            : inner.Decide(ctx);
}
```

See §8.4 for why I stopped escalating here rather than making it type-level.

### 4.9 The outbound fetcher — N-05

In `Boltway.Oidc.Net`, and there is nothing else in that assembly's public surface.

```csharp
public readonly struct AbsoluteHttpsUrl
{
    public string Value { get; }
    public string Host  { get; }
    public int    Port  { get; }
    /// <summary>https only; no fragment; no userinfo; parseable. There is no other constructor,
    /// so `file://`, `javascript:` and `gopher://` cannot reach the fetcher (CIMD §8.6).</summary>
    public static bool TryCreate(string raw, out AbsoluteHttpsUrl url);
}

public enum FetchPurpose { ClientIdMetadataDocument, JwksUri, LogoUri, SectorIdentifierUri, UpstreamDiscovery }

public sealed record SafeFetchRequest(AbsoluteHttpsUrl Url, FetchPurpose Purpose,
                                      int MaxBytes = 5 * 1024, TimeSpan? Total = null);

public abstract record FetchOutcome
{
    private FetchOutcome() { }
    public sealed record Ok(byte[] Body, MediaType ContentType, string? ETag, TimeSpan? MaxAge) : FetchOutcome;
    public sealed record Blocked(BlockReason Reason, string Detail)  : FetchOutcome;   // special-use IP, bad scheme
    public sealed record Redirected(int Status, string? Location)    : FetchOutcome;   // CIMD §5 MUST NOT follow
    public sealed record NotOk(int Status)                           : FetchOutcome;   // only 200 is Ok
    public sealed record TooLarge(int BytesRead)                     : FetchOutcome;
    public sealed record Timeout(TimeSpan Elapsed)                   : FetchOutcome;
}

public interface ISafeHttpFetcher
{
    Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken ct);
}
```

The implementation is the `SocketsHttpHandler` + `ConnectCallback` shape from
`client-id-metadata-document.md` §7.2: `AllowAutoRedirect = false`, `UseProxy = false`,
`UseCookies = false`, `Credentials = null`, `AutomaticDecompression = None`, connect 3 s / total 5 s,
resolve → `MapToIPv4()` → RFC 6890 range check → connect **to the validated `IPAddress`**, and a
byte-counted read loop capped at `MaxBytes` (the cap is on bytes read, not `Content-Length`).

`MediaType` parses and **ignores parameters** — §10 of REQUIREMENTS is explicit that
`application/json; charset=utf-8` must be accepted or every ChatGPT document is rejected.

The development relaxation (CIMD §8.6 MAY) is `SpecialUsePolicy.LoopbackDevelopment`, and
`SafeHttpFetcherOptions` validation **throws at startup** if it is set while
`IHostEnvironment.IsDevelopment()` is false. The dangerous configuration cannot boot in production.

Because `System.Net.Http` is unreferenceable outside this assembly (§7.4), there is no "accidentally
used a stock `HttpClient`" failure mode. Note the consequence I accept: `Federation.Google` must
fetch Google's discovery document through this fetcher. That is fine — Google is a globally routable
host — and it means the exception list stays empty, which is the whole point.

---

## 5. Request pipelines

### 5.1 `/authorize` (E-08) — N-11 made structural

The pipeline is a list of stages over a mutable `AuthorizeContext`. The guarantee is not the
ordering of the list; lists get reordered. The guarantee is that **`AuthorizeRedirectError` cannot be
constructed without a `ValidatedRedirect`, and only stage 3 can produce one**:

```csharp
namespace Boltway.Oidc.Server.Authorize;

/// <summary>Proof that a redirect URI was matched against this client's registrations.
/// Constructible only from RedirectMatch, which only RedirectUriMatcher returns.</summary>
public readonly struct ValidatedRedirect
{
    public string Value { get; }                       // the REQUESTED value (carries the ephemeral port)
    internal ValidatedRedirect(in RedirectMatch m) { … }
}

public sealed record AuthorizeRedirectError
{
    private AuthorizeRedirectError(…) { }
    /// <summary>The only factory. You cannot emit a redirect error before stage 3 (N-11, X-01, X-02).</summary>
    public static AuthorizeRedirectError Create(
        in ValidatedRedirect target, OAuthErrorCode code, string description,
        string? state, Issuer iss);                    // `iss` is REQUIRED — S-27/RFC 9207
}

public sealed record AuthorizeHtmlError    // 400, AS-rendered, no Location header
{
    public static AuthorizeHtmlError Create(OAuthErrorCode code, string description, string correlationId);
}
```

`state` and `iss` are constructor parameters, not optional set-later properties, so "we forgot `iss`
on the error path" has no code path either.

| # | Stage | Emits | Requirements |
|---|---|---|---|
| 0 | **`SecurityHeadersMiddleware`** (`Response.OnStarting`) | — | N-15: `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `default-src 'self'`, `form-action 'self'`, `base-uri 'none'` |
| 0b | **`AuthorizeExceptionBoundary`** | X-10 | catches everything; redirects `server_error` iff `ctx.ValidatedRedirect` is set, else HTML 400. An HTTP 500 past stage 3 is a defect |
| 1 | `S01_MethodAndParameters` → `IAuthorizationRequestSource` | HTML 400 | duplicate parameters (except `resource`) → X-04; `resource` read as `Request.Query["resource"].ToArray()`, never `[FromQuery] string` |
| 2 | `S02_ClientResolution` | **HTML 400** | X-01, X-03. `ClientId.TryParseFromRequest` → `IClientResolver` chain (`PreRegistered` → `Dynamic` → **`Cimd`**). CIMD fetch budget ≤ 2 s, serve stale on error (C-29, S-30) |
| 3 | `S03_RedirectValidation` | **HTML 400** | X-02, N-03, N-04. `RedirectUriMatcher.Match`. On success mints `ValidatedRedirect` |
|   | ────────── **redirect is now permitted, and only now is it constructible** ────────── | | |
| 4 | `S04_ResponseType` | redirect | X-07, X-05 |
| 5 | `S05_Pkce` | redirect | X-04, **N-02**: `code_challenge_method` must be present and `S256`; verifier grammar `43*128unreserved`; sets `PkceWasRequested` |
| 6 | `S06_Scope` | redirect | X-08, A-13, C-23 |
| 7 | `S07_Resource` | redirect | X-09, **N-01**: each `resource` → `ResourceKey` → `IResourceRegistry.Resolve`. Unknown and not-permitted return the **same** string and description (enumeration oracle) |
| 8 | `S08_OidcParameters` | redirect | X-16, X-04. `openid` gates OIDC (C-13); `nonce` never invented; `prompt`/`max_age` optional (C-12, U-12) |
| 9 | `S09_Authentication` | 303 → `/login` or redirect | X-12, X-14. **The user is authenticated before any automatic redirect.** Any `returnUrl` is gated by `Url.IsLocalUrl` |
| 10 | `S10_Consent` | 303 → `/consent` or redirect | X-13, X-06, **N-14**: the consent view model requires the `client_id` host and the requested redirect host; `client_name`/`logo_uri` HTML-encoded, length-capped, logo served from `logo_blob` on our origin |
| 11 | `S11_CodeIssuance` | — | `OpaqueSecret.Generate(AuthorizationCode)`; persists challenge + method + `PkceWasRequested` + `redirect_uri_used` + grant set |
| 12 | `S12_Response` | **303** | `code`, `state` verbatim, `iss` (S-27). Built with `QueryHelpers.AddQueryString`, never concatenation (§4.1 charset) |

CORS: `/authorize` is mapped **without** `RequireCors`, and `app.UseCors(policy)` is never called
globally (E-08, S-06 §2.6). A conformance test asserts no `Access-Control-Allow-Origin` on E-08 and
`*` on E-01..E-07/E-10/E-11.

### 5.2 `/token` (E-10)

| # | Stage | Requirements |
|---|---|---|
| 1 | `S01_FormParsing` | C-15. `MapPost("/token", …)` reading `Request.Form`. **`[FromBody]` is banned in this assembly** — a non-form content type produces `400` + an OAuth JSON body, never `415`. `resource` read as `form["resource"].ToArray()` |
| 2 | `S02_ClientAuthentication` | X-17 (exactly one mechanism), X-18 (401 + `WWW-Authenticate` iff the header was used, else 400) |
| 3 | `S03_GrantDispatch` | X-21. `GrantTypeTable` maps the string to a `GrantType` enum; unknown → `unsupported_grant_type`, **not** `invalid_request`. `password` is permanently absent (S-06 §2.4) |
| 4 | `S04_GrantHandler` | exhaustive `switch` over the sealed `GrantRequest` hierarchy — adding a grant type is a compile error until every site handles it |
| 5 | `S05_ResourceResolution` | X-23. `resource` must be in **this code's or this refresh token's** grant set; >1 at `/token` → `invalid_target`. **Never `invalid_grant`** (clients discard the refresh token) |
| 6 | `S06_Issuance` | N-01, N-09, N-10, N-08 |
| 7 | `S07_Response` | returns `TokenEndpointResult`, whose writer always sets `Cache-Control: no-store` + `Pragma: no-cache`. The handler's return type makes it unforgettable |

**Authorization-code handler, N-07 order (this order is the requirement):**

1. `OpaqueSecret.TryParse(code, TokenPurpose.AuthorizationCode)` → hash → `FindAsync`
   (returns redeemed rows too).
2. Client binding: `record.ClientId == authenticatedClient.ClientId` → else `invalid_grant`.
3. `redirect_uri`: if present in the request, ordinal-equal to `record.RedirectUriUsed` (S-02,
   RFC 6749 §4.1.3) → else `invalid_grant`.
4. PKCE XOR: `record.PkceWasRequested != verifierPresent` → `invalid_grant`. Then
   `FixedTimeEquals(SHA256(verifier)_base64url, record.CodeChallenge)`.
5. Expiry.
6. **Only now**: `TryRedeemAsync`. `false` ⇒ a *fully valid* replay ⇒ revoke the grant and its
   descendants. An attacker with a sniffed code but no verifier fails at step 4 and the legitimate
   client's tokens survive.

**Refresh handler, N-08:** `RedeemAsync` → exhaustive switch over the four cases:
`Rotated` → mint; `ReplayedWithinGrace` → return the *same* successor (idempotent, C-19's
proactive+reactive race); `ReuseDetected` → revoke family + add `grant_id` to `revoked_grants` +
high-severity audit event + `invalid_grant`; `NotFound` → `invalid_grant` (C-20; never
`invalid_request`, never a custom code).

---

## 6. Configuration model

### 6.1 Capabilities — N-06 and A-04/A-05/A-06

```csharp
public interface IServerCapability
{
    string Id { get; }                                        // "cimd", "dcr", "oidc", "logout", "jwt-bearer"
    bool IsEnabled { get; }                                    // read from bound options
    void Contribute(MetadataBuilder metadata);                 // the keys this capability advertises
    void MapEndpoints(IEndpointRouteBuilder endpoints);        // the routes it actually serves
    IEnumerable<CapabilityConflict> ConflictsWith(IReadOnlyList<IServerCapability> enabled);
}
```

One object owns both halves, so "advertised" and "actual" cannot drift — A-04 falls out for free
(disable DCR, the key disappears from **both** well-known documents in the same process).

`DcrCapability.ConflictsWith` returns a conflict when `CimdCapability` is enabled; startup throws
`CapabilityConflictException` naming the pair (`registration_endpoint` + `client_id_metadata_document_supported`,
N-06 / A-05 / U-02).

The stronger check, and the one I would not ship without:

```csharp
// Server/Capabilities/AdvertisedCapabilityAssertion.cs — runs at startup, after routing is built.
foreach (var (key, url) in metadata.EndpointValuedKeys())          // *_endpoint, jwks_uri
    if (!endpointDataSource.ResolvesTo(EndpointUrls.PathOf(url)))
        throw new AdvertisedCapabilityException(
            $"Metadata advertises '{key}' = {url} but no route serves it. (N-06)");
```

"Advertised capability == actual capability" becomes an assertion over the routing table rather than
a claim in a code review.

`MetadataBuilder` has **no overload that can emit an empty array** — `AddArray(string, IEnumerable<string>)`
no-ops when the sequence is empty (S-34 / RFC 8414 §3.2), and there is no `Add(string, string[])`.
Nulls omitted via `JsonIgnoreCondition.WhenWritingNull`. The document is serialized **once** into a
cached `byte[]` + `ETag` and written byte-identically from E-01..E-06 (A-21) — a single buffer is
the only way "byte-identical" survives a serializer settings change.

### 6.2 Options and startup validation

```csharp
[ConfigSection("Boltway:Oidc:Server")]
public sealed class ServerOptions
{
    [ConfigKey("The immutable issuer identifier. N-13. Never derived from Request.Host.", Requirement = "N-13")]
    [Required, Url] public string Issuer { get; set; } = "";

    [ConfigKey("Advertise CIMD as the client-acquisition mechanism.", Requirement = "A-06")]
    public bool EnableCimd { get; set; } = true;

    [ConfigKey("Advertise RFC 7591 dynamic client registration. Mutually exclusive with EnableCimd.",
               Requirement = "N-06")]
    public bool EnableDynamicClientRegistration { get; set; } = false;

    [ConfigKey("Access-token lifetime. Must exceed 5 minutes or Claude's proactive refresh thrashes.",
               Requirement = "C-19")]
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    [ConfigKey("Refresh-token reuse idempotency window.", Requirement = "N-08")]
    public TimeSpan RefreshReuseGraceWindow { get; set; } = TimeSpan.FromSeconds(45);
    …
}
```

`IValidateOptions<ServerOptions>` + `.ValidateOnStart()` asserts, with named messages: issuer is
`https`, has no query/fragment, has **no trailing slash**, is `Ordinal`-equal to the token-signing
issuer constant; `AccessTokenLifetime > 5 min` (C-19); `RefreshReuseGraceWindow ∈ [30 s, 60 s]`;
`EnableCimd XOR EnableDynamicClientRegistration`.

### 6.3 A-17 without a second list

The schema **is** the type. The anti-drift mechanism is the registration helper:

```csharp
public static IServiceCollection AddBoltwayOptions<TOptions>(
    this IServiceCollection services, IConfiguration config) where TOptions : class, new()
{
    var section = typeof(TOptions).GetCustomAttribute<ConfigSectionAttribute>()!.Path;
    services.AddOptions<TOptions>().Bind(config.GetSection(section))
            .ValidateDataAnnotations().ValidateOnStart();
    services.AddSingleton(ConfigSchemaBuilder.Describe<TOptions>());   // ← same call, always
    return services;
}
```

`ConfigSchemaBuilder.Describe<T>` reflects: property name → key path; property type → declared type;
`enum` members / `[AllowedValues]` → allowed values; `new T()` property initializers → defaults;
`[ConfigKey]` → description + requirement id. Current values come from `IOptionsMonitor<T>` at
request time.

There is no way to have a live config key that is missing from `GET /admin/config/schema`, because
binding and describing are the same call. A test asserts every `IOptions<>` registration in the
container has a matching `ConfigSchemaDescriptor`.

A-16 (all-or-nothing, read-back-verified, unknown keys rejected loudly):

```csharp
new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }
```

throws naming the offending member; the write path is deserialize → validate → persist → reload →
re-read → compare, all inside one transaction.

A-09 (correlation id on every rejection): a `CorrelationId` is minted in middleware, written to
`X-Request-Id`, appended to every `error_description` on the AS's own surfaces, and is a required
constructor parameter of `AuthorizeHtmlError`.

---

## 7. Testing architecture

### 7.1 Traceability for 187 IDs

```csharp
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public sealed class CoversAttribute(params string[] requirementIds) : Attribute
{
    public IReadOnlyList<string> RequirementIds { get; } = requirementIds;
}

[Covers("N-04", "A-19", "C-06")]
[Theory]
[InlineData("http://localhost:3118/callback", true)]
[InlineData("http://127.1:3118/callback",     false)]
…
public void Loopback_port_exception_ignores_port_on_both_sides(string requested, bool expected) { … }
```

`Boltway.Oidc.Traceability.Tests` then:

1. Parses `spec/REQUIREMENTS.md` with `^\|\s*\*{0,2}([SEXNCADU]-\d\d)\*{0,2}\s*\|` → the authoritative
   ID set, partitioned by prefix and by the `v1 level` column (`MUST`/`SHOULD`/`NOT`).
2. Reflects over every test assembly collecting `[Covers]` ids.
3. Asserts:
   - every **binding** id (170) has ≥ 1 covering test → **fails the build when the spec gains a row**;
   - every `[Covers]` id exists in the spec → catches typos and stale ids after a spec edit;
   - every id whose v1 level is `NOT` (S-12, S-36..S-42) has *only* negative tests
     ("we do not advertise this");
   - `U-nn` rows require an `[Unverified("U-09", "reason")]` marker, which produces a report
     section rather than a failure — U rows are questions, not requirements.
4. Writes `artifacts/requirement-coverage.md`. The submission traceability matrix is generated, not
   maintained.

### 7.2 Conformance tests

`WebApplicationFactory<SampleHost>`, one class per endpoint, one `[Fact]` per X-nn/E-nn/C-nn row.
Run against all three stores via a fixture matrix. The 41 error rows in §4 are largely table-driven:

```csharp
[Covers("X-17","X-18","X-19","X-20","X-21","X-22","X-23")]
[Theory, MemberData(nameof(TokenEndpointErrorRows))]   // rows generated FROM OAuthErrors.Table
public async Task Token_endpoint_error_row(OAuthErrorCode code, int status, string wire) { … }
```

Because the rows come from the same `FrozenDictionary` the production code uses, a wrong wire string
is a single-point failure, not 41 places to get right. And `OAuthErrors.Resolve(Surface, Code)`
**throws on an unlisted pair** — which is how "`access_denied` is never emitted from `/token`"
(§4.2) becomes structural rather than a note.

### 7.3 Store conformance

One abstract suite, three concrete fixtures:

```csharp
public abstract class RefreshRotationConformance<TFixture> where TFixture : IStoreFixture, new()
{
    [Covers("N-08")] [Fact] public async Task Two_concurrent_redemptions_produce_one_successor() { … }
    [Covers("N-08")] [Fact] public async Task Replay_outside_grace_window_revokes_the_family()   { … }
    [Covers("N-07")] [Fact] public async Task Replay_with_wrong_verifier_leaves_tokens_valid()   { … }
    [Covers("A-13")] [Fact] public async Task Identifier_comparison_is_case_sensitive()          { … }  // §3.6
}
public sealed class Sqlite_RefreshRotation     : RefreshRotationConformance<SqliteFixture> { }
public sealed class PostgreSql_RefreshRotation : RefreshRotationConformance<PostgreSqlFixture> { }
public sealed class InMemory_RefreshRotation   : RefreshRotationConformance<InMemoryFixture> { }
```

PostgreSQL via Testcontainers; skipped **with a stated reason** locally, required in CI. The
concurrency tests use `Task.WhenAll` over real connections — the point is to exercise the database's
atomicity, so an in-process lock would invalidate them.

Published as `Boltway.Oidc.Storage.Testing` so a customer writing a Dapper store runs our suite.

### 7.4 Architecture tests (Mono.Cecil — already pinned)

Rules as data, each carrying its N-nn:

```csharp
public sealed record ArchitectureRule(
    string Id, string Requirement, string Rationale,
    Func<IReadOnlyList<ModuleDefinition>, IEnumerable<Violation>> Check);
```

| Rule | Check | Note |
|---|---|---|
| **N-03** | In `Boltway.Oidc.Primitives.dll`, walk every instruction of `RedirectUriMatcher` **and, transitively, every method it calls within the assembly**, failing on any `MemberReference` whose `DeclaringType.FullName == "System.Uri"` | Transitivity is essential — without it the violation just moves one helper away |
| **N-05** | No `TypeReference`/`MemberReference` to `System.Net.Http.*`, `System.Net.WebRequest`, `System.Net.Sockets.Socket` in any Boltway assembly except `Boltway.Oidc.Net` | **Exception list is empty**; that is the claim |
| **N-12** | In `Server` + `Server.Ui`: no call to `Results::Redirect`/`RedirectPreserveMethod`/`LocalRedirect`, no `newobj RedirectResult`, no call to `ControllerBase::Redirect*`/`PageModel::RedirectToPage*`, and no `ldc.i4` operand of `307` or `308` anywhere | Blunt on the literals, deliberately. `SeeOtherResult` is the one sanctioned way out |
| **N-13** | In `Server` + `Server.Ui`: no reference to `HttpRequest::get_Host`, `get_Scheme`, `UriHelper::GetDisplayUrl`, `GetEncodedUrl` | Every emitted URL comes from `EndpointUrls(Issuer)` |
| **N-09** | `newobj TokenValidationParameters` exists in exactly one method: `ResourceServer.TokenValidationParametersFactory.Create` | Stronger than "assert the setters were called" — there is only one construction site to review |
| **N-16** | Reflect over EF's `IModel`: no entity property of type `string` whose name matches `(Secret\|Token\|Password\|Verifier)$`; every `*Hash` property is `byte[]` | Model-level, not source-grep — survives renames |
| **BAN** | `Random`, `Guid.NewGuid` (as a secret), `DateTime.Now`, `string.Equals` without `StringComparison` | Mostly already covered by the pinned `.editorconfig` (CA1307/CA1310/CA5394) |

Cecil is the authority; `BannedApiAnalyzers` (`BannedSymbols.txt` per project) is the same rules at
keystroke time. A `#pragma warning disable` defeats the analyzer and does not touch Cecil.

### 7.5 SSRF tests (N-05)

`SafeHttpFetcher` takes an internal `IAddressResolver` and an internal connect counter
(`InternalsVisibleTo` the test assembly) so the tests can assert **no socket was opened**, not merely
that the request failed:

| Case | Expect |
|---|---|
| `https://169.254.169.254/c.json` | `Blocked`, connect count 0 |
| `https://[::ffff:169.254.169.254]/c.json` | `Blocked` (IPv4-mapped unwrap) |
| host resolving to `127.0.0.1` | `Blocked` |
| public host → `302` → internal IP | `Redirected`, second connect count 0 |
| 6 KB body with `Content-Length: 100` | `TooLarge` (cap is on bytes read) |
| `Content-Type: application/json; charset=utf-8` | `Ok` (§10) |
| resolver returns public IP then internal IP on a second call | connects to the **first**, validated address |
| `SpecialUsePolicy.LoopbackDevelopment` in Production | startup throws |

### 7.6 Interop and preflight

- `Interop.Tests` replays the four documents in `spec/cimd-live-2026-08-03.json` through
  `CimdValidator`. All four must resolve. This pins C-04 (both auth-method spellings), C-06 (both
  ChatGPT redirect literals as exact strings), U-17 (Claude Code's cross-origin loopback redirect is
  exempt), and N-14 (ChatGPT's third-party-CDN `logo_uri` must be proxied, not hotlinked).
- A **nightly** job re-fetches the four URLs and diffs against the pinned file. Vendor drift becomes
  a red build, not a support ticket.
- `scripts/preflight.sh` runs the five Appendix commands against the sample host in CI, including the
  `jq -S` byte-equality diff of the two discovery documents (A-21).

---

## 8. Where the ceremony is *not* worth it

The brief asks for honesty about cost. These are the places I deliberately stopped.

1. **`ref struct` for plaintext secrets.** It is the strongest guarantee available — the compiler
   forbids storing the value in a field or capturing it across an `await`. It also cannot survive the
   mint path, which must carry a plaintext refresh token into a JSON response across at least one
   async boundary. Rejected. The cheaper guarantee (no entity has a `string` secret property,
   asserted over `IModel`) covers the actual failure mode, which is *persistence*, not *residency*.

2. **Value objects for every string.** `state`, `nonce`, `error_description`, `client_name` stay
   `string`. They are pass-through data with no comparison semantics and no invariant to protect.
   Wrapping them adds a `.Value` at every call site and prevents nothing. Value objects are reserved
   for the five things that are *compared*: issuer, client id, redirect URI, scope, resource
   identifier — plus secrets, which are hashed.

3. **`Result<T,E>` everywhere.** C# has no language support for it, and a codebase that is 100%
   `Result` reads badly and pushes people toward `.Unwrap()`. Closed result hierarchies are used in
   exactly four places, where the *branches are the requirement*: `RedirectMatch`,
   `RefreshRedemption`, `FetchOutcome`, `ClientAuthenticationResult`. Everywhere else: exceptions
   plus the `/authorize` exception boundary that owns X-10.

4. **Type-level proof that consent cannot be auto-approved for public clients.** I sketched a
   `ConsentDecision.AlreadyGranted(ConfidentialClientProof)` where the proof is unobtainable for a
   public client. It works, and it makes `IConsentPolicy` genuinely unpleasant to implement for a
   customer who just wants a different UI. A non-removable decorator plus a test is the right trade
   (§4.8). This is the one N-nn where I accept mechanism-3-and-a-test rather than mechanism 1.

5. **Source-generating the config schema.** Reflection runs once at startup over ~40 properties.
   A source generator is a build-time dependency, a debugging surface, and an extra thing to keep
   working across SDK bumps, in exchange for microseconds. Rejected.

6. **Hashed identifier columns to be collation-proof.** One `SetCollation("C")` in the PostgreSQL
   customization plus one cross-provider test buys the same guarantee (§3.6).

7. **An assembly per endpoint.** Assembly boundaries here exist for exactly two reasons: *reuse*
   (what does an RS-only customer take?) and *ban scope* (`BannedApiAnalyzers` and the Cecil rules
   are per-assembly). Anything else is a folder. Ten projects is already at the edge of what a
   two-week build can carry.

One more honest cost, not a rejection: **the twelve-stage `/authorize` pipeline is more code than a
single 300-line handler**, and it will feel like over-engineering for the first week. It buys N-11 as
a type-system property and it makes the twelve X-nn rows in §4.1 individually testable. I would pay
it again.

---

## 9. Practicalities

### 9.1 Package additions needed in `Directory.Packages.props`

All MIT/Apache-2.0, consistent with the pinned licence constraint:

```xml
<PackageVersion Include="Microsoft.CodeAnalysis.BannedApiAnalyzers" Version="4.14.0" />  <!-- MIT -->
<PackageVersion Include="Microsoft.CodeAnalysis.CSharp" Version="4.14.0" />              <!-- MIT, analyzers project -->
<PackageVersion Include="Testcontainers.PostgreSql" Version="4.6.0" />                   <!-- MIT -->
<PackageVersion Include="Microsoft.Extensions.Diagnostics.HealthChecks" Version="10.0.10" />
```

`Mono.Cecil` 0.11.6 is already pinned — the ground was laid with the architecture tests in mind.

### 9.2 Build order (each step leaves a green build and a runnable thing)

1. `Primitives` + `Primitives.Tests` — value objects, the redirect matrix, the error table.
   `Architecture.Tests` with the N-03 rule from day one.
2. `Net` + `Net.Tests` — SSRF fetcher and its matrix. N-05 rule added.
3. `Abstractions` + `Storage.InMemory` + `Storage.Tests` — the store contract and its suite.
4. `Server` skeleton: capabilities, metadata, E-01..E-07, `--doctor`-equivalent startup assertions.
   `scripts/preflight.sh` starts passing its first two commands here.
5. `/authorize` + `/token` + CIMD + `Server.Ui`. The end-to-end Claude Code flow (portless loopback)
   is the first green conformance test.
6. `Storage.EntityFrameworkCore` + both providers.
7. `ResourceServer` — and now the sample host is a complete AS + RS pair.
8. DCR, `/logout`, `/userinfo`, jwt-bearer, Google federation, admin schema.

### 9.3 What I would cut if the deadline halved

**Cut, in this order:**

1. **DCR entirely** — S-13/S-14/S-15, E-11..E-14, X-24..X-31, and the whole abuse/quota/GC apparatus
   in `dynamic-client-registration.md` §8. Both vendors do CIMD, N-06 forbids advertising both
   anyway, and A-08 says CIMD creates no client rows. This is the single largest chunk of work whose
   removal costs nothing at the two connectors that matter. Keep `IClientResolver`.
2. **Google federation** — local Argon2id passwords only. Keep `IExternalIdentityProvider` and ship
   `GoogleOidcProvider` in v1.1; it is one class against a working seam.
3. **`/logout`** (S-11) and the RP-initiated logout surface. SHOULD, not MUST; no MCP client uses it.
4. **jwt-bearer grant** (S-26b, C-32) — Claude Enterprise Managed Auth. Keep the URN out of
   `grant_types_supported` when the capability is off; N-06 makes that automatic.
5. **`client_credentials`**, **ES256** (RS256 only — still MTI and still the interop floor), and the
   admin config **write** path (keep the read-only `GET /admin/config/schema`; it is free, since it
   is reflection over types that exist regardless).
6. **PostgreSQL provider project** — SQLite only, with the provider seam and the abstract store suite
   intact. This is the *last* cut and I would fight it, because "runs on both" is a claim customers
   buy; but the seam is what makes it a week later rather than a rewrite.

**Never cut, at any deadline:**

- Any of the sixteen `N-nn` **and their mechanical guards**. Shipping N-03 as a code review instead
  of an architecture test saves two hours and is exactly how it regresses in month six. The guards
  are cheaper than the requirements they protect.
- `Primitives` and its value objects. Every other layer's correctness is downstream of them.
- The `ISafeHttpFetcher` single-HttpClient boundary.
- The capability model and the startup advertised-vs-routed assertion (N-06). It is ~80 lines and it
  is the difference between a connector that fails visibly at boot and one that fails silently in a
  customer's browser (U-02's measured failure).
- The error table and `OAuthErrors.Resolve` throwing on unlisted pairs.
- The `[Covers]` traceability test. Without it, "187 requirements" is a claim; with it, it is a
  build artifact — which is the thing that gets resold.
- The four live CIMD documents as tests, and the nightly re-fetch.
```
