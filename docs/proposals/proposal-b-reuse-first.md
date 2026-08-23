# Proposal B — Reuse-first architecture for the Boltway authorization server

**Angle:** this is a product that ships into other people's codebases, repeatedly. Every decision
below is made for deployment ten, not deployment one. Where that costs indirection, the cost is
stated. Where it does not pay, generalization is refused and the refusal is named.

**Repo location:** `/home/user/Boltway/auth/` (the `Directory.Build.props`,
`Directory.Packages.props`, `global.json` and the pinned drafts in `spec/` are already there and
this proposal builds on them, not around them).

**Sources honoured:** `REQUIREMENTS.md` §1–§10, with §10 winning on conflict with §6/§9.
Requirement IDs are cited inline. Where a requirement drives a *structural* decision — a file
boundary, a type shape, an assembly split — it is called out as such, because a requirement that is
only satisfied by careful coding is a requirement that will be violated by deployment four.

---

## 0. The three product decisions everything else follows from

Before the tree, three decisions that propagate everywhere. Each has a rejected alternative.

### 0.1 One deployment serves one issuer. Multi-tenancy is by host, and it is deferred.

`S-08` makes a path-less issuer a **product requirement**, not a convenience: a path-bearing issuer
obliges four live well-known URLs (`E-03`..`E-06`) and MCP clients probe them in an order nobody
controls. `N-13` then makes the issuer one immutable configured byte string that is never derived
from `Request.Host`.

Those two together kill the Keycloak model (`https://as.example.com/realms/{name}`) outright. The
only shapes left are **one issuer per process** or **one issuer per hostname, selected from a frozen
map built at startup**.

**v1 ships one issuer per process.** The customer gets a container, a DNS name, a database. Ten
customers is ten containers.

**But every table carries a `RealmId` from day one, and every store method takes it as its first
parameter.** This costs almost nothing now and costs a migration across ten live customer databases
later. The realm exists because a single customer with three brands is a real request, and because
`Tenancy: HostMapped` — a `FrozenDictionary<string, Realm>` keyed by exact-ordinal `Host`, resolved
once at startup, 404 on an unknown host — then becomes a v1.1 feature rather than a schema change.
Note precisely why host-mapping does not violate `N-13`: the request host **selects** among
pre-configured immutable issuer strings; it never **produces** one. The type makes that true:
`IssuerString` has no constructor reachable from request-handling code.

*Rejected:* shared multi-tenant process from v1. A bug in the redirect matcher then has a
cross-customer blast radius, and the `A-09` correlation story gets much harder. The savings are
hosting cost, which is the customer's, not ours.

*Naming trap:* the FictStory resource-server layer already uses "tenant" for the **subject-derived
data scope** (`identity.ts`, `assertSafeTenantId`). That is a different concept at a different
layer. The AS-side concept is **Realm**. Never use "tenant" in AS code.

### 0.2 What the customer consumes: a container by default, NuGet when they need code.

Three shapes, in the order a customer meets them:

| Shape | Who takes it | What it is |
|---|---|---|
| **Container** `ghcr.io/boltway/authserver:{version}` | ~80% of AS deployments | `Boltway.AuthorizationServer.Host` prebuilt. Config by env/file. Zero customer code. |
| **NuGet packages** | customers embedding the AS in their own host, or needing a custom user store / IdP | `Boltway.AuthorizationServer` + `Boltway.Storage.*`. A 20-line `Program.cs`. |
| **NuGet packages, RS only** | every customer with a .NET MCP server, whether or not they buy the AS | `Boltway.ResourceServer[.Mcp]`. No EF, no Razor, no AS. |

This forces a real constraint on the design: **the AS must be a library that a 20-line `Program.cs`
hosts.** The container is that `Program.cs`, prebuilt. There is no code path that only exists inside
the host project.

```csharp
// Boltway.AuthorizationServer.Host/Program.cs — the entire composition root
var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddBoltwayAuthorizationServer(builder.Configuration.GetSection("Boltway"))
    .AddEntityFrameworkStores(o => o.UseProviderFromConfiguration(builder.Configuration))
    .AddLocalPasswordAccounts()
    .AddGoogleFederation(builder.Configuration.GetSection("Boltway:Federation:Google"))
    .AddDefaultUi();
var app = builder.Build();
app.MapBoltwayAuthorizationServer();
return await app.RunBoltwayAsync(args);   // dispatches serve|migrate|doctor|conformance|seed|keys
```

*Rejected:* shipping the AS as source (a `dotnet new` template that copies the protocol code into the
customer repo). Every customer then owns a fork of the security-critical code and there is no upgrade
story at all. A template exists, but it references the packages; it never vendors them.

### 0.3 Both halves ship, and they share the comparison primitives.

`E-22`..`E-24` say we ship resource-server middleware. There is already a TypeScript implementation
of exactly that at `/home/user/FictStoryEngine/mcp-server/core/src`. §11 below answers whether
shipping both is coherent. The short version, because it drives the assembly split: **the AS and the
RS must agree byte-for-byte on issuer comparison, `resource` identity, `aud` matching, media-type
parsing and `WWW-Authenticate` quoting.** Shipping both from one repo lets those be *the same
compiled code* rather than two implementations kept in step by test. That is the argument for
`Boltway.OAuth.Primitives` existing as its own assembly, and it is the main reason the split
below is shaped the way it is.

---

## 1. Assembly split

Twelve shipped projects. Each row states the boundary's *reason*, and the reasons are of exactly
three kinds: **(R) reuse** — a customer takes this without the rest; **(E) enforcement** — the
boundary is what makes an architecture test possible; **(P) provider** — this varies per deployment
target.

| Project | Kind | Contains | Depends on |
|---|---|---|---|
| `Boltway.OAuth.Primitives` | R, E | Ordinal comparison, redirect matching (`N-03`/`N-04`), PKCE, base64url, media-type parsing, `WWW-Authenticate` build/parse, `303` helper, the `X-nn` error catalogue, the identifier value types, ULID, SHA-256 + `FixedTimeEquals` helpers | BCL only |
| `Boltway.OAuth.Net` | R, E | **The only** outbound HTTP that may reach an attacker-supplied URL (`N-05`), RFC 6890 blocklist, connect-pinning handler, clamped-TTL cache (`S-30`), circuit breaker | Primitives |
| `Boltway.OAuth.Tokens` | R | JWT/JWS/JWK types, RFC 9068 profile, signing-key ring abstractions, validation parameter factories with `ValidTypes`/`ValidAlgorithms` pinned (`N-09`) | Primitives, `Microsoft.IdentityModel.JsonWebTokens` |
| `Boltway.ResourceServer` | **R** | Bearer authentication handler, PRM endpoints (`E-22`/`E-23`), challenge builder (`X-32`..`X-35`), per-caller limits, `--doctor` preflight | Primitives, Net, Tokens, ASP.NET Core |
| `Boltway.ResourceServer.Mcp` | **R** | Stateless Streamable HTTP, JSON-RPC lazy-auth gate, tool-contract lint | ResourceServer |
| `Boltway.AuthorizationServer.Abstractions` | R, E | Every seam in §4, plus the request/response DTOs they exchange. **No ASP.NET Core dependency.** | Primitives, Tokens |
| `Boltway.AuthorizationServer` | E | The protocol engine and every endpoint | Abstractions, Net, Tokens, ASP.NET Core |
| `Boltway.AuthorizationServer.UI` | R | Razor Class Library: login, consent, error, logout. Security-critical fragments are **tag helpers, not views** (§8.3) | AuthorizationServer |
| `Boltway.Storage.EntityFrameworkCore` | P | `BoltwayDbContext`, entity configurations, store implementations | Abstractions, EF Core Relational |
| `Boltway.Storage.Sqlite` / `.PostgreSql` | P | Provider wiring **and that provider's migrations only** | Storage.EntityFrameworkCore |
| `Boltway.Federation.Google` | R | `GoogleOidcProvider` over the generic `OidcExternalProvider` base | Abstractions, Net |
| `Boltway.Conformance` | R | The executable requirement matrix as a CLI, runnable against a live deployment | Primitives, Net, Tokens |

Plus one non-shipped: `Boltway.AuthorizationServer.Host` (the container entrypoint).

**The RS-only customer takes four packages**: `Boltway.ResourceServer` (+ `.Mcp`), which
transitively pulls Primitives, Net and Tokens. No EF Core. No Razor. No `System.Data`. That is the
question the split is designed to answer, and it is why Primitives/Net/Tokens are three assemblies
rather than one `Boltway.Core`.

**Boundaries that exist for enforcement, not for reuse** — these are the ones that would look like
over-splitting if you did not know the rule they carry:

- **`Oauth.Net` is a separate assembly so `N-05` can be a one-line architecture test.** Rule: *no
  type outside `Boltway.OAuth.Net` may reference `System.Net.Http.HttpClient`,
  `HttpMessageHandler` or `IHttpClientFactory`.* One Cecil scan over every shipped assembly. If the
  fetcher lived alongside other code, the test would need an allowlist, and an allowlist is a place
  to add an entry.
  There is exactly one documented exception, and it is in the test with a comment: the Google
  federation handler sets `BackchannelHttpHandler` from the guarded handler, which requires naming
  the type. It is `Boltway.Federation.Google.GoogleOidcProvider` and nothing else.
- **`Abstractions` has no ASP.NET Core reference.** A customer writing an `IExternalIdentityProvider`
  or a store should be able to do it in a class library and unit-test it without a `WebApplication`.
  The consequence is that no seam may take `HttpContext`; they take request-shaped DTOs. That is a
  real constraint on §4 and it improved every signature there.
- **`UI` is separate** so branding is a package replacement or a view override, never a fork (§8.3).
- **`Storage.Sqlite` and `Storage.PostgreSql` are separate** so a Postgres customer does not carry
  SQLite's migration history, and so `MigrationsAssembly` resolution is unambiguous. Migrations are
  per-provider by construction in EF Core; pretending otherwise produces a migration folder that
  compiles under one provider and generates wrong DDL under the other.

**Target frameworks.** The AS is `net10.0` only — we control its host, it ships as a container.
**The RS packages multi-target `net8.0;net10.0`**, because they go into the *customer's* codebase and
the customer's TFM is not ours to choose. Refusing this makes the RS unsellable to anyone on the
current LTS. Cost: two `#if NET10_0_OR_GREATER` blocks (`Guid.CreateVersion7`, `System.Text.Json`
`AllowOutOfOrderMetadataProperties`). Override `TargetFrameworks` in those four `.csproj` files
against the `net10.0` default in `Directory.Build.props`.

---

## 2. Namespace and folder layout

Namespace == folder path, root `Boltway`. Below is file-level for the core protocol paths;
elsewhere, directory-level.

```
auth/
  Boltway.Auth.slnx
  Directory.Build.props · Directory.Packages.props · global.json · .editorconfig
  BannedSymbols.txt                    <- Microsoft.CodeAnalysis.BannedApiAnalyzers input (§7.3)
  spec/                                <- draft-ietf-oauth-v2-1-15.txt, ...-cimd-02.txt (pinned, U-15/U-16)
  docs/
    requirements.md                    <- the 187 IDs. CANONICAL. Parsed by the coverage test (§7.1)
    metadata.golden.json               <- the served AS metadata document, byte-reviewed (§7.5)
  src/
    Boltway.OAuth.Primitives/
      Ids/
        RealmId.cs  ClientIdentifier.cs  ResourceIdentifier.cs  IssuerString.cs
        ScopeSet.cs  GrantId.cs  SubjectId.cs  Ulid.cs
      Comparison/
        Ordinal.cs                      <- the ONLY place StringComparison is chosen
      Redirects/
        RedirectUriMatcher.cs           <- N-03. Zero System.Uri references, enforced (§7.3)
        LoopbackKey.cs                  <- N-04. Pure ordinal scanner, no IPAddress, no Uri
        RedirectUriPolicy.cs            <- registration-time validation; may use Uri as a predicate
        RegisteredRedirectUri.cs        <- { string Raw; RedirectKind Kind; string? LoopbackKey }
      Pkce/
        CodeChallenge.cs  CodeVerifier.cs  S256.cs
      Encoding/Base64Url.cs
      Http/
        MediaType.cs                    <- parse; ignore parameters (§10 correction to U-03)
        WwwAuthenticate.cs              <- quoting, escaping, length caps (X-32..X-35)
        SeeOther.cs                     <- N-12. The only redirect helper in the product
      Errors/
        OauthError.cs  ErrorCatalog.cs  ErrorCharset.cs
      Secrets/
        RandomSecret.cs  Sha256Hash.cs  ConstantTime.cs
    Boltway.OAuth.Net/
      GuardedFetcher.cs                 <- N-05. IOutboundFetcher's only implementation
      GuardedFetcherOptions.cs
      SpecialUseAddresses.cs            <- RFC 6890, v4 + v6, MapToIPv4 first
      ConnectPinningHandler.cs          <- SocketsHttpHandler.ConnectCallback to the validated IP
      FetchedDocument.cs                <- { byte[] Body; MediaType; CacheControl } — never HttpResponseMessage
      Caching/ClampedTtlCache.cs        <- S-30: floor 300s, ceiling 86400s, never caches errors
      CircuitBreaker.cs
      ServiceCollectionExtensions.cs
    Boltway.OAuth.Tokens/          Jwt/ · Jwk/ · Rfc9068/ · Keys/
    Boltway.ResourceServer/        Authentication/ · Metadata/ · Challenge/ · Limits/ · Doctor/
    Boltway.ResourceServer.Mcp/    Transport/ · LazyAuth/ · ToolContract/
    Boltway.AuthorizationServer.Abstractions/
      Clients/ · Users/ · Tokens/ · Consent/ · Stores/ · Federation/ · Requests/
    Boltway.AuthorizationServer/
      Authorize/
        AuthorizeEndpoint.cs            <- the ordered pipeline of N-11, and nothing else
        AuthorizeRequestReader.cs       <- IAuthorizationRequestSource dispatch + duplicate-param rule
        Steps/ClientResolutionStep.cs   <- step 6-7 (X-01, X-03)
        Steps/RedirectUriStep.cs        <- step 8 (X-02). THE LINE is at the end of this file
        AuthorizeErrorBoundary.cs       <- X-10. Everything past THE LINE runs inside this
        Steps/PkceStep.cs  ScopeStep.cs  ResourceStep.cs  PromptStep.cs  ResponseTypeStep.cs
        AuthorizationCodeIssuer.cs
      Token/
        TokenEndpoint.cs
        ClientAuthenticationDispatcher.cs   <- "exactly one mechanism" lives here, not in the seams
        Authenticators/NoneAuthenticator.cs ClientSecretBasicAuthenticator.cs
                       ClientSecretPostAuthenticator.cs PrivateKeyJwtAuthenticator.cs
        Grants/GrantDispatcher.cs AuthorizationCodeGrantHandler.cs RefreshTokenGrantHandler.cs
               ClientCredentialsGrantHandler.cs JwtBearerGrantHandler.cs
        Rotation/RefreshRotation.cs     <- N-08, incl. the 30-60s idempotency window
        Replay/CodeReplayHandler.cs     <- N-07, full validation before any revocation
      Cimd/
        CimdClientResolver.cs           <- S-16, the default client-acquisition path
        CimdDocument.cs                 <- reads BOTH auth-method spellings (C-04)
        CimdValidator.cs                <- §4/§4.1/§4.2 rules; same-origin-except-loopback (U-17)
        CimdCache.cs
      Metadata/
        AuthorizationServerMetadata.cs  <- the record; JsonIgnoreCondition + empty-array omission
        MetadataDocumentBuilder.cs
        IMetadataContributor.cs         <- N-06: a key exists iff its module registered
        MetadataConsistencyValidator.cs <- N-06 startup assertion, incl. the EndpointDataSource check
        WellKnownEndpoints.cs           <- E-01..E-06, all five shapes, one route table
      Keys/  Tokens/  Sessions/  Consent/  Registration/  Introspection/  Revocation/  Logout/  UserInfo/
      Startup/ForwardedHeadersSetup.cs  <- the ONLY place Request.Host/Scheme may be named (N-13)
      Startup/SecurityHeaders.cs        <- N-15, via Response.OnStarting
      Startup/ConfigSchema.cs           <- A-17 (§6.2)
      BoltwayAuthorizationServerExtensions.cs
    Boltway.AuthorizationServer.UI/   Areas/Boltway/Pages/ · TagHelpers/ · Branding/
    Boltway.Storage.EntityFrameworkCore/  BoltwayDbContext.cs · Entities/ · Configurations/ · Stores/ · Conventions/
    Boltway.Storage.Sqlite/  Boltway.Storage.PostgreSql/   Migrations/
    Boltway.Federation.Google/
    Boltway.Conformance/
    Boltway.AuthorizationServer.Host/
  tests/
    Boltway.OAuth.Primitives.Tests/
    Boltway.AuthorizationServer.Tests/
    Boltway.Storage.Tests/            <- one contract suite, three providers (§7.2)
    Boltway.Architecture.Tests/       <- Cecil. N-03, N-05, N-12, N-13, N-16 (§7.3)
    Boltway.ResourceServer.Tests/
    fixtures/cimd/*.json                   <- the four live documents, checked in (§7.4)
```

---

## 3. The domain model

### 3.1 Entities

Instants are `DateTimeOffset` in C#, `long` Unix-milliseconds in the database (§3.2). Every entity's
first column is `RealmId`. Every surrogate key is a `Ulid` stored as a 26-character Crockford base32
string (§3.2.4).

| Entity | Key | Fields that carry a requirement |
|---|---|---|
| `Realm` | `RealmId` | `Issuer` (raw string, `N-13`), `DisplayName`, `CreatedAt` |
| `Client` | `(RealmId, ClientId)` | `ClientKind` {`PreRegistered`,`Dynamic`} (`C-01` — **never re-derive from an `https://` prefix**), `ClientType` {`Public`,`Confidential`} (`S-05` §8.4), `TokenEndpointAuthMethod`, `SecretHash`+`SecretAlgorithm`, `JwksUri`, `JwksJson`, `GrantTypes`, `ResponseTypes`, `ScopeSet`, `Name`, `LogoUri`, `RegistrationAccessTokenHash`, `SoftwareId/Version`, `CreatedAt`, `LastUsedAt`, `ExpiresAt` (`C-18` TTL+GC) |
| `ClientRedirectUri` | `(RealmId, ClientId, Ordinal)` | `Raw` (**exact bytes as registered**), `Kind` {`Https`,`Loopback`,`PrivateUseScheme`}, `LoopbackKey` (precomputed, `N-04`) |
| `ResourceRegistration` | `(RealmId, Resource)` | `Resource` is any HTTPS URL **including a path** (`A-22`), `Name`, `ScopeSet`, `RequireResourceParameter` |
| `ScopeDefinition` | `(RealmId, Name)` | `DisplayName`, **`Description` rendered verbatim on consent (`A-14`)**, `EmphasizeOnConsent`, `IsDefault`. Normalized and validated on write (`A-13`) |
| `User` | `(RealmId, UserId)` | `SubjectId` (the emitted `sub`, `A-18`), `Username`, `EmailNormalized`, `PasswordHash` (Argon2id encoded string, or null for federated-only), `EmailVerified`, `DisabledAt` |
| `ExternalLogin` | `(RealmId, UpstreamIssuer, UpstreamSubject)` | `UserId`. **Exists from day one with one row per user (`D-10`).** The local `sub` is minted by us and never passed through from upstream |
| `AuthSession` | `(RealmId, SessionId)` | `UserId`, `Sid`, `AuthTime`, `Amr`, `Acr`, `ExpiresAt`, `ClientsUsed` (`D-09` seam) |
| `Grant` | `(RealmId, GrantId)` | `UserId`, `ClientId`, `ScopeSet`, `Resources` (**the grant set**, `S-18`), `CreatedAt`, `RevokedAt`, `RevocationReason` |
| `AuthorizationCode` | `(RealmId, CodeHash)` | `GrantId`, `ClientId`, `RedirectUriRaw`, `CodeChallenge`, `CodeChallengeMethod`, **`PkceWasRequested`** (`N-02` XOR), `Nonce`, `AuthTime`, `Sid`, `ScopeSet`, `Resources`, `IssuedAt`, `ExpiresAt`, `RedeemedAt`. **Rows are retained after redemption until `ExpiresAt`** so `N-07`'s "validate first, revoke second" is possible |
| `RefreshToken` | `(RealmId, TokenHash)` | `GrantId`, `FamilyId`, `ParentHash`, `ConsumedAt`, `SuccessorHash`, `IssuedAt`, `ExpiresAt`, `RevokedAt` (`N-08`) |
| `GrantRevocation` | `(RealmId, GrantId)` | `RevokedAt`, `NotAfter` — the denylist an RS consults for `X-33`. Rows GC'd at `NotAfter` |
| `SigningKey` | `(RealmId, Kid)` | `Alg`, `Use`, `PublicJwkJson`, `ProtectedPrivateKey`, `PublishFrom`, `SignFrom`, `SignUntil`, `PublishUntil` (§8.5 rotation) |
| `ClientAssertionJti` | `(RealmId, ClientId, Jti)` | `ExpiresAt` — `private_key_jwt` replay (`X-18`) |
| `ConsentGrant` | `(RealmId, UserId, ClientId)` | `ScopeSet`, `Resources`, `GrantedAt`, `ExpiresAt`. **Consulted only for confidential clients** (`N-14`, `S-05` §8.6) |

**Not an entity, deliberately:** a CIMD client. `A-08` requires 100 sequential CIMD connects to leave
the client-table row count unchanged. `CimdClientResolver` produces a **transient** `ResolvedClient`
from `ClampedTtlCache`; nothing is persisted. This is the single most important thing to not get
wrong in the storage layer, because "just cache it in the clients table" is the obvious move and it
breaks the zero-registration property CIMD exists for.

### 3.2 EF Core mapping across SQLite and PostgreSQL

Four provider divergences, four decisions, all applied globally in `ConfigureConventions` so no
per-entity discipline is required.

**3.2.1 Instants → `long` Unix milliseconds.** SQLite stores `DateTimeOffset` as TEXT-with-offset,
which does not order correctly; PostgreSQL stores `timestamptz`. Sidestep both.

```csharp
// Conventions/UnixMillisecondsConverter.cs
public sealed class UnixMillisecondsConverter()
    : ValueConverter<DateTimeOffset, long>(
        v => v.ToUnixTimeMilliseconds(),
        v => DateTimeOffset.FromUnixTimeMilliseconds(v));

protected override void ConfigureConventions(ModelConfigurationBuilder b)
{
    b.Properties<DateTimeOffset>().HaveConversion<UnixMillisecondsConverter>();
    b.Properties<ScopeSet>().HaveConversion<ScopeSetConverter, ScopeSetComparer>().HaveMaxLength(2048);
    b.Properties<ClientIdentifier>().HaveConversion<ClientIdentifierConverter>().HaveMaxLength(512);
    b.Properties<ResourceIdentifier>().HaveConversion<ResourceIdentifierConverter>().HaveMaxLength(512);
    b.Properties<RealmId>().HaveConversion<RealmIdConverter>().HaveMaxLength(64);
    b.Properties<Sha256Hash>().HaveConversion<Sha256HashConverter>().HaveMaxLength(43);  // base64url, unpadded
    b.Properties<Ulid>().HaveConversion<UlidConverter>().HaveMaxLength(26).AreFixedLength();
    b.Properties<string>().AreUnicode(true).HaveMaxLength(512);                          // default cap
}
```

Bonus: `exp`/`iat`/`auth_time` are NumericDate in JWTs, so the stored value is the emitted value with
no conversion, and `WHERE expires_at <= @now` is an index range scan on both providers. Cost: raw SQL
readability. Accepted; the `doctor` command prints instants humanly.

**3.2.2 No arrays.** Split by how the value is used, not by convenience.

- **Queried or uniqueness-constrained → child table.** Only `ClientRedirectUri` qualifies. It needs a
  count (`X-02`: "missing with ≠1 registered") and it needs per-URI metadata (`Kind`, `LoopbackKey`).
- **Read whole, never queried → a delimited value object.** `ScopeSet`, `GrantTypes`,
  `ResponseTypes`, `Resources`. `ScopeSet` serializes **space-delimited**, which is the wire format
  already; `A-13` forbids internal whitespace in a scope on write, so the delimiter is unambiguous
  *and validated*. `Resources` serializes newline-delimited (a newline cannot appear in a URI, and it
  is visually distinct in a database dump).

```csharp
public sealed class ScopeSetConverter()
    : ValueConverter<ScopeSet, string>(v => v.ToWireFormat(), v => ScopeSet.ParseTrusted(v));

// The trap: without a ValueComparer, EF treats ScopeSet as a mutable reference type and
// misses changes. Every collection-shaped converter needs its comparer registered with it.
public sealed class ScopeSetComparer()
    : ValueComparer<ScopeSet>((a, b) => a!.Equals(b), v => v.GetHashCode(), v => v.Clone());
```

**3.2.3 No native JSON columns.** SQLite's JSON support is a function library, not a column type, and
`jsonb` is Postgres-only. Every JSON-shaped field (`PublicJwkJson`, `JwksJson`, extensible property
bags) is `TEXT`/`text` through a `ValueConverter<T,string>` over a source-generated
`JsonSerializerContext`. **We never query inside them.** If a customer later needs `jsonb` querying,
that is a provider-specific `IEntityTypeConfiguration<T>` override in `Boltway.Storage.PostgreSql`
applied after the shared configuration — the seam exists, v1 does not use it.

**3.2.4 No `Guid`, no `identity`/`serial`.** `Guid` maps to `uuid` on Postgres and TEXT-or-BLOB on
SQLite, and the two orderings differ. Every surrogate key is `Ulid` — 128 bits, timestamp-prefixed,
rendered as 26 characters of Crockford base32, so it sorts lexicographically as TEXT on both
providers and is index-friendly. Client-generated, so inserts need no round-trip.

This also hands us `A-18` for free: **the `sub` we emit is a `Ulid`, charset `[0-9A-HJKMNP-TV-Z]{26}`.**
No `|`, no `/`, no `.`, no `@`. It is safe as a path segment, a filename, a cache key and a
column name, and the charset is documented in the metadata service documentation. This is a
deliberate improvement on `auth0|<hex>`, which forced FictStory to write a sanitiser and a
collision-disambiguation path.

**3.2.5 The rule that dissolves collation.** SQLite's `NOCASE` and PostgreSQL's collations differ,
and `A-13`/`N-03`/`S-28` all demand ordinal comparison.

> **Every security-relevant comparison happens in C# with `StringComparison.Ordinal`, never in a
> `WHERE` clause.** The database is a lookup keyed by a primary key or a hash. Any candidate set
> fetched by a looser query is re-filtered ordinally in memory before a decision is made.

That is enforceable (`Ordinal.cs` is the only place a `StringComparison` literal appears; an
architecture test asserts it) and it removes an entire class of provider divergence.

**3.2.6 Atomicity without a provider-specific concurrency token.** `N-07` and `N-08` both require
"rows-affected is the authority". `xmin` is Postgres-only and `rowversion` is SQL Server-only.
`ExecuteUpdateAsync` generates one statement on both providers and returns the affected count:

```csharp
public async Task<bool> TryMarkRedeemedAsync(RealmId realm, Sha256Hash hash, DateTimeOffset at, CancellationToken ct)
    => await db.AuthorizationCodes
        .Where(c => c.RealmId == realm && c.CodeHash == hash && c.RedeemedAt == null)
        .ExecuteUpdateAsync(s => s.SetProperty(c => c.RedeemedAt, at), ct) == 1;
```

A `false` return from a code that exists **is** the replay signal. The atomicity requirement is
stated in the store interface (§4.5) so an alternative store cannot implement it non-atomically
without noticing.

---

## 4. Extensibility seams

Nine seams. For each: the signature, what ships, what a customer writes. Two conventions run through
all of them and are the reason to prefer these over the obvious shapes:

- **No seam takes `HttpContext`.** They take request-shaped DTOs, so `Abstractions` needs no ASP.NET
  reference and a customer can unit-test an implementation in a class library.
- **Every seam whose misimplementation is a security defect ships with a guard decorator registered
  by our DI extension, not by the customer.** The engine re-applies the invariant on the way out. A
  seam is a place to change *policy*, never a place to reintroduce a defect.

### 4.1 Client authentication (`E-10`, `C-03`, `D-03`)

```csharp
public interface IClientAuthenticator
{
    /// The token_endpoint_auth_method value this handles. Contributed to metadata (N-06).
    string Method { get; }
    ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context, CancellationToken ct);
}

public sealed record ClientAuthenticationContext(
    RealmId Realm,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Form,
    AuthorizationHeaderCredentials? Header,
    string EndpointUrl,                          // U-08: accept issuer OR exact endpoint as `aud`
    IReadOnlyList<string> AcceptableAudiences,
    DateTimeOffset Now);

public abstract record ClientAuthenticationResult
{
    public sealed record NotAttempted : ClientAuthenticationResult;
    public sealed record Authenticated(ClientIdentifier ClientId, string Method) : ClientAuthenticationResult;
    public sealed record Failed(string ErrorDescription, bool CredentialCameFromHeader)
        : ClientAuthenticationResult;
}
```

**Ships:** `None`, `ClientSecretBasic`, `ClientSecretPost`, `PrivateKeyJwt`. **Customer writes:**
`TlsClientAuthAuthenticator` (`D-03`) — one class, one `AddClientAuthenticator<T>()` call.

`X-17`'s "more than one client-authentication mechanism" rule lives in
`ClientAuthenticationDispatcher`, not in the implementations, so a third-party authenticator cannot
break it. `X-18`'s "401 iff the credential came from the header" is why `Failed` carries
`CredentialCameFromHeader` rather than the dispatcher guessing.

### 4.2 External identity provider (`D-10`)

```csharp
public interface IExternalIdentityProvider
{
    string Scheme { get; }                       // "google"
    string DisplayName { get; }
    /// A-11: when unavailable, the login page renders a DISABLED control with this reason,
    /// rather than the provider silently vanishing.
    ValueTask<ProviderAvailability> GetAvailabilityAsync(RealmId realm, CancellationToken ct);
    ValueTask<ExternalChallenge> BeginAsync(ExternalLoginContext context, CancellationToken ct);
    ValueTask<ExternalLoginResult> CompleteAsync(ExternalCallbackContext context, CancellationToken ct);
}

public sealed record ExternalIdentity(
    string UpstreamIssuer, string UpstreamSubject,
    string? Email, bool EmailVerified, string? Name, string? PictureUri,
    IReadOnlyDictionary<string, string> RawClaims);
```

**Ships:** `OidcExternalProvider` (abstract base — issuer, client id/secret, scopes) and
`OAuth2ExternalProvider` (for GitHub-shaped providers that are not OIDC), with
`GoogleOidcProvider : OidcExternalProvider` as the reference. **Customer writes:** `sealed class
FacebookProvider : OidcExternalProvider` — a constructor and a claim map. Two bases rather than one
because GitHub has no ID token and pretending otherwise produces a base class full of nulls.

The seam **cannot** return a local `sub`: it returns `ExternalIdentity`, and `IUserProvisioner` maps
`(UpstreamIssuer, UpstreamSubject)` → local `User` through the `ExternalLogin` table. This is `D-10`
made structural — the disambiguation surface that FictStory's `identity.ts` had to reason about
cannot open, because upstream subjects never become local ones.

### 4.3 Token format and minting (`D-02`)

```csharp
public interface IAccessTokenFormat
{
    string TokenType { get; }                    // "Bearer"
    ValueTask<MintedToken> MintAsync(AccessTokenRequest request, CancellationToken ct);
}

public sealed record AccessTokenRequest(
    RealmId Realm, IssuerString Issuer, GrantId GrantId, SubjectId Subject,
    ClientIdentifier ClientId, ScopeSet Scopes,
    ResourceIdentifier Audience,                 // exactly ONE, and it has been validated
    DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    IReadOnlyList<Claim> AdditionalClaims);
```

**`Audience` is a single `ResourceIdentifier`, not a list, and that is `N-01` made structural.** You
cannot construct a request to mint an access token without naming exactly one validated resource.
There is no field to leave empty and no default to fall back to. The v1 policy — one resource per
access token; `/authorize` may carry several (the grant set), `/token` must name exactly one from
that set or get `X-23 invalid_target` — is expressed by the type rather than by a check somewhere.

**Ships:** `JwtAccessTokenFormat` (RFC 9068: `typ: at+jwt`, the seven required claims, `scope` as a
space-delimited string). **Guard decorator:** `MintedTokenAssertions` parses our own output once and
asserts `typ`, `aud` == the requested resource, and `iss` ordinal-equals `IssuerString`. One JWT
parse on a path with a 10-second budget is free, and it means a custom format cannot silently break
`N-01` or `N-09`.

**Customer writes:** an opaque `ReferenceAccessTokenFormat`. v1 ships this only as a test double, but
the double is a real implementation living in `Boltway.AuthorizationServer.Tests` — a seam whose
only implementation is the shipping one has not been proven to be a seam.

`D-02`'s DPoP requirement is discharged here: a `cnf`/`jkt` claim enters through `AdditionalClaims`
with no restructuring.

### 4.4 Claim mapping

```csharp
[Flags] public enum ClaimDestination { IdToken = 1, AccessToken = 2, UserInfo = 4 }

public interface IClaimSource
{
    ClaimDestination Destinations { get; }
    ValueTask ContributeAsync(ClaimContributionContext context, IClaimSink sink, CancellationToken ct);
}

public interface IClaimSink
{
    void Add(string name, string value);
    void Add(string name, long value);
    void Add(string name, bool value);
    void AddArray(string name, IReadOnlyList<string> values);
}
```

A **sink**, not a dictionary, and that is the point. `ClaimSink` throws `ReservedClaimException` for
`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `typ`, `azp`, `scope`, `client_id`, `cnf`. A customer
extension therefore **cannot** unify the ID-token and access-token audiences, which is `N-10`
surviving third-party code. A dictionary return type would make that a code review problem forever.

**Ships:** `StandardProfileClaimSource` (`profile`/`email` scopes → the OIDC standard claims),
`AuthenticationContextClaimSource` (`auth_time`, `amr`, `acr`). **Customer writes:** an
`OrganizationClaimSource` that adds `org_id` — the single most common request, and it is ten lines.

### 4.5 Stores

Split by aggregate, not one god interface, so a customer replacing user storage does not have to
reimplement refresh-token rotation. `IClientStore`, `IUserStore`, `IExternalLoginStore`,
`IAuthorizationCodeStore`, `IRefreshTokenStore`, `IGrantStore`, `IConsentStore`, `ISigningKeyStore`,
`IResourceStore`, `IScopeStore`, `IClientAssertionReplayStore`, `IRealmStore`.

Two carry a requirement in their signature:

```csharp
public interface IAuthorizationCodeStore
{
    Task StoreAsync(AuthorizationCodeRecord record, CancellationToken ct);
    Task<AuthorizationCodeRecord?> FindAsync(RealmId realm, Sha256Hash code, CancellationToken ct);

    /// MUST be atomic. Returns true iff THIS call transitioned the code from unredeemed to
    /// redeemed. A false return for a code that exists is a replay (N-07) — and the caller
    /// runs full validation before acting on it, so an implementation that races here
    /// converts a DoS defence into a DoS.
    Task<bool> TryMarkRedeemedAsync(RealmId realm, Sha256Hash code, DateTimeOffset at, CancellationToken ct);
}

public interface IRefreshTokenStore
{
    Task<RefreshTokenRecord?> FindAsync(RealmId realm, Sha256Hash token, CancellationToken ct);

    /// MUST be atomic: consumes `parent` and records `successor` in one statement.
    /// AlreadyConsumed carries the winner's successor so the loser can return the same
    /// token inside the idempotency window. Exactly one successor per parent, ever —
    /// forking the family here is GHSA-392p-2q2v-4372 (N-08).
    Task<RefreshConsumeResult> TryConsumeAsync(
        RealmId realm, Sha256Hash parent, RefreshTokenRecord successor,
        DateTimeOffset at, CancellationToken ct);

    Task RevokeFamilyAsync(RealmId realm, GrantId family, DateTimeOffset at, string reason, CancellationToken ct);
}
```

Putting atomicity **in the interface contract** is what makes the store a real seam. A customer
writing a DynamoDB store now knows which two operations need a conditional write, and the store
contract test suite (§7.2) runs concurrency tests against their implementation.

**Ships:** EF Core (SQLite + PostgreSQL) and in-memory. **Customer writes:** whatever they already
run, one aggregate at a time — `AddEntityFrameworkStores()` then `.ReplaceStore<IUserStore, MyUserStore>()`.

### 4.6 Authorization-request source — the PAR seam (`D-01`)

```csharp
public interface IAuthorizationRequestSource
{
    int Order { get; }
    /// Returns null when this source does not apply to the request.
    ValueTask<AuthorizationRequestParameters?> TryReadAsync(
        AuthorizationRequestInput input, CancellationToken ct);
}

public sealed record AuthorizationRequestInput(
    RealmId Realm,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Query,
    string? RequestUri, string? RequestObject);

public sealed record AuthorizationRequestParameters(
    IReadOnlyDictionary<string, IReadOnlyList<string>> Values,
    AuthorizationRequestOrigin Origin);

public enum AuthorizationRequestOrigin { QueryString, PushedRequest, RequestObject }
```

**Ships:** `QueryStringRequestSource`, the only v1 implementation. Adding `ParRequestUriSource` is
purely additive. `REQUIREMENTS.md` calls `D-01` "the *one* deferral that costs real rework later", so
three details are worth the cost now:

- `Values` is **list-valued**, so `X-04`'s repeated-parameter rule (every parameter except `resource`)
  is applied once in `AuthorizeRequestReader` and applies to PAR the day PAR lands.
- `Origin` exists so a per-client "PAR required" policy is expressible without changing the shape.
- `RequestObject` is in the input DTO even though `request_parameter_supported: false` — so JAR
  (`D-12`) does not force a second signature change. `D-12` also notes RFC 8707 §2.1: inside a request
  object, `resource` is `string | string[]`, which is why the value type is a list here too.

### 4.7 Subject identifier (`D-11`, `A-18`)

```csharp
public interface ISubjectIdentifierService
{
    ValueTask<SubjectId> GetSubjectAsync(
        RealmId realm, UserId user, ClientIdentifier client, SubjectContext context, CancellationToken ct);
}
```

**Ships:** `PublicSubjectIdentifierService` — ignores `client`, returns `User.SubjectId` (the Ulid).
**Customer/v1.1:** `PairwiseSubjectIdentifierService` keyed on `sector_identifier_uri`.

Called from exactly three places: the ID token, the access token, and UserInfo. An architecture test
asserts nothing else writes a `sub` claim, so pairwise stays consistent when it lands — that is the
failure mode `D-11` is guarding against, and it is a real one (a pairwise `sub` in the ID token and a
public one at UserInfo is a silent identity split).

### 4.8 Consent (`N-14`, `A-14`, `A-15`)

```csharp
public interface IConsentPolicy
{
    ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken ct);
}
public abstract record ConsentDecision
{
    public sealed record Prompt(IReadOnlyList<ScopeDisclosure> Scopes) : ConsentDecision;
    public sealed record Skip(ConsentGrantId Existing) : ConsentDecision;
    public sealed record Deny(string Reason) : ConsentDecision;
}
```

**Guard decorator, registered by us:** `ConsentPolicyGuard` re-tests `ClientType` on the way out and
downgrades `Skip` to `Prompt` for **every public client**, whatever the policy returned. `S-05` §8.6
and `N-14` are then true regardless of what a customer's policy does. This is the pattern in its
clearest form: the seam changes policy; it cannot remove the invariant.

`A-15` — "no configuration key exists to disable correct consent rendering" — is enforced by §8.3:
the disclosure block is a **tag helper**, not a view, so a customer overriding the consent page
cannot omit it without the page failing to compile the expected marker (asserted by a render test).

### 4.9 Signing-key protection

```csharp
public interface ISigningKeyProtector
{
    ValueTask<byte[]> ProtectAsync(RealmId realm, byte[] privateKeyPkcs8, CancellationToken ct);
    ValueTask<byte[]> UnprotectAsync(RealmId realm, byte[] protectedBlob, CancellationToken ct);
}
```

**Ships:** `DataProtectionKeyProtector` (default; key ring in the DB, root key from
`Keys:MasterKey`) and `DevelopmentNullProtector` (**refuses to start when
`ASPNETCORE_ENVIRONMENT=Production`**). **Customer writes:** the AWS KMS / Azure Key Vault / Vault
transit one. This seam exists at v1 because "where do the private keys live" is the first question
every customer security review asks, and answering it with a code change is a lost week.

### 4.10 Where I refuse to generalize

Generality has a price in indirection, and these are the places where the price is not worth paying
because the flexibility is exactly the vulnerability:

- **The redirect-URI matcher.** No interface. `internal static class RedirectUriMatcher`. Every
  customer who "just needs a wildcard for staging" is describing the open redirector that leaks
  `code` and `state` (`N-03`). The answer is to register the staging URI. A customer who genuinely
  needs different behaviour forks and owns it, visibly.
- **PKCE.** No `IPkcePolicy`. Unconditional `S256` (`N-02`). The draft's own confidential-client
  carve-out is declined in §1 of the requirements; adding a seam would re-open it.
- **The issuer.** No `IIssuerProvider`, no `IIssuerResolver` in v1. One config value, one
  `IssuerString` singleton (`N-13`).
- **The `alg` allow-list.** Configuration may **narrow** the set (RS256 only); the union is a
  compile-time constant. No `IAlgorithmPolicy`, because that is where `alg: none` re-enters
  (`N-09`, `S-23`).
- **The error-code mapping.** `X-01`..`X-41` is a static table. No `IErrorMapper`. Clients branch on
  exact strings (`C-20`: "`invalid_grant`, not `invalid_request` or a custom code"; `C-24`: any 403
  that is not `insufficient_scope` is terminal for Claude), so a customer "improving" a code is a
  client-breaking change dressed as configuration.
- **The well-known route paths.** Not configurable. `S-08`/`A-21` fix all five shapes.
- **Grant types.** The dispatcher is table-driven (`D-04` needs it), but registering a grant is an
  explicit `AddGrantType<T>()` call in code and the metadata contributor is derived from the
  registration — never from a config string. `N-06` requires advertised == actual, and a config
  string that adds a metadata entry without adding a handler is the exact failure it names.

---

## 5. Request pipeline

### 5.1 Application-level, before any endpoint

1. `UseForwardedHeaders` with `ForwardLimit = 1` and an **explicit** `KnownProxies` entry.
   `N-13`: clearing `KnownProxies`/`KnownNetworks` without re-adding the proxy trusts `X-Forwarded-*`
   from anyone. `ForwardedHeadersSetup.cs` is the only file permitted to name `HttpRequest.Host` or
   `HttpRequest.Scheme` (architecture test, §7.3).
2. HSTS (`S-33`), 1 year + subdomains + preload.
3. `SecurityHeaders` middleware, setting `N-15`'s headers in `Response.OnStarting` so Razor and the
   Identity UI cannot clobber them: CSP `default-src 'self'; frame-ancestors 'none'; form-action 'self';
   base-uri 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
4. Realm resolution (§0.1). Unknown host → 404 with `Cache-Control: no-store`.
5. Correlation id assigned and pushed into the logging scope (`A-09`), echoed as `X-Request-Id`.
6. **No global CORS.** `E-08` forbids CORS at `/authorize`; a global `UseCors` is how that gets
   violated. Per-endpoint `.RequireCors("oauth-public")` on `E-01`..`E-07`, `E-10`..`E-17`.
7. **No global fallback authorization policy.** A `FallbackPolicy = RequireAuthenticatedUser()` 401s
   the discovery documents — a documented, repeatedly-observed connector failure. Every
   `/.well-known/*` route carries an explicit `.AllowAnonymous()`, and an architecture test asserts
   no `FallbackPolicy` assignment exists in the AS.
8. Unmatched `/.well-known/*` → bare 404, `no-store`, no HTML, no SPA fallback, no redirect.

### 5.2 `/authorize` (E-08) — the ordering is itself `N-11`

```
 1  Rate limit (IP + client_id), before any body or outbound fetch
 2  IAuthorizationRequestSource dispatch                              (D-01 seam)
 3  Duplicate-parameter check — every parameter except `resource`     -> X-04 (but see step 8)
 4  client_id present, well-formed, non-empty?                        -> X-01  HTML 400, NO Location
 5  Client resolution by ClientKind discriminator:
       CIMD  -> GuardedFetcher, <=2s budget, stale-on-error           -> X-03  HTML 400, NO Location
       else  -> IClientStore                                          -> X-01  HTML 400, NO Location
 6  Client enabled?                                                   -> X-01  HTML 400, NO Location
 7  redirect_uri selection + EXACT ordinal match (N-03/N-04)          -> X-02  HTML 400, NO Location
    ================== THE LINE — redirect_uri is now trusted ==================
 8  AuthorizeErrorBoundary.Run(async () => {          // catch-all -> X-10 server_error AS A REDIRECT
 9      response_type == "code"                                       -> X-07  303
10      client permits authorization_code + code                      -> X-05  303
11      PKCE: challenge present, method == S256, grammar 43*128       -> X-04  303   (N-02)
12      request / request_uri / registration present                  -> X-16  303
13      prompt / max_age parse                                        -> X-04  303
14      scope resolution against ScopeDefinition                      -> X-08  303
15      resource resolution against ResourceRegistration              -> X-09  303   (N-01)
16      authenticate: session present? auth_time vs max_age?
             prompt=none and no session                               -> X-12  303
             else -> 303 to /login (returnUrl gated by Url.IsLocalUrl)
17      consent: IConsentPolicy -> ConsentPolicyGuard
             prompt=none and consent needed                           -> X-13  303
             else -> 303 to /consent
18      issue code: hash-stored, PkceWasRequested, redirect_uri raw,
                    sid, auth_time, scope set, RESOURCE GRANT SET
19      303 to redirect_uri with code + state (verbatim) + iss        (S-27, always, incl. errors)
    })
```

Steps 4–7 are the whole of `N-11`. Two structural notes:

- **`AuthorizeErrorBoundary` makes "after the line" a lexical fact.** Everything from step 9 runs
  inside a delegate passed to it. `X-10` exists precisely because "a 500 … cannot be returned to the
  client via an HTTP redirect", so an HTTP 500 escaping `/authorize` past step 7 is a defect —
  and now it is a defect that requires moving code out of a lambda rather than forgetting a
  `try/catch`.
- **`X-09` never distinguishes "unknown resource" from "client not permitted for this resource".**
  Same error, same description. It is an enumeration oracle otherwise.

Latency (`C-29`): the CIMD fetch at step 5 is inside a 10-second total budget. Budget it at ≤2s,
serve stale on error, warn-log at 25% of budget. No Argon2 verification and no synchronous migration
anywhere on this path.

### 5.3 `/token` (E-10)

```
 1  Cache-Control: no-store, unconditionally, via Response.OnStarting
 2  POST or 405. Content-Type parsed as a MEDIA TYPE with parameters ignored
    (§10: chatgpt.com sends `application/json; charset=utf-8` on its documents; equality
     comparison against a bare type is the bug that rejects every ChatGPT document — the
     same parser is used here). Wrong type -> X-17 400 + OAuth JSON body. NEVER 415.
 3  Form parse from Request.Form. Duplicate-parameter check.
 4  ClientAuthenticationDispatcher:
       zero attempted and grant needs a client -> X-18
       more than one attempted                 -> X-17
       failed                                  -> X-18, 401 iff header credential (+WWW-Authenticate)
 5  GrantDispatcher lookup on grant_type                              -> X-21 (never X-17)
 6  Client permits this grant type                                    -> X-20
 7  Grant handler:
      authorization_code:
         code hash lookup; if RedeemedAt != null -> CodeReplayHandler:
             run FULL validation first (client binding, PKCE, redirect_uri) -> X-19
             only if it ALL passes, revoke descendants                      (N-07)
         validate client binding, redirect_uri (accept-not-require, S-02),
         PKCE strict XOR against PkceWasRequested                     -> X-19 (N-02)
         TryMarkRedeemedAsync -> false means replay, go to CodeReplayHandler
      refresh_token:
         hash lookup; family revoked -> X-19
         TryConsumeAsync:
             Consumed        -> mint successor
             AlreadyConsumed -> inside 30-60s window: return the winner's successor
                                outside: RevokeFamilyAsync, X-19                 (N-08)
 8  Resource: exactly one, and it must be in the grant set            -> X-23 (never X-19)
 9  Scope narrowing against the grant                                 -> X-22
10  Mint: access token (aud = the resource, typ = at+jwt)
          refresh token (rotated, new family member)
          id_token IFF `openid` is in scope (aud = client_id)         (N-10, C-13)
11  200 application/json
```

`X-23` never becomes `X-19`: clients treat `invalid_grant` as "the refresh token is dead" and discard
it, converting a recoverable resource-selection error into a re-consent loop.

---

## 6. Configuration model

### 6.1 Shape and validation

```csharp
public sealed class BoltwayOptions
{
    /// The one immutable issuer identifier. https, no query, no fragment, no trailing slash.
    /// Emitted byte-for-byte as `issuer`, every `iss`, and the RFC 9207 parameter (N-13).
    [Required] public string Issuer { get; init; } = "";
    public ClientAcquisitionOptions ClientAcquisition { get; init; } = new();
    public TokenLifetimeOptions Lifetimes { get; init; } = new();
    public KeyOptions Keys { get; init; } = new();
    public UiOptions Ui { get; init; } = new();
    public StorageOptions Storage { get; init; } = new();
    public OutboundOptions Outbound { get; init; } = new();
}
```

Bound with `.Bind(section, o => o.ErrorOnUnknownConfiguration = true)` — that is the actual mechanism
behind `A-16`'s "unknown keys are rejected loudly, never silently dropped", and it costs one lambda.
Then `.ValidateDataAnnotations().Validate(...).ValidateOnStart()`.

Cross-cutting validation lives in `IValidateOptions<BoltwayOptions>` implementations, one per
rule, each naming its requirement:

- `IssuerValidator` (`N-13`): `https`, no query/fragment, no trailing slash, and **ordinal-equal to
  the value the token signer will emit**.
- `ClientAcquisitionValidator` (`N-06`/`A-05`): refuses to boot if `registration_endpoint` and
  `client_id_metadata_document_supported` would both appear. The message names the offending pair.
- `LifetimeValidator` (`C-19`): access-token TTL must exceed 5 minutes or Claude's proactive refresh
  thrashes. Default 15 minutes.
- `ScopeValidator` (`A-13`): scope names trimmed, no internal whitespace, no non-printables, no
  duplicates — and the error names the offending codepoint.

**`MetadataConsistencyValidator` is the strongest of these** and deserves its own note. It runs as an
`IStartupFilter` after routing is built and asserts, mechanically, that **every absolute URL in the
metadata document resolves to a route in `EndpointDataSource`**. That is `N-06` — "advertised
capability == actual capability" — reduced to a graph lookup rather than a promise. It is what
catches "CIMD advertised before the resolver was registered" and "`registration_endpoint` still
advertised after DCR was switched off".

`A-04` requires the toggle to take effect **without a restart**. The metadata document is built from
`IOptionsMonitor` and rebuilt on change — and **a hot-reloaded configuration that fails validation
does not take effect**: the old document is kept and the failure is logged at Error with the
correlation id. Silently serving an inconsistent document is worse than not reloading.

### 6.2 `A-17` without a hand-maintained second list

`GET /admin/config/schema` (`E-21`) must list every key with type, allowed values, default and
current value. Building that list by hand is exactly what `A-17` exists to prevent.

**Mechanism:** `ConfigSchema.Build()` reflects the options tree once at startup and reads:

| Column | Source |
|---|---|
| key path | property path, `:`-joined (`Lifetimes:AccessToken`) |
| type | the CLR type, mapped to a JSON type name |
| allowed values | enum members, or `[AllowedValues]`, or `[Range]` |
| default | the value on a freshly-constructed `new BoltwayOptions()` |
| current | the value from `IOptionsMonitor<T>.CurrentValue`, redacted when `[Secret]` |
| description | the `///` summary |

The description column is the only hard part. **v1: mark the generated XML documentation file as an
`EmbeddedResource` and parse it at startup** (`GenerateDocumentationFile` is already on in
`Directory.Build.props`). ~120 lines, no source generator, and the file is guaranteed present because
it is embedded rather than deployed alongside.

```xml
<ItemGroup>
  <EmbeddedResource Include="$(DocumentationFile)" LogicalName="Boltway.Options.xml" />
</ItemGroup>
```

A test asserts every options property has a summary, so "add a key, forget to document it" fails the
build. *Rejected:* a Roslyn source generator (better, but a week of work for the same output);
runtime XML file lookup next to the assembly (breaks in single-file and trimmed publishes).

The same builder backs `boltway doctor --print-config`, so the schema is inspectable without an
HTTP surface — which matters when the deadline halves (§8).

---

## 7. Testing architecture

### 7.1 Traceability: every one of the 187 IDs reaches a test

`docs/requirements.md` is checked into the repo and is the **canonical** ID list. Tests carry:

```csharp
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public sealed class RequirementAttribute(params string[] ids) : Attribute, ITraitAttribute
{
    public IReadOnlyList<string> Ids => ids;
    public IReadOnlyCollection<KeyValuePair<string,string>> GetTraits()
        => [.. ids.Select(id => new KeyValuePair<string,string>("requirement", id))];
}

[Fact, Requirement("N-01", "A-01")]
public async Task Token_issued_for_resource_A_is_rejected_at_resource_B() { … }
```

`RequirementCoverageTests` then:

1. parses the ID tables out of `docs/requirements.md`;
2. reflects over every test assembly for `[Requirement]`;
3. asserts every **binding** ID (170 of 187 — `U-nn` rows are questions) has at least one test;
4. asserts every `D-nn` has a **seam-exists** test — a compile-time assertion that the named interface
   is present with the named shape, so a deferral cannot quietly become an omission;
5. asserts no `[Requirement]` cites an ID that does not exist (catches typos and stale IDs);
6. writes `artifacts/requirement-coverage.json`.

That file is the sellable artifact. A customer's security review asks "how do you know you implement
RFC 8707 correctly"; the answer is a matrix with a test name in every row, generated by the build.
This is the same instinct as `LESSONS.md` rule 1 — every axis needs a third value — applied to our own
conformance claims: `covered` / `not covered` / **`deliberately deferred, seam asserted`**.

### 7.2 Store contract suites: one suite, three providers

```csharp
public abstract class RefreshTokenStoreContract
{
    protected abstract Task<IRefreshTokenStore> CreateAsync();

    [Fact, Requirement("N-08")]
    public async Task Two_concurrent_consumptions_produce_exactly_one_successor()
    {
        var store = await CreateAsync();
        var (a, b) = (NewSuccessor(), NewSuccessor());
        var results = await Task.WhenAll(
            store.TryConsumeAsync(Realm, parent, a, Now, default),
            store.TryConsumeAsync(Realm, parent, b, Now, default));
        Assert.Equal(1, results.Count(r => r is RefreshConsumeResult.Consumed));
        Assert.Equal(1, results.Count(r => r is RefreshConsumeResult.AlreadyConsumed));
    }
}

public sealed class SqliteRefreshTokenStoreTests    : RefreshTokenStoreContract { … }
public sealed class PostgresRefreshTokenStoreTests  : RefreshTokenStoreContract { … }  // Testcontainers, MIT
public sealed class InMemoryRefreshTokenStoreTests  : RefreshTokenStoreContract { … }
```

SQLite tests run against a **file**, never `:memory:` — `:memory:` hides connection-pooling and
locking behaviour, which is exactly what these tests are about. The suite is public API, shipped in
`Boltway.Storage.TestKit`, so a customer writing their own store inherits the concurrency tests
rather than discovering `N-08` in production.

### 7.3 Architecture tests

Two tools, deliberately:

- **`Microsoft.CodeAnalysis.BannedApiAnalyzers`** (MIT, from Roslyn) with `BannedSymbols.txt` — gives
  the developer a squiggle and a file:line at compile time.
- **Mono.Cecil over the built assemblies** — the backstop, because `#pragma warning disable` defeats
  an analyzer and does not defeat an IL scan. Cecil is already pinned in `Directory.Packages.props`.

```
# BannedSymbols.txt (excerpt)
P:System.Uri.AbsoluteUri;      N-03: normalization silently widens the redirect match set
P:System.Uri.AbsolutePath;     N-03
M:System.Uri.Equals(System.Object);  N-03
M:Microsoft.AspNetCore.Http.Results.Redirect(System.String,System.Boolean,System.Boolean);  N-12: 307
M:Microsoft.AspNetCore.Mvc.ControllerBase.RedirectPreserveMethod(System.String);            N-12
M:System.Net.IPAddress.IsLoopback(System.Net.IPAddress);  N-04: parse-then-check widens the host set
T:System.Random;               N-16: credentials come from RandomNumberGenerator
M:System.Guid.NewGuid;         N-16
```

```csharp
// N-03. The matcher file must contain no reference to System.Uri at all.
[Fact, Requirement("N-03")]
public void RedirectUriMatcher_never_references_System_Uri()
{
    var type = Primitives().MainModule.GetType("Boltway.OAuth.Primitives.Redirects.RedirectUriMatcher");
    var offenders = type.Methods.Where(m => m.HasBody)
        .SelectMany(m => m.Body.Instructions)
        .Select(i => i.Operand)
        .OfType<MemberReference>()
        .Where(r => r.DeclaringType?.FullName is "System.Uri" or "System.UriBuilder")
        .Select(r => r.FullName).Distinct().ToList();
    Assert.Empty(offenders);
}

// N-12. No 307/308 literal and no preserve-method call anywhere in the AS or UI assemblies.
[Fact, Requirement("N-12")]
public void No_status_307_or_308_after_a_credential_post()
{
    var offenders = AuthorizationServerAssemblies()
        .SelectMany(AllMethodsWithBodies)
        .Where(m => m.Body.Instructions.Any(i =>
               (i.OpCode == OpCodes.Ldc_I4 && i.Operand is 307 or 308)
            || (i.Operand is MethodReference r && r.Name.Contains("PreserveMethod", StringComparison.Ordinal))))
        .Select(m => m.FullName).ToList();
    Assert.Empty(offenders);   // failure message lists the offending methods
}

// N-05. Exactly one assembly may touch HttpClient.
[Fact, Requirement("N-05")]
public void Only_Oauth_Net_may_reference_HttpClient() { … }   // one allowlist entry, commented

// N-13. Request.Host / Request.Scheme are readable in exactly one file's worth of types.
[Fact, Requirement("N-13")]
public void Issuer_is_never_derived_from_the_request() { … }
```

Note the deliberate asymmetry: `RedirectUriMatcher` bans `System.Uri` **entirely**, while
`RedirectUriPolicy` (registration-time validation) may use `Uri.TryCreate` as a predicate and read
`Scheme`/`Host`/`Fragment` — because validating is not comparing. What it may never do is *store*
anything derived from the `Uri`: `RegisteredRedirectUri.Raw` is the bytes as supplied. That
distinction is the whole of `N-03` and it is why the two live in different files with different
rules.

`LoopbackKey.cs` similarly contains no `System.Uri` and no `IPAddress`: it is a hand-written ordinal
scanner (require the literal prefix `http://`, read to the next `/`, split at the last `:`, compare
the host part against the three literal strings `127.0.0.1`, `::1`, `localhost`, and take the
remaining raw path+query as the comparison key). `N-04`'s 16-row matrix — including
`http://localhost:0/callback` (reject) and `http://127.1/callback` (reject) — tests it directly.

### 7.4 Vendor fixtures, and a watch on them

The four live CIMD documents from `cimd-live-2026-08-03.json` are checked in as
`tests/fixtures/cimd/*.json` and the parser is tested against **all four real bodies**, not against
invented ones. Three properties in that data are live traps and get named tests:

- Claude uses RFC 7591's singular `token_endpoint_auth_method`; ChatGPT uses the plural RFC 8414
  *server* field `token_endpoint_auth_methods_supported`. Both spellings must be read (`C-04`).
- The effective default when the field is absent is **`none`**, not RFC 7591's `client_secret_basic`
  — CIMD §4.1 forbids symmetric secrets, so a spec-literal reader rejects every ChatGPT document.
- ChatGPT's `logo_uri` is on a third-party CDN (`persistent.oaistatic.com`), so `N-14`'s
  proxy-never-hotlink rule has a live case on day one, not a hypothetical one.

**A nightly CI job re-fetches the four URLs and diffs against the fixtures.** A vendor changing its
CIMD document is a change to our compatibility surface, and finding out from a customer is the
expensive way. This is a product feature, not a test: it is the same instinct as `boltway-audit`,
pointed at the two clients instead of at a prospect.

### 7.5 Golden files

`docs/metadata.golden.json` is the AS metadata document as served by the default profile, asserted
byte-for-byte (after canonical key sort) by a test. Any change to it is a reviewed diff in a pull
request, because that document **is** the client-facing contract, it propagates with a ~5-minute
cache (`C-30`), and there is no rollback signal when it is wrong.

The same test runs the `A-21` check: all five URL shapes return 200 with identical canonical bodies.
The Appendix's five `curl` commands are ported verbatim into `Boltway.Conformance` so a customer
runs them against their own deployment with one command.

### 7.6 What the conformance CLI is for

`Boltway.Conformance` ships in the container:

```
boltway conformance --issuer https://auth.example.com --resource https://mcp.example.com/mcp
```

It runs the unauthenticated checks (`E-01`..`E-07`, the seven fields, form-encoding at `/token`, a
never-seen CIMD `client_id` producing a 302, portless-vs-ported loopback), and — following
`LESSONS.md` rule 1 — every axis has three values, with `not measured` ranked **above** measured
negatives, because a question is cheaper to resolve than a change. This descends directly from
`core/src/audit/authorization-server.ts`, which already does this well; the C# version differs in
being pointed at our own product, which means it can also make **authenticated** assertions when
given a test credential.

---

## 8. Product concerns: the tenth deployment

### 8.1 Upgrade and migrations

- **The AS never migrates at startup.** `C-29` forbids synchronous migrations on the request path, and
  a three-replica deployment racing on `Database.Migrate()` is a real outage. Migration is a separate
  entrypoint: `boltway migrate`, run as a Kubernetes `Job` or a compose one-shot.
- **At boot the AS asserts the schema is current and refuses to start otherwise**, naming the exact
  command to run — the same shape as FictStory's `--doctor`, which exists because a server that starts
  with a broken configuration and discovers it on the first user connection is worse than one that
  refuses to start.
- **Expand/contract is a release rule, tested.** Every release's migrations must be applicable while
  the previous version is still serving. CI runs release N−1's test suite against release N's schema.
- **Migrations are never squashed after a public release.** Customer databases have arbitrary history
  and no shared starting point.
- **The metadata golden diff ships in the release notes.** "This release changes these metadata keys"
  is the only upgrade note most customers need, and `boltway doctor --compare-baseline` verifies
  a live deployment against the version's golden in one command.

### 8.2 Adding their own user store

`AddEntityFrameworkStores().ReplaceStore<IUserStore, AcmeDirectoryUserStore>()`. Three properties make
this survivable: `IUserStore` is one aggregate (they do not inherit refresh rotation); it takes no
`HttpContext` (they can unit-test it); and `Boltway.Storage.TestKit` gives them our contract suite.
The commonest real case is not a custom store at all but federation — `IExternalIdentityProvider` plus
`IUserProvisioner` — and that path involves no storage code.

### 8.3 Branding without forking

Three tiers, chosen so the common case needs no code:

1. **Options only** (the 90% case): `Ui:BrandName`, `Ui:LogoPath`, `Ui:PrimaryColor`,
   `Ui:CustomCssPath`, `Ui:SupportUrl`. The container mounts `/app/branding/`. Pages ship with **no
   external assets** — `N-15`'s `default-src 'self'` forbids them and `N-14` forbids hotlinked logos
   — so styling is CSS custom properties in one nonce'd inline `<style>` block, overridden by the
   customer's same-origin `/branding/custom.css`.
2. **View override**: `Boltway.AuthorizationServer.UI` is a Razor Class Library, so dropping
   `Areas/Boltway/Pages/Account/Login.cshtml` into the customer's own project wins over ours. No
   fork, no patch, and upgrades still flow.
3. **Full replacement**: `.AddUi<AcmeUi>()` implementing `IAuthorizationServerUi`.

**The security-critical parts of the consent page are tag helpers, not views.** `<consent-disclosure>`
renders the `client_id` host, the requested `redirect_uri` hostname, the all-loopback warning, and the
verbatim scope descriptions, with HTML-encoding and length caps applied in code. `N-14` and `A-15` are
then true at tiers 2 and 3 as well, because overriding a view cannot change compiled behaviour — and a
render test asserts the marker the tag helper emits is present in whatever template is registered. A
view that omits it fails the build, not production.

### 8.4 Operational shape

- Base image `mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled`, non-root, read-only root
  filesystem.
- Configuration by `CK__Authorization__Issuer=…` (double underscore) or `/app/config/boltway.json`.
- Entrypoints: `serve` (default), `migrate`, `doctor`, `conformance`, `seed`, `keys rotate`.
- `/healthz` — liveness only, answered from the request handler with no token, no storage, no call to
  any dependency. The reasoning is borrowed verbatim from `core/src/resource-server.ts`: a probe cannot
  carry credentials, so whatever it returns is public, and a health check that reaches downstream turns
  any unauthenticated caller into a load generator against them. `/readyz` separately checks database
  reachability, schema currency and the presence of an active signing key.
- **`C-31` is the #1 field failure mode and belongs in the deployment docs, not the code:** the AS host
  must publish an `A` record (Claude's egress is IPv4-only, so an `AAAA`-only host is unreachable) and
  must be reachable from `160.79.104.0/21`. A WAF in front of the *IdP* breaks the flow even when the
  MCP server is fine. `boltway doctor --external` states what it can and cannot verify from
  inside the network, and says so rather than guessing.

### 8.5 Key rotation

Two keys live at all times with distinct `kid`. A new key is published in JWKS for `PublishLeadTime`
(default 24 h — comfortably beyond any client's JWKS cache) before it begins signing; the retired key
stays published for at least the maximum access-token lifetime. `boltway keys rotate` plus an
optional schedule. This is in v1 because at deployment ten nobody remembers to rotate manually, and a
rotation that has never been exercised is a rotation that fails.

---

## 9. Resource-server side: borrow, differ, coherence

I read `/home/user/FictStoryEngine/mcp-server/core/src` (`auth/`, `metadata/`, `http/`, `limits/`,
`net/`). It is good code and most of it should be ported rather than re-derived.

### 9.1 Borrow, close to verbatim

| From | What | Why it transfers |
|---|---|---|
| `metadata/protected-resource.ts` | `protectedResourceMetadataPaths` — both shapes, **path-insertion** not appending, most-specific-first | `E-22`/`E-23`/`C-26`. `LESSONS.md` #6 is this exact bug found in `classify` |
| `auth/challenge.ts` | `quote` + `headerSafe`, and the insight behind them | An unescaped quote truncates `WWW-Authenticate` and eats `resource_metadata`, which is the discovery entry point (`X-32`..`X-35`) |
| `http/lazy-auth.ts` | `decideAccess`, `OPEN_METHODS`, fail-closed on unknown methods, "a batch is as protected as its most protected member", and reporting an unknown tool **as itself** rather than as a 401 | The last one is a diagnosability decision that cost real hours to learn; `A-09`/`A-12` are the same instinct |
| `auth/jwks.ts` | Single-flight refresh, unknown-`kid` refetch behind a cooldown, one unusable JWK not poisoning the set | The comment is right that `verify` runs before the rate limiter, so an anonymous caller sets the concurrency |
| `net/http-client.ts` | `CircuitBreaker` and the single-flight `TtlCache` | Both port directly; the TTL cache becomes `ClampedTtlCache` with `S-30`'s 300 s floor / 86 400 s ceiling |
| `limits/rate-limit.ts` | Keyed by tenant, **never by IP** | Every request arrives from the connector's egress range, so an IP-keyed limiter throttles all tenants together or none. Not obvious until it bites |
| `identity.ts` | The safe-id charset guard and the reasoning about many-to-one sanitisation | We avoid needing the sanitiser at all by emitting a Ulid `sub` (§3.2.4) — but the guard stays, because a *customer's* AS may not |
| `resource-server.ts` | `preflight()`, especially the issuer byte-match diagnostic | "Discovery tolerates a trailing slash; token validation does not" is the highest-value single check in the file |

### 9.2 Do differently

1. **The outbound fetcher.** `fetchJson` uses `redirect: "follow"` and has no IP blocklist. In C#, the
   RS uses **the same `GuardedFetcher` as the AS** for `jwks_uri`. That is not paranoia: `jwks_uri` is
   read out of a fetched metadata document, so it is only as trustworthy as that document, and it is
   the RS's entire trust root. This is the single biggest upgrade the port makes.
2. **Byte caps, not character caps.** `fetchJson` checks `content-length`, then reads the whole body
   and checks `text.length` — which is characters, after the body is already in memory. `N-05` requires
   a cap on **bytes read**, enforced while reading. C# caps the stream at 5 KB for CIMD.
3. **`bearerTokenFrom` collapses two error codes into one.** It returns `null` for both "absent" and
   "malformed", so a malformed `Authorization` header becomes `X-32` (401) when it must be `X-35`
   (400). `REQUIREMENTS.md` flags the consequence: getting this backwards makes clients retry-loop
   forever on refresh. C# returns a three-state `BearerTokenParseResult { None, Valid, Malformed }`.
4. **Pin `ValidTypes`.** `checkClaims` does not check `typ`. `N-09` requires `typ: at+jwt` on access
   tokens, and `TokenValidationParameters.ValidTypes` is unset by default in
   `Microsoft.IdentityModel` — so the stock configuration is non-conformant and an ID token is
   accepted as an access token. `Rfc9068ValidationParameters` pins `ValidTypes` and `ValidAlgorithms`
   and is the only way to construct them.
5. **A pre-authentication limiter.** The TS limiter is per-tenant only, but `verify` runs before the
   tenant is known — the code's own comment identifies JWKS refresh as the anonymous-concurrency
   surface. C# adds a cheap limiter keyed by token hash and remote address ahead of verification.
6. **Content-type parsing.** §10 of the requirements resolves `U-03`: `chatgpt.com` serves
   `application/json; charset=utf-8` and `claude.ai` serves bare `application/json`. A fetcher
   comparing by equality rejects every ChatGPT document. `MediaType.cs` parses and ignores
   parameters, and it is shared by the AS's CIMD fetcher and the RS's metadata fetcher — the same
   code, so the two cannot diverge.

### 9.3 Is shipping both coherent?

**Yes, and it is the strongest single argument for this assembly split — with one honest caveat.**

The AS and the RS must agree byte-for-byte on five things: issuer comparison, `resource` identity,
`aud` matching, media-type parsing, and `WWW-Authenticate` quoting. Every one of those lives in
`Boltway.OAuth.Primitives`, which both halves reference. An AS/RS disagreement is therefore
impossible **by construction** rather than prevented by test. Nobody who buys one half from one vendor
and the other half from another gets that property, and it is the difference between "we implement the
same RFCs" and "these two things cannot disagree".

Two more consequences worth stating: the conformance CLI can drive the AS and validate with the RS's
own verifier, so the end-to-end assertion uses production code on both ends; and `S-17`'s two
directions (the AS **consumes** `protected_resources`, the RS **produces** the PRM document) are
written once against one type.

**The caveat, stated plainly: the TypeScript `@boltway/mcp-core` does not go away, and most MCP
servers are TypeScript.** Two implementations of the same middleware is a genuine ongoing cost and
pretending otherwise would be dishonest. The resolution is not "port everyone to C#":

- The **RS contract** is a document plus a shared vector file, `tests/vectors/rs-conformance.json`:
  PRM path derivations, `WWW-Authenticate` construction cases (including the quote-escaping and
  truncation cases), the lazy-auth method allowlist, the bearer-header parse matrix with its expected
  status codes. **Both implementations run the same vectors.** One contract, two runtimes, one vector
  set — not two codebases drifting.
- The C# RS exists for customers whose MCP server is already .NET. We do not port anyone, and we do
  not lead with it.
- If the deadline halves, the C# RS is the first thing cut (§10) precisely because the TypeScript one
  already works and has a shipped connector behind it.

---

## 10. What I would cut if the deadline halved — and what must never be cut

### Cut, in this order

1. **The C# resource-server middleware** (`Boltway.ResourceServer[.Mcp]`, `E-22`–`E-24`). The
   TypeScript `@boltway/mcp-core` already does this and has a shipped connector behind it. Keep
   `Primitives` and `Net` — they are load-bearing for the AS — and keep the shared vector file so the
   port is mechanical later. Biggest single saving, lowest risk.
2. **DCR entirely** (`S-13`, `S-15`, `E-11`–`E-14`, `X-24`–`X-31`). CIMD is the default and covers both
   vendors with zero admin steps; `N-06` means DCR is not advertised anyway. Do not ship `/register` at
   all. Removes eight error codes, the registration-access-token pipeline, and the client-quota/GC
   machinery. `C-18` (Claude registering on every fresh connection) stops being a problem we have.
3. **`/logout`** (`S-11`, `E-18`) and **`/userinfo`** (`E-17`). Keep `openid`/`profile`/`email`
   advertised and deliver those claims in the ID token — `C-23` requires only that we never refuse an
   advertised scope, not that we run a UserInfo endpoint.
4. **Google federation** (`Boltway.Federation.Google`). Local Argon2id accounts only. **Keep the
   `IExternalIdentityProvider` seam and the `ExternalLogin` table** — the seam is 40 lines and the table
   is a migration we would otherwise pay for across every customer database.
5. **`client_credentials` and `jwt-bearer` grants** (`C-32` Enterprise Managed Auth). `N-06` then
   forces the URN out of `grant_types_supported`, which is correct and self-consistent. Costs us
   Claude Enterprise customers; that is a segment, not the product.
6. **`GET /admin/config/schema`** (`E-21`) as an HTTP endpoint. Keep `ConfigSchema.Build()` and expose
   it through `boltway doctor --print-config` — same code, no admin authentication surface to
   design.
7. **Multi-realm anything.** Keep the `RealmId` column and parameter (they are free now and expensive
   later); delete every code path that reads more than one realm.
8. **The PostgreSQL Testcontainers CI leg.** Keep the provider package and the contract suite; run the
   Postgres leg manually before each release instead of on every push.
9. **OpenTelemetry.** Keep structured logging with correlation ids — `A-09` is not cuttable.

### Never cut

- **All sixteen `N-nn` non-negotiables, and their mechanical guards.** The architecture tests (§7.3)
  are perhaps two days of work and they are the reason this can be sold into a customer's codebase at
  all. An AS whose exact-matching is a coding convention rather than a build failure is a liability
  transfer, not a product.
- **CIMD** (`S-16`). It is the entire zero-admin-step promise (`A-03`, `A-07`, `A-08`, `A-20`) and the
  reason "customer has no IdP" stops being a refusal and becomes a quote.
- **`resource` → `aud` binding** (`N-01`, `A-01`, `A-22`). Without it we have rebuilt the Auth0 trap we
  are selling the escape from, and RFC 8707 registers no discovery flag, so no client can tell.
- **Refresh rotation with family revocation and the 30–60 s idempotency window** (`N-08`, `C-19`,
  `C-21`). Cutting the window produces user-visible forced logouts that read as incidents; cutting the
  family revocation removes the only replay signal that exists.
- **Exact redirect matching including the loopback rule** (`N-03`, `N-04`, `A-19`). Claude Code does not
  work without the loopback rule; nothing is safe without the exact rule.
- **Both discovery documents in all five URL shapes** (`A-21`, `E-01`–`E-06`) and the seven fields in
  the Appendix check. It is one route-table entry each and it is the entire first impression.
- **The requirement-coverage test and the conformance CLI** (§7.1, §7.6). Without them this is a
  codebase someone wrote, not a product someone can deploy for the tenth time and verify in one
  command.
- **A correlation id on every rejection, present in the response** (`A-09`, `A-12`). `curl` alone must
  be a sufficient debugging tool. Every hour saved here is an hour not spent on a customer's incident
  bridge.

---

## Appendix — the judgement calls, and what was rejected

| Decision | Rejected alternative | Why |
|---|---|---|
| One issuer per process; `RealmId` column from day one | Shared multi-tenant process at v1 | `S-08` + `N-13` leave only host-mapping, and a shared process gives a redirect-matcher bug a cross-customer blast radius. The column is free now, a migration later |
| Container first, NuGet second | Source template that vendors the protocol code | A vendored fork has no upgrade story and no security-patch story |
| Three small assemblies (Primitives / Net / Tokens) rather than one Core | `Boltway.Core` | An RS-only customer must not carry EF or Razor, and `N-05`'s "exactly one HttpClient configuration" is only a one-line test if `Net` is its own assembly |
| Instants as `long` Unix ms | `DateTimeOffset` with per-provider configuration | SQLite orders TEXT-with-offset wrongly; the conversion also makes JWT NumericDate a direct read |
| `Ulid` string keys, no `Guid` | `Guid` primary keys | `uuid` vs TEXT/BLOB ordering diverges between providers; and the Ulid charset hands us `A-18` for free |
| Scopes as a space-delimited value object | A `ClientScope` child table | Never queried, and `A-13` already forbids the delimiter inside a value. The child table buys joins we never make |
| `AccessTokenRequest.Audience` is one `ResourceIdentifier` | `IReadOnlyList<ResourceIdentifier>` | `N-01` becomes structural: there is no way to mint a token without a validated resource, and no default to fall back to |
| `IClaimSink` rather than a returned dictionary | `IReadOnlyDictionary<string,object>` return | A sink can reject reserved names, so `N-10` survives customer extensions |
| Guard decorators on `IConsentPolicy`, `IClaimSource`, `IAccessTokenFormat` | Documenting the invariant | A documented invariant in a seam is violated by deployment four |
| No `IRedirectUriMatcher`, no `IPkcePolicy`, no `IErrorMapper` | Full pluggability | These are the three places where flexibility *is* the vulnerability. Wildcards, PKCE downgrade, and client-breaking error codes |
| BannedApiAnalyzers **and** Cecil | Either alone | `#pragma warning disable` defeats the analyzer; it does not defeat an IL scan. The analyzer gives file:line, Cecil gives the guarantee |
| RS packages multi-target `net8.0;net10.0` | `net10.0` everywhere | The RS lands in the customer's codebase and their TFM is not ours to choose. Two `#if` blocks is a cheap price for not being unsellable to the current LTS |
| Reflection + embedded XML docs for `A-17` | A Roslyn source generator | Same output, a week cheaper. The generator is the documented upgrade |
| Nightly re-fetch of the four vendor CIMD documents | Static fixtures only | The vendors are a moving dependency; finding out from a customer is the expensive way |
