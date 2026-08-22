# Proposal C — Operability First

**An OAuth 2.1 + OIDC authorization server for Boltway, designed so that every failure is
diagnosable from outside the process.**

Target: `net10.0`, SDK 10.0.302 (pinned in `/home/user/Boltway/auth/global.json`).
Package versions already centralised in `/home/user/Boltway/auth/Directory.Packages.props`.
Requirement IDs refer to `research/REQUIREMENTS.md`; §10 of that document wins on conflict.

---

## 0. The thesis, and what it changes

The field report this project comes from
(`research/anthropic-claude-client-behavior.md`, `FictStoryEngine/docs/integration/idp-configuration.md`)
is not a list of missing features. It is a list of **failures that could not be attributed**:

| Symptom in the field | Real cause | Where the answer was |
|---|---|---|
| "Oops!, something went wrong" in the browser | connection not domain-level | Monitoring → Logs, a surface the integrator could not reach |
| "Couldn't connect", no consent screen | tenant application quota | **nowhere** — administrative op, no log entry at all |
| `invalid_request: Unknown client: https://claude.ai/...` | CIMD advertised, client not imported | error vocabulary blamed the client for a correct request |
| social login button silently absent | connection not promoted | absence of a control is not an error message |
| `resource` ignored, `aud` wrong | undocumented `resource_parameter_profile` | a validation error message, discovered by sending a deliberately invalid value |

Four of the five are *unattributable* rather than *unimplemented*. So the architectural claim of
this proposal is narrow and specific:

> **A rejection that is not logged with a correlation id, and does not carry that id back to the
> caller, must be structurally impossible to write.**

Not "we have good logging". Structurally impossible: there is exactly one type that can produce a
non-2xx response from any OAuth endpoint, it cannot be constructed without a reason code and a
requirement id, and the act of writing it to the response is what emits the log line. A-09 becomes
a property of the type system rather than a habit.

Everything else in this document — the assembly split, the pipeline order, the doctor — is arranged
around that plus the sixteen N-nn, several of which (N-03, N-05, N-12) are statements about *where
code is allowed to live* and therefore belong in the assembly graph, not in a code review checklist.

**Cost honesty up front:** §9 says where I stop building observability, and why. Observability
that outweighs the thing observed is a real failure mode and I name the line.

---

## 1. Assembly split

`/home/user/Boltway/auth/` — twelve shipping projects, four test projects.

```
auth/
  Boltway.Auth.slnx
  global.json                                  (exists)
  Directory.Build.props                        (exists)
  Directory.Packages.props                     (exists)
  .editorconfig                                (new — carries the banned-API analyzer rules)
  spec/                                        (exists: pinned draft-15 + CIMD-02)
  src/
    Boltway.Auth.Abstractions/
    Boltway.Auth.Primitives/
    Boltway.Auth.Diagnostics/
    Boltway.Auth.Http/
    Boltway.Auth.Core/
    Boltway.Auth.Server/
    Boltway.Auth.ResourceServer/
    Boltway.Auth.Storage.EntityFrameworkCore/
    Boltway.Auth.Storage.Sqlite/
    Boltway.Auth.Storage.Postgres/
    Boltway.Auth.Storage.InMemory/
    Boltway.Auth.Federation.Google/
    Boltway.Auth.Cli/
    Boltway.Auth.Host/                    (reference deployment, not shipped as a package)
  tests/
    Boltway.Auth.Architecture.Tests/
    Boltway.Auth.Unit.Tests/
    Boltway.Auth.Conformance.Tests/
    Boltway.Auth.Interop.Tests/
```

### 1.1 The graph

```
                          Abstractions          (BCL only)
                          ▲   ▲    ▲   ▲
             ┌────────────┘   │    │   └──────────────┐
       Primitives         Diagnostics             Storage.EntityFrameworkCore
       (BCL only)      (+ Logging.Abstractions,        ▲          ▲       ▲
         ▲  ▲  ▲        System.Diagnostics)     Sqlite  Postgres  InMemory
         │  │  └──────────────┐  ▲  ▲
         │  │                 │  │  └──────────────────┐
         │  └── Http ─────────┘  │                     │
         │       ▲               │                     │
         │       │               │                     │
         └────── Core ───────────┘                     │
                  ▲                                    │
                  │                                    │
               Server ◄─────── Federation.Google       │
                  ▲                                    │
        Host ─────┴──── Cli                            │
                                                       │
       ResourceServer ──► Abstractions, Primitives, Diagnostics   ONLY
                          (never Core, never Server, never Storage.*)
```

### 1.2 Every project, what is in it, why the boundary is there

**`Boltway.Auth.Abstractions`** — `netstandard`-shaped, BCL references only, no ASP.NET, no
EF Core, no `Microsoft.IdentityModel`.
Contents: every seam interface (§4), the entity POCOs, `OAuthError` (the closed set of error-code
strings from X-01..X-41), `ClientKind`, `GrantType`, `ClientAuthMethod`, `Rejection`,
`ReasonCode`. Nothing here executes protocol logic.
*Why a boundary:* it is the only assembly a customer references when they implement their own
store or their own federation provider. If it dragged in EF Core, "write your own store" would
mean "take a dependency on the one you were replacing".

**`Boltway.Auth.Primitives`** — BCL only. **The N-03 assembly.**
Contents: `RedirectUriMatcher`, `OrdinalUri` (the *parsed but never normalised* representation),
`Base64Url`, `PkceVerifier`, `ResourceIdentifier`, `IssuerString`, `ScopeSet`, `SecretHasher`,
`ConstantTime`.
*Why a boundary:* the N-03 architecture test is `no type in this assembly may reference
System.Uri, at all`. That is a one-line Cecil predicate over an assembly, which is far more robust
than "no `Uri.Equals` in the file named `RedirectUriMatcher.cs`" — the latter is defeated by
someone adding a helper file next to it. Making the rule assembly-scoped means the enforcement
survives refactoring, which is the whole point of a mechanical guard.
The same trick is what makes `ResourceIdentifier` safe: RFC 8707 canonicalisation and RFC 3986 §6.2.1
comparison live here and physically cannot call `Uri`.

**`Boltway.Auth.Diagnostics`** — references Abstractions, `Microsoft.Extensions.Logging.Abstractions`,
`System.Diagnostics.DiagnosticSource`. No ASP.NET.
Contents: the event taxonomy (§8.1), `CorrelationId`, `RejectionWriter`, `AuthMetrics`,
`LatencyBudget`, `IDoctorProbe` / `DoctorReport` (§8.4).
*Why a boundary:* the resource-server middleware needs the taxonomy and the correlation id, and
must not need the AS. This assembly is the shared vocabulary between the two halves of the product.
It also means a customer's own MCP server logs and the AS logs use the same field names, which is
the difference between one grep and two.

**`Boltway.Auth.Http`** — the **N-05 assembly**. References Primitives, Diagnostics.
Contents: exactly one type that constructs a `SocketsHttpHandler`, one `IGuardedHttpClient`
implementation, the RFC 6890 range table, the `ConnectCallback`, the byte-cap stream wrapper,
and the S-30 cache.
*Why a boundary:* the requirement is "there must be exactly one HttpClient configuration that can
reach an attacker-supplied URL, and it must be impossible to accidentally use a stock one". The
architecture test is: **no assembly other than `Boltway.Auth.Http` may reference
`System.Net.Http.HttpClient..ctor`, `IHttpClientFactory.CreateClient`, or
`System.Net.Http.HttpMessageHandler`.** Federation.Google is the one deliberate exception and is
named in the test's allowlist with a comment explaining why (it talks to a configured, non-attacker-
supplied issuer — but even there it uses the guarded client for `jwks_uri`).

**`Boltway.Auth.Core`** — the protocol engine. References Abstractions, Primitives, Http,
Diagnostics, `Microsoft.IdentityModel.JsonWebTokens`. **No ASP.NET Core reference.**
Contents: the `/authorize` stage pipeline, the `/token` grant handlers, the CIMD resolver, client
authentication strategies, token minting, consent decisioning, key management, metadata document
generation.
*Why a boundary:* the pipeline is testable without a web host, which is what makes 187 conformance
tests affordable — most of them never start Kestrel. And the ban on `Microsoft.AspNetCore.Http` here
is what forces N-12 to be enforceable: a stage cannot call `Results.Redirect` because it cannot see
it. A stage returns a `StageOutcome`, and only `Server` turns that into bytes.

**`Boltway.Auth.Server`** — ASP.NET Core hosting. References Core, Storage.EFCore (for the
default DI registration only), `Microsoft.AspNetCore.*`, Serilog, OpenTelemetry.
Contents: endpoint mapping, middleware, Razor pages for login/consent/error/logout, options binding
and validation, the admin surface (E-21), `AddBoltwayAuthorizationServer()`.
*Why a boundary:* this is the only assembly that knows about HTTP status codes and `HttpContext`.
`OAuthResults.SeeOther` lives here and is the only redirect helper (N-12).

**`Boltway.Auth.ResourceServer`** — **the reuse answer.** References Abstractions,
Primitives, Diagnostics, `Microsoft.AspNetCore.Authentication.JwtBearer`,
`Microsoft.IdentityModel.JsonWebTokens`, and `Boltway.Auth.Http` (for `jwks_uri` fetching).
Contents: bearer validation with `ValidTypes`/`ValidAlgorithms` pinned (N-09), the RFC 9728 PRM
endpoints (E-22/E-23, both shapes), the `WWW-Authenticate` challenge builder (X-32..X-35),
RFC 7662 introspection client, the grant-id denylist client.
*Why a boundary — the question the brief asks:* **a customer who wants only the resource-server
middleware takes `Boltway.Auth.ResourceServer`, `.Primitives`, `.Diagnostics`,
`.Abstractions`, `.Http`. Five packages, no EF Core, no ASP.NET MVC/Razor, no AS.** That claim is
verified, not asserted — see the boundary test in §7.4, which is the C# port of FictStoryEngine's
`npm run check:boundary`, including step (4): copy the RS projects to an empty directory *without*
Core/Server/Storage present and build. If it builds, the boundary holds.

**`Boltway.Auth.Storage.EntityFrameworkCore`** — `AuthDbContext`, all `IEntityTypeConfiguration<T>`,
the store implementations, the value converters. Provider-neutral: **no `Npgsql` or `Sqlite` package
reference**, and an architecture test asserts that.

**`.Storage.Sqlite` / `.Storage.Postgres`** — thin. Each contains: the provider package reference,
one `IAuthProviderTweaks` implementation (collation, concurrency idiom, `EnableRetryOnFailure`), and
the migrations assembly. Two separate migration histories is the price of provider-agnostic EF Core
and is cheaper than the alternatives.
*Rejected:* one migrations assembly with provider `if`s inside `Up()`. It works until the first
`ALTER COLUMN` and then it does not.

**`.Storage.InMemory`** — hand-written store implementations over `ConcurrentDictionary`, **not**
`Microsoft.EntityFrameworkCore.InMemory`. Rationale: the EF in-memory provider does not enforce the
atomic-`UPDATE`-rows-affected semantics that N-07 and N-08 depend on, so tests that pass on it can
fail in production. The hand-written store implements the same compare-and-swap contract and has a
test asserting it under `Parallel.ForAsync`. (The EF in-memory package stays in
`Directory.Packages.props` for unrelated fixture use.)

**`Boltway.Auth.Federation.Google`** — reference `IExternalIdentityProvider`. One class plus
its options and its doctor probe. The whole point is that the diff for "add GitHub" is visibly one
file.

**`Boltway.Auth.Cli`** — `boltway-auth`: `doctor`, `keygen`, `probe`, `config schema`,
`config explain`. Ships as a `dotnet tool`.

**`Boltway.Auth.Host`** — the runnable reference: `Program.cs` (~40 lines), `appsettings.json`,
a Dockerfile. Not a NuGet package. Exists so `docker compose up` produces a working AS, because the
first thing a customer does is run it, and the second is diff their config against this one.

### 1.3 Honest cost

Three of those twelve projects (`Primitives`, `Http`, and arguably `Diagnostics`) exist primarily so
an architecture test can be written at assembly granularity. That is a real cost: more `.csproj`
files, more `<ProjectReference>` lines, a slower cold build. I take it because the alternative
enforcement — file-path or namespace-scoped rules — is defeated by ordinary refactoring, and N-03
and N-05 are the two places where being defeated by ordinary refactoring is a remote-code-execution
or account-takeover class bug. `Diagnostics` is the weakest of the three and could be folded into
`Abstractions` if project count becomes a problem; I keep it separate only because the RS
distribution then does not carry the entity POCOs.

---

## 2. Namespace and folder layout

Namespace == folder path, rooted at the assembly name. Core protocol paths to file granularity.

```
src/Boltway.Auth.Primitives/
  Uris/
    OrdinalUri.cs                  Parsed-but-unnormalised: Scheme, Host, Port, Path, Query, Raw.
                                   Built by a hand-written scanner over the RAW string. Never Uri.
    RedirectUriMatcher.cs          N-03 + N-04 + S-05 §7.1/§7.3. See §2.1 below.
    LoopbackHosts.cs               The three literal strings. No IPAddress.IsLoopback anywhere.
    ResourceIdentifier.cs          RFC 8707 canonical form; Ordinal comparison; A-22 path support.
    IssuerString.cs                N-13: immutable, validated, single instance.
  Crypto/
    Base64Url.cs                   RFC 4648 §5, unpadded.
    ConstantTime.cs                Wraps CryptographicOperations.FixedTimeEquals.
    SecretHasher.cs                SHA-256 of high-entropy tokens (N-16). NOT for passwords.
    TokenGenerator.cs              RandomNumberGenerator, 256-bit, typed prefixes.
  Pkce/
    CodeVerifierGrammar.cs         43*128unreserved, RFC 7636 §4.1.
    CodeChallenge.cs               S256 only; Appendix B vector is a test, not a comment.
  Scopes/
    ScopeSet.cs                    Ordered, deduped, A-13 normalise-on-write.

src/Boltway.Auth.Core/
  Authorization/
    AuthorizeRequest.cs            The raw parameter bag, before any validation.
    AuthorizePipeline.cs           N-11 stage order, hard-coded. See §5.1.
    Stages/
      01_ResolveClientStage.cs     N-11 step 1. Redirect is FORBIDDEN before this succeeds.
      02_ValidateRedirectUriStage.cs   N-11 step 2. After this, redirecting errors is permitted.
      03_ResponseTypeStage.cs
      04_PkceStage.cs              N-02.
      05_ScopeStage.cs
      06_ResourceStage.cs          N-01 / S-18 / X-09.
      07_PromptAndMaxAgeStage.cs   X-04, X-12..X-15.
      08_AuthenticateUserStage.cs
      09_ConsentStage.cs           N-14.
      10_IssueCodeStage.cs
    RedirectErrorBuilder.cs        state + iss (S-27) + charset sanitisation (§4.1 charset).
    AuthorizeOutcome.cs            Redirect | RenderHtmlError | RenderLogin | RenderConsent.
  Token/
    TokenRequest.cs
    TokenEndpoint.cs               Dispatch table keyed on grant_type (D-04/D-06 seam).
    Grants/
      AuthorizationCodeGrant.cs    N-07 replay order. See §5.2.
      RefreshTokenGrant.cs         N-08 rotation + grace window.
      ClientCredentialsGrant.cs
      JwtBearerGrant.cs            RFC 7523 / C-32, per-tenant issuer allowlist.
    ClientAuthentication/
      ClientAuthenticator.cs       Strategy dispatch; "more than one mechanism" ⇒ X-17.
      NoneAuthenticator.cs
      ClientSecretBasicAuthenticator.cs
      ClientSecretPostAuthenticator.cs
      PrivateKeyJwtAuthenticator.cs   U-08: accepts issuer OR token endpoint as aud.
  Clients/
    Cimd/
      CimdResolver.cs              S-16 orchestration; ≤2s budget (C-29); stale-on-error.
      CimdDocument.cs              Both spellings of token_endpoint_auth_method (C-04).
      CimdValidator.cs             §4 rules; X-03 reason codes, one per check.
      CimdCache.cs                 S-30 clamp 300s..86400s; never caches errors.
    ClientResolver.cs              ClientKind dispatch. Never re-derives kind from an https:// prefix.
  Tokens/
    AccessTokenMinter.cs           RFC 9068; typ=at+jwt (N-09); aud from resource (N-01).
    IdTokenMinter.cs               aud = client_id (N-10); typ=JWT.
    RefreshTokenMinter.cs          Opaque, hashed at rest (N-16).
    TokenClaims.cs
    Keys/
      SigningKeyRing.cs            Rotation with a publish-before-sign window (§9.3).
      JwkSetBuilder.cs             Public parameters only; test asserts no d/p/q/dp/dq/qi.
  Metadata/
    AuthorizationServerMetadata.cs     The record.
    MetadataBuilder.cs                 A-04: built from live options on every request, cached by ETag.
    MetadataInvariants.cs              N-06 startup assertion; S-34 zero-array omission.
  Consent/
    ConsentDecider.cs              S-05 §8.6: never auto-approve for public clients.
    ConsentPresentation.cs         N-14 fields the view MUST render.

src/Boltway.Auth.Server/
  Endpoints/
    AuthorizeEndpoint.cs           E-08. No CORS. Maps AuthorizeOutcome → IResult.
    TokenEndpoint.cs               E-10. [FromForm] only. Never [FromBody]. (C-15)
    DiscoveryEndpoints.cs          E-01..E-06, all five shapes, byte-identical (A-21).
    JwksEndpoint.cs                E-07.
    RegistrationEndpoints.cs       E-11..E-14 (opt-in profile).
    IntrospectionEndpoint.cs       E-15.
    RevocationEndpoint.cs          E-16.
    UserInfoEndpoint.cs            E-17.
    LogoutEndpoint.cs              E-18.
    AdminConfigEndpoints.cs        E-21 (A-16, A-17).
    WellKnownFallback.cs           Unmatched /.well-known/* ⇒ bare 404 + no-store.
  Http/
    OAuthResults.cs                SeeOther(303) — the ONLY redirect helper (N-12).
    SecurityHeadersMiddleware.cs   N-15, set in Response.OnStarting.
    CorrelationMiddleware.cs       A-09.
    LatencyBudgetMiddleware.cs     C-29, warn at 25%.
  Pages/  (Razor)
    Login.cshtml  Consent.cshtml  Error.cshtml  Logout.cshtml
  Options/
    AuthorizationServerOptions.cs  and the sub-option records (§6).
    OptionsSchema.cs               A-17, reflection + XML docs (§6.2).
    StartupValidation.cs           N-06, N-13, A-05.
```

### 2.1 `RedirectUriMatcher` — the single most load-bearing file

```csharp
namespace Boltway.Auth.Primitives.Uris;

/// <summary>
/// RFC 3986 §6.2.1 Simple String Comparison, with the RFC 8252 §7.3 loopback port exception.
/// N-03: System.Uri is not referenced by this assembly. Normalise at registration,
/// compare exactly at request time.
/// </summary>
public static class RedirectUriMatcher
{
    public static RedirectMatch Match(
        string requested,                       // raw, exactly as it arrived on the wire
        IReadOnlyList<string> registered);      // raw, exactly as stored at registration
}

public readonly record struct RedirectMatch(
    bool IsMatch,
    RedirectMatchReason Reason,                 // Exact | LoopbackPortExempt | NoMatch | Malformed
    string? MatchedRegisteredValue);
```

Algorithm, in order:

1. If `string.Equals(requested, r, StringComparison.Ordinal)` for any `r` → `Exact`. Done.
   This is the whole rule for HTTPS clients and it runs first so the common path never reaches the
   loopback code.
2. Otherwise, parse both sides with `OrdinalUri.TryParse` (a hand-written scanner: scheme up to
   `:`, authority to the next `/?#`, and so on — it lowercases *nothing*, percent-decodes *nothing*,
   resolves *nothing*).
3. Loopback exception applies only if **all** of: requested scheme is exactly `"http"`;
   requested host is one of the three literals `127.0.0.1`, `::1`, `localhost`
   (`LoopbackHosts.Contains`, ordinal); registered scheme is exactly `"http"`; registered host is
   the same literal. `IPAddress.IsLoopback` is never called — it accepts `127.1`, `2130706433`,
   `0.0.0.0` under some paths, and each of those widens the match set (N-04).
4. Under the exception, compare host (ordinal), escaped path (ordinal), escaped query (ordinal).
   **Port is ignored on both sides.** A fragment on either side → `Malformed`, never a match.
5. `http://localhost:0/callback` → rejected, because port 0 is not a port the client can actually
   listen on and accepting it is a marker for a fuzzed input. This is in the 16-row matrix.

Registration-time normalisation is a *separate* function (`RedirectUriNormaliser.NormaliseForStorage`)
that rejects rather than rewrites: fragment → reject, userinfo → reject, non-`https` non-loopback →
reject, uppercase scheme/host → reject with a message naming the fix. Nothing is silently rewritten,
because a silent rewrite is the mechanism by which the stored value stops equalling the sent value.

---

## 3. Domain model and EF Core mapping

### 3.1 Entities

All entity types live in `Boltway.Auth.Abstractions/Entities/`. All are mutable classes with
private setters where EF needs them; none carry EF attributes (mapping is entirely in
`IEntityTypeConfiguration<T>`, so the POCOs stay usable by a customer's non-EF store).

| Entity | Key | Notable fields |
|---|---|---|
| `Client` | `ClientId` (string, ≤512) | `Kind` (`Cimd`/`Dynamic`/`PreRegistered`), `ClientType` (`Public`/`Confidential`, S-05 §8.4), `ClientName`, `LogoUri`, `RedirectUris`, `GrantTypes`, `ResponseTypes`, `Scopes`, `TokenEndpointAuthMethod`, `JwksUri`, `JwksJson`, `SecretHash`, `SecretExpiresAt`, `RegistrationAccessTokenHash`, `TenantId`, `CreatedAt`, `LastUsedAt`, `Disabled`, `DisabledReason` |
| `ResourceRegistration` | `Resource` (string — the canonical RFC 8707 identifier, A-22 allows a path) | `DisplayName`, `Scopes`, `DefaultAccessTokenLifetime`, `AllowedClientIds` (null = all, A-03) |
| `ScopeDefinition` | `Name` | `ConsentDescription` (A-14, rendered verbatim), `ResourceId`, `IsOidcScope` |
| `User` | `UserId` (opaque, ours) | `PasswordHash` (Argon2id encoded string), `PasswordUpdatedAt`, `Email`, `EmailVerified`, `DisplayName`, `Locale`, `Disabled`, `TenantId` |
| `ExternalIdentity` | (`UpstreamIssuer`, `UpstreamSubject`) | `UserId`. D-10: exists from day one with one row per user |
| `AuthorizationCode` | `CodeHash` (SHA-256 hex) | `ClientId`, `UserId`, `GrantId`, `RedirectUri` (raw), `CodeChallenge`, `CodeChallengeMethod`, `PkceWasRequested` (N-02 XOR), `Nonce`, `AuthTime`, `Scopes`, `Resources`, `IssuedAt`, `ExpiresAt`, `RedeemedAt`, `RedeemedByRequestId` |
| `Grant` | `GrantId` (ULID-ish, ours) | `ClientId`, `UserId`, `Scopes`, `Resources` (the RFC 8707 **grant set**), `CreatedAt`, `RevokedAt`, `RevocationReason`. Access tokens carry `gid`; revoking here kills them all |
| `RefreshToken` | `TokenHash` | `GrantId`, `Generation` (int), `ParentTokenHash`, `SuccessorTokenHash`, `IssuedAt`, `ExpiresAt`, `ConsumedAt`, `ConsumedByRequestId`, `SuccessorAccessTokenJti` |
| `ConsentGrant` | (`UserId`, `ClientId`) | `Scopes`, `Resources`, `GrantedAt`, `ExpiresAt`. Public clients never read this for auto-approval (S-05 §8.6) |
| `SigningKey` | `Kid` | `Alg`, `PublicJwk`, `PrivateKeyProtected` (DataProtection), `State` (`Pending`/`Active`/`Retiring`/`Retired`), `NotBefore`, `ActivateAt`, `RetireAt` |
| `AuthSession` | `Sid` | `UserId`, `AuthTime`, `Acr`, `Amr`, `ExpiresAt`, `ClientIdsSeen` (D-09 seam) |
| `ReplayGuard` | (`Purpose`, `Jti`) | `ExpiresAt`. One table for `private_key_jwt` and `jwt-bearer` `jti` replay |
| `TenantQuota` | `TenantId` | `MaxClients`, `MaxClientsSoft`, `CurrentClients`. **Exists so A-09's "quota rejection produces no log" cannot recur** |

`Grant` is the pivot: N-08's family revocation, N-07's descendant revocation, and X-33's revoked-token
check all resolve to "is `Grant.RevokedAt` null", which is one indexed lookup the RS can cache for
seconds without correctness risk.

### 3.2 The three SQLite problems, and the answers

**(a) `DateTimeOffset` has no native ordering in SQLite.** SQLite stores it as TEXT
(`"2026-08-04 12:00:00+07:00"`), and `ORDER BY` on that is lexical, so `+07:00` sorts before
`-05:00` regardless of instant. Expiry sweeps and "is this token expired" would be wrong.

Answer: **store every instant as `long` Unix milliseconds UTC**, applied by convention so nobody
can forget:

```csharp
// Storage.EntityFrameworkCore/AuthDbContext.cs
protected override void ConfigureConventions(ModelConfigurationBuilder builder)
{
    builder.Properties<DateTimeOffset>()
           .HaveConversion<DateTimeOffsetToUnixMillisecondsConverter>()
           .HaveColumnType(_tweaks.Int64ColumnType);      // "bigint" | "INTEGER"

    builder.Properties<DateTimeOffset?>()
           .HaveConversion<NullableDateTimeOffsetToUnixMillisecondsConverter>()
           .HaveColumnType(_tweaks.Int64ColumnType);
}

// Storage.EntityFrameworkCore/Conversion/DateTimeOffsetToUnixMillisecondsConverter.cs
public sealed class DateTimeOffsetToUnixMillisecondsConverter
    : ValueConverter<DateTimeOffset, long>
{
    public DateTimeOffsetToUnixMillisecondsConverter()
        : base(v => v.ToUnixTimeMilliseconds(),
               v => DateTimeOffset.FromUnixTimeMilliseconds(v)) { }
}
```

*Rejected:* `timestamptz` on Postgres + TEXT on SQLite with provider-conditional configuration. It
gives two different sort semantics in the same codebase, which is exactly the class of bug that
only appears in production. The cost of the chosen approach is that `psql` shows integers; the
mitigation is a `v_auth_codes` view in the Postgres migration that renders `to_timestamp(...)`, so
the operator's ad-hoc query is still readable. Losing "pretty in psql" is worth gaining "the same
answer on both providers".

**(b) No array columns.** `RedirectUris`, `Scopes`, `Resources`, `GrantTypes` are all collections.

Answer: a `DelimitedStringList` value converter — ordinal-sorted at write, `\n`-joined (a character
the A-13 normaliser rejects inside a scope or URI, so it is unambiguous), with a `ValueComparer` so
EF change-tracking works:

```csharp
// Storage.EntityFrameworkCore/Conversion/StringListConverter.cs
public sealed class StringListConverter : ValueConverter<IReadOnlyList<string>, string>
{
    public StringListConverter()
        : base(v => string.Join('\n', v),
               v => v.Length == 0
                    ? Array.Empty<string>()
                    : v.Split('\n', StringSplitOptions.None)) { }
}

public sealed class StringListComparer : ValueComparer<IReadOnlyList<string>>
{
    public StringListComparer()
        : base((a, b) => a!.SequenceEqual(b!, StringComparer.Ordinal),
               v => v.Aggregate(0, (h, s) => HashCode.Combine(h, StringComparer.Ordinal.GetHashCode(s))),
               v => v.ToArray()) { }
}
```

The critical consequence, and it is a security property not a convenience: **no redirect-URI or
scope comparison is ever expressed as a SQL predicate.** We load the `Client` row by `ClientId` and
compare in memory with `StringComparison.Ordinal`. This is not just N-03 hygiene — PostgreSQL's `=`
on `text` under an ICU or `en_US.UTF-8` collation is not guaranteed byte-equality for all inputs,
and SQLite's `LIKE` is case-insensitive for ASCII by default. Delegating an exact-match security
decision to a database collation is a latent widening we simply never expose ourselves to.

*Rejected:* Postgres `text[]` (SQLite cannot), and EF 8+ primitive-collection JSON mapping (SQLite
support depends on the JSON1 extension being compiled in, which is true for the bundled
`SQLitePCLRaw` build but not guaranteed for a customer's system SQLite — and we never query inside
these values anyway, so the JSON capability buys nothing).

**(c) No native JSON columns.** `Grant.Properties` (the D-05 extensible bag) and
`Client.JwksJson` are JSON.

Answer: `string` columns holding JSON, never queried by the database, deserialised in the store.
`HasColumnType(_tweaks.JsonColumnType)` returns `"jsonb"` on Postgres (free indexing if a customer
wants it later) and `"TEXT"` on SQLite. Since we never write a `->>` predicate, the two behave
identically for us.

**(d) The fourth problem nobody lists: concurrency.** Postgres has `xmin` for optimistic
concurrency; SQLite has nothing equivalent, and `SaveChanges`-based concurrency tokens differ
between providers. N-07 and N-08 both need a compare-and-swap whose *rows-affected count is the
authority*.

Answer: those two operations never go through the change tracker. They are `ExecuteUpdateAsync`,
which is provider-neutral and returns the row count:

```csharp
// Storage.EntityFrameworkCore/Stores/EfAuthorizationCodeStore.cs
public async Task<CodeRedemption> TryRedeemAsync(
    string codeHash, string requestId, DateTimeOffset now, CancellationToken ct)
{
    var rows = await _db.AuthorizationCodes
        .Where(c => c.CodeHash == codeHash && c.RedeemedAt == null)
        .ExecuteUpdateAsync(s => s
            .SetProperty(c => c.RedeemedAt, now)
            .SetProperty(c => c.RedeemedByRequestId, requestId), ct);

    // rows == 1 -> we redeemed it. rows == 0 -> someone else did, or it never existed.
    // N-07: the row is NOT deleted; it stays until ExpiresAt so a replay can be fully validated
    // before we decide whether to revoke descendants.
    return rows == 1 ? CodeRedemption.Redeemed : CodeRedemption.AlreadyRedeemed;
}
```

The same shape guards `RefreshToken.ConsumedAt == null` for N-08. A doctor probe (§8.4) runs a
1000-way parallel redemption against the configured provider at startup in non-production
environments and fails if more than one caller wins — because "the CAS is real on this provider"
is a claim, and unverified claims are what this whole proposal is about.

### 3.3 Indices that matter

`AuthorizationCode(ExpiresAt)`, `RefreshToken(ExpiresAt)`, `RefreshToken(GrantId)`,
`Grant(UserId, ClientId)`, `Client(TenantId)`, `ReplayGuard(ExpiresAt)`.
A background `ExpirySweeper` deletes in bounded batches (`Take(1000)`) on a timer, never on the
request path — C-29 says nothing may be slow at `/token`, and a cascading delete triggered by a
token request is exactly how that happens.

---

## 4. Extensibility seams

All in `Boltway.Auth.Abstractions`. Real signatures.

### 4.1 Client authentication

```csharp
namespace Boltway.Auth.Abstractions.Clients;

public interface IClientAuthenticator
{
    /// <summary>The `token_endpoint_auth_method` value this strategy implements.</summary>
    string Method { get; }

    /// <summary>True if this request carries credentials of this strategy's shape — used to
    /// detect "more than one mechanism presented" (X-17) BEFORE any is verified.</summary>
    bool IsPresent(ClientAuthenticationContext context);

    ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context, CancellationToken ct);
}

public sealed record ClientAuthenticationContext(
    IReadOnlyDictionary<string, string> Form,
    string? AuthorizationHeader,
    string EndpointUrl,          // U-08: private_key_jwt aud may be this...
    string Issuer,               // ...or this. We accept both.
    CorrelationId CorrelationId);

public sealed record ClientAuthenticationResult(
    Client? Client,
    Rejection? Rejection,
    bool CredentialsCameFromAuthorizationHeader);   // X-18: decides 401 vs 400
```

v1 ships: `NoneAuthenticator`, `ClientSecretBasicAuthenticator`, `ClientSecretPostAuthenticator`,
`PrivateKeyJwtAuthenticator`.
A customer adds mTLS (D-03) by writing one class and calling
`.AddClientAuthenticator<TlsClientAuthAuthenticator>()`. The metadata document's
`token_endpoint_auth_methods_supported` is **generated from the registered set** (A-04/N-06), so
adding the class also advertises it — and removing it also un-advertises it. There is no second list.

### 4.2 External identity provider

```csharp
namespace Boltway.Auth.Abstractions.Federation;

public interface IExternalIdentityProvider
{
    /// <summary>Stable id used in URLs and the login page. Must be [a-z0-9-].</summary>
    string Scheme { get; }
    string DisplayName { get; }

    /// <summary>A-11: when this returns Unavailable, the login page renders a DISABLED control
    /// with <see cref="ProviderAvailability.Reason"/> shown to the user — it never vanishes.</summary>
    ValueTask<ProviderAvailability> GetAvailabilityAsync(
        string? clientId, CancellationToken ct);

    ValueTask<Uri> BuildChallengeAsync(ExternalChallengeContext context, CancellationToken ct);

    ValueTask<ExternalLoginResult> HandleCallbackAsync(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct);
}

public sealed record ProviderAvailability(bool Available, string? Reason);

public sealed record ExternalLoginResult(
    string UpstreamIssuer,
    string UpstreamSubject,          // D-10: NEVER becomes our `sub`
    IReadOnlyDictionary<string, string> Claims,
    Rejection? Rejection);
```

`GetAvailabilityAsync` is the direct answer to the field report's "social sign-in stays broken for
the CIMD client until that connection is promoted, and the symptom will be a missing login option
rather than an error" (A-11). A provider that cannot serve this client returns
`new ProviderAvailability(false, "This sign-in method is not enabled for claude.ai. Ask an
administrator to enable it.")` and the button renders greyed with that text under it. Silence is
not an available outcome.

v1 ships: `GoogleOidcProvider`. Adding GitHub is one class + one `AddExternalProvider<T>()`.

### 4.3 Token format and minting

```csharp
namespace Boltway.Auth.Abstractions.Tokens;

public interface IAccessTokenFormat
{
    string TokenType { get; }        // "Bearer". A DPoP format (D-02) would return "DPoP".

    ValueTask<MintedAccessToken> MintAsync(AccessTokenRequest request, CancellationToken ct);
}

public sealed record AccessTokenRequest(
    string Subject,
    string ClientId,
    string GrantId,
    ScopeSet Scopes,
    ResourceIdentifier Resource,     // N-01: singular, validated, non-null. Not "the default".
    DateTimeOffset AuthTime,
    IReadOnlyDictionary<string, object?> ExtraClaims);

public sealed record MintedAccessToken(
    string Value, string Jti, DateTimeOffset ExpiresAt, string Kid);
```

Note `Resource` is a non-nullable `ResourceIdentifier`, not a `string?`. The type system therefore
forbids minting a token without a resolved resource — N-01's "never stamp a house default when
`resource` was present" cannot be violated by a minting call site, only by the resolution stage,
which is one file with its own test.

v1 ships `Rfc9068JwtAccessTokenFormat`. An opaque-token format is one class; the introspection
endpoint already goes through the store rather than the JWT, so it keeps working.

### 4.4 Claim mapping

```csharp
public interface IClaimMapper
{
    /// <summary>Claims for the ID Token, gated on the `openid` scope (S-10, C-13).</summary>
    ValueTask<IReadOnlyDictionary<string, object?>> MapIdTokenClaimsAsync(
        ClaimMappingContext context, CancellationToken ct);

    ValueTask<IReadOnlyDictionary<string, object?>> MapUserInfoClaimsAsync(
        ClaimMappingContext context, CancellationToken ct);

    ValueTask<IReadOnlyDictionary<string, object?>> MapAccessTokenClaimsAsync(
        ClaimMappingContext context, CancellationToken ct);
}

public sealed record ClaimMappingContext(
    User User, Client Client, ScopeSet GrantedScopes, string Subject, AuthSession Session);
```

v1 ships `StandardOidcClaimMapper` (the `claims_supported` list from §3 of the requirements, gated
per scope). `claims_supported` in the metadata document is **generated by asking the registered
mappers what they can emit**, so A-04 holds here too.

### 4.5 Stores

```csharp
namespace Boltway.Auth.Abstractions.Storage;

public interface IClientStore
{
    ValueTask<Client?> FindByClientIdAsync(string clientId, CancellationToken ct);
    ValueTask<IReadOnlyList<Client>> ListByTenantAsync(string tenantId, int skip, int take, CancellationToken ct);
    ValueTask AddAsync(Client client, CancellationToken ct);
    ValueTask ReplaceAsync(Client client, CancellationToken ct);       // RFC 7592 PUT is full replacement
    ValueTask RemoveAsync(string clientId, CancellationToken ct);
    ValueTask<int> CountByTenantAsync(string tenantId, CancellationToken ct);   // quota, A-09
}

public interface IAuthorizationCodeStore
{
    ValueTask StoreAsync(AuthorizationCode code, CancellationToken ct);
    ValueTask<AuthorizationCode?> FindAsync(string codeHash, CancellationToken ct);
    /// <summary>Atomic compare-and-swap. rows-affected is the authority (N-07).</summary>
    ValueTask<CodeRedemption> TryRedeemAsync(string codeHash, string requestId, DateTimeOffset now, CancellationToken ct);
}

public interface IRefreshTokenStore
{
    ValueTask StoreAsync(RefreshToken token, CancellationToken ct);
    ValueTask<RefreshToken?> FindAsync(string tokenHash, CancellationToken ct);
    /// <summary>N-08: exactly one successor, ever. Returns the winner's successor to the loser.</summary>
    ValueTask<RotationResult> TryRotateAsync(
        string parentHash, RefreshToken successor, DateTimeOffset now, CancellationToken ct);
    ValueTask RevokeFamilyAsync(string grantId, string reason, DateTimeOffset now, CancellationToken ct);
}

public interface IGrantStore    { /* Find, Add, Revoke, IsActive */ }
public interface IUserStore     { /* FindById, FindByEmail, FindByExternalIdentity, Add, Update */ }
public interface IConsentStore  { /* Find, Upsert, Revoke, ListForUser */ }
public interface ISigningKeyStore { /* ListActive, ListPublishable, Add, Transition */ }
public interface IResourceStore { /* FindByIdentifier, List */ }
public interface IReplayGuardStore { ValueTask<bool> TryClaimAsync(string purpose, string jti, DateTimeOffset expiresAt, CancellationToken ct); }
```

v1 ships EF Core implementations of all of them plus in-memory. A customer replacing storage
implements ten interfaces; a customer replacing *one* (e.g. putting refresh tokens in Redis)
replaces one registration.

### 4.6 Authorization-request source — the PAR seam (D-01)

```csharp
namespace Boltway.Auth.Abstractions.Authorization;

public interface IAuthorizationRequestSource
{
    /// <summary>Ordered; the first source that Claims() a request owns it.</summary>
    int Order { get; }
    bool Claims(IReadOnlyDictionary<string, StringValues> query);

    ValueTask<AuthorizationRequestResolution> ResolveAsync(
        IReadOnlyDictionary<string, StringValues> query, CancellationToken ct);
}

public sealed record AuthorizationRequestResolution(
    AuthorizeRequest? Request, Rejection? Rejection);
```

v1 ships `QueryStringSource` (`Order = 100`, `Claims` returns true unconditionally). Adding PAR is
`ParRequestUriSource` with `Order = 10` claiming requests that carry `request_uri`, plus a `/par`
endpoint, plus the two metadata keys. **Nothing in the pipeline changes**, because stage 01 already
consumes an `AuthorizeRequest`, not an `HttpContext`. This is the one deferral flagged as costing
real rework later (FAPI 2.0), and this seam is what makes it additive.

### 4.7 Subject identifier (D-11)

```csharp
public interface ISubjectIdentifierService
{
    /// <summary>A-18: the returned value is opaque and safe to place in a URL path segment,
    /// a filename, or a cache key without further encoding. Charset is documented and tested.</summary>
    ValueTask<string> GetSubjectAsync(User user, Client client, CancellationToken ct);
}
```

v1 ships `PublicSubjectIdentifierService` (ignores `client`; returns `user.UserId`, which we mint
as 22 chars of base64url — so the `sub` charset we emit is `[A-Za-z0-9_-]{22}`, documented, and
contains no `|`, `/`, `:` or `.`). **UserInfo calls the same service**, so a later pairwise
implementation stays consistent by construction rather than by remembering.

### 4.8 Consent storage and presentation

```csharp
public interface IConsentStore { /* above */ }

public interface IConsentPresenter
{
    /// <summary>N-14. The returned model is what the view renders; the view has no other data.</summary>
    ValueTask<ConsentPresentation> BuildAsync(ConsentRequest request, CancellationToken ct);
}

public sealed record ConsentPresentation(
    string RelyingPartyHost,          // host of the client_id URL. NOT client_name. MCP MUST.
    string? SelfAssertedName,         // client_name, HTML-encoded, capped at 128 chars, secondary
    Uri? ProxiedLogoUrl,              // /consent/logo/{hash} on OUR origin. Never the source URL.
    string RedirectUriHost,           // MCP MUST
    bool AllRedirectsAreLoopback,     // MCP SHOULD: renders the loopback warning
    IReadOnlyList<ScopeLine> Scopes); // A-14: Description is the configured string, verbatim

public sealed record ScopeLine(string Name, string Description, bool HasConfiguredDescription);
```

`HasConfiguredDescription == false` renders the raw scope name **and** emits a
`consent.scope.description_missing` warning log naming the scope (A-14's second half). There is no
option to turn any of this off (A-15) — `ConsentPresentation` has no flags, so there is nothing to
turn off.

### 4.9 The guarded outbound fetcher (N-05)

```csharp
namespace Boltway.Auth.Abstractions.Net;

public interface IGuardedHttpClient
{
    /// <summary>The ONLY way to fetch an attacker-influenced URL. Used by CIMD,
    /// jwks_uri, logo_uri, sector_identifier_uri, request_uris.</summary>
    ValueTask<GuardedFetchResult> GetAsync(
        string url, GuardedFetchOptions options, CancellationToken ct);
}

public sealed record GuardedFetchOptions(
    int MaxBytes,                    // bytes READ, enforced on the stream, not Content-Length
    TimeSpan ConnectTimeout,         // 3 s
    TimeSpan TotalTimeout,           // 5 s; CIMD passes 2 s (C-29)
    string ExpectedMediaType);       // "application/json" — parsed, parameters ignored (§10 U-03)

public sealed record GuardedFetchResult(
    int StatusCode, string? Body, string? ETag, TimeSpan? MaxAge,
    IPAddress? ConnectedTo, Rejection? Rejection);
```

Implementation notes that are requirements, not choices:
`AllowAutoRedirect = false` (it defaults to **true** in .NET — a stock `HttpClient` violates
CIMD §5's MUST NOT); `UseProxy = false`, `UseCookies = false`, `Credentials = null`,
`AutomaticDecompression = None`; `SocketsHttpHandler.ConnectCallback` resolves the host, filters
the address list through the RFC 6890 table **after `MapToIPv4()`**, and connects to a validated
`IPAddress` — never re-resolving, which closes the DNS-rebinding TOCTOU; the response body is read
through a counting stream that aborts at `MaxBytes`.

---

## 5. Request pipeline

### 5.1 `/authorize` (E-08) — N-11 order is the security control

Each stage returns `StageOutcome`: `Continue`, `Reject(Rejection)`, or `Interrupt(AuthorizeOutcome)`.
The pipeline is a hard-coded array in `AuthorizePipeline.cs`, **not** DI-ordered — a DI-ordered
security control is a security control an operator can reorder.

| # | Stage | Guards | If it fails |
|---|---|---|---|
| 0 | `CorrelationMiddleware` | A-09 | — mints/echoes `X-Request-Id`, opens an `Activity` |
| 0 | `SecurityHeadersMiddleware` | **N-15** | registers `Response.OnStarting` so Razor cannot clobber CSP/XFO/Referrer-Policy |
| 0 | `LatencyBudgetMiddleware` | C-29 | starts a 10 s budget stopwatch; `DisableBuffering()` |
| 0 | Method + CORS | E-08 | `MUST NOT` have CORS — no `RequireCors` on this route |
| 1 | `IAuthorizationRequestSource.ResolveAsync` | D-01 seam | X-04 (repeated params) → **html 400**, no redirect yet |
| 2 | **`ResolveClientStage`** | N-11 ①, S-16, N-05 | X-01/X-03 → **html 400**. CIMD fetch happens here, ≤2 s, stale-on-error |
| 3 | **`ValidateRedirectUriStage`** | **N-03, N-04**, N-11 ② | X-02 → **html 400, no `Location` header** |
| — | *— redirecting errors becomes permitted here and not one line earlier —* | | |
| 4 | `ResponseTypeStage` | S-01 | X-07 → redirect |
| 5 | `PkceStage` | **N-02** | X-04 → redirect. Sets `PkceWasRequested` |
| 6 | `ScopeStage` | A-13, C-23 | X-08 → redirect |
| 7 | `ResourceStage` | **N-01**, S-18, A-02 | X-09 → redirect. Unknown and not-permitted return the *same string and description* (enumeration oracle) |
| 8 | `PromptAndMaxAgeStage` | U-12 | X-04 → redirect |
| 9 | `AuthenticateUserStage` | N-11 ③ | X-12 (`prompt=none`) → redirect; else `Interrupt(RenderLogin)` |
| 10 | `ConsentStage` | **N-14**, S-05 §8.6 | X-13/X-06 → redirect; else `Interrupt(RenderConsent)` |
| 11 | `IssueCodeStage` | N-16 | code hashed at rest; `Interrupt(Redirect)` |
| ∞ | `AuthorizeExceptionFilter` | X-10 | any unhandled exception **after stage 3** ⇒ `server_error` **redirect**, never HTTP 500. Before stage 3 ⇒ html 500. This split is the reason the filter must know the stage index, and it does |

Two things the table hides and that reviewers get wrong:

- Stage 3 failing must produce a response with **no `Location` header at all**. The architecture
  test for N-11 asserts the 400 response from an unregistered `redirect_uri` contains no `Location`
  and no `Refresh` header — the latter because a meta-refresh is a redirect the header test misses.
- The login and consent interrupts carry a `returnUrl` back into `/authorize`. That parameter is
  gated by `Url.IsLocalUrl` **and** re-validated against the stored request state on return, because
  `IsLocalUrl` alone accepts `//evil.example` on some historical versions and defence in depth here
  is one line.

### 5.2 `/token` (E-10)

| # | Step | Guards | Failure |
|---|---|---|---|
| 0 | Correlation, security headers, budget (10 s / 30 s refresh), `Cache-Control: no-store` | C-29 | |
| 1 | **Form binding only** — `Request.HasFormContentType`, else X-17 with an OAuth body | **C-15** | never 415. There is a test that POSTs `Content-Type: application/json` and asserts 400 + `{"error":"invalid_request"}` |
| 2 | `ClientAuthenticator.Detect` — count present mechanisms | X-17 | >1 ⇒ `invalid_request` **before** verifying any |
| 3 | `ClientAuthenticator.AuthenticateAsync` | X-18 | 401 + `WWW-Authenticate` iff creds came from the header, else 400 |
| 4 | Grant-type dispatch table | X-21 | unknown ⇒ `unsupported_grant_type`, **not** `invalid_request` |
| 5 | Grant-type-allowed-for-client | X-20 | `unauthorized_client` |
| 6 | Grant handler (§5.3) | | |
| 7 | `ResourceStage` (shared with `/authorize`) | **N-01**, X-23 | `invalid_target`, **never** `invalid_grant` — clients discard refresh tokens on `invalid_grant` |
| 8 | Mint + persist | N-09, N-10, N-16 | |

**Argon2 is not on this path.** Password verification exists only in the `/login` POST handler.
An architecture test asserts that no type reachable from `TokenEndpoint` references
`Konscious.Security.Cryptography`. This is C-29 enforcement: Argon2id at the parameters we use
costs ~100 ms and burns 64 MiB, and putting it behind a `/token` request under refresh-storm load
is how a 10 s budget becomes a 30 s queue.

### 5.3 The two hard grant handlers

**`AuthorizationCodeGrant` (N-07), in this exact order:**

1. Hash the presented code; `FindAsync`. Not found ⇒ `invalid_grant`.
2. **If already redeemed: run the full validation anyway** — client binding, `redirect_uri` (if
   sent), PKCE verifier. If *any* check fails ⇒ `invalid_grant` and **do not touch the grant**.
   This is the DoS defence: an attacker with a sniffed code but no verifier cannot kill the
   legitimate client's tokens.
   If *all* checks pass, this is a genuine replay by the legitimate holder ⇒ revoke the grant and
   all descendants, log `oauth.code.replay_detected` at `Warning` with the grant id.
3. Not yet redeemed: `TryRedeemAsync` (atomic). Lost the race ⇒ go to step 2's logic.
4. Validate client binding, `redirect_uri` (S-02: accept but never require; enforce per 6749 when
   present), PKCE **XOR** against `PkceWasRequested` (N-02 — both directions ⇒ `invalid_grant`).
5. Resolve `resource` against the code's grant set (X-23), mint, persist.

**`RefreshTokenGrant` (N-08):**

1. Hash, find. Unknown/expired/revoked ⇒ `invalid_grant` (C-20: that exact string).
2. If `ConsumedAt != null`:
   - `now - ConsumedAt <= GraceWindow` (default 45 s, configurable 30–60 s) **and**
     `SuccessorTokenHash != null` ⇒ **idempotent replay**: return the *same* pair the winner got.
     Log `oauth.refresh.grace_replay` at `Information`. This is Claude's proactive+reactive race
     (C-19) and it must not look like an attack.
   - Otherwise ⇒ **reuse detected**: `RevokeFamilyAsync`, log `oauth.refresh.reuse_detected` at
     `Warning`, return `invalid_grant`.
3. `TryRotateAsync(parentHash, successor)` — conditional `UPDATE … WHERE ConsumedAt IS NULL`.
   Rows-affected 0 ⇒ someone else won; re-read and take the grace path. **Never fork the family**
   (GHSA-392p-2q2v-4372).
4. Mint the new access token and the successor refresh token **in the same response** (C-21).

### 5.4 The Rejection type — how A-09 becomes structural

```csharp
namespace Boltway.Auth.Diagnostics;

/// <summary>The only value that can become a non-2xx OAuth response. Cannot be constructed
/// without a ReasonCode; cannot be written without emitting exactly one log record.</summary>
public sealed record Rejection
{
    public required ReasonCode Reason { get; init; }        // closed enum, one value per X-nn condition
    public required string OAuthError { get; init; }        // "invalid_client", …
    public required int HttpStatus { get; init; }
    public required string PublicDescription { get; init; } // A-12: goes in the body/redirect
    public string? PrivateDetail { get; init; }             // log only
    public string? RequirementId { get; init; }             // "N-03", "X-09" — appears in the log
    public int? RetryAfterSeconds { get; init; }
}

public interface IRejectionWriter
{
    /// <summary>Emits the structured log (with the correlation id), increments the counter,
    /// stamps the Activity, and returns the IResult. There is no other way to render one.</summary>
    IResult Write(HttpContext context, Rejection rejection);
}
```

The rules that make this work:
- `RejectionWriter.Write` is the **only** place `Results.Json`/`Results.Content` is called for a
  non-2xx on an OAuth route. An architecture test asserts no other type in `Server` produces a
  4xx/5xx `IResult`.
- `PublicDescription` is passed through `ErrorDescriptionSanitiser` before emission: strips
  everything outside `%x20-21 / %x23-5B / %x5D-7E` (no `"`, no `\`), caps at 240 chars, and
  **appends ` [ref: {correlationId}]`**. So the correlation id is in the redirect query string, in
  the JSON body, in the HTML page, and in the `WWW-Authenticate` — the same id the log carries. A
  user who screenshots "something went wrong [ref: 7f3a91c2]" has handed the operator a grep key.
- An unescaped `"` in `error_description` truncates a `WWW-Authenticate` header and eats
  `resource_metadata`, which is the discovery entry point — the sanitiser is the fix and it has its
  own fuzz test.

---

## 6. Configuration model

### 6.1 Shape

```csharp
namespace Boltway.Auth.Server.Options;

public sealed class AuthorizationServerOptions
{
    /// <summary>The one immutable issuer string (N-13). Emitted verbatim: never
    /// `new Uri(x).ToString()`, never derived from Request.Host.</summary>
    [Required, IssuerUrl]
    public string Issuer { get; set; } = "";

    /// <summary>Which client-acquisition mechanism is advertised. Exactly one (N-06/A-05).</summary>
    public ClientAcquisitionMode ClientAcquisition { get; set; } = ClientAcquisitionMode.Cimd;

    public CimdOptions Cimd { get; set; } = new();
    public DynamicRegistrationOptions DynamicRegistration { get; set; } = new();
    public TokenOptions Tokens { get; set; } = new();
    public ConsentOptions Consent { get; set; } = new();
    public KeyOptions Keys { get; set; } = new();
    public LatencyBudgetOptions Budgets { get; set; } = new();
    public StorageOptions Storage { get; set; } = new();
}

public sealed class TokenOptions
{
    /// <summary>Access-token lifetime. MUST exceed 5 minutes or Claude's proactive refresh
    /// thrashes (C-19).</summary>
    [Range(typeof(TimeSpan), "00:05:01", "24:00:00")]
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>N-08 idempotency window for concurrent refresh (C-19).</summary>
    [Range(typeof(TimeSpan), "00:00:30", "00:01:00")]
    public TimeSpan RefreshGraceWindow { get; set; } = TimeSpan.FromSeconds(45);

    [AllowedValues("RS256", "ES256")]
    public string DefaultSigningAlgorithm { get; set; } = "RS256";
}
```

Validation: `services.AddOptions<AuthorizationServerOptions>().Bind(...).ValidateDataAnnotations()
.Validate<IValidateOptions<...>>().ValidateOnStart()`, plus a hand-written
`IValidateOptions<AuthorizationServerOptions>` for the cross-field rules:

- **N-06/A-05:** `ClientAcquisition == Cimd && DynamicRegistration.Enabled` ⇒
  `Fail("ClientAcquisition=Cimd and DynamicRegistration.Enabled=true are mutually exclusive.
  A client that sees both advertised has been measured choosing DCR and then failing (U-02).
  Set DynamicRegistration.Enabled=false or ClientAcquisition=DynamicRegistration.")`
  Naming the offending pair is the acceptance criterion, so the message is tested.
- **N-13:** `Issuer` is `https`, no query, no fragment, **no trailing slash**, and `Ordinal`-equal
  to `IssuerString.Instance`.
- **N-06 (the general form):** every advertised capability is cross-checked against the DI
  container. `token_endpoint_auth_methods_supported` is generated from the registered
  `IClientAuthenticator` set. If someone hard-codes a value there that has no registered
  authenticator, startup fails.

### 6.2 A-17 without a second hand-maintained list

`GET /admin/config/schema` returns type, allowed values, default, current value, and a description
for every key. All five come from things that already exist:

| Field | Source |
|---|---|
| key path | recursive reflection over the options tree (`Tokens:AccessTokenLifetime`) |
| type | `PropertyInfo.PropertyType`, rendered to a friendly name |
| allowed values | enum members, or `[AllowedValues]`, or `[Range]`, or `[RegularExpression]` |
| **default** | `Activator.CreateInstance<TOptions>()` — a *fresh instance*. The property initialiser **is** the default; there is no second list to drift |
| current | the bound `IOptions<TOptions>.Value`, with `[Secret]`-marked properties rendered as `"***"` |
| description | the `///` XML doc comment, read from the generated XML file, which `Directory.Build.props` already emits (`GenerateDocumentationFile=true`) |

That last row is the trick that makes A-17 cheap. The description a developer writes for the next
developer becomes the description an operator reads at 2am, and there is exactly one copy of it. The
`.xml` file is embedded as a resource (`<EmbeddedResource Include="$(DocumentationFile)" />`) so it
ships with the assembly and works in a single-file publish.

A test asserts the schema endpoint enumerates **every** property reachable from
`AuthorizationServerOptions`, so adding an option without a doc comment fails the build
(`TreatWarningsAsErrors` + CS1591 already does most of this).

A-16 (all-or-nothing writes, unknown keys rejected loudly) is the `PATCH /admin/config` sibling:
bind into a fresh instance, reject on any unbound key by name, validate the whole result, write,
**read back and compare**, and return the read-back. The field report's "patching the whole flags
object silently drops the key" is not reproducible against an endpoint that returns what it stored.

---

## 7. Testing architecture

### 7.1 Requirement traceability without a hand-kept matrix

A checked-in `tests/requirements.tsv` — generated once from `REQUIREMENTS.md` by a script, then
version-controlled — has one row per ID: `id, section, binding(bool), title`.

```csharp
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public sealed class RequirementAttribute : Attribute
{
    public RequirementAttribute(params string[] ids) => Ids = ids;
    public string[] Ids { get; }
}

// usage
[Fact, Requirement("N-03", "S-28")]
public void RedirectUri_with_default_port_elided_does_not_match() { … }
```

One meta-test closes the loop:

```csharp
[Fact]
public void Every_binding_requirement_has_at_least_one_covering_test()
{
    var required = RequirementsTsv.Load().Where(r => r.Binding).Select(r => r.Id).ToHashSet();
    var covered  = typeof(ConformanceTests).Assembly.GetTypes()
        .SelectMany(t => t.GetMethods())
        .SelectMany(m => m.GetCustomAttributes<RequirementAttribute>())
        .SelectMany(a => a.Ids).ToHashSet();

    var uncovered = required.Except(covered).OrderBy(x => x).ToArray();
    Assert.True(uncovered.Length == 0,
        $"{uncovered.Length} binding requirements have no test: {string.Join(", ", uncovered)}");
}
```

This fails red on day one with 170 uncovered and becomes the build-out worklist. It is also the
answer to "did we actually do all 187" without anyone maintaining a spreadsheet. `U-nn` rows are
`binding=false` and are instead surfaced by a second test that *prints* them, so an unverified
assumption stays visible in CI output rather than being forgotten.

`dotnet test --logger "trx"` plus a small `ReportGenerator` step emits
`artifacts/requirement-coverage.md`, which is what goes in front of a customer.

### 7.2 Architecture tests (Mono.Cecil) — N-03 and N-12

```csharp
// tests/Boltway.Auth.Architecture.Tests/NonNegotiableTests.cs

[Fact, Requirement("N-03")]
public void Primitives_assembly_never_references_System_Uri()
{
    var module = ModuleDefinition.ReadModule(Asm.Primitives);

    var violations =
        from type in module.Types.SelectMany(Flatten)
        from method in type.Methods.Where(m => m.HasBody)
        from instr in method.Body.Instructions
        let reference = instr.Operand as MemberReference
        where reference?.DeclaringType?.FullName is "System.Uri" or "System.UriBuilder"
        select $"{type.FullName}.{method.Name} -> {reference.FullName}";

    // also catches fields, parameters, return types, generic args
    violations = violations.Concat(TypeUsageScanner.FindUsagesOf(module, "System.Uri"));

    Assert.True(!violations.Any(),
        "N-03: System.Uri must never be the input to a redirect-URI comparison. "
      + "It lowercases scheme+host, elides default ports, resolves dot segments and "
      + "percent-decodes — each of which silently widens the match set.\n"
      + string.Join("\n", violations));
}

[Fact, Requirement("N-12")]
public void No_307_or_308_redirect_anywhere_in_the_server()
{
    var module = ModuleDefinition.ReadModule(Asm.Server);
    var violations = new List<string>();

    foreach (var method in module.Types.SelectMany(Flatten).SelectMany(t => t.Methods).Where(m => m.HasBody))
    foreach (var instr in method.Body.Instructions)
    {
        // (a) a literal 307/308 pushed onto the stack
        if (instr.OpCode == OpCodes.Ldc_I4 && instr.Operand is int v and (307 or 308))
            violations.Add($"{method.FullName}: literal {v}");

        // (b) Results.Redirect(..., preserveMethod: true) — emits exactly 307
        if (instr.Operand is MethodReference mr
            && mr.Name is "Redirect" or "RedirectPreserveMethod"
            && mr.DeclaringType.FullName.StartsWith("Microsoft.AspNetCore.Http.Results")
            && PushesTrueForParameter(method, instr, "preserveMethod"))
            violations.Add($"{method.FullName}: Results.Redirect(preserveMethod: true)");

        // (c) TypedResults.RedirectPreserveMethod / StatusCodes.Status307*
        if (instr.Operand is FieldReference fr
            && fr.Name is "Status307TemporaryRedirect" or "Status308PermanentRedirect")
            violations.Add($"{method.FullName}: {fr.Name}");
    }

    Assert.True(violations.Count == 0,
        "N-12 / RFC 9700 §4.12: a 307 after a credential POST makes the browser re-POST the "
      + "user's password to the client. Use OAuthResults.SeeOther.\n" + string.Join("\n", violations));
}
```

Two more in the same file, same shape:

```csharp
[Fact, Requirement("N-05")]
public void Only_the_Http_assembly_constructs_an_HttpClient() { … }
// allowlist: Boltway.Auth.Http, and Federation.Google with a named justification.

[Fact, Requirement("C-29")]
public void Argon2_is_unreachable_from_the_token_endpoint() { … }
// call-graph walk from TokenEndpoint.* looking for Konscious.*
```

### 7.3 The other three test projects

- **`Unit.Tests`** — pure logic. The 16-row redirect matrix (N-04), RFC 7636 Appendix B vector,
  the `WWW-Authenticate` quoting fuzz, the RFC 6890 range table, `ScopeSet` normalisation.
- **`Conformance.Tests`** — `WebApplicationFactory` against the in-memory store, one test class per
  requirements section. This is where the five `curl` commands from the requirements appendix live
  as tests, and where the byte-identical-discovery-documents diff (A-21) runs.
- **`Interop.Tests`** — replays the four **real** CIMD documents from
  `research/cimd-live-2026-08-03.json`, checked in as fixtures. Each drives a complete
  authorize→consent→token→refresh flow against the test host. This is the test that would have
  caught C-04 (ChatGPT's plural field name) and §10's charset finding, because the fixture bodies
  are the actual bytes those vendors serve, `Content-Type` included.
  Plus a `[Fact(Skip=...)]`-by-default **live** variant that re-fetches the four URLs and fails if
  they have drifted from the fixtures — run nightly, not in PR CI. Drift in a vendor's client
  document is exactly the kind of thing that must not be discovered by a customer.

### 7.4 The reuse boundary test (the C# `check:boundary`)

```csharp
[Fact]
public void ResourceServer_distribution_does_not_drag_in_the_authorization_server()
{
    var closure = ProjectGraph.TransitiveClosure("Boltway.Auth.ResourceServer");
    Assert.Equal(
        new[] { "Boltway.Auth.Abstractions", "Boltway.Auth.Diagnostics",
                "Boltway.Auth.Http", "Boltway.Auth.Primitives",
                "Boltway.Auth.ResourceServer" },
        closure.OrderBy(x => x, StringComparer.Ordinal));
}
```

Plus the FictStoryEngine step (4) equivalent as a script, `eng/check-boundary.sh`: copy the five
projects into a scratch directory with no other sources present and `dotnet build`. A green build
there is proof; a passing reference-graph assertion alone is only evidence.

---

## 8. Operability — the part this proposal exists for

### 8.1 Event taxonomy

A closed enum, one value per rejection condition, mechanically derived from the X-nn table. Every
log record from an OAuth endpoint carries the same field set:

```
ts, level, event, reason, requirement, request_id, trace_id,
client_id, client_kind, tenant_id, sub, resource, grant_id, endpoint,
duration_ms, status, outcome
```

Event names (Serilog `SourceContext`-independent, so they survive a sink change):

```
oauth.authorize.received / .rejected / .redirected / .consent_shown / .code_issued
oauth.token.received / .rejected / .issued
oauth.refresh.rotated / .grace_replay / .reuse_detected
oauth.code.replay_detected
oauth.client.cimd_fetched / .cimd_stale_served / .cimd_rejected
oauth.client.registered / .quota_rejected          ← the field report's invisible failure
oauth.metadata.served
oauth.key.rotated / .published
oauth.login.succeeded / .failed / .provider_unavailable
oauth.consent.granted / .denied / .scope_description_missing
oauth.budget.warning                                ← C-29, at 25%
rs.token.rejected / .insufficient_scope
```

`Serilog` with `Serilog.Sinks.Console` in `CompactJsonFormatter` by default. Redaction is a
destructuring policy modelled on FictStoryEngine's `redact()`: regex for `Bearer\s+\S+` and
`eyJ[A-Za-z0-9._-]{20,}` over every string field, plus a key denylist. It runs on *every* field, not
the ones we remember — a JWT that ends up in an `error_description` because someone concatenated it
is exactly the leak that a field-selective redactor misses.

**The quota row is the point.** The field report's worst failure was a tenant quota rejection that
produced no log entry at all, because it happened on an administrative path. Here,
`oauth.client.quota_rejected` is a `Warning` with `tenant_id`, current count, and limit, and the
DCR response is a 429 with `Retry-After` and a description naming the quota (X-31). A quota
rejection that logs nothing is not reachable, because the only way to reject is `Rejection`, and
writing one logs.

### 8.2 Correlation

`CorrelationMiddleware` runs first on every route: echoes an inbound `X-Request-Id` if it matches
`^[A-Za-z0-9_-]{8,64}$` (rejecting anything else rather than logging attacker-controlled text),
otherwise mints 16 base64url chars. It sets `Activity.Current.SetTag("request_id", …)`, pushes it
into the Serilog `LogContext`, and adds it as a response header on **every** response including
errors and redirects. `ErrorDescriptionSanitiser` appends ` [ref: {id}]` (§5.4). The HTML error page
renders it in a `<code>` block large enough to read in a screenshot.

Cost: one middleware, ~60 lines. This is the highest-value-per-line item in the whole proposal.

### 8.3 Metrics and the latency budgets

`System.Diagnostics.Metrics`, exported via OpenTelemetry OTLP (already in
`Directory.Packages.props`), meter name `Boltway.Auth`:

| Instrument | Type | Tags |
|---|---|---|
| `oauth.request.duration` | Histogram\<double\> ms | `endpoint`, `outcome`, `grant_type` |
| `oauth.rejection` | Counter | `reason`, `endpoint`, `client_kind` |
| `oauth.cimd.fetch.duration` | Histogram | `outcome` ∈ `hit`/`miss`/`stale`/`error` |
| `oauth.refresh.rotation` | Counter | `result` ∈ `rotated`/`grace_replay`/`reuse` |
| `oauth.budget.headroom` | Histogram (fraction of budget consumed) | `endpoint` |
| `oauth.key.active_count` | ObservableGauge | — |
| `oauth.store.duration` | Histogram | `operation` |

`LatencyBudgetMiddleware` holds the per-endpoint budget (10 s for E-01..E-07/E-10/E-11, 30 s for
the refresh path, 2 s for the CIMD fetch inside `/authorize`) and emits
`oauth.budget.warning` at **25%** with the elapsed breakdown per stage — C-29 says aim well under,
and a warning at 2.5 s on a 10 s budget is the only signal that arrives before customers do.

The stage breakdown matters: `AuthorizePipeline` records elapsed per stage into the `Activity` as
events, so a slow `/authorize` says *which stage* (almost always the CIMD fetch or the store).
Without it, "authorize is slow" is a fortnight.

### 8.4 The doctor — the C# equivalent of FictStoryEngine's `--doctor`

FictStoryEngine's `diagnostics.ts` has three sections (tool catalogue, resource server config,
live authorization-server preflight) and returns *data* — `{ text, failed }` — so a deploy script
gates on the exit code and a human reads the same output. That shape is right and I keep it:

```csharp
namespace Boltway.Auth.Diagnostics;

public interface IDoctorProbe
{
    string Section { get; }
    /// <summary>Ordering within a section; probes that others depend on run first.</summary>
    int Order { get; }
    ValueTask<DoctorFinding> RunAsync(CancellationToken ct);
}

public sealed record DoctorFinding(
    DoctorLevel Level,          // Ok | Warn | Fail | NotMeasured
    string Message,
    string? Remediation,
    string? RequirementId);
```

**`NotMeasured` is a first-class level, ranked above measured negatives in the report.** That is
straight out of `Boltway/LESSONS.md` rule 1: "Every axis needs a third value… so that 'no host
was probed' cannot read like 'no IdP is there'." A doctor that reports `Fail` when it simply could
not reach something reproduces exactly the error that document is about.

Probes live **next to the feature they check**, not in a central file, so a feature and its probe
cannot drift. `boltway-auth doctor` (and `--doctor` on the host) runs all of them and exits
non-zero on any `Fail`.

What it checks:

*Configuration (static, no network):*
1. `Issuer` is https, no trailing slash, no query/fragment, and `Ordinal`-equal to the
   token-signing issuer constant (N-13). — *the FictStory audit's `1.2a` "issuer matches byte for
   byte", which it calls out as "cheap to check, expensive to discover during a review".*
2. Exactly one client-acquisition mechanism advertised (N-06/A-05), naming both if not.
3. Every advertised `token_endpoint_auth_methods_supported` value has a registered
   `IClientAuthenticator`.
4. Every advertised scope has a `ConsentDescription` (A-14), listing those that do not.
5. Every scope string survives A-13 normalisation unchanged — **naming the offending codepoint**.
   (Auth0 compared `"story:read "` literally and the dashboard rendered it identically to
   `story:read`.)
6. Every registered `ResourceRegistration.Resource` is a canonical RFC 8707 identifier.
7. At least one `Active` signing key, RSA ≥ 2048 or EC P-256, and at least one `Publishable` key.
8. Data-protection keys are persisted (not the default ephemeral in-container ring — the single
   most common "everyone got logged out on deploy" cause).
9. `AccessTokenLifetime > 5 min` (C-19) and `RefreshGraceWindow ∈ [30s, 60s]` (N-08).

*Capability proof (network, the N-06 half that config validation cannot do):*
10. Fetch our own five discovery URLs (E-01..E-06) **over the loopback interface using the
    configured issuer host header**, and assert all five bodies are byte-identical after canonical
    JSON sort (A-21).
11. Assert `code_challenge_methods_supported == ["S256"]` is present in **both** documents (C-09 —
    Claude refuses to proceed without it).
12. Assert `registration_endpoint` is absent iff DCR is disabled, in both documents (A-04).
    *This is the check that catches the Auth0 behaviour where the endpoint stays advertised after
    the feature is switched off.*
13. Fetch our own JWKS and assert no `d`/`p`/`q`/`dp`/`dq`/`qi` member appears anywhere (N-16),
    and that every key has a `kid` and a `use`.
14. **Resolve a real CIMD document end to end** — by default
    `https://claude.ai/oauth/claude-code-client-metadata` — through the guarded fetcher, and report
    the resolved `client_name`, redirect URIs, and auth method. If CIMD is advertised, this proves
    it *works*, which is precisely the gap the field report names: "CIMD advertises before it works,
    and the failure looks like the client's fault." `NotMeasured` (not `Fail`) when egress is
    deliberately blocked, with the reason.
15. SSRF self-test: assert the guarded fetcher refuses `https://169.254.169.254/`,
    `https://[::ffff:169.254.169.254]/`, and a 302-to-private-IP, **before any socket connect**.
    Running the guard against known-bad inputs at startup is cheaper than trusting it.
16. Mint a token for a registered resource and validate it with the **resource-server** validator
    configured from published metadata — a live N-01/N-09/N-13 round trip through the same code a
    customer's MCP server runs.
17. Store round trip: write and read back one row, report the latency, and run the parallel-CAS
    check (§3.2 (d)) in non-production.

*Environment (the #1 field failure mode, C-31):*
18. `dig`-equivalent on the issuer host: resolve `A` and `AAAA`. **Fail** if there is no `A` record
    (connectors are IPv4-only), and **Warn** if any resolved address is not globally routable.
19. `NotMeasured` with an explicit note that reachability from Anthropic's egress range
    `160.79.104.0/21` **cannot be established from inside your own network** — with the exact
    command to run from outside. This is the single most valuable line in the whole report and it
    is honest about what it does not know rather than printing a green tick.

Output is the same two-column text FictStory produces, plus `--json` for a deploy gate.

### 8.5 The admin surface (A-16, A-17)

Deliberately small. Four endpoints, all behind an admin policy, all `no-store`:

- `GET /admin/config/schema` — §6.2.
- `GET /admin/config` — current values, secrets masked.
- `PATCH /admin/config` — all-or-nothing, unknown keys 400 by name, read-back-verified.
- `GET /admin/doctor` — the doctor report as JSON, so a monitoring system can alert on it.

Explicitly **not** built: a UI, user management, a client browser, an audit-log viewer. Those are a
product, and this is a component. `boltway-auth` CLI covers the operator's actual needs.

---

## 9. Failure modes under load and partial failure

### 9.1 CIMD host down mid-`/authorize`

Budget 2 s (C-29 — the fetch is inside a 10 s user-visible flow). Behaviour, in order:

1. Cache hit within TTL (S-30 clamp: floor 300 s, ceiling 86 400 s, honouring `Cache-Control`) —
   no fetch at all. This is the common case: Claude's own document changes approximately never.
2. Miss or stale: **single-flight** per `client_id` (`SemaphoreSlim` keyed by the URL) so a
   thundering herd after a cache expiry produces one outbound request, not one per user.
3. Fetch fails or times out, **and a stale entry exists** ⇒ serve stale, log
   `oauth.client.cimd_stale_served` at `Warning` with the entry's age, increment
   `oauth.cimd.fetch.duration{outcome=stale}`. The flow continues. Stale entries are retained for
   24 h beyond their TTL for exactly this.
4. Fetch fails and **no** stale entry exists ⇒ this is a first-ever connection for that client.
   We cannot proceed. But note *where* we are: stage 2, before `redirect_uri` validation, so
   redirecting is forbidden (N-11) — it is an **html 400** carrying `invalid_client` and a
   description naming which check failed (A-07), plus the correlation id.
   *Judgement call:* X-11 `temporarily_unavailable` would be the friendlier code, but it is a
   redirect-delivered error and we have no validated redirect URI yet. Rendering HTML is the only
   safe option, so the HTML must be good: it names the URL we tried to fetch, the outcome
   (`timeout after 2000ms`), and the correlation id. `curl -D-` on it is a complete diagnosis (A-12).
5. **Errors are never cached** (S-30). A CIMD host that recovers must work on the next request, not
   in five minutes.

### 9.2 Database slow at `/token`

- **Argon2 is architecturally excluded** from this path (§5.2, with a Cecil test). The `/token`
  path touches: one client lookup, one code or refresh lookup, one CAS update, two inserts.
- Every store call has a `CancellationToken` derived from the endpoint budget. At 25% of budget an
  `oauth.budget.warning` fires naming the slow operation via `oauth.store.duration`.
- Connection pool exhaustion is the real risk under a refresh storm. `EnableRetryOnFailure` is
  configured **off** for `/token` operations and on for background work: a retry inside a 10 s
  budget converts a fast failure into a timeout, and a timeout is worse for the client than a
  `temporarily_unavailable` it can retry itself.
- Load shedding: when the pool is saturated beyond a threshold, `/token` returns **503 +
  `Retry-After`** rather than queuing. A 503 at 200 ms is a better outcome for Claude than a 200 at
  11 s, which is scored as a failure anyway (C-29: terminal "even if your server eventually
  completes the request").
- Cold start: migrations **never** run on the request path. `dotnet ef database update` is a deploy
  step and the doctor fails if pending migrations exist. The field report's "no synchronous
  migrations" is a deployment property, so it is checked at startup, not hoped for.

### 9.3 JWKS rotation racing verification

Three-phase, time-based, no coordination needed between instances:

1. **Publish** — new key enters `Pending`, appears in JWKS immediately, **signs nothing**.
2. Wait `PublishLeadTime` (default 10 min, and it must exceed the metadata `max-age=300` plus
   Claude's ~5 min discovery staleness window, C-30). Enforced by a config validation rule that
   states that arithmetic in its failure message.
3. **Activate** — key becomes `Active` and starts signing. Any verifier that fetched JWKS in the
   last 10 minutes already has it.
4. **Retire** — old key moves to `Retiring`: stops signing, stays in JWKS for at least the maximum
   access-token lifetime, then `Retired` and drops out.

The race that remains is a verifier holding a JWKS cache older than the lead time and seeing an
unknown `kid`. That is the resource server's problem and `Boltway.Auth.ResourceServer` handles
it: on unknown `kid`, one re-fetch, rate-limited to once per 60 s per issuer (so a bogus-`kid` flood
cannot be turned into a JWKS DoS against the AS), then `invalid_token` if still unknown.
`oauth.key.rotated` and the `oauth.key.active_count` gauge make a stuck rotation visible.

### 9.4 Two refreshes racing (N-08)

Covered mechanically in §5.3. The operational point: `oauth.refresh.rotation{result=grace_replay}`
is expected to be **non-zero and small** in healthy traffic, because Claude's proactive and reactive
refreshes genuinely race (C-19). The alert is not on its presence but on `result=reuse` — and on
`grace_replay` climbing toward the same order of magnitude as `rotated`, which means the grace
window is too short for the observed client behaviour. That is a dashboard row, and it is the
difference between "users report random logouts" and "the window is 45 s and p99 refresh spacing is
52 s".

### 9.5 Partial failure of an identity provider

`IExternalIdentityProvider.GetAvailabilityAsync` is called when rendering the login page, with a
500 ms budget and a cached result (30 s). Unavailable ⇒ disabled control with the reason (A-11),
never a missing button. If the provider's own token endpoint fails mid-callback, the user returns to
`/login` with a legible message carrying the correlation id, not to a generic error page.

---

## 10. Where I stop building observability

Observability infrastructure that outweighs the thing observed is a real failure mode, and this
proposal is more exposed to it than most. The line:

**Built, because each maps to a specific failure that cost real hours in the field report:**
correlation ids end to end · the `Rejection` type (rejection cannot be silent) · the event taxonomy ·
the seven metrics · the budget warning at 25% · the doctor · `GET /admin/config/schema`.
Estimated cost: ~1 200 lines across `Diagnostics` plus ~400 in `Server`. Roughly 6% of the codebase.

**Not built:**

- **No audit-log storage, no audit-log query API, no admin UI.** Structured JSON on stdout is the
  interface; the customer already has a log stack, and if they do not, an audit table in our
  database is the wrong place for it anyway. Rejected explicitly, because "admin dashboard" is how
  a component becomes a product.
- **No custom tracing.** OpenTelemetry's ASP.NET Core instrumentation plus our `Activity` tags is
  the whole story. We do not ship a trace viewer or a sampling policy.
- **No per-request debug mode.** A `?debug=1` that returns internal detail is a disclosure
  vulnerability wearing a diagnostic hat. The correlation id is the supported path from a user's
  screenshot to the operator's log, and it is enough.
- **No health-check framework beyond one `/healthz` returning 200/503.** The doctor is the deep
  check and it runs on demand, not every 10 seconds — probe #14 makes an outbound request to
  `claude.ai`, and doing that on a liveness probe is how you get rate-limited by a vendor and then
  file it as their bug (`LESSONS.md`, the conduct point).
- **No metric per requirement id.** Tempting, given §7.1's traceability machinery. It would produce
  ~170 counters that nobody reads. `oauth.rejection{reason}` with ~40 reason values is the right
  cardinality; the requirement id lives in the log record where it is useful during an
  investigation, not in a time series.
- **No log sampling or dynamic level control.** Total volume is bounded by human-scale auth
  traffic. If a customer needs it, Serilog's `LoggingLevelSwitch` is a config line they can add.

The general rule I applied: **an observability feature earns its place if it converts a class of
"user reports something is broken" into "operator runs one command".** Everything above the line
does; everything below it produces data that would only be read by someone who already knew the
answer.

---

## 11. What I would cut if the deadline halved, and what must never be cut

Ordered by what I would drop first.

**Cut first, in this order:**

1. **RFC 7592 DCR management (E-12..E-14, S-15).** CIMD is the default path (A-06/A-20) and creates
   no client records, so nothing in the primary flow touches these. ~2 days.
2. **`/logout` (E-18, S-11).** SHOULD, not MUST; no MCP client uses it. Omit
   `end_session_endpoint` — N-06 then makes the absence correct rather than a silent gap. ~1 day.
3. **`client_credentials` grant.** No connector uses it; every connection must carry user consent.
4. **`jwt-bearer` / Enterprise Managed Auth (C-32, S-26b).** Beta, Team/Enterprise only. Keep the
   URN out of `grant_types_supported` — advertising it and not implementing it is an N-06 violation,
   which is worse than not offering the feature.
5. **Google federation (`Federation.Google`).** Local Argon2id accounts alone complete every flow.
   Keep `IExternalIdentityProvider` — the seam is a day, the implementation is three.
6. **Postgres provider** (ship SQLite only, keeping the provider-neutral EF layer intact). Reversible
   in a day *because* §3.2 kept the mapping neutral; this is what that discipline buys.
7. **The admin surface (E-21, A-16/A-17)**, downgraded to `boltway-auth config schema` in the
   CLI. Same reflection code, no HTTP endpoint, no auth policy for it.
8. **The metrics exporter.** Keep the `Meter` and the instruments (they are ~50 lines and removing
   them later is worse than keeping them); drop the OTLP wiring and the dashboards.

**Never cut, in any circumstance:**

- **All sixteen N-nn**, and specifically their *mechanical guards*, not just their behaviour. The
  Cecil tests for N-03 and N-12 are half a day each. A deadline that cannot absorb one day cannot
  absorb an open redirector.
- **The `Rejection` type and correlation ids.** Cutting these does not save time, it *spends* it:
  the field report is a ledger of hours lost to exactly their absence. This is the one place where
  the observability work is on the critical path rather than beside it.
- **CIMD (S-16) end to end, including the SSRF guard (N-05).** It is the default client-acquisition
  path for both vendors. There is no v1 without it, and an unguarded fetcher is an SSRF primitive
  with a public trigger.
- **PKCE S256 with the XOR (N-02), exact redirect matching with the loopback exception
  (N-03/N-04), `aud` bound to `resource` (N-01), refresh rotation with the grace window (N-08).**
  These four are the whole security argument.
- **The doctor's configuration section (checks 1–9).** It is a day of work and it is the thing that
  makes a customer's first deployment succeed instead of generating a support thread.
- **The `Interop.Tests` fixtures.** Four JSON documents and four flows. They are the only test that
  proves the product does the thing it is for.

The deadline pressure should fall on `app`-shaped surface — endpoints, providers, admin
convenience — never on `core`-shaped guarantees. That is the same rule
`FictStoryEngine/CLAUDE.md` states for its own deadline, and it was right there too.
