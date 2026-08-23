# Boltway Authorization Server — design

OAuth 2.1 + OpenID Connect authorization server, written from scratch in C# on `net10.0`, intended
to be deployed repeatedly into customer projects. Claude.ai, Claude Code and ChatGPT MCP connectors
must all drive it with zero vendor-specific patching and zero per-connection admin steps.

Requirement IDs (`S-nn` spec, `E-nn` endpoint, `X-nn` error, `N-nn` non-negotiable, `C-nn` client
compatibility, `A-nn` Auth0-trap, `D-nn` deferred, `U-nn` unverified) refer to
[`spec/REQUIREMENTS.md`](../spec/REQUIREMENTS.md). **§10 of that document is a live measurement and
wins on conflict with §6 and §9.**

---

## 0. Provenance of this document

Three independent architecture proposals were produced — security-first, reuse-first,
operability-first — and they are checked in beside this file as
[`proposals/`](./proposals/). This document synthesizes them.

**The three adversarial judge passes that were supposed to score the proposals never ran.** The
subagent tool layer failed three times (a permission handler stripping required parameters), and
the agents correctly refused to fabricate verdicts from files they could not read. So the critique
in §1.3 is **mine, produced by reading the three proposals directly** — one reader, not three
independent lenses.

That is a weaker input than was designed for, and it is recorded here rather than smoothed over,
because `LESSONS.md` in this repository is about exactly this failure: recording *"we did not
measure this"* as *"this is not there."* The flaws in §1.3 are real and found; the claim **not**
being made is that they are the complete set. The mitigation is that §7's traceability test fails
the build for any binding requirement without a covering test, so a design gap surfaces as a red
build rather than as a silent omission.

---

## 1. Decision record

### 1.1 The winning skeleton: security-first (Proposal A)

The product's value proposition *is* the sixteen `N-nn` non-negotiables. A customer buying this is
buying "the redirect matcher cannot be widened", not "an OAuth server exists". Proposal A converts
twelve of the sixteen from *"a rule someone must remember"* into *"there is no code path"*, and the
remaining four into build failures. That ordering — no-code-path > build-fails > compile-warns —
is the spine of the design.

The mechanism ranking is kept verbatim:

| Strength | Mechanism | Defeated by accident? | Defeated deliberately? |
|---|---|---|---|
| 1 | **No code path exists** — the operation needs a type that cannot be constructed | No | Only by adding a type (visible in review) |
| 2 | **Build fails** — Mono.Cecil scan over compiled IL, run as a test | No | Only by editing the rule file (visible in review) |
| 3 | **Compile fails** — `BannedApiAnalyzers` + `TreatWarningsAsErrors` | No | Yes, `#pragma warning disable` — mechanism 2 backstops it |

### 1.2 What was grafted

**From Proposal B (reuse-first)** — these are product decisions the security-first proposal did not
reach for, and three of them are strictly better engineering:

| Graft | Why it wins |
|---|---|
| **`sub` is a ULID**, 26 chars of Crockford base32, `[0-9A-HJKMNP-TV-Z]{26}` | Satisfies `A-18` *by construction*. No `\|`, `/`, `.`, or `@`, so it is safe as a path segment, filename, cache key and column name with no sanitiser and no collision-disambiguation path. This is a deliberate improvement on `auth0\|<hex>`, which forced FictStory to write both |
| **`RealmId` on every table and every store method from day one** | Free now, a migration across ten live customer databases later. `S-08` (path-less issuer) + `N-13` (issuer never from `Request.Host`) leave only one-issuer-per-process or host-mapped selection; the column makes host-mapping a v1.1 feature rather than a schema change |
| **Every security-relevant comparison happens in C# with `StringComparison.Ordinal`, never in a `WHERE` clause** | Dissolves the entire PostgreSQL-collation class of bug rather than patching it. See §1.3 flaw 4 for the necessary carve-out |
| **A CIMD client is not an entity** | `A-08` requires 100 sequential CIMD connects to leave the client table unchanged. "Just cache it in the clients table" is the obvious move and it breaks the zero-registration property CIMD exists for |
| **RS packages multi-target `net8.0;net10.0`**; the AS stays `net10.0` | The RS lands in the *customer's* codebase and their TFM is not ours to choose. Refusing this makes it unsellable to anyone on the current LTS |
| **Consent security fragments are tag helpers, not views** | `N-14`/`A-15` survive a customer overriding the Razor view, because overriding a view cannot change compiled behaviour. **Kept as a principle, discarded as a mechanism — see §2's note on the UI package.** What shipped reaches the same property with no Razor at all |
| **Container first, NuGet second; the AS is a library a 20-line `Program.cs` hosts** | A source template that vendors the protocol code gives every customer a fork with no security-patch story |
| Migration discipline: never at startup, expand/contract tested, never squashed after release | `C-29` forbids synchronous migrations on the request path, and three replicas racing `Database.Migrate()` is an outage |

**From Proposal C (operability-first)** — the field report this project is built on is a ledger of
*undiagnosable* failure, not missing features:

| Graft | Why it wins |
|---|---|
| **The `Rejection` type + one writer** | Makes `A-09` structural: a rejection cannot be *rendered* without emitting exactly one structured log carrying the correlation id, because the same method writes both. See §3.1 for what shipped and how the guarantee is actually held — it is compile + build + runtime in three layers, not one, and the id reaches the user through `X-Request-Id` rather than through `error_description` |
| **`DoctorLevel.NotMeasured` as a first-class level, ranked above measured negatives** | Straight out of `LESSONS.md` rule 1. A doctor that reports `Fail` when it merely could not reach something reproduces the exact error that document is about |
| **Config-schema descriptions come from `///` XML doc comments** | `GenerateDocumentationFile` is already on. The description a developer writes for the next developer becomes the one an operator reads at 2am, with exactly one copy. Makes `A-17` nearly free |
| **Doctor probes live next to the feature they check** | A feature and its probe cannot drift |
| CIMD stale-serve + single-flight; `/token` load-sheds 503 rather than queuing; `EnableRetryOnFailure` **off** on `/token` | A retry inside a 10 s budget converts a fast failure into a timeout, and `C-29` scores a slow success as a failure anyway |
| **JWKS three-phase rotation** with `PublishLeadTime` > metadata `max-age` + client staleness | Config validation states that arithmetic in its failure message |
| Alert on `refresh.rotation{result=reuse}`; watch `grace_replay` climbing toward `rotated` | The difference between "users report random logouts" and "the window is 45 s and p99 refresh spacing is 52 s" |

### 1.3 Flaws found, and their resolution

Found by reading the proposals against each other and against the spec. Each is a real defect in the
proposal as written.

| # | Flaw | Where | Resolution |
|---|---|---|---|
| 1 | **`ResourceIdentifier.Register` is `public static`** while its comment claims "only callable by `IResourceRegistry` implementations". A public static factory is callable by anyone, so `N-01`'s "no way to get a `ResourceIdentifier` except through the registry" is false as written — the strongest structural claim in the design had a hole | A §3.1 | Constructor and factory become `internal`, with `InternalsVisibleTo` only for the storage assembly that rehydrates registrations. `IResourceRegistry` is the sole public path. Architecture test asserts no `public` member of `ResourceIdentifier` returns one |
| 2 | **`ValidatedRedirect` can be forged.** Its constructor takes a `RedirectMatch`, but `RedirectMatch.Exact(...)` is a public static factory in `Primitives`, so any code in `Server` could mint a fake match and then a fake `ValidatedRedirect` — defeating `N-11` | A §5.1 | `RedirectMatch`'s factories become `internal` to `Primitives`; only `RedirectUriMatcher.Match` can produce a non-`None` value. Cecil rule: `ValidatedRedirect`'s constructor has exactly one call site |
| 3 | **`InvariantGlobalization=true` (already committed) contradicts `ui_locales_supported: ["en-US","vi-VN"]`** in the metadata document | Mine, in `Directory.Build.props` vs REQUIREMENTS §3 | Keep `InvariantGlobalization=true` — an AS has no business depending on ICU, and it reinforces ordinal comparison. Localization is **resource-string lookup only**, no culture-sensitive formatting. `ui_locales_supported` is emitted only for locales with a shipped resource file, generated from what exists (`N-06`) |
| 4 | **"Never compare in a `WHERE` clause" is violated on day one** by the most important queries in the system — `N-07`/`N-08`'s conditional `UPDATE ... WHERE code_hash = @h` | B §3.2.5 vs B §3.2.6 | The rule is restated precisely: **no *identifier string* comparison in SQL.** Hash lookups on fixed-length `byte[]`/base64url primary keys are byte-exact on both providers and are not subject to collation. `PostgreSqlModelCustomization` still sets `COLLATE "C"` on identifier columns as cheap insurance, and a cross-provider test asserts `WHERE client_id = 'ABC'` finds zero rows against `'abc'` |
| 5 | **`Rejection` and `AuthorizeRedirectError` collide.** C routes every rejection through `IRejectionWriter`, but A requires redirect-delivered errors to be unconstructible without a `ValidatedRedirect`. Naively merging them re-opens `N-11` | A §5.1 vs C §5.4 | Layered: `Rejection` is the **diagnostic payload** (reason, requirement id, correlation id, log obligation). `AuthorizeHtmlError` and `AuthorizeRedirectError` are the **delivery types**, and the redirect one still requires a `ValidatedRedirect`. `IRejectionWriter` accepts a delivery type, never a bare `Rejection`, for `/authorize` |
| 6 | **`GenerateDocumentationFile` + `TreatWarningsAsErrors` makes CS1591 an error on every undocumented public member** — measured, it fires immediately | Mine, measured | Deliberate, but scoped: CS1591 stays an **error** in `Primitives`, `Abstractions` and every options type (public API surface and the `A-17` description source), and is downgraded to **warning** elsewhere via a `Directory.Build.props` condition |
| 7 | **`SQLitePCLRaw 2.1.11` carries a high-severity advisory** (GHSA-2m69-gcr7-jv3q), pulled transitively by `EntityFrameworkCore.Sqlite 10.0.10` | Mine, measured | Pinned all four SQLitePCLRaw packages to **2.1.12** (measured clean). Already committed. Note the 3.x line is unusable: `lib.e_sqlite3` has 3.53.3 but `bundle` and `core` stop at 3.0.5 |
| 8 | **No Docker in this environment**, so the Testcontainers PostgreSQL leg cannot run | Mine, measured | ~~The Postgres store-conformance leg is `[SkippableFact]` with a **stated reason**, reported as `NotMeasured` — never as a pass. Required in CI where Docker exists; the SQLite and InMemory legs always run~~ **Superseded.** Skipping was the wrong resolution and the reason is in the flaw's own premise: a leg that skips where nobody is watching is a leg that never runs, and PostgreSQL is what deploys — so the only relational implementation anyone actually exercised was the one that does not. It is now a hard failure (`PostgresDatabase` throws, and says how to get a server), Testcontainers is not used, and `scripts/postgres.sh` supplies the server: a container where a Docker daemon answers, a native cluster where none does. Measured in this environment — no daemon, PostgreSQL 17.10 from PGDG, 62/62 |
| 9 | **Access-token lifetime defaults disagree** — A says 10 min, C says 1 h | A §6.2 vs C §6.1 | **30 minutes.** `C-19`: Claude refreshes proactively up to 5 min early, so a 10-min token refreshes every 5 min, which is thrash; a 1-h token means up to an hour of revocation lag against a stateless RS that validates offline. 30 min gives ~25-min refresh spacing and bounded revocation lag. Range stays `[5:01, 24:00]` and the tradeoff is documented on the property |
| 10 | **`ui_locales_supported`, `service_documentation`, `op_policy_uri`, `op_tos_uri` are emitted unconditionally** in the REQUIREMENTS §3 sample, which violates `N-06` if unconfigured | REQUIREMENTS §3 | All four are emitted **only when configured**. `MetadataBuilder` has no overload that emits a null or empty value |

**Raised and deliberately not fixed:**

- **Ten to twelve assemblies is a lot for a first build.** Kept anyway: the splits exist for exactly
  two reasons — reuse (what does an RS-only customer take?) and **ban scope** (`BannedApiAnalyzers`
  and Cecil rules are per-assembly). `N-03` and `N-05` are assembly-scoped claims and collapsing the
  projects would turn both into allowlists, and an allowlist is a place to add an entry.
- **The twelve-stage `/authorize` pipeline is more code than one 300-line handler.** Kept: it buys
  `N-11` as a type-system property and makes the twelve `X-nn` rows individually testable.
- **`Boltway.Conformance` as a shipped CLI** (B) is kept but demoted to the cut list — it is a
  product differentiator, not a correctness requirement.

---

## 2. Project split

Namespace root `Boltway`. Namespace tracks folder exactly; file-scoped namespaces are already
an error in `.editorconfig`.

```
                    Boltway.OAuth.Primitives        (BCL only)
                     │           │            │
       ┌─────────────┘           │            └──────────────┐
       ▼                         ▼                           ▼
Boltway.OAuth.Net   Boltway.OAuth.Tokens   Boltway.ResourceServer
   (the ONE HttpClient)   (JWT/JWK, RFC 9068)          (bearer + PRM middleware)
       │                         │                           │
       │   ┌─────────────────────┴──────────┐                ▼
       │   ▼                                ▼      Boltway.ResourceServer.Mcp
       │  Boltway.AuthorizationServer.Abstractions
       │   │                                │
       └──►│                                ▼
           ▼                    Boltway.Storage.EntityFrameworkCore
    Boltway.AuthorizationServer            │            │
       │            │                           ▼            ▼
       │                                 ...Storage.Sqlite  ...Storage.PostgreSql
       │
       └──► Boltway.Federation.Google        Boltway.Storage.InMemory
```

| Project | Kind | Contains | Boundary reason |
|---|---|---|---|
| `Boltway.OAuth.Primitives` | reuse + **enforcement** | Value objects (`IssuerString`, `ClientIdentifier`, `RegisteredRedirectUri`, `RequestedRedirectUri`, `ScopeName`, `ScopeSet`, `ResourceIdentifier`, `SubjectId`, `GrantId`, `RealmId`, `Ulid`, `Sha256Hash`, `OpaqueSecret`), `RedirectUriMatcher`, the `X-nn` error table, PKCE, `Base64Url`, `MediaType`, `WwwAuthenticate`, `SeeOther` | **The ban list is per-project.** Putting the matcher here lets `Uri.AbsoluteUri`/`AbsolutePath`/`Equals`/`ToString`/`IdnHost`/`DnsSafeHost` be banned project-wide with no collateral damage. This is `N-03`'s enforcement scope. Also the only assembly both halves need, so zero framework deps |
| `Boltway.OAuth.Net` | reuse + **enforcement** | `ISafeHttpFetcher` + its single implementation, RFC 6890 blocklist, connect-pinning handler, per-remote-host outbound budget (`X-31`), `KeyedRateLimiter`, `NegativeResultBreaker` | **`N-05` is an assembly-scoped claim.** One Cecil rule: no reference to `System.Net.Http.*`/`WebRequest`/`Sockets.Socket` outside this assembly. **The exception list is empty** — that emptiness *is* the guarantee |
| `Boltway.OAuth.Tokens` | reuse | JWT/JWS/JWK types, RFC 9068 profile, `Rfc9068ValidationParameters` with `ValidTypes`/`ValidAlgorithms` pinned (`N-09`), signing-key ring | Shared by the AS (minting) and the RS (validating). One implementation means they cannot disagree |
| `Boltway.ResourceServer` | **reuse** | Bearer handler, PRM endpoints (`E-22`/`E-23`), challenge builder (`X-32`..`X-35`), per-caller limits, preflight | The reuse deliverable. Multi-targets `net8.0;net10.0` |
| `Boltway.ResourceServer.Mcp` | **reuse** | Stateless Streamable HTTP, JSON-RPC lazy-auth gate, tool-contract lint | Separate so a non-MCP resource server does not carry it |
| `Boltway.AuthorizationServer.Abstractions` | reuse + enforcement | Every seam in §5, plus the DTOs they exchange | **No ASP.NET Core reference.** Forces every seam to take request-shaped DTOs rather than `HttpContext`, so a customer can unit-test an implementation in a class library |
| `Boltway.AuthorizationServer` | enforcement | The protocol engine, every endpoint, CIMD **including the clamped-TTL document cache (`S-30`)**, metadata, capabilities, `LoginThrottle`, `Rejection` | Ban scope for `N-12` (307/308), `N-13` (`Request.Host`), `[FromBody]` |
| ~~`Boltway.AuthorizationServer.UI`~~ | **not built** | Was to be a Razor Class Library: login, consent, error, logout, with security-critical fragments as tag helpers | **Superseded — see the note below.** The property it existed for is held by three tiers inside `AuthorizationServer`, and no Razor was needed to get it |
| `Boltway.Storage.EntityFrameworkCore` | provider | `DbContext`, configurations, stores, the conditional-`UPDATE` redemption | **Contains no provider package reference** — that is what keeps "runs on both" true rather than aspirational |
| `…Storage.Sqlite` / `…Storage.PostgreSql` | provider | Provider wiring + that provider's migrations only | EF bakes provider SQL into migrations; two assemblies is forced, not chosen |
| `Boltway.Storage.InMemory` | reuse | Non-persistent store, same contract suite | Customers need it for their own tests; it is what proves the three implementations agree |
| `Boltway.Federation.Oidc` | reuse | The generic OIDC relying party: `OidcExternalProvider`, its options, the discovery/JWKS cache | **Does not reference `Boltway.AuthorizationServer`.** So "a provider knows nothing about the server's endpoints, cookies or pipeline" is a compiler-checked fact — a provider that could see the server could read the pending-request cookie |
| `Boltway.Federation.Google` | reuse | One static class: Google's issuer, a scheme name, a display name | Kept out of `AuthorizationServer` so "Google is not special" is structurally true. **There is no `GoogleOidcProvider`** — the generic provider needed no subclass, and a class existing only to be named after a vendor would be the thing this split prevents. Its endpoints come from discovery, so the three-different-hosts shape costs nothing |

Non-shipped: `Boltway.AuthorizationServer.Host` (container entrypoint),
`Boltway.Conformance` (CLI), `samples/`, `tools/Boltway.OAuth.Analyzers`.

**The RS-only customer takes `Boltway.ResourceServer[.Mcp]`**, transitively pulling
`Primitives`, `Net`, `Tokens`. No EF Core, no Razor, no `Abstractions`, no AS.

### The UI package, and why it is not there

This row said branding would be "a package replacement or view override, never a fork". The
package was never built, and for most of that time branding **was** a fork: `IInteractionRenderer`
was the only seam, so changing a colour meant reimplementing both pages and inheriting every N-14
obligation with them. The sentence was true as an intention and false as a description, which is
the shape `LESSONS.md` is about.

What shipped instead is three tiers, all inside `Boltway.AuthorizationServer`:

| Tier | Seam | Changes | What the deployment takes on |
|---|---|---|---|
| 1 | `InteractionOptions` | Stylesheets, logo, product name | Nothing. No setting reaches the N-14 block |
| 2 | `IInteractionLayout` | The whole document around the server's markup | One condition, and it is **verified at render time** |
| 3 | `IInteractionRenderer` | The markup itself | `N-14`, `A-11`, `A-14` in full |

The tag-helper idea was aimed at a real property — that a customer's override cannot change
compiled behaviour — and tier 2 reaches it more directly than a tag helper would. The server
renders the security-critical markup and hands it over as a finished string, so a layout has
exactly **one** way to lose a requirement rather than one per field; `DefaultInteractionRenderer`
checks that single condition on every render and throws rather than serving a consent page with no
consent on it. A tag helper can be left out of a view silently. This cannot.

Tier 3 still exists and still hands over everything, so the obligation is real — which is why
`Boltway.Interaction.Testing` ships as a package carrying `InteractionRendererContract` and
`InteractionLayoutContract`. That is the same arrangement as the store contracts, for the same
reason: a contract nobody outside this repository can run is a contract only this repository is
held to.

Razor was reconsidered on its merits and still refused: a view engine means a second package, a
runtime compilation step, and a template language in which the N-14 fields are optional. It earns
its place when this needs multiple locales or per-tenant themes, and not before.

---

## 3. Interface contracts

These are the seams between independently-built files. They are the part that must be exactly right
before parallel implementation starts.

```csharp
// ── Boltway.OAuth.Net ────────────────────────────────────────────────────
public enum FetchPurpose { ClientIdMetadataDocument, JwksUri, LogoUri, SectorIdentifierUri, UpstreamDiscovery }

public sealed record SafeFetchRequest(
    AbsoluteHttpsUrl Url,
    FetchPurpose     Purpose,
    int              MaxBytes = 5 * 1024,
    TimeSpan?        Total    = null);

public abstract record FetchOutcome
{
    private FetchOutcome() { }
    public sealed record Ok(byte[] Body, MediaType ContentType, string? ETag, TimeSpan? MaxAge) : FetchOutcome;
    public sealed record Blocked(BlockReason Reason, string Detail)  : FetchOutcome;
    public sealed record Redirected(int Status, string? Location)    : FetchOutcome;  // CIMD §5: MUST NOT follow
    public sealed record NotOk(int Status)                           : FetchOutcome;  // only 200 is Ok
    public sealed record TooLarge(int BytesRead)                     : FetchOutcome;
    public sealed record Timeout(TimeSpan Elapsed)                   : FetchOutcome;
}

public interface ISafeHttpFetcher
{
    Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken ct);
}

// ── Abstractions / client authentication ──────────────────────────────────────
public enum ClientAuthMethod { None, ClientSecretBasic, ClientSecretPost, PrivateKeyJwt }

public sealed record ClientAuthenticationContext(
    IReadOnlyDictionary<string, string>                Headers,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Form,
    IssuerString                                       Issuer,
    string                                             EndpointUrl,  // U-08: accept issuer OR this as `aud`
    OAuthSurface                                       Surface);

public interface IClientAuthenticator
{
    ClientAuthMethod Method { get; }
    /// <summary>True iff THIS mechanism's credentials are present. MUST NOT validate them.</summary>
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

// ── Abstractions / stores: thin where safe, NOT thin where atomicity IS the requirement ──
public interface IAuthorizationCodeStore
{
    Task StoreAsync(RealmId realm, AuthorizationCodeRecord record, CancellationToken ct);
    /// <summary>Returns REDEEMED rows too — N-07 needs to validate a replayed code fully.</summary>
    Task<AuthorizationCodeRecord?> FindAsync(RealmId realm, Sha256Hash hash, CancellationToken ct);
    /// <summary>Atomic. True iff THIS call performed the redemption (rows-affected == 1).</summary>
    Task<bool> TryRedeemAsync(RealmId realm, Sha256Hash hash, DateTimeOffset now, CancellationToken ct);
}

public abstract record RefreshRedemption
{
    private RefreshRedemption() { }
    public sealed record Rotated(RefreshTokenRecord Successor)            : RefreshRedemption;
    public sealed record ReplayedWithinGrace(RefreshTokenRecord Existing) : RefreshRedemption;
    public sealed record ReuseDetected(GrantId Grant)                     : RefreshRedemption;
    public sealed record NotFound                                         : RefreshRedemption;
}

public interface IRefreshTokenStore
{
    /// <summary>The whole rotation decision lives here because the atomicity is provider-specific.
    /// Exactly one successor per parent, ever — forking the family on concurrent redemption is a
    /// known CVE class (GHSA-392p-2q2v-4372) and defeats reuse detection entirely.</summary>
    Task<RefreshRedemption> RedeemAsync(
        RealmId realm, Sha256Hash presented, RefreshTokenSeed successor,
        DateTimeOffset now, TimeSpan graceWindow, CancellationToken ct);
}

// ── Abstractions / identity ───────────────────────────────────────────────────
public readonly record struct ProviderAvailability(bool Enabled, string? DisabledReason)
{
    public static ProviderAvailability Available => new(true, null);
    /// <summary>A-11: the reason is REQUIRED. There is no return value meaning "hide me".</summary>
    public static ProviderAvailability Disabled(string reason) => new(false, reason);
}

// SHIPPED, with three differences from this sketch and two members added since. See 3.2.
public interface IExternalIdentityProvider
{
    string Scheme      { get; }
    string DisplayName { get; }
    ValueTask<ProviderAvailability> GetAvailabilityAsync(ClientRecord client, CancellationToken ct);
    Task<ChallengeDescriptor> BeginAsync(ExternalLoginContext ctx, CancellationToken ct);
    Task<ExternalLoginResult> CompleteAsync(ExternalCallbackContext ctx, CancellationToken ct);
}

/// <summary>Carries the upstream subject and nothing else identity-shaped. The local `sub` is a
/// ULID minted by us and joined through ExternalLogin — never passed through from upstream (D-10).</summary>
public sealed record ExternalPrincipal(
    string UpstreamIssuer, string UpstreamSubject, IReadOnlyDictionary<string, string> Claims);

// ISubjectIdentifierService was declared here — SubjectId ForClient(UserAccount, ClientRecord) — as
// D-11's seam for pairwise subjects. It shipped, was called by nothing, and could not have been
// called: the token path carries grant.Subject and loads no UserAccount. Deleted 2026-08-22; see
// D-11 in spec/REQUIREMENTS.md for what pairwise would now cost.

// ── Abstractions / tokens ─────────────────────────────────────────────────────
public sealed record AccessTokenDescriptor(
    IssuerString Issuer, GrantId GrantId, SubjectId Subject, ClientIdentifier Client,
    ResourceIdentifier Audience,                  // NON-NULLABLE — N-01 has no bypass
    ScopeSet Scope, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string JwtId,
    AuthenticationContextInfo Auth,
    IReadOnlyDictionary<string, object?> Extra);  // D-02 seam: a `cnf`/`jkt` claim lands here

public sealed record IdTokenDescriptor(
    IssuerString Issuer,
    ClientIdentifier Audience,                    // N-10: a DIFFERENT TYPE. Cannot be confused.
    SubjectId Subject, string? Nonce, DateTimeOffset AuthTime, string? AtHash, /* … */);

public interface IAccessTokenFormat
{
    string TokenTypeHint { get; }                 // "at+jwt"
    ValueTask<MintedToken> MintAsync(AccessTokenDescriptor descriptor, CancellationToken ct);
}
public interface IIdentityTokenFormat
{
    ValueTask<MintedToken> MintAsync(IdTokenDescriptor descriptor, CancellationToken ct);
}
public sealed record MintedToken(string Wire, DateTimeOffset ExpiresAt, string? Kid);

// ── Abstractions / claims ─────────────────────────────────────────────────────
public sealed class ClaimSink
{
    /// <summary>Throws ReservedClaimException on a protocol claim, so a customer mapper cannot
    /// overwrite `aud` (N-01) or `iss` (N-13).</summary>
    public void Add(string name, object? value);
}
public interface IClaimsMapper
{
    ValueTask MapAsync(ClaimMappingContext ctx, ClaimSink sink, CancellationToken ct);
}

// ── Abstractions / the PAR seam (D-01) ────────────────────────────────────────
public abstract record AuthorizationRequestResolution
{
    private AuthorizationRequestResolution() { }
    public sealed record Resolved(IReadOnlyDictionary<string, IReadOnlyList<string>> Parameters)
        : AuthorizationRequestResolution;
    public sealed record Rejected(OAuthErrorCode Code, string Description)
        : AuthorizationRequestResolution;
}

public interface IAuthorizationRequestSource
{
    string Name { get; }
    bool CanHandle(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters);
    ValueTask<AuthorizationRequestResolution> ResolveAsync(AuthorizationRequestInput input, CancellationToken ct);
}

// ── Abstractions / resources — N-01's chokepoint ──────────────────────────────
public interface IResourceRegistry
{
    /// <summary>The ONLY way to obtain a ResourceIdentifier. null ⇒ invalid_target (X-09 / X-23).
    /// Unknown and not-permitted MUST return the same null and the same description — distinguishing
    /// them is an enumeration oracle.</summary>
    ValueTask<ResourceIdentifier?> ResolveAsync(RealmId realm, ResourceKey key, ClientRecord client, CancellationToken ct);
}

// ── Diagnostics — A-09. SHIPPED; see 3.1 for the differences from this sketch ─
public sealed record Rejection
{
    public ReasonCode     Reason      { get; }  // closed enum, one value per distinguishable cause
    public OAuthErrorCode Error       { get; }
    public string         Description { get; }  // A-12: reaches the body/redirect
    public string?        PrivateDetail { get; }  // log only; control characters stripped, capped
    public Exception?     Cause       { get; }  // log only; set for X-10 and nothing else

    public static Rejection Of(ReasonCode reason, OAuthErrorCode error, string description,
                               string? privateDetail = null, Exception? cause = null);
}

// No IRejectionWriter interface. See 3.1.

public interface IDoctorProbe
{
    string Section { get; }
    int    Order   { get; }
    ValueTask<DoctorFinding> RunAsync(CancellationToken ct);
}

/// <summary>NotMeasured is first-class and ranks ABOVE measured negatives in the report.
/// LESSONS.md rule 1: a probe that reports Fail when it merely could not reach something
/// reproduces the exact error that document is about.</summary>
public enum DoctorLevel { Ok, Warn, Fail, NotMeasured }

public sealed record DoctorFinding(DoctorLevel Level, string Message, string? Remediation, string? RequirementId);
```

---

### 3.1 A-09, as built

This subsection exists because the row about `Rejection` in §1.2 was **false for the whole of the
project's history until 2026-08-05**. `Rejection`, `IRejectionWriter`, `ReasonCode` and `IDoctorProbe`
appeared nowhere in `src/` or `tests/`, and a review with a capturing `ILoggerProvider` at Trace level
measured what was actually emitted:

| Surface | Rejection classes | Product log lines |
|---|---|---|
| `/authorize`, `/token`, `/login`, `/consent` | 16 | **0** |
| Resource server `400`/`401`/`403` | 9 | **0** |
| Unhandled exception / abandoned request | 2 | 2 |

The sink was working — a deliberately-throwing `IClientResolver` produced `[Error] … unhandled
exception (X-10)` from the same run — so this is a measurement of absence rather than of a broken
instrument. No resource-server response carried a correlation id at all.

**What shipped, and how strong each part is.** The design's ranking in §1.1 is no-code-path >
build-fails > compile-fails; A-09 now rests on three layers rather than one, and it is worth being
exact about which is which:

| Layer | Mechanism | What it holds |
|---|---|---|
| Runtime, structural | `RejectionResult.ExecuteAsync` is non-virtual and calls `Record` — which emits the line and stamps `X-Request-Id` — **before** the abstract `WriteAsync` that produces the body. There is no ordering in which a rejection is delivered unlogged | For every rejection that goes through this type |
| Compile | `AuthorizeHtmlError`, `AuthorizeRedirectError.Create` and `OAuthJsonResults.Error` all *require* a `Rejection`. No overload takes a bare code and description | You cannot construct a rejection response without the payload the writer logs |
| Build | `StructuralRuleTests.Only_the_rejection_writer_produces_an_error_response`: `OAuthErrors.Resolve` has exactly one caller per server assembly, and no other method in either assembly carries a 4xx/5xx constant | You cannot add a second, unlogged error path without a red build |

**There is no `IRejectionWriter` interface.** The sketch above had one, and an interface is the wrong
shape here: a seam is a place a customer substitutes an implementation, and "the log is emitted"
must not be substitutable. The concrete `RejectionResult` base class holds it instead, and the
architecture rule is what stops a second one appearing.

**The correlation id is returned in `X-Request-Id`, not in `error_description`.** A-09 permits
either. The header is the only channel that works on all four delivery shapes this server emits: a
redirect error's description lives in the `Location` query of a `303` the browser immediately
navigates away from, a challenge's description competes with `resource_metadata` inside one quoted
header, and `error_description` is filtered to OAuth 2.1 §4.1.2.1's character set and capped at 240
characters — so an id appended to a long description is an id that gets truncated. It also keeps the
id off the wire to the client's own redirect URI, which is a third party by design.

**What is convention rather than structure**, stated so nobody has to rediscover it:

- One refusal is not an OAuth error response and cannot go through `RejectionResult`: a rejected
  username and password re-renders the sign-in form at `200` (E-20). It calls the same `Record`
  method from `InteractionHtmlResult`, so it produces the same line and the same header — but
  nothing forces the rejecting factory to be chosen over the plain one. `LoginFlowTests`
  covers it.
- The two `[LoggerMessage]` declarations are duplicated, one per server assembly. The only assembly
  both reference is `Primitives`, which is BCL-only by design and cannot take
  `Microsoft.Extensions.Logging.Abstractions`. The event id, template and property names are
  identical, and a test in each suite pins the property set so drift is a red build.
- Two `404`s are outside the rule by name: the well-known "this server publishes no document here"
  answers on both servers. They carry no OAuth error, no description and nothing request-derived,
  and RFC 9728 §3.1 probing depends on them.

### 3.2 D-10, as built

Federated sign-in shipped, and three things about the sketch in §3 turned out to be wrong. They are
recorded here rather than edited into the sketch, because a design document whose sketches silently
become the code is one nobody can use to see what changed.

| Sketch | Shipped | Why |
|---|---|---|
| `GetAvailabilityAsync(ClientRecord client, …)` | `GetAvailabilityAsync(ExternalProviderContext ctx, …)`, whose `Client` is **nullable** | A-11 is a per-client requirement, so the login page resolves the client its `returnUrl` names — and that resolution can fail for reasons unrelated to the decision (an evicted CIMD entry plus an unreachable origin, a spent outbound budget). The non-nullable signature cannot be implemented without inventing a client record. A record type also leaves room for what the page learns later |
| The provider mints `state`, `nonce`, PKCE | **The server mints all three**; the provider is handed them | Three values whose only job is to be unguessable, generated once with `RandomNumberGenerator`, is a property that holds for every provider ever added. Per-provider generation holds until someone reaches for `Guid.NewGuid` |
| The provider checks `nonce` | `ExternalPrincipal.Nonce` is returned **uncompared**; the server compares it | The value it must equal is in the browser's pending-request cookie, which a provider cannot see — that is what keeps this assembly free of `HttpContext`. One comparison, constant-time, for every provider |

**Two members were added after it shipped, and both are deliberately not defaulted:**

| Member | Why it exists | Why no default implementation |
|---|---|---|
| `string Issuer { get; }` | `/me` reports which providers are already linked, and a link is stored as `(issuer, subject)`. Without the issuer on the interface there is no way to match a stored link back to the provider that made it | A default returning `""` compiles everywhere and makes every provider report "not linked" on a page whose entire job is to say whether it is |
| `ValueTask<string?> GetChallengeOriginAsync(CancellationToken ct)` | The sign-in page must widen `form-action` to the origin its provider button redirects to, and only the provider knows that origin — for OIDC it comes from discovery, falling back to the issuer's authority | A default returning `null` compiles everywhere and produces a button that does nothing in a browser, silently, exactly the defect this method was added to fix |

Both are the `A-11` shape: an interface member whose default answer is indistinguishable from a
correct one is a way of not asking the question. Adding a member without a default breaks every
implementation at compile time, which is the point — there are two in this repository and the
compiler names both.

Two further things worth stating because they are not visible from the interface:

- **`Boltway.Federation.Oidc` does not reference `Boltway.AuthorizationServer`.** A provider
  that could see the server could read the pending-request cookie, and the compiler is what stops it.
- **The account-linking rule is `(upstream issuer, upstream subject)` and nothing else.** Its
  structural half used to be that `IUserStore` had no method finding an account by email address at
  all, asserted by reflection — an absent method cannot be called from anywhere. That half was
  spent when signing in with a verified address shipped, because the sign-in form needs exactly the
  lookup federation must not have. **The guard moved from the interface's shape to the call site**:
  `StructuralRuleTests.Only_the_sign_in_form_resolves_an_account_by_address` reads the IL for
  callers of `FindByVerifiedEmailAsync` and allows one type. The reflection test stays, narrowed —
  it now names the one lookup permitted to exist, so a *second* email lookup is a violation whoever
  calls it. Recorded here rather than edited away because "no such method" is the kind of guarantee
  a reader will assume is still load-bearing.

---

## 4. The `/authorize` pipeline — `N-11` made structural

The guarantee is not the ordering of a list; lists get reordered. It is that
**`AuthorizeRedirectError` cannot be constructed without a `ValidatedRedirect`, and only stage 3 can
mint one** (with flaw 2 fixed: `RedirectMatch`'s factories are `internal` to `Primitives`, so only
`RedirectUriMatcher.Match` produces a non-`None` value).

| # | Stage | Emits | Requirements |
|---|---|---|---|
| 0 | `SecurityHeadersMiddleware` (via `Response.OnStarting`) | — | `N-15` — `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `default-src 'self'`, `form-action 'self'` **as the baseline, widened per response by `SecurityHeaders.AllowFormActionTo`** (see below), `base-uri 'none'` |
| 0b | `AuthorizeExceptionBoundary` | `X-10` | Redirects `server_error` iff a `ValidatedRedirect` exists, else HTML 400. **An HTTP 500 past stage 3 is a defect** |
| 1 | `S01_MethodAndParameters` → `IAuthorizationRequestSource` | HTML 400 | `X-04`. `resource` read via `Query["resource"].ToArray()`, never `[FromQuery] string` |
| 2 | `S02_ClientResolution` | **HTML 400** | `X-01`, `X-03`. Resolver chain PreRegistered → Dynamic → **CIMD**. Fetch budget ≤ 2 s, serve stale on error |
| 3 | `S03_RedirectValidation` | **HTML 400** | `X-02`, `N-03`, `N-04`. On success mints `ValidatedRedirect` |
| | ───── **redirect is now permitted, and only now is it constructible** ───── | | |
| 4 | `S04_ResponseType` | redirect | `X-07`, `X-05` |
| 5 | `S05_Pkce` | redirect | `X-04`, **`N-02`** — method present and `S256`; verifier grammar `43*128unreserved`; sets `PkceWasRequested` |
| 6 | `S06_Scope` | redirect | `X-08`, `A-13`, `C-23` |
| 7 | `S07_Resource` | redirect | `X-09`, **`N-01`** — each `resource` → `ResourceKey` → `IResourceRegistry`. Unknown and not-permitted are indistinguishable |
| 8 | `S08_OidcParameters` | redirect | `X-16`, `X-04`. `openid` gates OIDC (`C-13`); `nonce` never invented; `prompt`/`max_age` optional |
| 9 | `S09_Authentication` | 303 → `/login` | `X-12`, `X-14`. User authenticated before any automatic redirect; `returnUrl` gated by `Url.IsLocalUrl` |
| 10 | `S10_Consent` | 303 → `/consent` | `X-13`, `X-06`, **`N-14`** — view model requires the `client_id` host and the requested redirect host; logo served from `logo_blob` on our origin |
| 11 | `S11_CodeIssuance` | — | Persists challenge + method + `PkceWasRequested` + `redirect_uri_used` + grant set |
| 12 | `S12_Response` | **303** | `code`, `state` verbatim, `iss` (`S-27`). Built with `QueryHelpers.AddQueryString`, never concatenation |

`/authorize` is mapped **without** `RequireCors`, and `app.UseCors(policy)` is never called globally
(`E-08`, RFC 9700 §2.6).

**`form-action` is not a constant, and stage 0 cannot know its value.** Chrome and Safari apply the
directive to the *redirect chain* a submission follows, not only to its immediate target — so a form
that posts same-origin and is answered with a 303 to somewhere else is blocked at the 303, after the
POST has been processed. Two pages here do exactly that: the consent POST answers with a redirect to
the client, and the sign-in page's provider button answers with one to the upstream. Both are
therefore widened, for that response only, by `SecurityHeaders.AllowFormActionTo` — the header is
written in `Response.OnStarting`, so whatever the pipeline learned after stage 0 is in the policy.
The baseline stays `'self'` and each addition is a single validated origin: the client's
*already-validated* redirect URI, or the configured provider's authorization origin.

Worth stating because of how it failed: **`curl` does not enforce CSP.** Every measurement of the
provider button by `curl` was a correct 303 to Google while every browser refused to leave the page,
and the defect was found by a person pressing the button on the real host. A test asserting the
header's sources (`InteractionFlowTests.FormAction`, `ExternalLoginFlowTests`) is the substitute; an
end-to-end request that follows the redirect is not one.

**Authorization-code grant, `N-07` order — this order *is* the requirement:**

1. Parse → hash → `FindAsync` (returns redeemed rows too).
2. Client binding, else `invalid_grant`.
3. `redirect_uri` if present must equal the one used at `/authorize`.
4. **PKCE XOR** against `PkceWasRequested`, then `FixedTimeEquals`.
5. Expiry.
6. **Only now** `TryRedeemAsync`. `false` ⇒ a *fully valid* replay ⇒ revoke the grant and descendants.

An attacker with a sniffed code but no verifier fails at step 4, and the legitimate client's tokens
survive. The naive "seen twice ⇒ revoke" is a denial-of-service (OAuth 2.1 §7.5.2 SHOULD NOT).

---

## 4.1 Rate limiting and abuse control — `X-31`

**Every limit below is enforced per process.** The server runs as several instances behind a load
balancer, each holds its own counters in memory, and none of them can see the others. A fleet of *n*
replicas therefore admits up to *n* times each number here, a caller spread across the fleet is
counted separately by each replica, and a breaker open on one says nothing about the rest. These are
bounds on **what one instance can be made to spend**, which is where the CPU, the memory and the
outbound sockets are. They are not an account lockout and not a fleet-wide quota; that needs a shared
store, and nothing here is a substitute for one.

Measured on a four-core host, same harness both sides, over `TestServer` — so the absolute latencies
are not deployment numbers, but the two columns are directly comparable:

| | Before | After |
|---|---|---|
| 50 anonymous `GET /authorize`, one failing `client_id` | 50 outbound fetches, 50×400 | **3 fetches**, 3×400 + 47×429 with `Retry-After: 60` |
| 100 anonymous fetches across 100 ports of one host | 100 reached the network layer | **60**, then `RateLimited` |
| 64 concurrent first resolutions of one `client_id` | 64 fetches | **1**, all 64 resolved |
| 1024-document cache fill, then a **new** client connects and authorizes 10× | never cached — **10 fetches** | **1** |
| …a client **in use throughout** the fill | 0 further fetches | 0 further fetches |
| …a client cached **before** the fill and idle through it | 0 further fetches | **1** — the cost of evicting instead of refusing admission |
| expired entry + origin answering 503 | authorization fails | served stale; hard-fails once past the 1 h window |
| 100 concurrent `POST /login`, one reused antiforgery token | 100 hashes, peak 9 in flight, p50 2.9 s, an unrelated `GET /.well-known/…` stalled 2.3 s | **10 hashes**, peak 4, p50 0.22 s, canary max 0.25 s |
| 300 concurrent, same | 300 hashes, peak 68, p50 10.4 s, canary stalled 11.5 s | **10 hashes**, peak 4, p50 0.03 s, canary max 0.06 s |
| 300 concurrent, **distinct source and username each** — the shape neither counter can see | 300 hashes, peak 63, p50 14.6 s, canary stalled 14.0 s | **42 hashes**, peak 4, p50 2.1 s, canary max 0.13 s |

Login p50 after the change moved between 0.03 s and 0.22 s across three runs; the shape rather than
the digit is the result. The last row is the one that shows what each control is doing: with the two
counters blind, everything the concurrency bound cannot fit is shed with a `Retry-After` and the rest
of the server stays at its idle latency.

| Limit | Default | Why this number |
|---|---|---|
| CIMD fetches per `client_id` | 10 / min | A resolved document is cached ≥ 300 s (`S-30`'s floor), so one client costs ≤ 1 fetch per 5 min per instance. Fifty times its ceiling |
| CIMD breaker | 3 consecutive failures → 60 s, doubling to 10 min | The authorization was going to fail anyway; what changes is that it fails in microseconds with a `Retry-After` instead of after a DNS lookup and a TLS handshake |
| Outbound fetches per remote host | 60 / min | ≈ 300 distinct clients on one host all refreshing in the same minute. The two live vendors publish two documents each |
| Stale-serve window | 1 h past expiry | Survives every transient outage worth surviving; short against the 24 h ceiling on a fresh entry. Stated as a trade: a client that takes its document down keeps being trusted for this long |
| CIMD cache | 1024 entries, least-recently-**used** evicted | Not by expiry: a filler declaring `max-age=86400` clamps to the ceiling and a vendor declaring `max-age=300` clamps to the floor, so expiry-ordering evicts the vendors first |
| `/login` per username | 10 / 15 min, 15 s backoff doubling to 5 min | Someone who has forgotten which password they used makes three or four attempts. The ceiling is deliberately low: the counter is keyed on the *submitted* name, so anyone can aim attempts at anyone, and a long lockout is a denial-of-service tool |
| `/login` per source | 30 / 15 min, 1 min doubling to 15 min | A source is not a person — an office behind one address is several. **Behind a proxy that does not populate `RemoteIpAddress` this is one bucket for the whole deployment**: configure `UseForwardedHeaders`, or `LoginThrottleOptions.ClientKey` |
| Concurrent password verifications | one per core | Argon2id at `m=19456,t=2,p=1` is CPU-bound and allocates 19 MiB per hash for its duration. More in flight than there are cores buys no throughput and costs both memory and a blocked thread each |

Against `C-19`/`C-29`: Claude treats the whole authorization step as terminal after roughly ten
seconds and refreshes proactively up to five minutes early. Nothing above trips on that traffic — the
control for each limit is a test driving vendor-shaped volume through the shipped defaults and
asserting it is untouched, because a limit that trips on ordinary traffic is worse than none.

**The antiforgery token is deliberately still reusable.** One `GET /login` mints a cookie+token pair
that drove 300 concurrent POSTs. Making it single-use was measured and rejected: a POST refused
before the hash costs 0.1–0.5 ms and a `GET /login` that mints a token costs 0.1–0.8 ms, against
~95 ms for the Argon2id it would otherwise reach — so single-use raises an attacker's cost by roughly
a factor of two on a step that is already two to three orders of magnitude cheaper than the thing it
triggers, while the per-source counter and the concurrency bound cut the same flood by 30×. Against
that it would cost a per-instance used-token set (a guarantee that is false on the second replica —
each instance would grant one more use), a broken double-submit, and a broken browser back-button.
The thing worth bounding is the hash, and the hash is bounded directly.

---

## 5. Build order

Each step leaves a green build and something runnable.

| Step | Projects | Milestone |
|---|---|---|
| 1 | `Primitives` + tests + `Architecture.Tests` with the `N-03` rule **from day one** | The 16-row redirect matrix and the RFC 7636 Appendix B vector pass |
| 2 | `Net` + tests | SSRF matrix passes; `N-05` Cecil rule active |
| 3 | `Tokens` + tests | `at+jwt` minting and `Rfc9068ValidationParameters` |
| 4 | `Abstractions` + `Storage.InMemory` + store contract suite | The contract exists and one implementation satisfies it |
| 5 | `AuthorizationServer` skeleton: capabilities, metadata, `E-01`..`E-07`, startup assertions, doctor config checks | `preflight.sh` passes its first two commands |
| 6 | `/authorize` + `/token` + CIMD + the interaction pages | **← the end-to-end authorization-code flow first runs here.** The Claude Code portless-loopback flow is the first green conformance test |
| 7 | `Storage.EntityFrameworkCore` + Sqlite + PostgreSql | Contract suite passes on all three stores |
| 8 | `ResourceServer` (+ `.Mcp`) | Sample host is a complete AS + RS pair; the doctor's mint-and-validate round trip works |
| 9 | DCR, `/logout`, `/userinfo`, jwt-bearer, Google federation, admin schema | Feature completion |

---

## 6. Cut list

**Cut in this order if the deadline halves:**

1. **DCR entirely** (`S-13`/`S-15`, `E-11`–`E-14`, `X-24`–`X-31`) — both vendors do CIMD, `N-06`
   forbids advertising both anyway, and `A-08` means CIMD creates no client rows. Largest single
   saving, zero cost at the two connectors that matter. Keep `IClientResolver`.
2. **The C# resource-server middleware** — the TypeScript `@boltway/mcp-core` already works and
   has a shipped connector behind it. Keep `Primitives`/`Net`/`Tokens` and the shared vector file.
3. **`/logout`** (`S-11`) and **`/userinfo`** (`E-17`) — deliver claims in the ID token instead.
4. **Google federation** — local Argon2id only. **Keep the seam and the `ExternalLogin` table**; the
   table is a migration we would otherwise pay for across every customer database.
5. **`client_credentials` and `jwt-bearer`** — `N-06` then correctly forces the URN out of
   `grant_types_supported`.
6. **The admin HTTP surface** — keep `ConfigSchema.Build()` behind the CLI.
7. **Multi-realm code paths** — keep the `RealmId` column and parameter.
8. **The PostgreSQL provider** — last, and fought for. The seam is what makes it a week rather than
   a rewrite.

**Never cut, at any deadline:**

- **All sixteen `N-nn` *and their mechanical guards*.** Shipping `N-03` as a code-review convention
  instead of an architecture test saves two hours and is exactly how it regresses in month six.
- **CIMD end to end including the SSRF guard.** It is the entire zero-admin-step promise, and an
  unguarded fetcher is an SSRF primitive with a public trigger.
- **`resource` → `aud` binding.** Without it we have rebuilt the Auth0 trap we are selling the escape
  from — and RFC 8707 registers no discovery flag, so no client can detect it.
- **Refresh rotation with family revocation and the 30–60 s grace window.**
- **Exact redirect matching with the loopback exception.** Claude Code does not work without the
  loopback rule; nothing is safe without the exact rule.
- **The `Rejection` type and correlation ids.** Cutting these does not save time, it spends it. Kept honest by §3.1, which records that this line was true in the document and false in the code for the whole of the project's history until 2026-08-05.
- **The requirement-coverage test.** Without it, "187 requirements" is a claim; with it, it is a
  build artifact — and the artifact is what gets resold.
- **The four live CIMD documents as tests, plus the nightly re-fetch.** The vendors are a moving
  dependency; finding out from a customer is the expensive way.

Deadline pressure falls on `app`-shaped surface — endpoints, providers, admin convenience — never on
`core`-shaped guarantees. That is the rule `FictStoryEngine/CLAUDE.md` states for its own deadline,
and it was right there too.
