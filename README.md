# Boltway — OAuth 2.1 authorization server for MCP connectors

[![ci](https://github.com/TobiiNT/Boltway/actions/workflows/ci.yml/badge.svg)](https://github.com/TobiiNT/Boltway/actions/workflows/ci.yml)
[![Boltway.AuthorizationServer on NuGet](https://img.shields.io/nuget/v/Boltway.AuthorizationServer?label=Boltway.AuthorizationServer&color=004880)](https://www.nuget.org/packages/Boltway.AuthorizationServer)
[![Boltway.Mcp on NuGet](https://img.shields.io/nuget/v/Boltway.Mcp?label=Boltway.Mcp&color=004880)](https://www.nuget.org/packages/Boltway.Mcp)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/TobiiNT/Boltway/blob/main/LICENSE)

An OAuth 2.1 + OpenID Connect authorization server, written from scratch in C# for .NET 10, aimed
at one job: putting an MCP server behind authentication that Claude and ChatGPT can complete without
an administrator in the loop. It ships as libraries you host, plus a resource-server half your MCP
server references.

**What it is not.** Not a general-purpose identity provider, and not a replacement for Entra ID or
Auth0. There is no user registration flow and no multi-tenancy. Rate limiting exists on two paths
only and is per process — see [Before the second replica](#before-the-second-replica). Several
protocol endpoints are deliberately absent; several others simply have not been built. The
difference is spelled out below, because a list that blurs the two is worse than no list.

## Contents

**[What you get](#what-you-get)** · [Install](#install) · [What is built and off by
default](#what-is-built-and-off-by-default) · [What is deliberately not
implemented](#what-is-deliberately-not-implemented) · [What is not built yet](#what-is-not-built-yet)

**[Hosting it yourself](#hosting-it-yourself)** — [the smallest host that
starts](#the-smallest-host-that-starts) · [the services you
supply](#the-services-a-deployment-must-supply) · [an upstream
provider](#signing-in-through-an-upstream-provider) · [the sign-in and consent
pages](docs/INTERACTION-PAGES.md) · [translating them](docs/LOCALIZATION.md)

**[Running it](#running-it)** — [target frameworks](#supported-target-frameworks) · [before the
second replica](#before-the-second-replica) · [production checklist](#production-checklist) ·
[the tests](#running-the-tests)

**Reference** — [layout](#layout) · [roadmap](ROADMAP.md) · [versions](#versions-and-changes) ·
[design](docs/DESIGN.md) · [requirements](spec/REQUIREMENTS.md) · [all
documents](docs/README.md)

---

## What you get

Everything in this table is **on with no flag**, in the default configuration the
[smallest host](#the-smallest-host-that-starts) builds. The three lists after it are the other three
states a capability can be in — on but off by default, absent on purpose, absent because nobody has
written it — and keeping the four apart is the whole point: this section exists because its absence
let *What it is not* claim for a release that there was no admin UI and no durable storage when both
had shipped.

| | What you get |
|---|---|
| **The flow** | Authorization code with **PKCE required of every client**, public and confidential alike. Exact redirect-URI matching, `303` rather than `307`, `Cache-Control: no-store`, and the six OAuth 2.1 token-endpoint error codes |
| **Tokens** | RFC 9068 `at+jwt` access tokens, an ID token when `openid` is granted, and refresh tokens with **derived rotation** — a rotated token's successor is computed rather than stored, and replaying a consumed one revokes the whole family *and* the grant behind it. Grants: `authorization_code`, `refresh_token` |
| **Audience** | RFC 8707 resource indicators. A token is minted for the resource the client named, and a resource server that checks `aud` refuses one minted for somebody else |
| **Discovery** | RFC 8414 `/.well-known/oauth-authorization-server`, OIDC `/.well-known/openid-configuration`, and `/.well-known/jwks.json`, all three routed unconditionally. `/userinfo` is the one optional endpoint that is **on** by default — it discloses only what the caller's own token already carries |
| **Clients with no registration step** | CIMD (Client ID Metadata Document): a client that has never been registered here connects by naming the URL its metadata lives at. That is what lets Claude and ChatGPT complete a connection with nobody in the loop. Client authentication: `none` and `client_secret_basic` |
| **The pages** | Sign-in, consent, and error pages, rendered by the server and routed unconditionally. The consent page satisfies **N-14**, a MUST in the MCP specification: the `client_id` host leads, a self-asserted `client_name` is marked unverified beneath it, the redirect host is shown, and a redirect landing on the user's own machine carries a warning |
| **Local accounts or an upstream** | Argon2id password hashing, or a generic OpenID Connect relying party with Google as configuration over it. **One of the two is required, not both and not neither**, and a host with neither refuses to start with a message naming both ways out |
| **The MCP half** | `Boltway.ResourceServer` gates your API on a bearer token, publishes RFC 9728 protected-resource metadata, and enforces scope per endpoint with `.RequireScope(...)`. `Boltway.Mcp` layers connector-shaped tool-error semantics over it. Neither references the authorization server |
| **Key rotation that does not need you awake** | `SigningKeyRing` models Pending → Active → Retiring with a publish lead time, and `JwksKeySource` on the resource server follows `jwks_uri` out of discovery rather than a hand-filled list |
| **Two images you can run** | `hosts/Boltway.AuthorizationServer.Host` is the server configured entirely by environment; `hosts/Boltway.AdminBff` is the admin UI. Both have a `Dockerfile`, and [`docker-compose.yml`](docker-compose.yml) brings up the pair, PostgreSQL, and a TLS proxy in front of them |
| **Storage that survives a restart** | PostgreSQL and SQLite over EF Core, each with its own migrations, both running one shared contract suite. **PostgreSQL is the one to deploy** — SQLite is a development provider and [the reason is below](#what-is-not-built-yet) |
| **Observability** | Three meters, and an append-only administrative audit log. Nothing is published until the host calls `AddMeter` — see the [checklist](#production-checklist), because an unnamed meter is silence that looks like health |

**What proves it rather than asserts it.** `MetadataHonestyTests` drives every advertised grant
through `/token` and sweeps for an endpoint the document promises and nothing routes, so this table
cannot drift from the metadata document without the build going red. And
[`samples/drive-flow.sh`](samples/README.md) walks the whole thing end to end in fifteen steps —
`401` with `resource_metadata`, RFC 9728, discovery, `/authorize` for a CIMD client nobody
registered, sign-in, consent, code, `/token`, the decoded token, a scope refusal, a refresh, and the
same refresh token presented twice inside the grace window to show the retry is idempotent.

---

## Install

```bash
dotnet add package Boltway.AuthorizationServer     # the server you host
dotnet add package Boltway.Mcp                     # the half your MCP server references
```

To watch a whole flow before writing anything:

```bash
dotnet run --project samples/Boltway.Sample.AuthorizationServer   # terminal 1
dotnet run --project samples/Boltway.Sample.ResourceServer        # terminal 2
./samples/drive-flow.sh                                           # terminal 3
```

Or, with Docker, the pair plus PostgreSQL: `cp .env.example .env && docker compose up`.
See [`samples/README.md`](samples/README.md) and [Hosting it yourself](#hosting-it-yourself).

---

## What is built and off by default

**This section exists because its absence made the next one wrong.** Two categories — absent on
purpose, and absent because nobody has written it — have no room for *present, and not switched on*,
so a capability that grew a default got filed as one of the two and stayed there.
`client_credentials` sat under "deliberately not implemented" after it was implemented.
Under-claiming is the safe direction to be wrong in, which is exactly why it survived: nothing
breaks, and nobody looks.

Off is the right default for every row here. The point is that "off" and "absent" are different
words.

| Capability | Turned on by | Why off |
|---|---|---|
| `client_credentials` grant | adding the name to `GrantTypesSupported` | `Token/ClientCredentialsGrant.cs`, and an arm in `TokenEndpoint`'s dispatch. Narrowed on purpose: the client names an **owner** and the token is issued for that account. A client acting purely for itself is refused with `ReasonCode.ClientHasNoOwner`, because a `sub` that is a client id resolves against no account, so roles and attribution have nothing to read |
| `/introspect` | `IntrospectionEnabled` | it answers questions about somebody else's token, so an unnecessary one is a surface that exists to be probed |
| `private_key_jwt` client authentication | adding `ClientAuthMethod.PrivateKeyJwt` to `TokenEndpointAuthMethods` | RFC 7523. The client signs an assertion with its own key and this server verifies it against the `jwks_uri` in the client's metadata — an outbound fetch to a URL the client chose, which is why it goes through the guarded fetcher and why enabling it is a decision rather than a default. Both vendors currently offer `none` beside it and this server prefers `none`, so switching it on changes nothing for them; it changes what a client that offers **only** assertions gets. Startup refuses the method without an `IClientAssertionReplayStore` |
| `/revoke` | `RevocationEnabled` | RFC 7009. Confidential clients only — `none` is never advertised for it, because an endpoint that accepted an unauthenticated caller would revoke on anyone's say-so. Revoking either token type revokes the grant behind it: the denylist is keyed on the grant and access tokens are signed rather than stored, so "revoke this access token and leave the session running" is not a state this server can represent |
| `/logout` | `EndSessionEnabled` | routed by `MapInteraction`, not by `MapBoltwayAuthorizationServer` — it is a page |
| Administration API and CLI | `AdministrationEnabled` | one `UserAdministration` behind both callers, with `RealmId` threaded through every lookup. Seven CLI verbs — `new-user`, `set-role`, `set-password`, `disable`/`enable`, `set-email`, `revoke-sessions`, `anonymise` — and `/admin/users` list-create-read-patch plus password reset, session revocation and anonymise, and `/admin/audit` over an append-only audit log. Bearer-only: an architecture test over the routing table refuses a cookie principal on it (N-17) |
| Self-service API (`/account/*`) | `SelfServiceEnabled` | `E-33`–`E-38`, bearer-only. A person reads their own account, changes their own password with the current one, sees and ends their own sessions, and sees and withdraws what they have approved |
| Self-service pages (`/me`, `/me/password`, `/me/sessions`, `/me/consents`) | `SelfServicePagesEnabled` | `E-46`, the same capabilities as a browser page. Cookie-authenticated with antiforgery, and refuses a bearer — the mirror of the row above, on purpose |
| Password reset by email (`/forgot`) | `PasswordRecoveryEnabled` | `E-39`–`E-44`. Startup refuses it without an `INotificationSender`, and the sign-in page draws the link only when it is on, because a dead link is worst for the one person least able to recover from it. `/forgot` is a page rather than a link to `E-39`, which answers JSON — pointing a browser at the endpoint would have shown somebody a line of JSON |
| Access-token revocation actually taking effect | `IAccessTokenRevocationCheck` on the resource server, plus `/introspect` here | signed tokens are not looked up, so without it a revoked grant lags by one access-token lifetime |
| Durable storage | `AddBoltwayPostgreSqlStores(...)` instead of the in-memory call | see the next section for the sample's wiring and for why not the SQLite one |

`/userinfo` is **on** by default, so it is in [What you get](#what-you-get) rather than here. It is
the one endpoint of this kind that discloses only what the caller's own access token already
carries.

## What is deliberately not implemented

These are absent on purpose. The rule is N-06 — never advertise a capability you do not have — and
each of these was measured returning `404` while the discovery document promised it.

- **The jwt-bearer assertion grant** (`urn:ietf:params:oauth:grant-type:jwt-bearer`). It and
  `client_credentials` were both once accepted by configuration with no handler behind them.
  `KnownGrantTypes` now lists exactly the grants `TokenEndpoint`'s dispatch has an arm for, so
  enabling a name with nothing behind it is a startup failure rather than a runtime surprise, and
  `MetadataHonestyTests.Every_advertised_grant_has_a_handler` drives every listed name through
  `/token`. `client_credentials` has since grown an arm and moved to the table above; this one
  has not.
- **A second `authorization_servers` entry on the resource server.** RFC 9728 permits an array;
  Claude reads only the first. A second entry would be advertised and then refused.
- **Persisting a CIMD client.** A hundred sequential CIMD connections leave the client table
  unchanged, by design. The cache is in memory, bounded and expiring.
- **Pairwise subject identifiers**, and now with no seam pretending otherwise.
  `ISubjectIdentifierService` used to sit under *not built yet* as "exists and nothing on the token
  path calls it", which was true and was the wrong thing to keep: its signature took a `UserAccount`
  and a `ClientRecord`, while the token path carries a `SubjectId` off the grant and never loads an
  account. Wiring it would have meant a store read per token issuance, so it would not have saved
  the hunt through call sites it existed to prevent — a seam that did not fit its own seam. A seam
  nothing can call is a claim that a decision has been made, and deleting it is how the claim stops
  being made. Pairwise, if ever wanted, is `(subject, client)` threaded through `TokenIssuer` and
  `UserInfoEndpoint` plus a salt that is permanent once set.

`/revoke` and `private_key_jwt` are **not** on this list any more; both are built and both are in
the table above. That closes the set that started it — `/userinfo`, `/logout`, `/introspect` and
`/revoke` were the four endpoints this server advertised and did not serve, and each one now routes
and advertises from a single flag.

## What is not built yet

Not decisions. Gaps. [`ROADMAP.md`](ROADMAP.md) is the wider version of this list — what an
authorization server gets judged on, measured against Keycloak on a named commit — and says plainly
that nothing in it is committed to. What is here is narrower and closer to the code.

- **Dynamic client registration (RFC 7591).** `ClientRegistrationProfile.DynamicRegistration` exists
  and **selecting it is a startup failure**, with a message naming CIMD as the way out. Nothing
  routes `/register`. Refusing at startup rather than quietly not advertising is deliberate: a
  deployment that asked for dynamic registration wants it, and publishing a document without it and
  starting anyway answers a different question than the one the operator asked.
- **SQLite does not meet the concurrent-redemption requirement.** It is a supported provider for
  development and is not one for a deployment. Under concurrent load
  `Redeeming_many_times_in_parallel_still_succeeds_exactly_once` intermittently fails with
  `SQLite Error 1: 'cannot start a transaction within a transaction'` — reproducible in roughly a
  third of runs of the storage contract, one worker in sixteen, and **undiagnosed**. What is known,
  what was wrongly recorded as ruled out, and what is now measured is on
  `SqliteRelationalStoreBehavior`. Pooling is off for a SQLite file database because a pooled handle
  is the one poisoning route that has been demonstrated; that removes a route, not the cause, and is
  not recorded as a fix. PostgreSQL is unaffected and runs the same contract.
- **The samples still wire the in-memory stores**, so a sample loses everything on restart. Durable
  storage itself is built: call `AddBoltwaySqliteStores(connectionString)` or
  `AddBoltwayPostgreSqlStores(connectionString)` instead of `AddBoltwayInMemoryStores()`, and run
  `dotnet ef database update` as a deploy step — neither call creates or migrates the database,
  deliberately.
- **Rate limiting beyond `/authorize`'s CIMD fetch and `POST /login`.** Those two are bounded (X-31,
  and `docs/DESIGN.md` §4.1 gives the numbers and the measurements). Nothing else is: there is no
  ASP.NET Core rate limiter, no per-subject budget, and no load shedding at `/token`. **And every
  limit that does exist is per process** — each instance counts only its own traffic, so a fleet of
  *n* replicas admits *n* times each number and a caller spread across the fleet is counted
  separately by each. They bound what one instance can be made to spend; they are not an account
  lockout and not a fleet-wide quota. Put a shared limiter in front if you need one, and read
  [Before the second replica](#before-the-second-replica) first — the limiters are one row of a
  longer list, and one of the others is a security property rather than a budget.
- **A kid-miss trigger on the resource server's key source.** `JwksKeySource` fetches the
  authorization server's discovery document, checks its `issuer`, reads `jwks_uri`, and refreshes in
  the background as the snapshot ages, so a rotation no longer stops a resource server dead. What it
  does **not** do is react to a token naming a `kid` it has not seen:
  `ProtectedResourceOptions.SigningKeySource` is synchronous and on the request path, so there is
  nowhere to await a fetch, and `CurrentKeys` deliberately returns the stale snapshot rather than
  blocking.

  That is survivable because of `PublishLeadTime`, not because it does not matter. A key ring
  publishes a key at least `PublishLeadTime` before it signs — 24 hours by default, floor ten
  minutes — and `CacheLifetime` defaults to five, so an ordinary rotation is seen long before it is
  used. **An emergency rotation that skips the lead time is the case with no cover**, and there the
  first token signed by the new key is rejected and the ones after the next refresh are not.

  Assign `JwksKeySource.CurrentKeys` to `SigningKeySource`, not to `SigningKeys` — the list is
  mutable state a request enumerates while a refresher writes it, which is a rotation-day failure of
  its own. In an MCP connector, `services.AddJwksSigningKeys(issuer)` from `Boltway.Mcp` wires the
  source, primes it at startup, and refuses to start without keys.
- **Upstream identity providers other than one.** Federated sign-in ships —
  `Boltway.Federation.Oidc` is a generic OpenID Connect relying party and
  `Boltway.Federation.Google` is configuration over it — but only one has been driven against
  a live provider's real behaviour, and that one is a fake this repository hosts. Nothing here has
  talked to Google, Entra or Okta; the discovery form probed is OIDC Discovery's append spelling
  only, and an upstream that omits the `typ` header on its ID tokens is refused. D-10's
  `sub`-disambiguation concern is unchanged: a second issuer is the point at which it starts to
  matter.
- **Multi-target for the resource server package.** `DESIGN.md` calls for `net8.0;net10.0`. It is
  `net10.0` only, and [Supported target frameworks](#supported-target-frameworks) has the measured
  reason and what it would cost.

**Two things landed narrower than their design and say so here as well as in code.** The
administrative audit entry is written *immediately after* the change rather than in the same
transaction, because every relational store here creates its own `DbContext` per call. And revoking
sessions kills refresh chains but reaches **access tokens already issued** only where a resource
server asks: those tokens are signed rather than looked up, so nothing about them changes when a
grant is revoked. `IGrantStore.IsRevokedAsync` is the denylist, `/introspect` is how a resource
server reads it, and `IAccessTokenRevocationCheck` is what calls it on the way in — all three off
unless a deployment turns them on, and a deployment that has not is back to one access-token
lifetime of lag. Designed in [`docs/USER-MANAGEMENT.md`](docs/USER-MANAGEMENT.md), requirements in
`spec/REQUIREMENTS.md` §11.

---

## Hosting it yourself

The authorization server is a library you host, so a deployment writes a `Program.cs`. The container
image in [`hosts/`](hosts/Boltway.AuthorizationServer.Host/README.md) is the alternative — the same
library, configured entirely by environment, if you would rather not.

### The smallest host that starts

Discovery served, `/authorize` validating. Measured at **45 lines**, of which 12 are `using`
directives.

```csharp
using System.Security.Cryptography;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Interaction;
using Boltway.AuthorizationServer.Resources;
using Boltway.Identity.Passwords;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var now = TimeProvider.System.GetUtcNow();
var key = new SigningKeyHandle("dev-1", SigningAlgorithm.RS256, new RsaSecurityKey(RSA.Create(2048)));
_ = ScopeSet.TryParse("stories.read", out var scopes, out _);

builder.WebHost.UseUrls("https://localhost:7443");
builder.Services.AddSingleton(new SigningKeyRing([new ManagedSigningKey(key, SigningKeyState.Active, now, now)]));
builder.Services.AddBoltwayInMemoryStores();
builder.Services.AddSingleton<IUserStore, InMemoryUserStore>();
builder.Services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserSession, CookieUserSession>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
builder.Services.AddSingleton<IResourceRegistry>(ConfiguredResourceRegistry.Create(
    new Dictionary<string, (string Name, ScopeSet Scopes)>(StringComparer.Ordinal)
    {
        ["https://localhost:7444/mcp"] = ("MCP server", scopes),
    }));

builder.Services.AddBoltwayAuthorizationServer(options =>
{
    options.Issuer = "https://localhost:7443";
    options.ScopesSupported.Add("openid");
    options.ScopesSupported.Add("offline_access");
    options.ScopesSupported.Add("stories.read");
    options.RefreshTokenDerivationKey = RandomNumberGenerator.GetBytes(32);
});

var app = builder.Build();
app.UseAuthentication();
app.MapBoltwayAuthorizationServer();
app.Run();
```

Project references: `Boltway.AuthorizationServer`, `Boltway.Identity`,
`Boltway.Storage.InMemory`.

**What those 45 lines actually get you**, measured rather than assumed: the host starts,
`/.well-known/openid-configuration` and `/.well-known/jwks.json` answer `200`, and `/authorize`
validates a request and refuses an unusable client with a message naming the rule it broke. They do
**not** get you a completed flow — there is no user account to sign in as, and a CIMD client's
document has to be fetchable. `DESIGN.md` says "the AS is a library a 20-line `Program.cs` hosts";
45 is the real number for a host that starts. The runnable sample is 229 lines, 104 of them comments
explaining which parts of it a deployment must not copy.

### The services a deployment must supply

`MapBoltwayAuthorizationServer` checks every one of these before it maps a route, and reports
**all** the missing ones in a single exception rather than one per restart. That check is the
difference between a five-minute wiring session and the alternative, which was measured: a host with
nine of these missing started cleanly, logged `Now listening on`, served both discovery documents
with `200`, and failed on the first real client — sometimes after the user had already typed a
password.

| Service | What it decides | In the box | You write it when |
|---|---|---|---|
| `SigningKeyRing` | which keys sign tokens and appear in JWKS | `SigningKeyRing`, `SigningKeyHandle`, three-phase rotation states | always — the key material is yours; the ring is not defaulted |
| `IResourceRegistry` | which resources this server issues tokens for, and each one's scopes | `ConfiguredResourceRegistry.Create(...)` | resources are discovered at runtime rather than declared at startup |
| `IGrantStore` | the grant behind every issued token | `AddBoltwayInMemoryStores()` | you need persistence — `AddBoltwayPostgreSqlStores(...)`, see below |
| `IAuthorizationCodeStore` | codes between `/authorize` and `/token` | same call | same |
| `IRefreshTokenStore` | refresh tokens and their rotation families | same call | same |
| `IConsentStore` | what each user has already agreed to | same call | same |
| `IConsentPolicy` | whether to show the consent page | `AlwaysAskConsentPolicy` — registered for you | you want "do not re-ask for our own first-party client". Compare `RequestedScope` and `RequestedResources` against `Existing`, not merely whether `Existing` is non-null |
| `IClientSecretStore` | confidential-client secrets | `NoClientSecretsStore` — registered for you | you have a confidential client. Public CIMD clients never reach it |
| `IClientAssertionReplayStore` | which RFC 7523 assertions have already been used | `AddBoltwayInMemoryStores()`, and both relational packages | **only** when `TokenEndpointAuthMethods` contains `private_key_jwt`, and then startup refuses to run without it. The in-memory one is a development implementation in a stronger sense than its siblings: a per-process replay set admits one use of an assertion **per replica** |
| `IUserSession` | who is signed in, and *when they proved it* | `CookieUserSession` | your users are authenticated by something other than this server's cookie |
| `IUserStore` | accounts, for `POST /login` and for resolving a federated identity | `InMemoryUserStore` | you have a directory. **Not** registered by `AddBoltwayInMemoryStores()` |
| `IPasswordHasher` | password verification | `Argon2idPasswordHasher` | never, unless you are migrating existing hashes |

**One of `IPasswordHasher` or an `IExternalIdentityProvider` is required, not both and not neither.**
A deployment with local accounts registers the hasher; a federation-only deployment registers a
provider and no hasher, and its sign-in page renders no password form. A host with neither does not
start, and the message names both ways out.

### Signing in through an upstream provider

```csharp
builder.Services.AddExternalIdentityProvider(
    GoogleFederation.Options(clientId, clientSecret));

// Only when ExternalLoginOptions.UnknownIdentity is Provision.
builder.Services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));

builder.Services.AddBoltwayAuthorizationServer(options =>
{
    options.Issuer = "https://auth.example.com";
    // Refuse (the default) turns away an upstream identity no local account is linked to.
    // Provision creates a brand-new local account for it — open registration, so it is opt-in.
    options.ExternalLogin.UnknownIdentity = UnknownExternalIdentityPolicy.Provision;
});
```

Any OpenID Connect provider is the same call with a different `OidcProviderOptions`: an issuer, a
client id and a secret. The endpoints come from the issuer's discovery document.

**An upstream identity is matched to a local account by `(issuer, subject)` and by nothing else.**
Not by email address, and not by email address plus `email_verified` — that is a claim made by the
upstream about a check this server did not perform. `IUserStore` therefore has no method that finds
an account by email at all. To attach an upstream identity to an *existing* account, the account
signs in first and posts to `/external/{scheme}/link`, and the session that finishes the round trip
must be the one that started it.

An on-premises provider on a private address needs one more line, because the RFC 6890 address check
is on by default for upstream fetches — a discovery document names further URLs, and that is what the
check is guarding:

```csharp
builder.Services.AddExternalIdentityProvider(options, transport => transport.AllowPrivateAddresses = true);
```

Three more are required and are **not** in that error message, because you get them from the
framework or from the library without asking:

- **`IHttpContextAccessor`** — `CookieUserSession` takes one. Forgetting `AddHttpContextAccessor()`
  fails at startup, but with the framework's generic "Unable to resolve service for type
  `IHttpContextAccessor` while attempting to activate `CookieUserSession`" rather than with the
  guided message the others get.
- **Cookie authentication** — `AddAuthentication(...).AddCookie(...)`, and set
  `Cookie.SameSite = Lax`. `Strict` is not sent on the top-level cross-site navigation from
  `claude.ai`, so every user looks signed out on every connect.
- **`IUserSignIn`, `IInteractionLayout`, `IInteractionRenderer`, `TimeProvider`, `IAntiforgery`** — all registered by
  `AddBoltwayAuthorizationServer` with `TryAdd`, so registering your own first wins.

In the CIMD profile (the default), `AddBoltwayAuthorizationServer` also registers
`CimdClientResolver` and a hardened `ISafeHttpFetcher`. Register your own `IClientResolver`
implementations **before** that call: resolvers run in registration order and CIMD is the only one
that makes an outbound request, so it belongs last.

---

### Changing the sign-in and consent pages

Three tiers, and **take the lowest one that does what you need** — each step up hands you a
requirement you then own. Tier 1 is a product name, a logo and a stylesheet, and no code. Tier 2
replaces `IInteractionLayout`: your document, the server's page inside it. Tier 3 replaces
`IInteractionRenderer`: total control, and you own N-14, A-11 and A-14 in full.

Both seams are `TryAdd`, so a registration made **before** `AddBoltwayAuthorizationServer` wins and
one made after it silently does nothing. Whichever of the last two you take,
`Boltway.Interaction.Testing` ships as a package so you can run the same contract we do against your
own markup.

**Language is a fourth axis, orthogonal to all three.** Every sentence these pages say is a key a
deployment replaces with a JSON file, `ui_locales` picks the language per request, and untranslated
keys fall back to English one string at a time.

→ [`docs/INTERACTION-PAGES.md`](docs/INTERACTION-PAGES.md) for all three tiers, the CSP rules and
the two form fields that break silently. → [`docs/LOCALIZATION.md`](docs/LOCALIZATION.md) for the
language axis.

---

## Running it

Four things a deployment decides before it is a deployment: which framework it can reference at all,
what changes on the day somebody adds a second replica, the twelve settings with no safe default,
and how to run the suite.

### Supported target frameworks

**`net10.0`, every package, and that is a limit rather than a preference.** An MCP server on
net8.0 — the LTS supported until November 2026 — cannot reference `Boltway.ResourceServer` or
`Boltway.Mcp` at all. Not with warnings: at all. `docs/DESIGN.md` asked for `net8.0;net10.0` on the
resource-server half for exactly that reason, in exactly those words — *"the RS lands in the
customer's codebase and their TFM is not ours to choose"* — and it is not done.

What it would take, measured on 2026-08-23 against SDK 10.0.111 rather than assumed:

| | |
|---|---|
| the net8.0 targeting pack in CI | **not a blocker.** It restores from nuget.org, and an ASP.NET Core net8.0 library using `FrameworkReference` builds with no workflow change |
| `System.Buffers.Text.Base64Url` | **the blocker.** .NET 9 and later. `Boltway.OAuth.Primitives` wraps it, and compiling that assembly against net8.0 fails on all three call sites |
| `string.IndexOf(char, StringComparison)` | also .NET 9+, and `CA1307` is promoted to an error here, so `ResourceIdentifier` needs a conditional too |

So the work is a hand-written unpadded base64url behind a `#if`, in the primitive that encodes PKCE
verifiers, `jti` values and JWK thumbprints — where the padding rule is byte-exact and getting it
wrong is a PKCE mismatch on every request, with an error that mentions nothing about padding. That
is a decision about writing crypto-adjacent code, not a packaging chore.

The authorization server staying `net10.0` is fine either way: it is a deployable you run, not a
library that lands in somebody else's build.

---

### Before the second replica

**One replica is the configuration everything below is correct in.** Nothing here is a bug at *n* = 1
and every item changes meaning at *n* = 2, so this is the list to read on the day somebody scales the
deployment out — which is a day nobody plans as a protocol change.

The facts were already written down, each beside the thing it describes: `LoginThrottle` says a
second instance enforces twice its numbers, `CimdClientResolver` says everything it keeps is per
process, `ClientKeySource` says the same, and so on. Eleven files, each locally honest, and nowhere
to look on the day it matters — which is how the first draft of the table below came to be missing
`RecoveryThrottle`. A single-instance deployment makes the answer today *nothing to do*; the point
of the table is that the answer is written down before that changes.

| Per process | *n* replicas cost | What to do |
|---|---|---|
| **Client-assertion replay store**, when it is the in-memory one | **The property, not a bound.** Each replica holds its own set, so one captured assertion authenticates once *per replica* | Use `AddBoltwayPostgreSqlStores`. This is the only row where *n* > 1 breaks a security guarantee rather than loosening a budget, and startup cannot detect it — it checks that a store is registered, not that it is shared |
| `POST /login` throttle | *n* × the attempts before backoff, per account and per source | Accept, or put a shared limiter in front. Note `LoginThrottleOptions.ClientKey` if the proxy does not populate `RemoteIpAddress` |
| `/forgot` recovery throttle, when `PasswordRecoveryEnabled` is on | *n* × the reset mail one address can be made to receive — the abuse here is aimed at a person's mailbox rather than at this server | Accept, or front it. Off by default, so this row applies only to a deployment that turned the flow on |
| `/authorize`'s CIMD fetch budget and its negative-result breaker | *n* × the outbound fetches one `client_id` can provoke | Accept: the per-host limiter below is the bound that protects the stranger |
| `SafeHttpFetcher` per-host budget (60/min) | *n* × 60/min against any one origin | Accept, or front it. LESSONS #9's conduct point lives here |
| `ClientKeySource` cache and its unknown-`kid` refresh floor | *n* × the refetch rate against a client's `jwks_uri`; *n* independent staleness windows | Accept |
| `CimdClientResolver` cache | *n* × the fetches, and *n* windows in which a retired client document is still trusted | Accept |
| `JwksKeySource` cache (resource server) | *n* × the fetches against the authorization server's own JWKS | Accept |
| `UpstreamEndpointClient` per-host budget (federation) | *n* × the requests to an upstream identity provider | Accept |
| `AdminBff`'s in-memory `ITicketStore` | An operator is signed out whenever the load balancer moves them | Shared `ITicketStore`, or sticky sessions |

**Three things are not on this list because the production checklist already forces them**: durable
storage, a signing key shared between replicas, and a `RefreshTokenDerivationKey` that is stable
across instances. A per-process derivation key does not fail loudly — it makes the refresh grace
window work only when two racing requests land on the same node, which presents as flakiness.

---

### Production checklist

Twelve things, in the order they bite. Each is a decision a deployment makes once; none of them has
a default that is right for everyone, which is why none of them has one.

| | What to do | Why, and what it costs to skip |
|---|---|---|
| 1 | **Durable storage.** `AddBoltwayPostgreSqlStores`, and migrate as a deploy step | With the in-memory stores a restart loses every refresh token (users re-authorize), every consent record (users are asked again), and any authorization in flight. Two replicas share none of it. Not the SQLite one — it is a development provider and [the reason is above](#what-is-not-built-yet) |
| 2 | **A real signing key, with rotation.** Generate it outside the process, keep it across restarts, share it between replicas | `SigningKeyRing` models Pending → Active → Retiring: publish a key for at least `PublishLeadTime` (default 24h, floor 10 minutes) before it signs, and keep a retiring key published for at least one access-token lifetime after it stops. A key that signs before verifiers have seen its `kid` produces signature failures nobody diagnoses as a timing problem |
| 3 | **A durable replay store if you offer `private_key_jwt`** | `AddBoltwayPostgreSqlStores` registers one. The in-memory implementation is not a weaker version of it here the way it is for grants and consents — it is a per-process set, so *n* replicas admit *n* uses of one captured assertion, and nothing about that is visible from outside. Startup refuses the method with no store at all; it cannot tell a shared store from a per-process one |
| 4 | **A key source on every resource server, not a hand-filled list.** `JwksKeySource.CurrentKeys` assigned to `ProtectedResourceOptions.SigningKeySource`, or `AddJwksSigningKeys(issuer)` in an MCP connector | A host that fills `SigningKeys` by hand is a host whose rotation day is an outage, and item 2 guarantees there will be one. Keep `JwksKeySourceOptions.CacheLifetime` below the server's `PublishLeadTime` — the defaults, five minutes against a ten-minute floor, already are — and leave `AllowPrivateAddresses` clear on the client you hand it |
| 5 | **`RefreshTokenDerivationKey` stable across restarts and instances.** At least 32 bytes | Worth as much as every refresh token this server will ever issue, so store it where the signing keys live. A per-process key makes the refresh grace window work only when two racing requests land on the same node — which looks like flakiness rather than a bug |
| 6 | **TLS and HSTS** | The issuer must be `https`, path-less, and with no trailing slash. It is compared byte for byte by every client |
| 7 | **`ForwardedHeaders` behind a proxy** | So the scheme and client address are the real ones. The issuer itself is never derived from the request, so a misconfigured proxy will not corrupt it — but cookie `Secure` policy and logging both depend on getting this right |
| 8 | **Decide whether the per-process rate limits are enough**, and set `LoginThrottleOptions.ClientKey` if your proxy does not populate `RemoteIpAddress` | `/authorize`'s CIMD fetch and `POST /login` are bounded per process — `docs/DESIGN.md` §4.1, and [Before the second replica](#before-the-second-replica) for everything else that is per process. `/token` is not bounded at all. Without `ClientKey`, every user shares one per-source bucket and thirty attempts across all of them exhausts it |
| 9 | **`AllowPrivateAddresses` clear** | It disables the RFC 6890 special-use address check *entirely*, which turns `/authorize` into an unauthenticated port scanner. `AddCimdClientResolver` refuses to build such a fetcher outside `Development` — but measured, that refusal happens when the fetcher is first resolved, on the first `/authorize`, **not at startup**. The host binds and serves discovery first, then fails on the first client |
| 10 | **Name the meters, and alert on one of them.** `AuthorizationServerMetrics.MeterName`, `StorageMetrics.MeterName`, and on a resource server `ResourceServerMetrics.MeterName` | Nothing is published unless the host calls `AddMeter`, and an unnamed meter is not an error — it is silence that looks like a healthy system. The one alert to build first is `failed_open` on the revocation check, because `IntrospectionRevocationCheck` fails **open**: [the host README](hosts/Boltway.AuthorizationServer.Host/README.md#alerting-on-revocation) has the expression and the one `reason` that deserves its own alert rather than a threshold |
| 11 | **Run the doctor** against the configuration you would actually start with — `docker run --rm --env-file .env ghcr.io/<owner>/boltway-auth doctor`, or `ConfigurationDoctor.Run(options, keyRing)` hosting the library yourself | It prints every check rather than stopping at the first, exits non-zero on any `Fail`, and distinguishes `NotMeasured` from `Pass` — a check that could not run is never rendered green. `Warn` does not fail the exit code: telling "wrong" from "worth a look" is the job, and collapsing the two makes it a thing people stop running |
| 12 | **Check what your discovery document promises.** Every URL in it should answer | That is the one failure mode this project has paid for most often, and the reason N-06 is the rule cited most in this repository |

---

### Running the tests

```bash
./scripts/postgres.sh up          # once per machine boot
dotnet test Boltway.slnx
```

`Boltway.Storage.PostgreSql.Tests` needs a **real PostgreSQL server** and fails — it does not
skip — without one. That is the point: a storage suite that skips itself when the database is
missing is green in exactly the situation where it measured nothing, and PostgreSQL is what a
deployment runs. Skipping it would leave SQLite as the only relational implementation anyone ever
executed.

`postgres.sh up` gets you one either way:

| | |
|---|---|
| a Docker daemon answers | `postgres:17-alpine`, published on `127.0.0.1:5432`, same image and environment as the CI service container |
| no daemon | a native cluster — installs `postgresql-17` with apt (adding PGDG only if the distribution's own archive does not carry 17), creates the cluster if the package's postinst was blocked from doing so, starts it, and creates the login |

Both paths end at `Host=127.0.0.1;Port=5432;Username=boltway;Password=boltway`, which is
what the fixture defaults to and what CI configures. Point it somewhere else with
`BOLTWAY_TEST_POSTGRES`. `postgres.sh status` says which backend is in play and whether the
server answers; `postgres.sh down` stops it and keeps the data.

The login is `CREATEDB`, not superuser — the fixture makes a database per test class and needs
nothing more. The major version is pinned in one place at the top of the script and used for both
the image tag and the apt package, so local and CI cannot drift apart unnoticed.

---

## Layout

| Project | |
|---|---|
| `Boltway.OAuth.Primitives` | scopes, redirect matching, PKCE, error surfaces, ordinal identity types |
| `Boltway.OAuth.Tokens` | JWT minting, RFC 9068 validation parameters, JWKS, the key ring |
| `Boltway.OAuth.Net` | the one outbound HTTP client allowed to fetch a URL we do not control |
| `Boltway.AuthorizationServer.Abstractions` | the seams, with no ASP.NET Core dependency |
| `Boltway.AuthorizationServer` | the endpoints, the pipeline, CIMD, the metadata document |
| `Boltway.ResourceServer` | the MCP-side half: bearer gate and RFC 9728 metadata |
| `Boltway.Identity` | Argon2id password hashing, ULID subjects |
| `Boltway.Storage.InMemory` | the four stores, plus a user store — per process, so read *Before the second replica* |
| `Boltway.Storage.EntityFrameworkCore` | the relational implementation the two providers below share |
| `Boltway.Storage.Sqlite`, `Boltway.Storage.PostgreSql` | the two providers, with their own migrations |
| `Boltway.Federation.Oidc`, `Boltway.Federation.Google` | signing in against an upstream identity provider |
| `Boltway.Notifications`, `Boltway.Notifications.Smtp` | the notification seam and one implementation |
| `Boltway.Mcp` | the MCP-shaped half of a connector: tool-error semantics and the authentication seam, layered over the official MCP SDK |

That is `src/`, and it is not the whole tree. Three directories beside it are what most people
actually reach for first, and this table listed none of them:

| Directory | |
|---|---|
| `hosts/` | two things you can run rather than reference. `Boltway.AuthorizationServer.Host` is the authorization server as one image for every deployment, configured entirely by environment; `Boltway.AdminBff` is the admin UI, and it is an OAuth client rather than a page on the server because `N-17` forbids reaching an admin endpoint with a cookie. Each has a `Dockerfile` and its own README. Neither packs |
| `testing/` | the contracts, shipped so a deployment runs the same suite we do. `Boltway.Interaction.Testing` for a replaced layout or renderer, `Boltway.Storage.Testing` for a store you wrote. A seam worth replacing is a seam worth shipping a contract for |
| `samples/` | the smallest pair that completes a whole flow, plus `drive-flow.sh`, which walks it end to end from the `401` to a refreshed token |

`Boltway.ResourceServer` does not reference `Boltway.AuthorizationServer`, and that absence
is the design: the two are separate deployables.

Everything lives in one tree with one solution, and that is load-bearing rather than tidy.
`Boltway.Mcp` spent its life in a second tree with a solution of its own, which meant the
architecture rules in `tests/Boltway.Architecture.Tests` never walked it — they only ever scanned
`src/`. Folding the trees together turned two of those rules red on the first run, one of them
because the MCP layer was fetching a key set over the network outside the guarded HTTP client every
other outbound fetch in the repository goes through. A project outside the scan is not a project the
scan approved, and nothing anywhere said so.

Further reading: [`docs/DESIGN.md`](docs/DESIGN.md), [`spec/REQUIREMENTS.md`](spec/REQUIREMENTS.md).

## Roadmap

[`ROADMAP.md`](ROADMAP.md) is what is missing, measured against what an authorization server gets
judged on. It is a gap list rather than a plan with dates, and it says so: nothing in it is
committed to, and the point of writing it down is that a reader can tell an absence somebody chose
from one nobody has looked at.

[What is not built yet](#what-is-not-built-yet) above is the narrower version, closer to this code.

## Versions and changes

`0.x`, and at `0.x` anything may break. What that means concretely, what `1.0` will promise, and
which assemblies are the stable seam are in [`VERSIONING.md`](VERSIONING.md); what actually changed
in each version, including the breaks, is in [`CHANGELOG.md`](CHANGELOG.md).

Both are linked from here rather than only from the repository root because this file is the readme
packed into every one of the eighteen packages — somebody who arrived from nuget.org has no other
route to them.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).

Apache rather than MIT for the patent grant: this is protocol code, and a contributor licensing
their patents alongside their copyright is the difference that matters to anyone adopting it inside
a company. Every dependency is MIT or Apache-2.0 — `Directory.Packages.props` says why two obvious
candidates are deliberately absent.

Security reports go to [`SECURITY.md`](SECURITY.md), not to the issue tracker.
