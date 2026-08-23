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

**What it is.** The authorization code flow with PKCE, refresh tokens with derived rotation, RFC 8707
resource indicators, RFC 8414 and OIDC discovery, RFC 9728 protected-resource metadata, and CIMD
(Client ID Metadata Document) client identification — so a client that has never been registered
here can connect by naming the URL its metadata lives at.

**What it is not.** Not a general-purpose identity provider, and not a replacement for Entra ID or
Auth0. There is no user registration flow and no multi-tenancy. Rate limiting exists on two paths
only and is per process — see below. Several protocol endpoints are deliberately absent; several
others simply have not been built. The difference is spelled out below, because a list that blurs
the two is worse than no list.

This paragraph used to say there was no admin UI and no durable storage implementation, and both had
been built by the time anybody read it. That is the failure *What is built and off by default*
exists to catch, arriving at the one place every reader starts: `hosts/Boltway.AdminBff` is an admin
UI with its own image, and `Boltway.Storage.PostgreSql` is a durable store with its own migrations.
Account management is still off by default — an HTTP API, a CLI and, behind separate flags, pages —
and that part was true.

---

## Quickstart

The smallest host that starts and serves discovery. Measured at **45 lines**, of which 12 are
`using` directives.

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

To run something that completes a whole flow instead:

```bash
dotnet run --project samples/Boltway.Sample.AuthorizationServer   # terminal 1
dotnet run --project samples/Boltway.Sample.ResourceServer        # terminal 2
./samples/drive-flow.sh                                                # terminal 3
```

See [`samples/README.md`](samples/README.md).

---

## The services a deployment must supply

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

## Changing the sign-in and consent pages

Three tiers. **Take the lowest one that does what you need**, because each step up hands you a
requirement you then own.

The consent page is governed by N-14, which is a MUST in the MCP specification: the host of the
`client_id` URL leads, the self-asserted `client_name` is subordinate to it and marked unverified,
the requested redirect host is shown, and a redirect landing on the user's own machine carries an
explicit warning. A page missing any of that looks finished.

**Tier 1 — theme.** No code.

```csharp
o.Interaction.ProductName = "Northwind";              // goes in <title>, never in a heading
o.Interaction.LogoPath = "/img/northwind.svg";
o.Interaction.StylesheetPaths.Add("/css/authorization.css");
```

Serve the files yourself — `app.UseStaticFiles()` and a folder under `wwwroot`. Every path must be
an absolute path **on this origin**; a CDN URL is refused at startup, because these pages send
`default-src 'self'` and the browser would refuse it silently at render time instead. Nothing here
can reach the part of the page N-14 governs.

**Tier 2 — layout.** Your document, the server's page inside it.

```csharp
services.AddSingleton<IInteractionLayout, NorthwindLayout>();   // BEFORE AddBoltwayAuthorizationServer
```

`Wrap(InteractionPage page)` returns the whole document and must contain `page.Body` **verbatim and
unencoded**. That body is the server's markup, with every N-14 field already in the required order,
so a layout has exactly one way to lose a requirement — and the renderer checks that one condition
on every render and throws rather than serving a consent page with no consent on it. Header, footer,
navigation, classes and language are all yours.

**Inline script or style in a layout** needs a nonce, which is off by default because the shipped
pages have none:

```csharp
o.Interaction.UseContentSecurityPolicyNonce = true;
```

Then branch on it — never assume it, or the page breaks when someone turns it off:

```csharp
if (page.Nonce is not null) sb.Append($"<script nonce=\"{page.Nonce}\">…</script>");
```

The policy gains `script-src 'self' 'nonce-…'` and `style-src 'self' 'nonce-…'` — `'self'` stays in
both, so your stylesheet keeps loading. `frame-ancestors`, `base-uri`, `object-src` and
`form-action` are untouched, and nothing anywhere adds `'unsafe-inline'` or `'unsafe-eval'`. Two
things a nonce cannot rescue: a `style="…"` attribute and an `onclick=` handler. Those need
`'unsafe-hashes'`, which is not offered — use a class and an external file.

Most dynamic UI needs none of this. `default-src 'self'` already allows `<script src="/js/app.js">`
from your own origin, so a compiled bundle or a self-hosted htmx works with the policy unchanged.

**Tier 3 — renderer.** The markup itself.

```csharp
services.AddSingleton<IInteractionRenderer, NorthwindRenderer>();
```

Total control, and you now own N-14, A-11 and A-14 in full. Two things that are easy to miss and
break silently: `POST /consent` reads `form["decision"]` and compares it to `"approve"` ordinally,
so a control named anything else ships a page whose Approve button denies; and `POST /login` reads
`username` and `password`.

**Whichever of the last two you take, run the contract.** `Boltway.Interaction.Testing` ships as
a package for this — derive `InteractionLayoutContract` or `InteractionRendererContract`, override
one factory method, and get the requirements asserted against your own output, including that
nothing on the page is something the CSP will refuse.

```csharp
public sealed class NorthwindRendererTests : InteractionRendererContract
{
    protected override IInteractionRenderer NewRenderer() => new NorthwindRenderer();
}
```

Both seams use `TryAdd`, so a registration made **before** `AddBoltwayAuthorizationServer`
wins. Registering after it does nothing, silently.

---

## What is deliberately not implemented

These are absent on purpose. The rule is N-06 — never advertise a capability you do not have — and
each of these was measured returning `404` while the discovery document promised it.

`/revoke` used to head this list and no longer does: it is implemented, and the section below has
it. That closes the set — `/userinfo`, `/logout`, `/introspect` and `/revoke` were the four endpoints
this server advertised and did not serve, and each one now routes and advertises from a single flag.
`MetadataHonestyTests.The_sweep_catches_an_endpoint_that_is_advertised_but_not_routed` used the last
of those flags as its control and had to be rebuilt when it ran out; it now serves a deliberately
broken document from a stub rather than pointing at a real flag, which is what that test's own note
said to do when this day came.

`private_key_jwt` has left this list too, for the section below. It sat here on the reasoning that
omitting it was survivable while every client we serve offers `none` beside it — a **measurement,
not a rule**, and one that had already moved once. The fixture that watches it is
`spec/cimd-live-2026-08-17.json`; the implementation is what makes the measurement stop mattering.

- **The jwt-bearer assertion grant** (`urn:ietf:params:oauth:grant-type:jwt-bearer`). It and
  `client_credentials` were both once accepted by configuration with no handler behind them.
  `KnownGrantTypes` now lists exactly the grants `TokenEndpoint`'s dispatch has an arm for, so
  enabling a name with nothing behind it is a startup failure rather than a runtime surprise, and
  `MetadataHonestyTests.Every_advertised_grant_has_a_handler` drives every listed name through
  `/token`.
  `client_credentials` has since grown an arm and moved to the section below; this one has not.
- **A second `authorization_servers` entry on the resource server.** RFC 9728 permits an array;
  Claude reads only the first. A second entry would be advertised and then refused.
- **Persisting a CIMD client.** A hundred sequential CIMD connections leave the client table
  unchanged, by design. The cache is in memory, bounded and expiring.

## What is built and off by default

**This section exists because its absence made the list above wrong.** Two categories — absent on
purpose, and absent because nobody has written it — have no room for *present, and not switched on*,
so a capability that grew a default got filed as one of the two and stayed there. `client_credentials`
sat under "deliberately not implemented" after it was implemented. Under-claiming is the safe
direction to be wrong in, which is exactly why it survived: nothing breaks, and nobody looks.

Off is the right default for every row here. The point is that "off" and "absent" are different
words.

| Capability | Turned on by | Why off |
|---|---|---|
| `client_credentials` grant | adding the name to `GrantTypesSupported` | `Token/ClientCredentialsGrant.cs`, and an arm in `TokenEndpoint`'s dispatch. Narrowed on purpose: the client names an **owner** and the token is issued for that account. A client acting purely for itself is refused with `ReasonCode.ClientHasNoOwner`, because a `sub` that is a client id resolves against no account, so roles and attribution have nothing to read |
| `/introspect` | `IntrospectionEnabled` | it answers questions about somebody else's token, so an unnecessary one is a surface that exists to be probed |
| `private_key_jwt` client authentication | adding `ClientAuthMethod.PrivateKeyJwt` to `TokenEndpointAuthMethods` | RFC 7523. The client signs an assertion with its own key and this server verifies it against the `jwks_uri` in the client's metadata — an outbound fetch to a URL the client chose, which is why it goes through the guarded fetcher and why enabling it is a decision rather than a default. Both vendors currently offer `none` beside it and this server prefers `none`, so switching it on changes nothing for them; it changes what a client that offers **only** assertions gets. Startup refuses the method without an `IClientAssertionReplayStore` |
| `/revoke` | `RevocationEnabled` | RFC 7009. Confidential clients only — `none` is never advertised for it, because an endpoint that accepted an unauthenticated caller would revoke on anyone's say-so. Revoking either token type revokes the grant behind it: the denylist is keyed on the grant and access tokens are signed rather than stored, so "revoke this access token and leave the session running" is not a state this server can represent |
| `/logout` | `EndSessionEnabled` | routed by `MapInteraction`, not by `MapBoltwayAuthorizationServer` — it is a page |
| Administration API and CLI | `AdministrationEnabled` | bearer-only, and an architecture test over the routing table refuses a cookie principal on it (N-17) |
| Self-service API (`/account/*`) | `SelfServiceEnabled` | bearer-only |
| Self-service pages (`/me`, `/me/password`, `/me/sessions`, `/me/consents`) | `SelfServicePagesEnabled` | cookie-authenticated with antiforgery, and refuses a bearer |
| Password reset by email (`/forgot`) | `PasswordRecoveryEnabled` | startup refuses it without an `INotificationSender`; the sign-in page draws the link only when it is on, because a dead link is worst for the one person least able to recover from it |
| Access-token revocation actually taking effect | `IAccessTokenRevocationCheck` on the resource server, plus `/introspect` here | signed tokens are not looked up, so without it a revoked grant lags by one access-token lifetime |
| Durable storage | `AddBoltwayPostgreSqlStores(...)` instead of the in-memory call | see the next section for the sample's wiring and for why not the SQLite one |

`/userinfo` is **on** by default and so is not in this table. It is the one endpoint here that
discloses only what the caller's own access token already carries.

## What is simply not built yet

Not decisions. Gaps.

- **Dynamic client registration (RFC 7591).** `ClientRegistrationProfile.DynamicRegistration` exists
  and **selecting it is a startup failure**, with a message naming CIMD as the way out. Nothing
  routes `/register`.

  This bullet used to say the profile made the document advertise `registration_endpoint` while both
  methods on that path answered `404` — measured, and true when written. Validation refuses the
  profile now, so the document is never built and the 404 is unreachable. The correction matters
  because the two are different instructions: "do not select this" versus "you cannot". Refusing at
  startup rather than quietly not advertising is deliberate — a deployment that asked for dynamic
  registration wants it, and publishing a document without it and starting anyway answers a
  different question than the one the operator asked.
- **Durable storage is built but not wired into the sample.** `Boltway.Storage.Sqlite` and
  `Boltway.Storage.PostgreSql` implement all five stores over
  `Boltway.Storage.EntityFrameworkCore`, each with its own migrations, and both run the shared
  contract suite — the PostgreSQL one against a live server rather than a container-less skip. Call
  `AddBoltwaySqliteStores(connectionString)` or
  `AddBoltwayPostgreSqlStores(connectionString)` instead of `AddBoltwayInMemoryStores()`,
  and run `dotnet ef database update` as a deploy step: neither call creates or migrates the
  database, deliberately. `samples/` still wires the in-memory stores, so the sample loses everything
  on restart. **PostgreSQL is the one to deploy** — see the next item for what SQLite does not do.
- **SQLite does not meet the concurrent-redemption requirement.** It is a supported provider for
  development and is not one for a deployment. Under concurrent load
  `Redeeming_many_times_in_parallel_still_succeeds_exactly_once` intermittently fails with
  `SQLite Error 1: 'cannot start a transaction within a transaction'` — reproducible in roughly a
  third of runs of the storage contract, one worker in sixteen, and **undiagnosed**. What is known,
  what was wrongly recorded as ruled out, and what is now measured is on
  `SqliteRelationalStoreBehavior`. Pooling is off for a SQLite file database because a pooled handle
  is the one poisoning route that has been demonstrated; that removes a route, not the cause, and is
  not recorded as a fix. PostgreSQL is unaffected and runs the same contract.
- **Rate limiting beyond `/authorize`'s CIMD fetch and `POST /login`.** Those two are bounded (X-31,
  and `docs/DESIGN.md` §4.1 gives the numbers and the measurements). Nothing else is: there is no
  ASP.NET Core rate limiter, no per-subject budget, and no load shedding at `/token`. **And every
  limit that does exist is per process** — each instance counts only its own traffic, so a fleet of
  *n* replicas admits *n* times each number and a caller spread across the fleet is counted
  separately by each. They bound what one instance can be made to spend; they are not an account
  lockout and not a fleet-wide quota. Put a shared limiter in front if you need one, and read
  [Before the second replica](#before-the-second-replica) first — the limiters are one row of a
  longer list, and one of the others is a security property rather than a budget.
- **A kid-miss trigger on the resource server's key source.** `Boltway.OAuth.Net.JwksKeySource`
  closes the gap this entry used to describe — it fetches the authorization server's discovery
  document, checks its `issuer`, reads `jwks_uri`, and refreshes in the background as the snapshot
  ages, so a rotation no longer stops a resource server dead. What it does **not** do is react to a
  token naming a `kid` it has not seen: `ProtectedResourceOptions.SigningKeySource` is synchronous
  and on the request path, so there is nowhere to await a fetch, and `CurrentKeys` deliberately
  returns the stale snapshot rather than blocking.

  That is survivable because of `PublishLeadTime`, not because it does not matter. A key ring
  publishes a key at least `PublishLeadTime` before it signs — 24 hours by default, floor ten minutes
  — and `CacheLifetime` defaults to five, so an ordinary rotation is seen long before it is used.
  **An emergency rotation that skips the lead time is the case with no cover**, and there the first
  token signed by the new key is rejected and the ones after the next refresh are not.

  Assign `JwksKeySource.CurrentKeys` to `SigningKeySource`, not to `SigningKeys` — the list is
  mutable state a request enumerates while a refresher writes it, which is a rotation-day failure of
  its own. `samples/Boltway.Sample.ResourceServer` wires the source and refreshes once at
  startup so the first request does not arrive at an empty set. In an MCP connector,
  `services.AddJwksSigningKeys(issuer)` from `Boltway.Mcp` does both and refuses to start
  without keys.
- **Upstream identity providers other than one.** Federated sign-in ships —
  `Boltway.Federation.Oidc` is a generic OpenID Connect relying party and
  `Boltway.Federation.Google` is configuration over it — but only one has been driven against
  a live provider's real behaviour, and that one is a fake this repository hosts. Nothing here has
  talked to Google, Entra or Okta; the discovery form probed is OIDC Discovery's append spelling
  only, and an upstream that omits the `typ` header on its ID tokens is refused. D-10's
  `sub`-disambiguation concern is unchanged: a second issuer is the point at which it starts to
  matter.
- **Self-service, which is built.** Two surfaces: the API (`/account/*`, `E-33`–`E-38`, behind
  `SelfServiceEnabled`, bearer-only) and the pages (`/me`, `/me/password`, `/me/sessions`,
  `/me/consents`, `E-46`, behind `SelfServicePagesEnabled`, cookie-authenticated with antiforgery
  and refusing a bearer). Between them a person can read their own account, change their own
  password with the current one, see and end their own sessions, and see and withdraw what they have
  approved.

  The password-reset-by-email flow is built too — `E-39`–`E-44`, behind `PasswordRecoveryEnabled`,
  which startup refuses without an `INotificationSender`. The sign-in page links to it, and the link
  is drawn only when that flag is on, because `/forgot` is not routed otherwise and a dead link is
  worst for the one person least able to recover from it.

  This entry used to name two gaps and both are closed. The consents page is the one above. The
  missing `forgot password` link needed a page rather than a link: `E-39` answers JSON, so pointing
  a browser at it would have shown somebody a line of JSON — `/forgot` is the page, and it calls the
  same service in process rather than posting to the endpoint.

  The two *inconsistencies* this entry used to name are closed. `DisabledAt` was enforced on both
  sign-in paths and settable by nothing; `email_verified` was emitted in every token and set to true
  by nothing. Both have a control now — `disable`/`enable` and `set-email --verified` — and the
  second is an operator asserting the address rather than this server checking it, which is stated
  where it is set.

  What is built: `RealmId` through every lookup; one `UserAdministration` behind both callers; seven
  CLI verbs (`new-user`, `set-role`, `set-password`, `disable`/`enable`, `set-email`,
  `revoke-sessions`, `anonymise`); `/admin/users` list-create-read-patch, password reset, session
  revocation and anonymise, plus `/admin/audit`, all bearer-only and refusing a cookie principal by
  an architecture test over the routing table; and an append-only administrative audit log.

  Two things landed narrower than the design and say so in code, spec and doc rather than only
  here. The audit entry is written **immediately after** the change rather than in the same
  transaction, because every relational store here creates its own `DbContext` per call. And
  revoking sessions kills refresh chains, and reaches **access tokens already issued** only where a
  resource server asks. Those tokens are signed rather than looked up, so nothing about them changes
  when a grant is revoked; `IGrantStore.IsRevokedAsync` is the denylist, `/introspect` is how a
  resource server reads it, and `IAccessTokenRevocationCheck` in `Boltway.ResourceServer` is
  what calls it on the way in. All three are off unless a deployment turns them on, and a deployment
  that has not is back to one access-token lifetime of lag. Designed in
  [`docs/USER-MANAGEMENT.md`](./docs/USER-MANAGEMENT.md), requirements in `spec/REQUIREMENTS.md`
  §11.
- **Pairwise subject identifiers.** Not built, and now with no seam pretending otherwise.
  `ISubjectIdentifierService` used to sit here as "exists and nothing on the token path calls it",
  which was true and was the wrong thing to keep: its signature took a `UserAccount` and a
  `ClientRecord`, while the token path carries a `SubjectId` off the grant and never loads an
  account. Wiring it would have meant a store read per token issuance, so it would not have saved
  the hunt through call sites it existed to prevent — it was a seam that did not fit its own seam.
  Deleted: a seam nothing can call is a claim that a decision has been made, and deleting it is how
  the claim stops being made.
  Pairwise, if ever wanted, is `(subject, client)` threaded through `TokenIssuer` and
  `UserInfoEndpoint` plus a salt that is permanent once set.
- **Multi-target for the resource server package.** `DESIGN.md` calls for `net8.0;net10.0`. It is
  `net10.0` only.

---

## Before the second replica

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

## Production checklist

- [ ] **Durable storage.** With the in-memory stores, a restart loses every refresh token (users
      re-authorize), every consent record (users are asked again), and any authorization in flight.
      Two replicas share none of it. Swap in `AddBoltwayPostgreSqlStores` and migrate as a
      deploy step — see above. Not the SQLite one: it is a development provider and the reason is
      two items up.
- [ ] **A real signing key, with rotation.** Generate it outside the process, keep it across
      restarts, share it between replicas. `SigningKeyRing` models Pending → Active → Retiring:
      publish a key for at least `PublishLeadTime` (default 24h, floor 10 minutes) before it signs,
      and keep a retiring key published for at least one access-token lifetime after it stops. A key
      that signs before verifiers have seen its `kid` produces signature failures nobody diagnoses as
      a timing problem.
- [ ] **A durable replay store if you offer `private_key_jwt`.** `AddBoltwayPostgreSqlStores`
      registers one. The in-memory implementation is not a weaker version of it here, the way it is
      for grants and consents — it is a per-process set, so *n* replicas admit *n* uses of one
      captured assertion, and nothing about that is visible from outside. Startup refuses the method
      with no store at all; it cannot tell a shared store from a per-process one.
- [ ] **A key source on every resource server, not a hand-filled list.**
      `JwksKeySource.CurrentKeys` assigned to `ProtectedResourceOptions.SigningKeySource`, or
      `AddJwksSigningKeys(issuer)` if you are hosting an MCP connector, which wires that and primes
      it at startup. A host that fills `SigningKeys` by hand is a host whose rotation day is an
      outage, and the item above guarantees there will be one. Keep `JwksKeySourceOptions.CacheLifetime` below the authorization
      server's `PublishLeadTime` — the defaults, five minutes against a ten-minute floor, already
      are — and leave `AllowPrivateAddresses` clear on the client you hand it.
- [ ] **`RefreshTokenDerivationKey` stable across restarts and instances.** At least 32 bytes, and
      worth as much as every refresh token this server will ever issue, so store it where the signing
      keys live. A per-process key makes the refresh grace window work only when two racing requests
      land on the same node — which looks like flakiness rather than a bug.
- [ ] **TLS and HSTS.** The issuer must be `https`, path-less, and with no trailing slash — it is
      compared byte for byte by every client.
- [ ] **`ForwardedHeaders` behind a proxy**, so the scheme and client address are the real ones. The
      issuer itself is never derived from the request, so a misconfigured proxy will not corrupt it —
      but cookie `Secure` policy and logging both depend on getting this right.
- [ ] **Rate limiting.** `/authorize`'s CIMD fetch and `POST /login` are bounded per process — see
      `docs/DESIGN.md` §4.1, and **[Before the second replica](#before-the-second-replica)** for
      every other thing that is per process and what each costs at *n* > 1. `/token` is not bounded
      at all. Two things need a decision at deploy
      time: whether the per-process bounds are enough for the number of replicas you run, and
      `LoginThrottleOptions.ClientKey` if your proxy does not populate `RemoteIpAddress` — without
      it every user shares one per-source bucket and thirty attempts across all of them exhausts it.
- [ ] **`AllowPrivateAddresses` clear.** It disables the RFC 6890 special-use address check
      *entirely*, which turns `/authorize` into an unauthenticated port scanner.
      `AddCimdClientResolver` refuses to build such a fetcher outside `Development` — but measured,
      that refusal happens when the fetcher is first resolved, on the first `/authorize`, **not at
      startup**. The host binds and serves discovery first, then fails on the first client.
- [ ] **Name the meters, and alert on one of them.** Nothing here is published unless the host calls
      `AddMeter`, and an unnamed meter is not an error — it is silence that looks like a healthy
      system. There are three: `AuthorizationServerMetrics.MeterName`, `StorageMetrics.MeterName`,
      and, on a resource server, `ResourceServerMetrics.MeterName`.

      The last one carries the number this checklist would otherwise have no way to ask for.
      `IntrospectionRevocationCheck` **fails open** — when the authorization server cannot be
      reached, the request is allowed through and a warning is logged. That is deliberate, and it
      means revocation silently stops working for as long as the two cannot talk. Alert on
      `boltway.resource.revocation.check` where `outcome="failed_open"`, as a fraction of the
      decisions that actually asked:

      ```
      failed_open / (live + revoked + failed_open)
      ```

      `outcome="cached"` is excluded on purpose — it is a hit rate, and dividing by it makes the
      number move with traffic rather than with reliability. One `reason` deserves its own alert
      rather than a threshold: `credential_rejected` is this resource server's own secret being
      wrong, it never recovers on its own, and it presents as revocation quietly doing nothing
      forever.
- [ ] **Run the doctor.** `ConfigurationDoctor.Run(options, keyRing)` reports what is legal but
      wrong, and distinguishes `NotMeasured` from `Pass`.
- [ ] **Check what your discovery document promises.** Every URL in it should answer. That is the one
      failure mode this project has paid for most often.

---

## Running the tests

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

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).

Apache rather than MIT for the patent grant: this is protocol code, and a contributor licensing
their patents alongside their copyright is the difference that matters to anyone adopting it inside
a company. Every dependency is MIT or Apache-2.0 — `Directory.Packages.props` says why two obvious
candidates are deliberately absent.

Security reports go to [`SECURITY.md`](SECURITY.md), not to the issue tracker.
