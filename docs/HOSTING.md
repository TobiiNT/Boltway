# Hosting the authorization server

The authorization server is a library, so a deployment writes its own `Program.cs`. This is that
file: the smallest one that starts, every service you have to supply, and the extra call for signing
people in against an upstream identity provider.

Prefer not to write it at all? [`hosts/Boltway.AuthorizationServer.Host`](../hosts/Boltway.AuthorizationServer.Host/README.md)
is this same library as one image, configured entirely by environment.

Split out of the root README, which was spending a third of its length on a subject most readers
reach on their second day.

- [The smallest host that starts](#the-smallest-host-that-starts)
- [The services a deployment must supply](#the-services-a-deployment-must-supply)
- [Signing in through an upstream provider](#signing-in-through-an-upstream-provider)
- Theming the pages: [`INTERACTION-PAGES.md`](INTERACTION-PAGES.md)
- Replacing the English text: [`LOCALIZATION.md`](LOCALIZATION.md)

---

## The smallest host that starts

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

## Signing in through an upstream provider

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
