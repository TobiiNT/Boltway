// A runnable Boltway authorization server.
//
// It is a development sample. Five things in it are deliberately not what a deployment does — the
// signing key, the stores, the refresh derivation key, the loopback exemption for CIMD fetches, and
// the seeded user — and each is marked DEV: below with what the real answer is. Nothing here is
// production-ready, and the point of saying so at each site rather than once at the top is that a
// reader who copies one block out of context still sees it.
//
//   dotnet run --project samples/Boltway.Sample.AuthorizationServer
//
// See samples/README.md for how to drive a whole flow with curl, and ../README.md for what every
// service below is for.

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Interaction;
using Boltway.AuthorizationServer.Resources;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;

const string Issuer = "https://localhost:7443";
const string McpResource = "https://localhost:7444/mcp";
const string DemoClientPath = "/clients/demo-cli";

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls(Issuer);

// ─────────────────────────────────────────────────────────────────────────────
// Signing keys
// ─────────────────────────────────────────────────────────────────────────────

// DEV: generated in memory at startup, so every restart invalidates every token this process
// issued and a second replica would sign with a key the first one's clients have never fetched.
// A deployment loads a key from a KMS, an HSM or a key vault, keeps it across restarts, and shares
// it between replicas. SigningKeyRing models the three-phase rotation that needs (Pending →
// Active → Retiring); this ring has exactly one key and never rotates, which is the one thing a
// sample can honestly show about rotation: nothing.
var devKey = new SigningKeyHandle("dev-1", SigningAlgorithm.RS256, new RsaSecurityKey(RSA.Create(2048)));
var startedAt = TimeProvider.System.GetUtcNow();

builder.Services.AddSingleton(new SigningKeyRing(
[
    new ManagedSigningKey(devKey, SigningKeyState.Active, startedAt, startedAt),
]));

// ─────────────────────────────────────────────────────────────────────────────
// The seams MapBoltwayAuthorizationServer requires
// ─────────────────────────────────────────────────────────────────────────────

// DEV: everything this call registers is in memory. Refresh tokens, consent records and any
// authorization in flight are lost on restart, and two replicas share none of it.
//
// There are two durable alternatives now, and this sample deliberately does not use either:
// AddBoltwaySqliteStores(connectionString) and AddBoltwayPostgreSqlStores(connectionString)
// register the same five stores over EF Core. Neither creates or migrates the database — that is a
// `dotnet ef database update` deploy step — and a sample that needed one before it would run is a
// sample nobody runs. Swap the line below for one of those when persistence matters.
builder.Services.AddBoltwayInMemoryStores();

// Not part of AddBoltwayInMemoryStores — it registers the four grant/consent stores only.
// Users are a separate decision because a deployment that authenticates against its own directory
// implements IUserStore against that and never uses this one.
builder.Services.AddSingleton<IUserStore, InMemoryUserStore>();
builder.Services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();

// CookieUserSession reads HttpContext.User, so it needs the accessor and it needs cookie
// authentication configured. It is the read half only: signing a user in is IUserSignIn's job,
// and the server registers CookieUserSignIn itself.
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserSession, CookieUserSession>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        // Lax, not Strict. The browser reaches /authorize by a top-level cross-site navigation
        // from claude.ai or chatgpt.com, and a Strict cookie is not sent on that navigation — so
        // every user would look signed out on every connect. (The antiforgery cookie the server
        // registers stays Strict; it is only ever needed on a same-site form POST.)
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.HttpOnly = true;
    });

// Which resources this server will issue tokens for, and what each one's scopes are. Left with the
// default requireResourceParameter: true, so an /authorize request must name a resource — with one
// resource registered the registry could default to it, and the point of not doing that here is
// that the sample exercises the RFC 8707 path a real MCP client takes.
builder.Services.AddSingleton<IResourceRegistry>(ConfiguredResourceRegistry.Create(
    new Dictionary<string, (string Name, ScopeSet Scopes)>(StringComparer.Ordinal)
    {
        [McpResource] = ("Sample MCP server", ParseScopes("stories.read")),
    }));

// The CIMD resolver fetches the client's metadata document over HTTP, and its fetcher refuses
// loopback and private addresses (RFC 6890) because /authorize would otherwise be an
// unauthenticated port scanner. This sample serves its demo client's document from itself, on
// localhost, so it has to lift that check — which AddCimdClientResolver permits only when
// IHostEnvironment.IsDevelopment().
//
// The `if` is load-bearing, and this is the measurement rather than caution. Registering these
// options unconditionally and starting with ASPNETCORE_ENVIRONMENT=Production does NOT fail at
// startup: the host binds, logs "Now listening on", and serves both discovery documents. The guard
// lives inside the ISafeHttpFetcher factory, which nothing resolves until the first /authorize —
// so the refusal arrives as a server_error on the first real client instead of at deploy time.
//
// DEV: a deployment does not register this at all. Real clients publish their documents on the
// public internet (https://claude.ai/oauth/mcp-oauth-client-metadata), which needs no exception.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton(new SafeHttpFetcherOptions { AllowPrivateAddresses = true });
}

builder.Services.AddBoltwayAuthorizationServer(options =>
{
    options.Issuer = Issuer;

    // openid and offline_access are both required by validation, for reasons worth repeating:
    // this server publishes an OpenID Provider metadata document, and a client asks for a refresh
    // token only when offline_access is advertised.
    options.ScopesSupported.Add("openid");
    options.ScopesSupported.Add("offline_access");
    options.ScopesSupported.Add("stories.read");

    // Shown on the consent page verbatim — the page never derives text by parsing a scope name.
    // Omitting one is not an error: validation collects it into ScopesWithoutDescriptions for the
    // doctor to report, and the page falls back to the raw scope plus a note that none is set.
    options.ScopeDescriptions["openid"] = "Confirm who you are.";
    options.ScopeDescriptions["offline_access"] = "Stay connected without asking you again.";
    options.ScopeDescriptions["stories.read"] = "Read your stories.";

    // DEV: 32 random bytes per process. Refresh tokens are derived from this, so a restart or a
    // second replica computes different successors and every outstanding refresh token stops
    // working. It must be stable across restarts and shared between instances, and it is worth as
    // much as every refresh token this server will ever issue — so it belongs wherever the signing
    // keys live, not in a config file.
    options.RefreshTokenDerivationKey = RandomNumberGenerator.GetBytes(32);
});

var app = builder.Build();

// Populates HttpContext.User from the cookie, which is where CookieUserSession reads it.
//
// Explicit, and NOT load-bearing here: measured by deleting it, the whole flow still completes,
// because WebApplication inserts the authentication middleware itself once authentication services
// are registered. It is written out because a host that assembles its own pipeline gets no such
// help, and because a reader should be able to see where in the order this happens rather than
// infer that it happens at all.
app.UseAuthentication();

app.MapBoltwayAuthorizationServer();

// ─────────────────────────────────────────────────────────────────────────────
// A client, with no registration step
// ─────────────────────────────────────────────────────────────────────────────

// This is the product's central claim in one endpoint: nothing here writes to a client table, no
// administrator imports anything, and the server has never seen this client before the first
// authorization request names it. The client_id IS this URL, and the document at it is the
// registration.
//
// Served from the sample only so it needs no internet. In the field the document lives wherever
// the client's vendor publishes it.
app.MapGet(DemoClientPath, () => Results.Content(
    new JsonObject
    {
        // CIMD §4: the document must name the URL it was fetched from, compared as a raw string.
        // That self-reference is the whole security model — without it, anyone who can host a JSON
        // file could publish a document claiming any client_id.
        ["client_id"] = Issuer + DemoClientPath,
        ["client_name"] = "Boltway sample CLI",

        // A loopback redirect (RFC 8252 §7.3), matched ignoring the port. https redirect URIs would
        // additionally have to be same-origin with the client_id; loopback ones resolve on the
        // user's own machine and have no web origin to compare against.
        ["redirect_uris"] = new JsonArray("http://127.0.0.1:5099/callback"),
        ["grant_types"] = new JsonArray("authorization_code", "refresh_token"),
        ["response_types"] = new JsonArray("code"),

        // A public client. CIMD §4.1 forbids every shared-secret method, so this or private_key_jwt
        // are the only two a document can declare — and private_key_jwt is not implemented here.
        ["token_endpoint_auth_method"] = "none",
    }.ToJsonString(),
    // Must be JSON: the resolver refuses a document served as anything else.
    "application/json"));

// ─────────────────────────────────────────────────────────────────────────────
// A user to sign in as
// ─────────────────────────────────────────────────────────────────────────────

// DEV: seeded in code, with the password in the source. A deployment has a registration flow, or
// an existing directory behind its own IUserStore.
await SeedDemoUserAsync(app.Services);

await app.RunAsync();

static ScopeSet ParseScopes(params string[] names)
{
    if (!ScopeSet.TryParse(string.Join(' ', names), out var parsed, out var error))
    {
        throw new InvalidOperationException(error);
    }

    return parsed;
}

static async Task SeedDemoUserAsync(IServiceProvider services)
{
    var users = services.GetRequiredService<IUserStore>();
    var hasher = services.GetRequiredService<IPasswordHasher>();

    // A ULID, minted by the shipped factory rather than chosen. A-18: the sub this server emits
    // needs no sanitising as a path segment, filename or column value, and that is a property of
    // what mints it.
    var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

    await users.StoreAsync(
        new UserAccount(subject, "demo", "demo@example.com", EmailVerified: true, hasher.Hash("demo-password")),
        CancellationToken.None);
}
