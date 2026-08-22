// The MCP side: a resource server that accepts access tokens from the sample authorization server.
//
// What it is here to show is the handshake Claude actually performs — 401 with a pointer, fetch the
// pointer, discover the authorization server, come back with a token — and that the resource server
// half needs no reference to the authorization server half.
//
//   dotnet run --project samples/Boltway.Sample.ResourceServer
//
// Start the authorization server first; this host fetches its JWKS at startup and keeps it current
// from then on, so a key rotation does not stop it. See samples/README.md.

using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.ResourceServer.Authorization;
using Boltway.ResourceServer.Bearer;
using Boltway.ResourceServer.Configuration;
using Boltway.ResourceServer.DependencyInjection;
using Boltway.ResourceServer.Endpoints;

const string AuthorizationServer = "https://localhost:7443";
const string Self = "https://localhost:7444";

// Exactly the URL a user would type into Claude, path included. RFC 9728 §3.3 makes this a
// byte-for-byte identity check: a trailing slash here is a different resource, and a client that
// built the metadata URL from the other spelling is required to discard what it fetched.
const string Resource = Self + "/mcp";

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls(Self);

if (!IssuerString.TryCreate(AuthorizationServer, out var issuer, out var issuerError))
{
    throw new InvalidOperationException(issuerError);
}

// The one outbound client this host is allowed to make a request with. Everything it fetches is
// guarded: the address is resolved once and pinned, RFC 6890 special-use results are refused,
// redirects are not followed, and there is a per-origin budget.
//
// DEV: AllowPrivateAddresses, because the sample authorization server is on loopback and the
// address check refuses that by default — rightly, since it is what stops an operator-configured
// URL from turning this process into a port scanner. A deployment leaves it clear.
var upstream = new UpstreamEndpointClient(new UpstreamEndpointClientOptions
{
    AllowPrivateAddresses = true,
});

// Fetches the authorization server's discovery document, checks its `issuer` against the one above,
// reads `jwks_uri`, and holds the keys. CurrentKeys() re-fetches in the background as the snapshot
// ages, so a key rotation is picked up without this host being restarted or edited.
using var signingKeys = new JwksKeySource(issuer, upstream);

builder.Services.AddBoltwayProtectedResource(options =>
{
    options.Resource = Resource;
    options.ResourceName = "Boltway sample MCP server";

    // One authorization server, deliberately — it is both the expected `iss` on every token and the
    // single entry in the published metadata. There is no way to list a second, because advertising
    // an issuer whose tokens this server would then refuse presents as a successful sign-in
    // followed by a permanent 401.
    options.AuthorizationServer = AuthorizationServer;

    // Read by a client when a 401 challenge carries no `scope` of its own. Not `offline_access` —
    // that is an authorization-server concern and the MCP specification says a protected resource
    // should not list it.
    options.ScopesSupported.Add("stories.read");
    options.ScopesSupported.Add("stories.write");

    // A source rather than the SigningKeys list, and the difference is not stylistic. The list is
    // mutable state that requests read while a refresher writes it; a source is read fresh on every
    // validation and replaced by reference, so a rotation is an assignment rather than a structural
    // modification of a List<T> somebody is enumerating.
    //
    // This host previously fetched the JWKS once at startup with a bare HttpClient and never again,
    // with a comment saying so. That is the defect JwksKeySource exists to remove: the host was
    // correct until the day the authorization server rotated a key, and then rejected every token
    // with a diagnosis that reads like a missing key rather than a stale one.
    options.SigningKeySource = signingKeys.CurrentKeys;
});

var app = builder.Build();

// Once, before serving, so the first request does not arrive at an empty key set. Failing here is
// the point: a resource server that starts with no keys serves 401 to every caller holding a
// perfectly good token, and that presents as an authentication problem rather than as the startup
// ordering problem it is. Start the authorization server first — see samples/README.md.
var warm = await signingKeys.RefreshAsync(CancellationToken.None);

if (warm.Outcome is not JwksRefreshOutcome.Refreshed)
{
    throw new InvalidOperationException(
        $"Could not fetch signing keys from {AuthorizationServer}: {warm.Detail}. "
        + "Start the sample authorization server first.");
}

// After routing, before the endpoints. Before routing there is no endpoint yet, so the gate cannot
// see that the metadata document is anonymous and would challenge the one response that has to work
// before anything else can; after the endpoints, the handler has already produced a 200.
app.UseRouting();
app.UseBoltwayProtectedResource();

// The RFC 9728 document, at both the path-inserted form (which the challenges point at) and the
// root form (which Claude falls back to).
app.MapProtectedResourceMetadata();

// A local rather than an inline array literal, so the analyzer's CA1861 (do not reallocate a
// constant array on every call) stays satisfied on a handler that runs per request.
string[] stories = ["The Salt Road", "Nine Days of Rain"];

app.MapGet("/mcp/stories", (HttpContext http) =>
{
    // Present only because the middleware validated a token; there is no invalid state to check.
    var token = http.GetBearerToken()!;

    return Results.Json(new
    {
        subject = token.Principal.FindFirst("sub")?.Value,
        scopes = token.Scopes,
        stories,
    });
})
.RequireScope("stories.read");

// Here to show what a scope the token does not carry looks like: 403 with insufficient_scope and
// the whole required list in the challenge, not just the missing part.
app.MapGet("/mcp/stories/draft", () => Results.Json(new { draft = "unfinished" }))
    .RequireScope("stories.read", "stories.write");

await app.RunAsync();
