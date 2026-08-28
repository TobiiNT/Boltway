// A Boltway authorization server you can deploy.
//
// The sample next door marks five things DEV: - the signing key, the stores, the refresh
// derivation key, the loopback exemption for CIMD fetches, and the seeded user. This host is
// the other half of each of those sentences. Everything it needs arrives as configuration, so
// one image serves every deployment and the thing that differs between them is a secret rather
// than a build.
//
// It refuses to start rather than starting wrong. A server that comes up with a freshly
// generated signing key looks healthy, passes its probe, is sent traffic, and issues tokens
// that no resource server can verify - and the user is told to sign in again, forever, for a
// problem that signing in cannot fix. Every required setting below is checked before the host
// binds a port.

using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.HttpOverrides;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Interaction;
using Boltway.AuthorizationServer.Resources;
using Boltway.Federation.Google;
using Boltway.Federation.Oidc;
using Boltway.Identity.Passwords;
using Boltway.Notifications;
using Boltway.Notifications.Smtp;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.OAuth.Tokens;
using Boltway.ResourceServer.DependencyInjection;
using Boltway.ResourceServer.Endpoints;
using Boltway.Storage.EntityFrameworkCore;
using Boltway.Storage.PostgreSql;
using Boltway.Storage.Sqlite;
using Boltway.AuthorizationServer.Host;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging.Console;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Microsoft.EntityFrameworkCore;
using Boltway.OAuth.Primitives.Ids;
using Boltway.AuthorizationServer.Administration;

// What a deployment needs that is not "serve traffic", so the image is self-sufficient and CI
// needs neither a shell recipe nor the `dotnet ef` tool.
//
// Migrations are a command rather than something startup does. Two replicas starting together
// would race the same migration, and the failure is a half-applied schema - which is the one
// state neither a retry nor a rollback fixes.
//
// **This string and the `subcommands` array below are one list written twice, and they have to be
// edited together.** A verb in the usage and not in the array is a documented command that answers
// "unknown subcommand"; a verb in the array and not here is a command nobody can find. This
// branch added five while `main` added the guard, which is exactly the merge that gets one of
// the two halves - it is worth checking against `grep -oE 'args is \[ ?"[a-z-]+"'` rather than
// by reading.
//
// There is a third list, and it is the dispatch blocks themselves. The array now decides both
// "is this a verb" and "did that verb get its arguments", so a verb in the array with no block
// answers `was not given the arguments it takes` however it is called - visible, and refusing
// rather than serving, which is the direction to be wrong in.
const string usage = """
                     usage: dotnet Boltway.AuthorizationServer.Host.dll [subcommand]

                       new-key <kid> [pending]           mint a key entry for the SIGNING_KEYS secret
                       new-client-secret                 mint a client secret and print its hash for CLIENTS
                       migrate                           apply pending migrations and exit
                       doctor                            report what is legal but wrong, and exit
                       new-user <handle> [email] [role]  create a local account and print its password once
                       set-role <handle> <role|->        change what an account's tokens claim it is
                       set-roles <handle> <role...|->    the same, for an account holding several
                       roles                             list the roles this realm defines
                       new-role <id> [name] [perm...]    define one
                       set-role-name <id> <name>         reword one, which no token notices
                       set-role-permissions <id> [perm...]
                                                         replace what one stands for
                       delete-role <id>                  remove one, and every assignment of it
                       service-account <handle> <scope...>
                                                         create or rotate one, printing the secret once
                       service-account-off <handle>      stop it obtaining tokens, keeping the secret
                       service-account-on <handle>       let it obtain them again
                       delete-service-account <handle>   remove it; the secret is gone
                       set-password <handle>             generate a new password for one and print it once
                       disable <handle>                  stop sign-in for one, leaving everything else
                       enable <handle>                   restore it
                       set-email <handle> <addr|-> [--verified]
                                                         set or clear an address, and say if it is proven
                       revoke-sessions <handle>          revoke every grant one account holds
                       anonymise <handle> --yes-i-mean-it
                                                         tombstone an account, irreversibly

                     With no subcommand, serves traffic.
                     """;

// Asked for, rather than mistyped: stdout and zero. Measured while writing the guard below -
// `--help` starts with `-`, so the exemption that keeps `--urls` working would have exempted
// it too, and the most natural thing a person types would still have booted a server.
if (args is [var asked, ..] && asked is "help" or "--help" or "-h" or "-?" or "/?")
{
    Console.WriteLine(usage);
    return;
}

// This list used to exist only as the comment above, which meant a token matching none of it
// fell past every guard into the serve path. `docker compose run --rm auth help` therefore
// printed no usage and did not exit: it booted a second authorization server, holding the same
// SIGNING_KEYS and the same DATABASE_URL as the real one, with its own Data Protection key ring
// that no volume persists. `--rm` never fired, because the process never exited, and
// `docker compose ps` cannot show it - one-off containers are not listed. Measured once at 24
// hours before anyone noticed; the only reason it served no traffic is that a `compose run`
// container does not get the service's network alias, which is luck rather than design.
//
// Both exemptions are load-bearing. `-` covers ASP.NET's own switches, `--urls` above all, and
// `=` covers its unprefixed `key=value` form. The server is legitimately started with either,
// and with no arguments at all, so only a bare unrecognised word is refused.
// An array rather than a `is not (... or ...)` pattern, because there is now a second guard at
// the end of the dispatch blocks that has to ask the same question. Written twice, the two would
// answer differently the first time somebody adds a verb to one of them - which is the defect
// the comment above the usage string is already about, and it is not worth having a third copy.
string[] subcommands =
[
    "new-key", "new-client-secret", "migrate", "doctor",
    "new-user", "set-role", "set-roles", "set-password",
    "roles", "new-role", "set-role-name", "set-role-permissions", "delete-role",
    "service-account", "service-account-off", "service-account-on",
    "delete-service-account",
    "disable", "enable", "set-email", "revoke-sessions", "anonymise",
];

if (args is [var subcommand, ..]
    && !subcommands.Contains(subcommand, StringComparer.Ordinal)
    && !subcommand.StartsWith('-')
    && !subcommand.Contains('='))
{
    Console.Error.WriteLine($"unknown subcommand `{subcommand}`.");
    Console.Error.WriteLine();
    Console.Error.WriteLine(usage);
    Environment.Exit(2);
    return;
}

if (args is [ "new-key", var kid, ..])
{
    Console.WriteLine(DurableSigningKeys.NewRsaEntry(
        kid, args.Contains("pending") ? SigningKeyState.Pending : SigningKeyState.Active));
    return;
}

// A client secret this server will accept, and the hash to put in CLIENTS.
//
// It cannot be a passphrase somebody invents. `ClientAuthenticator` parses the presented value as
// an OpaqueSecret with TokenPurpose.ClientSecret before it hashes anything, so a secret without the
// `bw_cs_` prefix and 32 bytes of base64url behind it fails authentication whatever its hash says -
// and the refusal is the same `invalid_client` as a wrong password, which is a bad afternoon.
// Measured while wiring the admin BFF, which is the first confidential client this repository has.
//
// Printed as two lines because they go to two places: the secret to the client's own configuration,
// and the hash to this server's CLIENTS. Neither side ever needs the other's copy.
if (args is [ "new-client-secret", ..])
{
    var minted = OpaqueSecret.Generate(TokenPurpose.ClientSecret);

    Console.WriteLine("secret " + minted.Wire);
    Console.WriteLine("sha256 " + Convert.ToBase64String(Sha256Hash.Of(minted).Value));
    return;
}

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// ─────────────────────────────────────────────────────────────────────────────
// Identity of this server
// ─────────────────────────────────────────────────────────────────────────────

// Every token ever issued carries this as `iss`, and every resource server compares it
// ordinally. Changing it is not a config change - it invalidates every outstanding token and
// every client's cached discovery document.
var issuer = Required("ISSUER", "the public https URL of this server, e.g. https://auth.example.com");

// ─────────────────────────────────────────────────────────────────────────────
// Signing keys - the one that ends a demo if it is wrong
// ─────────────────────────────────────────────────────────────────────────────

// Not generated. See DurableSigningKeys: on a platform that scales to zero, "restart" means
// "any quiet ten minutes", so a per-process key is not an edge case, it is the normal case.
//
// To create the first one:
//   dotnet run --project hosts/Boltway.AuthorizationServer.Host -- new-key 2026-08
var keyRing = new SigningKeyRing(DurableSigningKeys.Parse(
    Required("SIGNING_KEYS", "the JSON key ring — run this host with `new-key <kid>` to mint one")));

builder.Services.AddSingleton(keyRing);

// ─────────────────────────────────────────────────────────────────────────────
// Storage
// ─────────────────────────────────────────────────────────────────────────────

// Postgres when a connection string is set, SQLite when a file path is, and nothing otherwise.
// There is deliberately no in-memory fallback: it would let a misconfigured deployment start
// and lose every grant on the next scale event, which is a data-loss bug wearing a default's
// clothing.
var postgres = config["DATABASE_URL"] ?? config.GetConnectionString("Postgres");
var sqlite = config["SQLITE_PATH"];

if (postgres is { Length: > 0 })
{
    builder.Services.AddBoltwayPostgreSqlStores(Normalise(postgres));
}
else if (sqlite is { Length: > 0 })
{
    builder.Services.AddBoltwaySqliteStores($"Data Source={sqlite}");
}
else
{
    throw new InvalidOperationException(
        "No database. Set DATABASE_URL (Postgres), or SQLITE_PATH (a file, development only). " +
        "There is no in-memory option here on purpose — it starts fine and loses every grant on the " +
        "next restart.");
}

builder.Services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();

// ─────────────────────────────────────────────────────────────────────────────
// Where mail goes
// ─────────────────────────────────────────────────────────────────────────────

// SMTP_HOST is what turns this on, and PASSWORD_RECOVERY below is refused without it - an email
// flow with nowhere to send is a reset endpoint that answers 202 and delivers nothing, and every
// signal says it worked.
//
// A deployment sending through an API rather than a socket registers its own INotificationSender
// before AddBoltwayAuthorizationServer and leaves SMTP_HOST unset; the seam is a package
// boundary rather than a setting, which is why there is no SMTP_PROVIDER here.
if (config["SMTP_HOST"] is { Length: > 0 } smtpHost)
{
    builder.Services.AddSingleton(new SmtpNotificationOptions
    {
        Host = smtpHost,
        Port = int.TryParse(config["SMTP_PORT"], out var smtpPort) ? smtpPort : 587,

        // Unset means Auto, which reads the port: 465 is implicit TLS, anything else is STARTTLS.
        // So Cloudflare Email Service - 465, implicit, and it offers nothing else - is `SMTP_PORT`
        // and no second setting, and the value that would have had to agree with it cannot
        // disagree. `SMTP_SECURITY` is here for a server on a port that says nothing about its
        // mechanism, and for the sidecar that wants `none`.
        //
        // This replaced `SMTP_STARTTLS`, a boolean that could not express implicit TLS at all: with
        // it on you got STARTTLS on any port, and with it off you got plaintext. There was no
        // setting of it that reached Cloudflare.
        Security = ParseSmtpSecurity(config["SMTP_SECURITY"]),
        Username = config["SMTP_USERNAME"],
        Password = config["SMTP_PASSWORD"],
        From = Required("SMTP_FROM", "the address mail is sent from, since SMTP_HOST is set"),
        FromName = config["SMTP_FROM_NAME"],
    });

    builder.Services.AddSingleton<Boltway.Notifications.INotificationSender>(sp =>
        new SmtpNotificationSender(
            sp.GetRequiredService<SmtpNotificationOptions>(),
            sp.GetRequiredService<Boltway.Notifications.INotificationRenderer>()));
}

// ─────────────────────────────────────────────────────────────────────────────
// What the mail says
// ─────────────────────────────────────────────────────────────────────────────
//
// The pages could be translated and the mail could not. Measured on a running deployment with
// UI_DEFAULT_LOCALE=vi: every page came out in Vietnamese and the reset mail arrived in English,
// which is the message somebody reads while locked out and least able to work past a language they
// do not use.
//
// A file or a variable, never both, and the same shape as UI_TRANSLATIONS above - except that this
// is one set of sentences rather than one per culture, and NotificationText says why: the culture in
// scope when a notification is sent belongs to whoever caused it, which for an operator's reset is
// not the person receiving it.
//
// Anything left out stays English, per property. A half-supplied file is a half-translated mail
// rather than a blank one.
var notificationTextInline = config["NOTIFICATION_TEXT"];
var notificationTextPath = config["NOTIFICATION_TEXT_FILE"];

if (notificationTextInline is { Length: > 0 } && notificationTextPath is { Length: > 0 })
{
    throw new InvalidOperationException(
        "NOTIFICATION_TEXT and NOTIFICATION_TEXT_FILE are both set. They are two ways to supply one "
        + "record and there is no correct way to merge them: set the file, or set the variable.");
}

var notificationTextJson = notificationTextPath is { Length: > 0 }
    ? await File.ReadAllTextAsync(notificationTextPath)
    : notificationTextInline;

if (notificationTextJson is { Length: > 0 })
{
    var source = notificationTextPath is { Length: > 0 } ? notificationTextPath : "NOTIFICATION_TEXT";

    var text = JsonSerializer.Deserialize<NotificationText>(
        notificationTextJson,
        JsonSerializerOptions.Web)
        ?? throw new InvalidOperationException($"{source} is not a JSON object.");

    // Refused at startup rather than at the moment somebody is waiting for a reset link. A
    // configured sentence with a placeholder the message does not supply throws inside the sender,
    // which catches and logs - so the mail silently does not arrive, on the one flow where its not
    // arriving is the whole problem.
    if (text.Problems() is { Count: > 0 } broken)
    {
        throw new InvalidOperationException(
            $"{source} has {broken.Count} sentence(s) that will not render: "
            + string.Join("; ", broken));
    }

    builder.Services.AddSingleton(text);
    builder.Services.AddSingleton<Boltway.Notifications.INotificationRenderer>(
        sp => new Boltway.Notifications.DefaultNotificationRenderer(
            sp.GetRequiredService<NotificationText>()));
}

// `new-user` used to construct this inline. It is a registration now because UserAdministration
// takes it, and because federated provisioning already resolved it from the container - a
// deployment that switched UnknownIdentity to Provision would have been refused at startup with a
// message naming exactly this line.
builder.Services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserSession, CookieUserSession>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        // Lax, not Strict. The browser reaches /authorize by a top-level cross-site navigation
        // from claude.ai, and a Strict cookie is not sent on that - so every user would look
        // signed out on every connect.
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.HttpOnly = true;

        // Without this line the cookie is unrevokable, and that is the whole of it. The ticket is
        // self-contained, so changing a password or ending every application's access left any
        // browser already holding one signed in - for the fourteen days ASP.NET Core defaults to,
        // sliding forward on every use. SessionRevalidation is what refuses one, and it does
        // nothing at all unless it is named here.
        //
        // SessionRevalidation controls how often it asks, and therefore how long an invalidated
        // session keeps working; the option's own comment carries that trade.
        options.Events.OnValidatePrincipal = SessionRevalidation.ValidateAsync;
    });

// ─────────────────────────────────────────────────────────────────────────────
// Which resources this server issues tokens for
// ─────────────────────────────────────────────────────────────────────────────
//
//   RESOURCES='{"https://connector.example.com/mcp":{"name":"Acme Docs","scopes":"docs:read docs:write"}}'
//
// The URL is the audience, compared byte for byte by the resource server. A trailing slash
// here is a different resource, and the mismatch surfaces on the client as a generic failure
// to connect while both servers log a clean 200.
// Read here rather than inside the options callback, because the protected-resource registration
// below has to know whether either surface is served.
var adminApi = Flag(config, "ADMIN_API", @default: false);
var selfService = Flag(config, "SELF_SERVICE", @default: false);

// One name for "is there a bearer surface here", because the registration below and the middleware
// at the bottom of this file have to agree and they are six hundred lines apart.
//
// They did not. The middleware was added unconditionally and the service it resolves was not, so a
// deployment turning on only the cookie surfaces - SELF_SERVICE_PAGES and PASSWORD_RECOVERY, which
// need no bearer validation at all - refused to start with `Unable to resolve service for type
// ProtectedResource`, naming an internal type and nothing a person could act on. Every probe until
// then had happened to have one of these two flags on.
var bearerSurface = adminApi || selfService;

var resources = JsonSerializer.Deserialize<Dictionary<string, ResourceEntry>>(
    Required("RESOURCES", "a JSON map of resource URL to {name, scopes}"),
    JsonSerializerOptions.Web)
    ?? throw new InvalidOperationException("RESOURCES is not a JSON object.");

if (resources.Count == 0) throw new InvalidOperationException("RESOURCES names no resource, so no token could ever be issued.");

// ─────────────────────────────────────────────────────────────────────────────
// The administrative surfaces bring their own resource
// ─────────────────────────────────────────────────────────────────────────────
//
// `ADMIN_API=true` is the whole configuration. This block derives the rest, and the reason is
// that there is no rest to derive from anywhere else: the URL is the issuer with `/admin` on it,
// and the scopes are `AdminScopes`, which is a constant in this library naming the endpoints in
// this library. Every value was already known here.
//
// It used to demand them. `ADMIN_RESOURCE` was required, it had to appear in `RESOURCES` as well,
// and startup refused with "ADMIN_RESOURCE is `…` and RESOURCES does not list it" - a server
// asking an operator to tell it something it had just computed, in two places, in JSON. Turning
// on an admin API cost four settings and a paragraph of documentation, and three of the four were
// this program dictating its own answer back to itself.
//
// **`ADMIN_RESOURCE` is still read, and it is now only an override**, for the deployment §1.4
// describes that puts the admin API on its own hostname.
//
// N-06 falls out rather than being enforced. The resource exists when a surface serves it and
// does not exist otherwise, so there is no state in which its scopes are advertised, consented
// to, or minted into a token that every call would 404 - which is what this measured before,
// including a consent screen asking somebody to approve `users:write` on a server that would
// then refuse it, and tokens that would come alive if the flag were ever set back.
var adminResource = config["ADMIN_RESOURCE"] is { Length: > 0 } overridden
    ? overridden
    : issuer.TrimEnd('/') + AuthorizationServerPaths.AdminPrefix.TrimEnd('/');

if (bearerSurface)
{
    // Only what is served. `users:self` belongs to /account/*, the administrative scopes to
    // /admin/*, and a deployment running one of them must not advertise the other's - that is
    // the same N-06 rule one level down, and the reason this is two conditions rather than one
    // list.
    //
    // `Administrative` is the users pair and the roles pair together: the role endpoints accept
    // `roles:read`/`roles:write` as well as the directory-wide pair, and advertising the narrow
    // ones here is what lets a service account be scoped to the vocabulary without holding a
    // single account - the picker offers exactly what is advertised.
    var adminScopes = new List<string>();
    if (adminApi) adminScopes.AddRange(AdminScopes.Administrative);
    if (selfService) adminScopes.Add(AdminScopes.Self);

    // A RESOURCES entry wins, so a deployment that wants a different name for it still can - but
    // it no longer has to write one to be allowed to start.
    if (!resources.ContainsKey(adminResource))
    {
        resources[adminResource] = new ResourceEntry
        {
            Name = "Administration",
            Scopes = string.Join(' ', adminScopes),
        };
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Which resource a bare sign-in is audienced at
// ─────────────────────────────────────────────────────────────────────────────
//
// An OIDC client asks for `openid email` and sends no `resource`: RFC 8707 is an OAuth extension,
// OIDC does not require it, and there is no metadata field through which a server could tell a
// client it were needed. On a deployment with two registrations `DefaultForAsync` correctly refuses
// to guess between them, so every such sign-in ended in `invalid_target` - measured with Grafana,
// against a server whose own /userinfo was sitting there ready to answer it.
//
// **Derived, not configured, and it has to be `adminResource`.** This is not a preference between
// registered resources: `AddBoltwayProtectedResource` below sets `o.Resource = adminResource`,
// so that is the single audience the bearer middleware in front of /userinfo accepts. Nominating
// anything else would mint a token /userinfo rejects - a sign-in that now fails one step later, at
// the profile fetch, with a 401 no operator would connect to this setting.
//
// So there is deliberately no `OIDC_RESOURCE` to set. An override here would exist only to be
// wrong, and it would follow `ADMIN_RESOURCE` for free anyway, since both read the same variable.
//
// Null when no bearer surface is served, which is the same condition that registered the resource
// above - the registry throws on a nomination it cannot resolve, and these two flags being one
// variable is what keeps that impossible rather than merely unlikely.
var oidcResource = bearerSurface ? adminResource : null;

builder.Services.AddSingleton<IResourceRegistry>(ConfiguredResourceRegistry.Create(
    resources.ToDictionary(
        r => r.Key,
        r => (r.Value.Name ?? r.Key, ParseScopes(r.Key, r.Value.Scopes)),
        StringComparer.Ordinal),
    oidcResource: oidcResource));

// ─────────────────────────────────────────────────────────────────────────────
// Clients this deployment registered by hand
// ─────────────────────────────────────────────────────────────────────────────
//
//   CLIENTS='{"northwind-admin":{"name":"Northwind admin","redirectUris":"https://admin.example.com/signin-oidc",
//              "secretSha256":"<base64 of SHA-256 of the secret>"}}'
//
// Optional, and empty in most deployments: Claude and ChatGPT identify themselves by a metadata
// URL, so nothing here is needed to serve them. What needs it is a *confidential* client - the
// admin BFF is the one this repository ships - because a secret has no business in a document
// served over the public internet, so such a client cannot be a CIMD one.
//
// Registered before AddBoltwayAuthorizationServer, because resolvers are tried in order and
// that call adds the CIMD one: a configured id is then answered from configuration rather than
// after an outbound fetch that was never going to find anything.
//
// The SECRET IS A HASH. `secretSha256` is base64 of SHA-256 of the secret, so this value can sit in
// a GitHub Variable, a compose file or a log line without being a credential:
//
// **It is not a passphrase.** `ClientAuthenticator` parses the presented value as an OpaqueSecret
// before hashing it, so a secret this server did not mint fails authentication whatever its hash
// says. Run this host with `new-client-secret`, which prints both halves:
//
//   secret bw_cs_…      → the client's own configuration
//   sha256 …            → this value
//
// ── A resource server, for revocation ────────────────────────────────────────
//
//   CLIENTS='{"northwind-connector":{"name":"Northwind connector","introspectionOnly":true,
//              "secretSha256":"<base64 of SHA-256 of the secret>"}}'
//
// The third kind, and the reason it needs a flag at all: RFC 7662 §2.1 requires `/introspect` to be
// authorized, so a resource server that wants ending a session to cut access needs a client here -
// and that client authorizes nobody and acts as nobody. Without `introspectionOnly` this host
// refuses to start, because a client with neither a redirect URI nor an owner is otherwise a
// configuration mistake and is refused as one. Measured, before the flag existed: the process
// exited on `CLIENTS entry … registers no redirect URI`, on the deploy that turned revocation on.
//
// **Do not reach for one of the other two instead.** A placeholder `redirectUris` is a live
// authorization-code target for whoever steals the secret, and `owner` grants the far larger power
// of acting as an account through `client_credentials` - both were tried, and both trade a real
// capability away to satisfy a validation rule. What this flag buys is exactly the right to ask
// whether a token somebody already presented is still live: `IntrospectionOnlyClientTests` drives
// the three refusals that hold it to that.
//
// ── A service account ────────────────────────────────────────────────────────
//
//   CLIENTS='{"northwind-nightly":{"name":"Nightly report","owner":"usr_01J…",
//              "scopes":"docs:read","secretSha256":"<base64 of SHA-256 of the secret>"}}'
//
// `owner` is what makes it one, and it changes the kind of client rather than adding a field. It
// then uses `client_credentials` and nothing else, carries no redirect URI, and is issued exactly
// the scopes named here - see ConfiguredClient.GrantTypes for why the two sets do not overlap.
//
// **The owner's roles are the ceiling.** A service account owned by an account that holds every
// role is a non-expiring credential with that reach; owned by an account holding one narrow role,
// it can only do
// that role's work. Make it its own account, with `new-user`, and give it the least role that does
// the job. Configuring one is also what turns the grant on: `grant_types_supported` gains
// `client_credentials` when at least one client names an owner, so there is no second knob to
// set and none to forget.
var serviceAccounts = false;

if (config["CLIENTS"] is { Length: > 0 } clientsJson)
{
    var configured = JsonSerializer.Deserialize<Dictionary<string, ClientEntry>>(
        clientsJson, JsonSerializerOptions.Web)
        ?? throw new InvalidOperationException("CLIENTS is not a JSON object.");

    var clients = configured.Select(ParseClient).ToArray();
    serviceAccounts = clients.Any(c => c.Owner is not null);

    builder.Services.AddConfiguredClients(clients);
}

// ─────────────────────────────────────────────────────────────────────────────
// Clients the administrative surface stores reach the token endpoint
// ─────────────────────────────────────────────────────────────────────────────
//
// This line was missing for as long as service accounts have existed, and every layer around the
// gap worked: the store was registered, so the grant was advertised; the admin API wrote rows and
// read them back; the UI showed the secret. Then /token answered `invalid_client - No client is
// registered with that identifier` for the very credential the page had just handed over, because
// the resolver chain held configuration and CIMD and had never been told about the table.
//
// Found on production, by the first service account anybody minted for real use, minutes after it
// was created. The end-to-end suite proves exactly this wiring - six of its nine tests fail with
// this exact error when the call is removed - but it proves it in a host the fixture builds, and
// this host is not that one. A test can pin a library's composition; only this file can compose
// this deployment.
//
// After AddConfiguredClients and before AddBoltwayAuthorizationServer, which is the order
// the library documents: resolvers run configuration first, the table second, CIMD last, and the
// secret stores chain the same way - which is what keeps the configured confidential clients
// (this deployment's admin UI and Grafana) authenticating after this call.
if (builder.Services.Any(
        d => d.ServiceType == typeof(Boltway.AuthorizationServer.Abstractions.Clients.IClientStore)))
{
    builder.Services.AddStoredClients();
}

// ─────────────────────────────────────────────────────────────────────────────
// What a new account holds when its creator names no role
// ─────────────────────────────────────────────────────────────────────────────
//
//   DEFAULT_ROLES='member'          (role ids, space separated - usually one)
//
// Unset, creation behaves as it always has: no role unless one is named, and `new-user` warns
// about the token that will carry no claim. Set, an account created without a role holds these
// instead - every path, because the defaulting lives in UserAdministration.CreateAsync rather
// than in any caller. A named role still wins outright; see AccountDefaults for why the two are
// never unioned.
//
// Every id here must be one the realm defines, or creation fails at the assignment with a message
// naming it. The `migrate` verb checks this after seeding, so a deploy that runs it - which is
// every deploy of the compose file this ships with - finds the typo before `up -d` does.
if (config["DEFAULT_ROLES"] is { Length: > 0 } defaultRoles)
{
    var defaultRoleIds = defaultRoles.Split(
        ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // The ADMIN_ROLES lesson, applied here before it repeats: a set-but-empty value was legal,
    // silent, and meant something nobody intended, discovered at the wrong moment. AccountDefaults
    // itself refuses an empty set too, but this message names the variable a person can fix.
    if (defaultRoleIds.Length == 0)
    {
        throw new InvalidOperationException(
            "DEFAULT_ROLES is set and names no role id. Unset it, or name one — space separated.");
    }

    builder.Services.AddSingleton(new AccountDefaults(defaultRoleIds));
}

// ─────────────────────────────────────────────────────────────────────────────
// Validating the tokens this server issues to itself
// ─────────────────────────────────────────────────────────────────────────────
//
// §1.12: the admin and self-service surfaces validate bearer tokens with Boltway
// .ResourceServer, and there is no second validator. This is that sentence, wired.
//
// Without it those surfaces are routed, advertise their scopes, and refuse every token - because
// `AdminAuthorization.Check` reads `HttpContext.User` and nothing in this image was populating it
// with a bearer principal. Measured by pointing the admin BFF at a running host: it authenticated,
// obtained a token with `users:read users:write`, and got "Unauthenticated" from /admin/users.
//
// `adminResource` is the audience those tokens must carry, derived above from the issuer or taken
// from ADMIN_RESOURCE when a deployment overrides it. A separate resource from any connector's
// (§1.4), so a token minted for a customer's MCP server cannot be replayed here.
if (bearerSurface)
{
    builder.Services.AddBoltwayProtectedResource(o =>
    {
        o.Resource = adminResource;
        o.AuthorizationServer = issuer;
        o.ResourceName = "Administration";

        // The key ring in this process, read per validation. The server that signs these tokens is
        // this one, so fetching its own JWKS over the network would be an outbound request to
        // itself - and one that fails while it is still starting.
        //
        // A closure over the instance rather than a container lookup: the same object the signing
        // side holds, so a rotation is visible to the validator on the next call rather than at the
        // next restart. S-52 is what makes reading it per validation safe.
        o.SigningKeySource = keyRing.PublicVerificationKeys;
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Federated sign-in
// ─────────────────────────────────────────────────────────────────────────────

// Optional, and worth having before a demo: "Sign in with Google" tells the whole story in
// one screen, where a password form invites the question of who is managing passwords.
var googleClientId = config["GOOGLE_CLIENT_ID"];
if (googleClientId is { Length: > 0 })
{
    // Refused at startup, because the alternative is where it used to surface. Google requires the
    // secret at its token endpoint, so without one the server boots, the button renders, the round
    // trip to Google succeeds, the user consents - and the *callback* fails, after they have done
    // everything asked of them. Measured on a running deployment: "invalid_request - the sign-in
    // could not be completed", with the real cause only in the server log, because the exchange is
    // the first moment anything looks at the secret.
    //
    // A deploy pipeline is why this can happen quietly: GOOGLE_CLIENT_SECRET was on that
    // deployment's optional list, so an unset GitHub secret wrote no line at all and every check
    // stayed green. Half-configured is the state to refuse; not-configured is already handled by
    // the branch above.
    if (config["GOOGLE_CLIENT_SECRET"] is not { Length: > 0 } googleClientSecret)
    {
        throw new InvalidOperationException(
            "GOOGLE_CLIENT_ID is set and GOOGLE_CLIENT_SECRET is not. Google requires the secret at "
            + "its token endpoint, so sign-in would fail on the callback — after the user has "
            + "already signed in at Google — rather than here. Set it, or unset GOOGLE_CLIENT_ID to "
            + "turn Google sign-in off.");
    }

    builder.Services.AddExternalIdentityProvider(
        GoogleFederation.Options(googleClientId, googleClientSecret));

    // Refuse by default, and the default is the right one for a company that demos to
    // prospects: with `provision`, anyone in the world holding an account at the configured
    // upstream gets one here - including the prospect who clicks through your demo and ends up
    // in your production directory. A deployment federating to its own corporate tenant wants
    // the other value, and should have to say so.
    builder.Services.Configure<ExternalLoginOptions>(options =>
        options.UnknownIdentity =
            string.Equals(config["EXTERNAL_UNKNOWN_IDENTITY"], "provision", StringComparison.OrdinalIgnoreCase)
                ? UnknownExternalIdentityPolicy.Provision
                : UnknownExternalIdentityPolicy.Refuse);
}

// The pages' language, as configuration rather than as code.
//
// One image serves every deployment, so the words on the sign-in page cannot be compiled into it -
// a Vietnamese deployment and an English one are the same binary with different environment. The
// library ships English and falls back to it per string, so a partial translation is a partial
// translation rather than a broken page.
//
//   UI_DEFAULT_LOCALE=vi
//   UI_TRANSLATIONS_FILE=/etc/boltway/ui/translations.json
//   UI_TRANSLATIONS='{"vi":{"LoginTitle":"Đăng nhập","LoginUsername":"Tên đăng nhập"}}'
//
// Both hold the same JSON: culture name to key-to-text. The file is there because a translation is
// a document rather than a setting - it is edited by whoever writes the words, reviewed in a diff,
// and 27 sentences of it on one line of a .env is a thing nobody proofreads. The variable stays for
// a deployment with nowhere to mount a file. Setting both is refused rather than ranked: there is
// no reading of it where the answer is obvious, and picking one silently is how a deployment ends
// up serving the copy nobody edited.
//
// Keys are the constants on InteractionText. An unknown key is ignored rather than fatal: a
// translation written against a newer version of the library must not stop this one from starting.
//
// A culture with an empty object - `{"en": {}}` - is served entirely from the built-in English.
// That is how a deployment whose default is Vietnamese also offers English: English is the
// per-string fallback, and a fallback is not a culture the middleware will match `ui_locales`
// against until something lists it.
var uiTranslations = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

var inlineTranslations = config["UI_TRANSLATIONS"];
var translationsPath = config["UI_TRANSLATIONS_FILE"];

if (inlineTranslations is { Length: > 0 } && translationsPath is { Length: > 0 })
{
    throw new InvalidOperationException(
        "UI_TRANSLATIONS and UI_TRANSLATIONS_FILE are both set. They are two ways to supply one "
        + "table and there is no correct way to merge them: set the file, or set the variable.");
}

var translationsJson = translationsPath is { Length: > 0 }
    ? await File.ReadAllTextAsync(translationsPath)
    : inlineTranslations;

if (translationsJson is { Length: > 0 })
{
    var source = translationsPath is { Length: > 0 } ? translationsPath : "UI_TRANSLATIONS";

    var parsed = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(
        translationsJson,
        JsonSerializerOptions.Web)
        ?? throw new InvalidOperationException($"{source} is not a JSON object.");

    var known = InteractionText.Keys.ToHashSet(StringComparer.Ordinal);

    foreach (var (culture, strings) in parsed)
    {
        var unknown = strings.Keys.Where(key => !known.Contains(key)).ToList();

        if (unknown.Count > 0)
        {
            // Reported, not fatal. A key this version does not have is a translation written for
            // another one, and refusing to start over it would make upgrading the library a
            // coordinated change with whoever holds the strings.
            Console.Error.WriteLine(
                $"{source}['{culture}'] has {unknown.Count} key(s) this build does not know, "
                + $"which will be ignored: {string.Join(", ", unknown)}");
        }

        uiTranslations[culture] = strings
            .Where(pair => known.Contains(pair.Key))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
    }
}

var uiDefaultLocale = config["UI_DEFAULT_LOCALE"] ?? "en";
var uiLocalized = uiTranslations.Count > 0 || config["UI_DEFAULT_LOCALE"] is not null;

if (uiLocalized)
{
    builder.Services.AddBoltwayInteractionLocalization(uiDefaultLocale, uiTranslations);
}

builder.Services.AddBoltwayAuthorizationServer(options =>
{
    options.Issuer = issuer;

    // Settable in the library since it was written, and settable from this image only now. A
    // consumer referencing the package could tune any of these; a consumer running the container -
    // which the README offers as the ordinary way to deploy - could not, so the two audiences got
    // different products from one codebase. Unset leaves the library's default, and each is
    // validated by AuthorizationServerOptions against its own floor and ceiling rather than here.
    if (Duration(config, "ACCESS_TOKEN_LIFETIME") is { } accessTokens) options.AccessTokenLifetime = accessTokens;
    if (Duration(config, "REFRESH_TOKEN_LIFETIME") is { } refreshTokens) options.RefreshTokenLifetime = refreshTokens;
    if (Duration(config, "AUTH_CODE_LIFETIME") is { } codes) options.AuthorizationCodeLifetime = codes;
    if (Duration(config, "SESSION_REVALIDATION") is { } revalidation) options.SessionRevalidation = revalidation;
    if (Duration(config, "REAUTH_FRESHNESS") is { } freshness) options.ReauthenticationFreshness = freshness;

    // Derived rather than read from a variable of its own, and that is the whole point: two knobs
    // that have to agree are two knobs that eventually do not.
    //
    // **It asks whether this server CAN serve the grant, not whether anybody is using it yet**, and
    // the difference was a real defect for the length of one deploy. The condition was "a configured
    // client names an owner", which is only the CLIENTS path - so a service account created through
    // the admin API, the CLI or the checkbox went into the clients table, the grant stayed
    // unadvertised, and /token answered `unsupported_grant_type` for a credential that had just been
    // handed to somebody. The whole administrative surface was unreachable through the one route
    // built for it.
    //
    // A registered IClientStore is what makes the table possible, so it is the honest half of the
    // condition. N-06 holds either way: with a store, this server genuinely does support the grant,
    // whether or not a row exists yet. A deployment with neither a store nor a configured owner
    // still advertises nothing, which is the case the original condition got right.
    var canHoldServiceAccounts = builder.Services.Any(
        d => d.ServiceType == typeof(Boltway.AuthorizationServer.Abstractions.Clients.IClientStore));

    if (serviceAccounts || canHoldServiceAccounts)
    {
        options.GrantTypesSupported.Add("client_credentials");
    }

    options.ScopeDescriptions["openid"] = "Confirm who you are.";
    options.ScopeDescriptions["offline_access"] = "Stay connected without asking you again.";

    // The administrative scopes get shipped words too, and the reason is what the page said
    // without them. Measured on a running server: the consent screen for the one client that can
    // change every account in the deployment read
    //
    //   users:read  (no description configured for this scope)
    //   users:write (no description configured for this scope)
    //
    // which is A-14 behaving exactly right - it refuses to invent text by parsing a scope name -
    // on the page where a person most needs to know what they are agreeing to. A-14 forbids
    // guessing; it does not forbid this server describing scopes it defines itself. These three
    // are not a deployment's vocabulary, they are ours: `AdminScopes` declares them and
    // `/admin/*` and `/account/*` are what honour them.
    //
    // A deployment still overrides them through SCOPE_DESCRIPTIONS, which is how they get
    // translated. What this changes is the floor: legible English rather than a blank.
    options.ScopeDescriptions[AdminScopes.Read] = "Read every account in this organisation.";
    options.ScopeDescriptions[AdminScopes.Write] =
        "Create, change and disable every account in this organisation.";
    options.ScopeDescriptions[AdminScopes.Self] = "Manage your own account.";

    // The narrow role pair, described with the same care and the write half with its true weight:
    // changing what a role stands for reaches every account that holds it, so the sentence must
    // not read smaller than users:write just because the scope is narrower.
    options.ScopeDescriptions[AdminScopes.RolesRead] = "Read the roles this organisation defines.";
    options.ScopeDescriptions[AdminScopes.RolesWrite] =
        "Define and change roles — what everyone holding them may do.";

    // `email` is what releases the address into an access token, and it is a scope so that it is
    // a thing the user is shown and agrees to. A resource that wants it lists `email` among its
    // own scopes in RESOURCES; one that does not gets a token carrying the handle and nothing
    // else. The handle is not scoped, because it goes into an audit trail rather than a mailing
    // list - see AddSubjectClaimsFromAccounts below.
    options.ScopeDescriptions["email"] = "See your email address.";

    // The union, added once each. `ScopesSupported.Add` refuses a repeat - an advertised scope
    // is a promise, and two entries for one scope is a document that describes itself twice -
    // and the three protocol scopes above are exactly the ones a resource is most likely to
    // declare as well. Adding them straight, then looping over RESOURCES, refused to start with
    // "Scopes are configured more than once: email" the first time a resource named `email`,
    // which is the configuration this feature asks a deployment to write.
    //
    // The page never derives text by parsing a scope name, so a scope with no description shows
    // as its raw name - legible, but it reads like a leak.
    var scopes = new SortedSet<string>(StringComparer.Ordinal) { "openid", "offline_access", "email" };

    foreach (var declared in resources.Values.SelectMany(
        r => (r.Scopes ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries)))
    {
        scopes.Add(declared);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The two account surfaces
    // ─────────────────────────────────────────────────────────────────────────

    // Both off, and both reachable, which is the part that was missing. The endpoints were built,
    // routed behind a flag, and this image set neither flag and offered no setting that could -
    // exactly what END_SESSION turned out to be below, found the same way. An endpoint nothing can
    // turn on is an endpoint nobody has.
    //
    // Off by default because N-06 is "a deployment gets the surface it asked for", and for the
    // admin API also because it is the highest-value target in the system: a flaw there is not a
    // leaked document, it is the directory. A deployment managing accounts over ssh should not be
    // serving one.
    //
    // Two settings rather than one. A deployment that administers over ssh and still wants people
    // to see their own sessions is ordinary, and a single flag would make it impossible without
    // also exposing the directory.
    options.AdministrationEnabled = adminApi;
    options.SelfServiceEnabled = selfService;

    // The pages, which are a third surface rather than a rendering of the second: cookie plus
    // antiforgery instead of a bearer token, so they need no scope and a deployment can want them
    // without wanting the API. A person in a browser is the case they exist for.
    options.SelfServicePagesEnabled = Flag(config, "SELF_SERVICE_PAGES", @default: false);

    // The email flows. Off, and the one surface flag with a prerequisite the server checks: turning
    // it on without an INotificationSender is refused at startup rather than producing a reset
    // endpoint that answers 202 and delivers nothing. SMTP_HOST below is what registers one.
    options.PasswordRecoveryEnabled = Flag(config, "PASSWORD_RECOVERY", @default: false);

    // The scopes each surface authorizes on, added only when it is served. Startup refuses the
    // other way round - a routed endpoint whose scope is unadvertised is unreachable, and reads to
    // an operator as a permissions bug in whatever they are holding - and advertising a scope no
    // endpoint honours is the same defect pointing the other way.
    if (options.AdministrationEnabled)
    {
        scopes.Add(AdminScopes.Read);
        scopes.Add(AdminScopes.Write);
    }

    if (options.SelfServiceEnabled)
    {
        scopes.Add(AdminScopes.Self);
    }

    foreach (var scope in scopes)
    {
        options.ScopesSupported.Add(scope);
    }

    foreach (var (scope, description) in ScopeDescriptions(config))
    {
        options.ScopeDescriptions[scope] = description;
    }

    // Worth as much as every refresh token this server will ever issue: they are derived from
    // it, so a value that differs between restarts or replicas silently breaks every one. It
    // belongs wherever the signing keys live.
    options.RefreshTokenDerivationKey = Convert.FromBase64String(
        Required("REFRESH_TOKEN_DERIVATION_KEY", "32 random bytes, base64 — `openssl rand -base64 32`"));

    if (options.RefreshTokenDerivationKey.Length < 32)
        throw new InvalidOperationException("REFRESH_TOKEN_DERIVATION_KEY must decode to at least 32 bytes.");

    // ─────────────────────────────────────────────────────────────────────────
    // Sign-out
    // ─────────────────────────────────────────────────────────────────────────

    // On here, where the library has it off, and the difference is the point rather than an
    // oversight. `EndSessionEnabled` is off in `AuthorizationServerOptions` because it sits with
    // `UserInfoEnabled`, `RevocationEnabled` and `IntrospectionEnabled` - flags for endpoints
    // that do not exist yet, where the default has to be "not advertised". `/logout` stopped
    // being one of those when it was routed; it is implemented and tested, and this host is the
    // shared machine the sign-out work was about, so a deployment that never heard of this
    // setting should get a way to end a session rather than not.
    //
    // Left off, the endpoint was unreachable from this image at all: nothing here set the flag
    // and there was no setting to set it with. Northwind found it the expensive way, by translating
    // the six sign-out strings into Vietnamese for a page that answered 404.
    //
    // Routed and advertised move together in the library, so either value keeps N-06.
    options.EndSessionEnabled = Flag(config, "END_SESSION", @default: true);

    // RFC 7662 introspection, for a resource server that wants ending a session to take effect
    // before the access token expires. Off unless asked for, and asking for it is two decisions
    // rather than one: this flag, and a confidential client in CLIENTS for the resource server to
    // authenticate with - §2.1 requires the endpoint to be authorized, so it is unreachable
    // without one and this flag alone gives nobody anything.
    //
    // What it is worth: an access token here is a signed JWT that a resource server verifies
    // offline, so `/me/sessions` "end this session" reaches nothing until the token expires. With
    // this on and a resource server calling it, that lag becomes the resource server's own cache
    // window instead.
    //
    // Routed and advertised move together in the library, so either value keeps N-06.
    options.IntrospectionEnabled = Flag(config, "INTROSPECTION", @default: false);

    // RFC 7009. Implemented, routed and advertised from the option - and until now this image read
    // no variable for it, so the one deployment shape the README calls the ordinary way to run this
    // could not turn it on at all. That is the same defect the two entries above are about, one
    // layer out: an endpoint nothing can enable is an endpoint nobody has, whatever the library
    // does.
    //
    // Off by default, matching the option. Confidential clients only, and `none` is never advertised
    // for it: an endpoint that accepted an unauthenticated caller would revoke on anyone's say-so.
    options.RevocationEnabled = Flag(config, "REVOCATION", @default: false);

    // On by default, and the variable exists to turn it *off* - the mirror of the case above, and
    // it was equally unreachable. `/userinfo` is the one endpoint here that discloses only what the
    // caller's own access token already carries, so leaving it on is right for almost everybody;
    // "almost" is the reason a deployment gets a say.
    options.UserInfoEnabled = Flag(config, "USERINFO", @default: true);

    // ─────────────────────────────────────────────────────────────────────────
    // How the sign-in and consent pages look
    // ─────────────────────────────────────────────────────────────────────────

    // The lowest of the three tiers, and the only one this host uses. It cannot reach the part of
    // the consent page that says who is asking and where the code is going, so a deployment gets
    // its own typography without acquiring N-14 - which is exactly what it should get, since the
    // page a user reads carefully is not a place to hand out obligations by accident.
    //
    // UI_PRODUCT_NAME is the one worth setting. It lands in the <title>, and the browser tab is
    // how a user with several open decides which server is asking them for a password.
    options.Interaction.ProductName = config["UI_PRODUCT_NAME"];
    options.Interaction.LogoPath = config["UI_LOGO_PATH"];

    // Space-separated, like RESOURCES' scope lists. Defaults to the sheet in this image, and
    // setting it to an empty string is how a deployment gets the bare unstyled pages back - the
    // stylesheet is a default rather than a decision this host makes for everyone.
    //
    // Every path is validated same-origin at startup, because these pages send
    // `default-src 'self'` and a CDN URL would be refused by the browser rather than by anything
    // that could tell the operator.
    foreach (var stylesheet in (config["UI_STYLESHEETS"] ?? "/css/authorization.css")
        .Split(' ', StringSplitOptions.RemoveEmptyEntries))
    {
        options.Interaction.StylesheetPaths.Add(stylesheet);
    }

    // Which way in leads. Off keeps the order this host has always had - password form first,
    // providers under it. A deployment where nearly everyone signs in through a provider sets this
    // and stops opening its front door with two empty text fields.
    //
    // It reorders the markup rather than the stylesheet, because CSS `order` would move the buttons
    // and leave the tab order where it was.
    options.Interaction.ProvidersFirst =
        string.Equals(config["UI_PROVIDERS_FIRST"], "true", StringComparison.OrdinalIgnoreCase);

    // Off unless a deployment replaced the layout with one that has inline script or style. The
    // pages this host serves have neither, so a nonce here would be a token in a header that
    // nothing uses.
    options.Interaction.UseContentSecurityPolicyNonce =
        string.Equals(config["UI_CSP_NONCE"], "true", StringComparison.OrdinalIgnoreCase);

    // Advertised == served, from the one function that answers "which languages is this". The
    // middleware is configured from the same call, so the discovery document cannot come to claim
    // a language nobody is served - and the map-time check that compares the two stays as the
    // backstop for whoever writes the next host.
    if (uiLocalized)
    {
        foreach (var culture in InteractionLocalization.SupportedCultures(uiDefaultLocale, uiTranslations))
        {
            options.UiLocalesSupported.Add(culture);
        }
    }
});

// Without this the access token says `sub: 01KZAWCB5XY91G8N9XG84WR1EN` and nothing else about
// who is calling, so every resource server behind this one records a ULID where a person
// belongs. Measured on one connector: it had a whole attribution path -
// commit author, actor line, refusal messages naming the caller - and all of it degraded to
// the identifier the moment it moved off static tokens, with nothing failing to report it.
//
// Not a config flag. A flag here has one wrong value that produces exactly that silence, and
// the deployment learns about it from a git history it cannot read months later.
builder.Services.AddSubjectClaimsFromAccounts();

// ─────────────────────────────────────────────────────────────────────────────
// Who may administer the directory
// ─────────────────────────────────────────────────────────────────────────────
//
// `ADMIN_API=true` routes `/admin/*` and puts `users:read users:write` on the consent screen.
// `AdminAuthorization.Check` then asks whether the token carries the scope and - correctly, by
// design - never reads the role, because turning a role into an entitlement belongs to
// `IScopeEntitlementPolicy`, in the deployment.
//
// Nothing was composing there. The library registers `PermissiveScopeEntitlementPolicy` with
// `TryAdd` so the seam exists in every deployment, and this host never replaced it, so the answer
// to "who may administer the directory" was **anyone who can sign in**. Measured on a running
// server: an account created for a throwaway test was offered the same consent screen for
// `users:read users:write` as the deployment's own administrator, and could have disabled them.
//
// So the roles are required rather than defaulted, and the server refuses to start without them.
// The alternative shapes are both worse. A default like `admin` silently disagrees with a
// deployment whose administrators hold some other role, and locks everyone out at the next
// sign-in; leaving it
// unset and permissive is the state this paragraph is about. This is the same trade
// `PASSWORD_RECOVERY` makes with a mail sender - refuse loudly at startup rather than be wrong
// quietly, later, on somebody else's afternoon.
//
// Registered after `AddBoltwayAuthorizationServer`, not before: the library uses `TryAdd`, so
// a registration made first would be the one that survives and this one would never run.
if (adminApi)
{
    var adminRoles = (config["ADMIN_ROLES"] ?? string.Empty)
        .Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    if (adminRoles.Length == 0)
    {
        throw new InvalidOperationException(
            "ADMIN_ROLES is not set, and ADMIN_API is on. It is the roles whose accounts may hold "
            + $"`{AdminScopes.Read}` and `{AdminScopes.Write}` — without it every account that can "
            + "sign in can administer every other one. Set it to the role your administrators "
            + "already have, e.g. ADMIN_ROLES=founder, and check it against `set-role`.");
    }

    builder.Services.AddSingleton<IScopeEntitlementPolicy>(new AdminRoleScopePolicy(adminRoles));
}

// ─────────────────────────────────────────────────────────────────────────────
// Logs and traces
// ─────────────────────────────────────────────────────────────────────────────

// Cloud Run already ships stdout to Cloud Logging with no agent and no configuration, so the
// logs were arriving before this line existed. What they were not was queryable: a string
// payload lands in `textPayload`, which Google's own documentation says "you can search but
// you can't index". A JSON object lands in `jsonPayload`, where a field is a field.
//
// That matters more here than in most services. RejectionResult emits every field of a refusal
// as a named property precisely so that "how many AccessTokenRejected in the last hour, and did
// they all name the same kid" is a query - and the console provider was flattening all of it
// back into a sentence at the last step.
//
// **Which shape, though, is the deployment's to pick.** This used to install the Google formatter
// unconditionally, in an image the README calls one image for every deployment: the field names it
// emits are Google's - `severity`, `logging.googleapis.com/trace` - and its own doc says they are
// not interchangeable. GOOGLE_CLOUD_PROJECT only ever gated the trace fields, so a deployment on
// anything else got a payload shaped for a product it does not run and no way back to the
// framework's own formatters short of editing this file.
//
// `json` is the default because it is the one that is right everywhere: structured, queryable, and
// vendor-neutral. `cloud-logging` is the same idea with Google's spelling, and a deployment that
// wants it now says so. `simple` is the framework's human-readable console, for a terminal.
switch (LogFormat(config))
{
    case "cloud-logging":
        builder.Services.Configure<CloudLoggingOptions>(o => o.ProjectId = config["GOOGLE_CLOUD_PROJECT"]);
        builder.Logging.AddConsole(o => o.FormatterName = CloudLoggingFormatter.FormatterName);
        builder.Logging.AddConsoleFormatter<CloudLoggingFormatter, ConsoleFormatterOptions>();
        break;

    case "simple":
        builder.Logging.AddSimpleConsole();
        break;

    default:
        builder.Logging.AddJsonConsole();
        break;
}

// Traces from the framework's own instrumentation, and nothing hand-rolled. That line is often
// attributed here to DESIGN.md; it is not in DESIGN.md, which says nothing about OpenTelemetry at
// all. It came from one of three competing architecture proposals, none of them recorded as
// adopted, and those files have since been deleted for describing a system that was not built. So
// it is a reason somebody once gave, not an instruction anybody issued.
//
// OTEL_EXPORTER_OTLP_ENDPOINT unset means no exporter is added at all. The alternative - always
// exporting, to a default that is not reachable - is a background thread retrying forever and a
// log line about it every minute, which is how observability becomes the thing being diagnosed.
var otlp = config["OTEL_EXPORTER_OTLP_ENDPOINT"];

if (otlp is { Length: > 0 })
{
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService("boltway-auth"))
        .WithTracing(t => t
            .AddAspNetCoreInstrumentation(o =>
                // The probe is most of the traffic on a min-instances=1 service and none of the
                // signal.
                o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/health")))
        .WithMetrics(m => m
            // ASP.NET Core's own instrumentation already publishes http.server.request.duration by
            // route and status, which is why this server does not publish a second latency metric
            // that would say the same thing under a name only we use.
            .AddAspNetCoreInstrumentation()
            // Two meters, because Boltway.Storage.EntityFrameworkCore cannot reference the
            // authorization server - the dependency runs the other way, which is what lets a
            // customer replace storage without taking the server with it. One meter per
            // instrumented library is also what OpenTelemetry asks for.
            .AddMeter(AuthorizationServerMetrics.MeterName)
            .AddMeter(StorageMetrics.MeterName)
            // GC, thread pool and working set. The one instrumentation taken from Grafana's .NET
            // distribution rather than the distribution itself - `Grafana.OpenTelemetry` bundles
            // this, but the package carrying ASP.NET Core instrumentation with it also carries
            // AWS, Cassandra, Elasticsearch and Redis, which is dependency surface this image has
            // no use for.
            //
            // It earns its place here because Argon2id is configured m=19456, and the ~19 MiB per
            // login in flight that buys is the sizing decision this deployment actually rests on.
            // That number is in compose.yml as a measurement taken once; this is the same number
            // as a series, so the next person does not have to take it on trust.
            .AddRuntimeInstrumentation())
        // The sentence, not its template. `IncludeFormattedMessage` is false by default -
        // measured against 1.17.0 rather than read off a changelog - and false means the body of
        // every exported record is `boltway-auth · realm {Realm}` with the values only in
        // the attributes beside it. CloudLoggingFormatter above writes the rendered sentence
        // *and* the named properties, and a second log surface that drops half of that is the
        // one somebody opens first and learns to trust less.
        //
        // This call is not what turns logging on - UseOtlpExporter does that on its own, measured
        // - it only carries the options. Without it the export still happens, just unreadably.
        .WithLogging(configureBuilder: null, configureOptions: o =>
        {
            o.IncludeFormattedMessage = true;
            o.IncludeScopes = true;
        })
        // `UseOtlpExporter` rather than an `AddOtlpExporter` per signal, and the difference is a
        // URL path rather than a preference.
        //
        // With the per-signal calls the endpoint has to carry `/v1/{signal}` itself - the .NET
        // exporter's own README: "When using OtlpExportProtocol.HttpProtobuf, the full URL MUST
        // be provided, including the signal-specific path v1/{signal}." One
        // OTEL_EXPORTER_OTLP_ENDPOINT cannot then serve both traces and metrics, so a vendor
        // gateway that takes a base URL needs a variable per signal, and the failure when it does
        // not get one is a 404 at the collector: nothing throws here, nothing is logged, and the
        // deployment looks exactly like tracing was never switched on.
        //
        // UseOtlpExporter appends the path from a base URL instead. Measured against a listener
        // that records what it is called with: one base URL and `http/protobuf` produced POSTs to
        // /v1/traces, /v1/metrics and /v1/logs, each carrying the Authorization header from
        // OTEL_EXPORTER_OTLP_HEADERS.
        //
        // **It also enables logging, and that is a behaviour change for anyone already setting
        // this variable.** Upstream: "Calling UseOtlpExporter automatically enables logging,
        // metrics, and tracing" - and unlike metrics and tracing, logs need no source or meter
        // enabled, so records start leaving the process the moment the endpoint is set. That is
        // wanted here: Docker deletes a container's logs with the container, so every deploy
        // takes the evidence of whatever it was fixing. It is still a thing to have decided
        // rather than discovered on a bill.
        //
        // It cannot be combined with AddOtlpExporter - that throws NotSupportedException - so if
        // a signal ever needs its own endpoint, this whole block goes back to per-signal calls
        // with per-signal variables, not one of each.
        .UseOtlpExporter();
}

var app = builder.Build();

// Somebody has to be able to sign in, and nothing else here creates an account: there is no
// registration endpoint, and federated sign-in refuses an unknown identity by default. Without
// this the first deployment comes up healthy with no way in at all.
//
// The password is generated rather than taken as an argument - an argument is visible in the
// process list and in shell history - and printed once, to be moved into a vault by hand.
// Somebody has to be able to sign in, and nothing else here creates an account: there is no
// registration endpoint, and federated sign-in refuses an unknown identity by default. Without
// this the first deployment comes up healthy with no way in at all.
//
// The three verbs below parse arguments and print; every rule they used to hold now lives in
// `UserAdministration`, because the moment an HTTP admin surface exists these become the second
// implementation of operations that already have one - and the half that drifts first is the part
// nobody sees from the outside.
if (args is [ "new-user", var handle, ..])
{
    await using var userScope = app.Services.CreateAsyncScope();
    var administration = userScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = userScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    // Positional-but-unordered: whichever trailing argument has an `@` is the address and the
    // other is the role. Two optional positionals in a fixed order is the shape where somebody
    // types `new-user ada founder` and silently creates an account whose email is "founder".
    var rest = args[2..];
    var email = Array.Find(rest, a => a.Contains('@', StringComparison.Ordinal));
    var newRole = Array.Find(rest, a => !a.Contains('@', StringComparison.Ordinal));

    var created = await administration.CreateAsync(
        Actor.Cli, realm, handle, email, newRole, CancellationToken.None);

    Console.WriteLine($"handle   {created.Handle}");
    Console.WriteLine($"subject  {created.Subject}");
    if (created.Email is not null) Console.WriteLine($"email    {created.Email}");
    Console.WriteLine($"role     {created.Role ?? "(none)"}");
    Console.WriteLine($"password {created.Password}");
    Console.WriteLine();
    Console.WriteLine("Printed once. Put it in the vault; this command cannot show it again.");

    // An account with no role gets a token with no `role` claim, and a resource server reading one
    // will fall back to whatever it treats as least privileged. Said here rather than left to be
    // discovered as "the knowledge base is empty" on the day of a demo.
    if (created.Role is null)
    {
        Console.WriteLine();
        Console.WriteLine(
            "No role set, so this account's tokens carry no `role` claim. Set one with "
            + $"`set-role {created.Handle} <role>`.");
    }

    return;
}

// People forget passwords, and `new-user` prints one exactly once. Without this the only way back
// in was to run `new-user` again - which mints a *new* subject, so it does not reset anything: it
// creates a second account sharing the handle, orphaning the first one's consent grants and refresh
// token families while a sign-in by username picks whichever the store happens to return.
//
// **It takes no password.** `UserAdministration` generates one and has no parameter for anything
// else, which is what keeps that true of every future caller rather than only of this one.
if (args is [ "set-password", var who, ..])
{
    await using var passwordScope = app.Services.CreateAsyncScope();
    var administration = passwordScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = passwordScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    var reset = await administration.ResetPasswordAsync(Actor.Cli, realm, who, CancellationToken.None);

    if (reset.Status is AdministrationStatus.NoSuchAccount)
    {
        Console.Error.WriteLine($"No account with handle '{who}'.");
        Environment.Exit(1);
        return;
    }

    if (reset.Status is AdministrationStatus.Gone)
    {
        // The account was found a moment ago, so this means it was removed in between - rare, and
        // worth an exit code rather than a printed password nobody can use.
        Console.Error.WriteLine($"'{who}' could not be updated; it may have just been removed.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"handle   {who}");
    Console.WriteLine($"subject  {reset.Subject}");
    Console.WriteLine($"password {reset.Password}");
    Console.WriteLine();
    Console.WriteLine("Printed once. Put it in the vault; this command cannot show it again.");
    Console.WriteLine();

    // Said because the opposite is the reasonable guess, and guessing wrong here means believing a
    // stolen session is over when it is not. Access tokens are signed, not looked up, so nothing
    // can withdraw one before it expires; refresh tokens are derived from a key this did not touch.
    Console.WriteLine(
        "Sessions and refresh tokens already issued keep working. This changes what the sign-in "
        + "form accepts, nothing else.");
    return;
}

// Promotions happen, and a role that could only be set at creation would be a default rather than
// an authorization model.
// The role table, as five verbs. `roles` reads; the rest write, and each one prints what it did
// rather than a bare success, because "what does editor stand for now" is the question the next
// person asks and a shell that answered nothing sends them to the database.
if (args is ["roles", ..])
{
    await using var listScope = app.Services.CreateAsyncScope();
    var administration = listScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = listScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    var defined = await administration.ListRolesAsync(realm, CancellationToken.None);

    if (defined.Count == 0)
    {
        // Not silence. An empty table is the state where nobody can be given a role at all, and a
        // command that printed nothing reads as "it worked" rather than "there is nothing here".
        Console.WriteLine("No roles defined. `new-role <id>` defines one.");
        return;
    }

    foreach (var role in defined)
    {
        var permissions = role.Permissions.Count == 0
            ? "(nothing)"
            : string.Join(' ', role.Permissions.Order(StringComparer.Ordinal));

        Console.WriteLine($"{role.Id,-16} {role.Name,-24} {permissions}");
    }

    return;
}

if (args is ["service-account", var svcHandle, ..])
{
    await using var svcScope = app.Services.CreateAsyncScope();
    var administration = svcScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = svcScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    try
    {
        var created = await administration.CreateServiceAccountAsync(
            Actor.Cli, realm, svcHandle, args[2..], CancellationToken.None);

        if (created.Status is AdministrationStatus.NoSuchAccount)
        {
            Console.Error.WriteLine($"no account `{svcHandle}` in realm `{realm.OrDefault.Value}`.");
            Environment.Exit(1);
            return;
        }

        Console.WriteLine($"client_id     {created.ClientId}");
        Console.WriteLine($"client_secret {created.Secret}");
        Console.WriteLine();

        // Said here rather than left to a manual, because this is the one moment it is true and
        // the reader is looking at the value while they read it.
        Console.WriteLine("The secret is shown once and is not stored. Run this again to rotate it.");
        Console.WriteLine($"It acts as `{svcHandle}` and can do whatever that account's roles allow.");
    }
    catch (ArgumentException refused)
    {
        Console.Error.WriteLine(refused.Message);
        Environment.Exit(1);
    }

    return;
}

if (args is [("service-account-off" or "service-account-on") and var svcToggle, var svcSubject, ..])
{
    await using var toggleScope = app.Services.CreateAsyncScope();
    var administration = toggleScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = toggleScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    var turningOn = svcToggle is "service-account-on";

    var result = await administration.SetServiceAccountEnabledAsync(
        Actor.Cli, realm, svcSubject, turningOn, CancellationToken.None);

    if (result.Status is AdministrationStatus.NoSuchAccount)
    {
        Console.Error.WriteLine($"`{svcSubject}` has no service account.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"{result.ClientId} {(turningOn ? "can obtain tokens again" : "can no longer obtain tokens")}.");

    if (!turningOn)
    {
        // The caveat that has to travel with the action. A service account holds no refresh token,
        // so the window is one access-token lifetime and nothing can extend it - but it is not
        // zero, and somebody who reads "off" as "off now" will be wrong for that long.
        Console.WriteLine("Tokens already issued keep working until they expire.");
    }

    return;
}

if (args is ["delete-service-account", var svcGone, ..])
{
    await using var deleteScope = app.Services.CreateAsyncScope();
    var administration = deleteScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = deleteScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    var result = await administration.DeleteServiceAccountAsync(
        Actor.Cli, realm, svcGone, CancellationToken.None);

    if (result.Status is AdministrationStatus.NoSuchAccount)
    {
        Console.Error.WriteLine($"`{svcGone}` has no service account.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"{result.ClientId} is gone. Tokens already issued keep working until they expire.");
    return;
}

if (args is ["new-role", var newRoleId, ..])
{
    await using var roleScope = app.Services.CreateAsyncScope();
    var administration = roleScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = roleScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    // Positional-but-unordered, the same shape `new-user` uses: a permission is snake_case and a
    // display name is not, so whichever trailing argument carries no underscore is the name. Two
    // optional positionals in a fixed order is where somebody types `new-role editor docs_read` and
    // silently creates a role called "docs_read".
    var rest = args[2..];
    var permissions = Array.FindAll(rest, a => a.Contains('_', StringComparison.Ordinal));
    var displayName = Array.Find(rest, a => !a.Contains('_', StringComparison.Ordinal));

    try
    {
        var created = await administration.CreateRoleAsync(
            Actor.Cli, realm, newRoleId, displayName, permissions, CancellationToken.None);

        Console.WriteLine($"id          {created.Id}");
        Console.WriteLine($"name        {created.Name}");
        Console.WriteLine($"permissions {(created.Permissions.Count == 0
            ? "(nothing)"
            : string.Join(' ', created.Permissions.Order(StringComparer.Ordinal)))}");
        Console.WriteLine();
        Console.WriteLine("Nobody holds it yet. `set-roles <handle> " + created.Id + "` assigns it.");
    }
    catch (Exception refused) when (refused is ArgumentException or InvalidOperationException)
    {
        Console.Error.WriteLine(refused.Message);
        Environment.Exit(1);
    }

    return;
}

if (args is ["set-role-name", var namedRole, var newName, ..])
{
    await using var nameScope = app.Services.CreateAsyncScope();
    var administration = nameScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = nameScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    if (!await administration.SetRoleNameAsync(Actor.Cli, realm, namedRole, newName, CancellationToken.None))
    {
        Console.Error.WriteLine($"No role `{namedRole}` in this realm.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"id          {namedRole}");
    Console.WriteLine($"name        {newName}");
    Console.WriteLine();

    // The whole reason the id and the name are separate fields.
    Console.WriteLine("No token changes. Nothing matches on a name.");
    return;
}

if (args is ["set-role-permissions", var permissionedRole, ..])
{
    await using var permissionScope = app.Services.CreateAsyncScope();
    var administration = permissionScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = permissionScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    try
    {
        if (!await administration.SetRolePermissionsAsync(
            Actor.Cli, realm, permissionedRole, args[2..], CancellationToken.None))
        {
            Console.Error.WriteLine($"No role `{permissionedRole}` in this realm.");
            Environment.Exit(1);
            return;
        }
    }
    catch (ArgumentException malformed)
    {
        Console.Error.WriteLine(malformed.Message);
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"id          {permissionedRole}");
    Console.WriteLine($"permissions {(args.Length > 2 ? string.Join(' ', args[2..]) : "(nothing)")}");
    Console.WriteLine();
    Console.WriteLine("Replaced, not added to. Tokens already issued carry the old set until they expire.");
    return;
}

if (args is ["delete-role", var doomedRole, ..])
{
    await using var deleteScope = app.Services.CreateAsyncScope();
    var administration = deleteScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = deleteScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    if (!await administration.DeleteRoleAsync(Actor.Cli, realm, doomedRole, CancellationToken.None))
    {
        Console.Error.WriteLine($"No role `{doomedRole}` in this realm.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"deleted  {doomedRole}");
    Console.WriteLine();
    Console.WriteLine(
        "Every assignment of it went too. Accounts that held only this one now hold none, and their "
        + "tokens keep it until they expire.");
    return;
}

if (args is ["set-roles", var multiTarget, var firstRole, ..])
{
    await using var rolesScope = app.Services.CreateAsyncScope();
    var administration = rolesScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = rolesScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    // `-` clears, the same convention every other setter here uses, and for the same reason: an
    // empty argument list is what a shell hands over when a variable was not set.
    string[] wanted = firstRole == "-" ? [] : args[2..];

    try
    {
        var change = await administration.SetRolesAsync(
            Actor.Cli, realm, multiTarget, wanted, CancellationToken.None);

        if (change.Status is not AdministrationStatus.Ok)
        {
            Console.Error.WriteLine($"No account with handle '{multiTarget}'.");
            Environment.Exit(1);
            return;
        }

        Console.WriteLine($"handle   {multiTarget}");
        Console.WriteLine($"subject  {change.Subject}");
        Console.WriteLine($"roles    {(wanted.Length == 0 ? "(cleared)" : string.Join(' ', wanted))}");
        Console.WriteLine();
        Console.WriteLine("Replaced, not added to. Tokens already issued keep the old set until they expire.");
    }
    catch (InvalidOperationException undefined)
    {
        // Names the id that does not exist, which is the next thing to type.
        Console.Error.WriteLine(undefined.Message);
        Environment.Exit(1);
    }

    return;
}

if (args is [ "set-role", var target, var assigned, ..])
{
    await using var roleScope = app.Services.CreateAsyncScope();
    var administration = roleScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = roleScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    // `-` clears it. An empty string would too, but an empty string is also what a shell hands
    // over when a variable was not set, and "the deploy silently removed everyone's role" is not a
    // thing this command should be able to do by accident.
    var requested = assigned == "-" ? null : assigned;

    var change = await administration.SetRoleAsync(Actor.Cli, realm, target, requested, CancellationToken.None);

    if (change.Status is not AdministrationStatus.Ok)
    {
        // Exit code, not just a sentence. This runs as a Cloud Run job, and a job that prints a
        // complaint and succeeds is one whose failure is only visible to somebody reading logs.
        Console.Error.WriteLine($"No account with handle '{target}'.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"handle   {target}");
    Console.WriteLine($"subject  {change.Subject}");
    Console.WriteLine($"role     {change.Role ?? "(cleared)"}");
    Console.WriteLine();
    Console.WriteLine("Tokens already issued keep the old role until they expire.");
    return;
}

// The rule this closes was enforced and unsettable: both sign-in paths refuse an account whose
// `disabled_at` is set, and nothing in the library, the CLI or any store method could set it. The
// only way to lock somebody out was SQL against a live directory.
//
// It stops the next sign-in and nothing else. Access tokens are signed rather than looked up, so an
// issued one keeps working until it expires - said here because "I disabled them" is otherwise
// heard as "they are out", which during an incident is the wrong belief to hold.
if (args is [ "disable" or "enable", var subjectHandle, ..])
{
    await using var enableScope = app.Services.CreateAsyncScope();
    var administration = enableScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = enableScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;
    var clock = enableScope.ServiceProvider.GetRequiredService<TimeProvider>();

    var shouldEnable = args[0] == "enable";

    var result = await administration.SetEnabledAsync(
        Actor.Cli, realm, subjectHandle, shouldEnable, clock.GetUtcNow(), CancellationToken.None);

    if (result.Status is not AdministrationStatus.Ok)
    {
        Console.Error.WriteLine($"No account with handle '{subjectHandle}'.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"handle   {subjectHandle}");
    Console.WriteLine($"subject  {result.Subject}");
    Console.WriteLine($"state    {(result.DisabledAt is null ? "enabled" : "disabled since " + result.DisabledAt)}");

    if (!shouldEnable)
    {
        Console.WriteLine();
        Console.WriteLine(
            "This stops the next sign-in. Access tokens already issued are signed rather than "
            + "looked up, so they keep working until they expire.");
    }

    return;
}

// `email_verified` is in every token this server has ever issued and nothing set it, so a resource
// server trusting the claim was reading a constant. This is what can make it mean something.
//
// One command for both halves, because they are one fact: changing an address while leaving the
// flag true carries a proof about the old address onto the new one.
if (args is [ "set-email", var emailHandle, var address, ..])
{
    await using var emailScope = app.Services.CreateAsyncScope();
    var administration = emailScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = emailScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

    // `-` clears it, the same convention `set-role` uses, and for the same reason: an empty string
    // is what a shell hands over when a variable was not set.
    var newEmail = address == "-" ? null : address;

    // Opt-in, and it is an operator asserting the address rather than this server checking it. The
    // flow that checks - a link sent to the address - is not built.
    var verified = args.Contains("--verified");

    var result = await administration.SetEmailAsync(
        Actor.Cli, realm, emailHandle, newEmail, verified, CancellationToken.None);

    if (result.Status is not AdministrationStatus.Ok)
    {
        Console.Error.WriteLine($"No account with handle '{emailHandle}'.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"handle   {emailHandle}");
    Console.WriteLine($"subject  {result.Subject}");
    Console.WriteLine($"email    {result.Email ?? "(cleared)"}");
    Console.WriteLine($"verified {result.Verified}");

    if (newEmail is not null && !result.Verified)
    {
        Console.WriteLine();
        Console.WriteLine(
            "Tokens will carry `email_verified: false`. Pass --verified only if somebody has "
            + "actually proven this address belongs to them.");
    }

    return;
}

// E-30. Revokes grants, which kills every refresh chain descended from them - the refresh handler
// loads the grant and refuses when it is not active. It does *not* reach an access token already
// issued, for the same reason `disable` does not, and the command says so rather than letting
// "I signed them out" be heard as "they are out".
if (args is [ "revoke-sessions", var sessionsHandle, ..])
{
    await using var sessionsScope = app.Services.CreateAsyncScope();
    var administration = sessionsScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = sessionsScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;
    var clock = sessionsScope.ServiceProvider.GetRequiredService<TimeProvider>();

    var result = await administration.RevokeSessionsAsync(
        Actor.Cli, realm, sessionsHandle, clock.GetUtcNow(), CancellationToken.None);

    if (result.Status is not AdministrationStatus.Ok)
    {
        Console.Error.WriteLine($"No account with handle '{sessionsHandle}'.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"handle   {sessionsHandle}");
    Console.WriteLine($"subject  {result.Subject}");
    Console.WriteLine($"revoked  {result.Revoked} grant(s)");
    Console.WriteLine();
    Console.WriteLine(
        "Refresh tokens stop at their next rotation. Access tokens already issued are signed "
        + "rather than looked up, so they keep working until they expire. This did not disable "
        + "the account or change its password.");

    return;
}

// E-31. The one irreversible command here, and the only one that asks for a flag.
//
// Not because a flag is protection - anyone typing this is typing it deliberately - but because
// the flag is where the sentence "this cannot be undone" gets read. `disable` is the reversible
// operation and it is one word away; somebody reaching for the wrong one should find out here.
if (args is [ "anonymise", var anonHandle, ..])
{
    if (!args.Contains("--yes-i-mean-it"))
    {
        Console.Error.WriteLine(
            "anonymise is irreversible: the username becomes a tombstone, and the email, password, "
            + "role and every linked upstream identity are gone. The account row stays, so the audit "
            + "trail keeps its referent.");
        Console.Error.WriteLine();
        Console.Error.WriteLine("If that is what you want: anonymise " + anonHandle + " --yes-i-mean-it");
        Console.Error.WriteLine("If you want it reversible: disable " + anonHandle);
        Environment.Exit(1);
        return;
    }

    await using var anonScope = app.Services.CreateAsyncScope();
    var administration = anonScope.ServiceProvider.GetRequiredService<UserAdministration>();
    var realm = anonScope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;
    var clock = anonScope.ServiceProvider.GetRequiredService<TimeProvider>();

    var result = await administration.AnonymiseAsync(
        Actor.Cli, realm, anonHandle, clock.GetUtcNow(), CancellationToken.None);

    if (result.Status is not AdministrationStatus.Ok)
    {
        Console.Error.WriteLine($"No account with handle '{anonHandle}'.");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"was      {anonHandle}");
    Console.WriteLine($"subject  {result.Subject}");
    Console.WriteLine($"handle   {result.Handle}");
    Console.WriteLine($"revoked  {result.Revoked} grant(s)");
    Console.WriteLine();
    Console.WriteLine(
        "The account row is still there and disabled, so audit entries and grant history keep "
        + "their referent. Access tokens already issued keep working until they expire.");

    return;
}

// README's production checklist has said "Run the doctor. ConfigurationDoctor.Run(options, keyRing)"
// for as long as ConfigurationDoctor has existed, and there was no way to run it: zero callers
// outside src/ and tests/, no endpoint, and not a verb. An instruction with nothing behind it is
// the same defect as an advertised endpoint that 404s, on the operator's surface instead of the
// protocol's.
//
// Here rather than beside `new-key`, because it needs the configured graph - which is the point:
// it reports what this deployment's own settings and key ring add up to, not what is legal in
// general.
//
// Exits non-zero on any Fail so a deploy can gate on it, and prints every check rather than
// stopping at the first, for the same reason MapBoltwayAuthorizationServer reports all missing
// services at once. Warn does not fail: distinguishing "wrong" from "worth a look" is the whole
// job, and collapsing the two makes it a thing people stop running.
if (args is ["doctor", ..])
{
    // GetRequiredService<AuthorizationServerOptions>, not IOptions<> - AddBoltwayAuthorizationServer
    // registers the configured instance with AddSingleton rather than through the options pattern,
    // so IOptions<> hands back a fresh default. Measured: the doctor then reported "The issuer is
    // required" against a host whose ISSUER was set, which is a diagnostic lying about the thing it
    // exists to diagnose. Every other call site in the repository resolves it this way.
    var report = ConfigurationDoctor.Run(
        app.Services.GetRequiredService<AuthorizationServerOptions>(),
        app.Services.GetRequiredService<SigningKeyRing>());

    foreach (var check in report)
    {
        Console.WriteLine($"{check.Status,-12} {check.Id,-26} {check.Title}");

        if (check.Detail is { Length: > 0 })
        {
            Console.WriteLine($"{"",-12} {check.Detail}");
        }
    }

    Environment.Exit(report.Any(c => c.Status is DoctorStatus.Fail) ? 1 : 0);
    return;
}

// Positional, like every other verb. `args.Contains("migrate")` matched the token anywhere in
// argv, so a stray one in a position nobody intended applied migrations - which is exactly what
// the comment at the top says making this a command was supposed to prevent.
if (args is ["migrate", ..])
{
    await using var scope = app.Services.CreateAsyncScope();
    var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AuthDbContext>>();
    await using var db = await factory.CreateDbContextAsync();

    var pending = (await db.Database.GetPendingMigrationsAsync()).ToList();
    await db.Database.MigrateAsync();

    Console.WriteLine(pending.Count == 0
        ? "Schema is current; nothing to apply."
        : $"Applied {pending.Count} migration(s): {string.Join(", ", pending)}");

    // The roles a deployment declares, created here if absent - and only here.
    //
    //   SEED_ROLES='{"member":{"name":"Member","permissions":"docs_read"}}'
    //
    // In the migrate step rather than at server startup, for the same reason the migrations
    // themselves are (C-29): one deliberate write path, run once per deploy, never raced by
    // replicas coming up together. And create-if-absent rather than converge-to-config, because
    // after bootstrap the definitions belong to the admin surface - SeedRolesAsync has the whole
    // argument. So standing up a fresh directory is `migrate` and nothing else, while a deploy
    // over a live one changes no role anybody has touched.
    //
    // The vocabulary in the value is the deployment's own: permission names mean whatever its
    // resource servers say they mean, and this server stores them without interpreting them.
    if (config["SEED_ROLES"] is { Length: > 0 } || config["DEFAULT_ROLES"] is { Length: > 0 })
    {
        var administration = scope.ServiceProvider.GetRequiredService<UserAdministration>();
        var realm = scope.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().Realm;

        if (config["SEED_ROLES"] is { Length: > 0 } seedJson)
        {
            try
            {
                var seeded = await administration.SeedRolesAsync(
                    Actor.Cli, realm, ParseRoleSeeds(seedJson), CancellationToken.None);

                foreach (var outcome in seeded)
                {
                    Console.WriteLine(outcome.Created
                        ? $"Defined role `{outcome.Id}`."
                        : $"Role `{outcome.Id}` is already defined; left as it is.");
                }
            }
            catch (Exception refused)
                when (refused is ArgumentException or InvalidOperationException or JsonException)
            {
                Console.Error.WriteLine(refused.Message);
                Environment.Exit(1);
                return;
            }
        }

        // After seeding, so the normal arrangement - DEFAULT_ROLES naming a role SEED_ROLES
        // defines - passes on the deploy that introduces both. What this catches is the typo, and
        // it catches it in a deploy log instead of at the first account creation, which is the
        // only other place the store's own refusal would surface.
        if (config["DEFAULT_ROLES"] is { Length: > 0 } defaulted)
        {
            foreach (var id in defaulted.Split(
                ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (await administration.FindRoleAsync(realm, id, CancellationToken.None) is null)
                {
                    Console.Error.WriteLine(
                        $"DEFAULT_ROLES names `{id}`, which this realm does not define. Every "
                        + "account created without a role would fail at the default assignment. "
                        + "Seed it with SEED_ROLES, define it with `new-role`, or drop it.");
                    Environment.Exit(1);
                    return;
                }
            }

            Console.WriteLine($"Default role(s) for new accounts: {defaulted} — all defined.");
        }
    }

    return;
}

// The same failure as the guard at the top, arriving from the other side.
//
// That guard proves the first token is a verb this host answers to. It does not prove the
// arguments after it matched anything: every verb taking a positional is dispatched by a list
// pattern that requires the elements to be there, so `set-role ada` - a real verb, one argument
// short - passes the guard, matches no block, and falls through to `app.RunAsync()` below.
// Measured: that boots a full authorization server holding the same SIGNING_KEYS and DATABASE_URL
// as the real one, with its own Data Protection key ring that no volume persists, listening and
// serving metadata. `docker compose run --rm auth set-role ada` is how a person meets it, and
// `--rm` never fires because the process never exits.
//
// Reaching here with a known verb can only mean the arguments were wrong, because every block
// above returns. So it is refused the same way an unknown verb is - usage, exit 2 - rather than
// serving. Placed after the last block and before anything binds a port.
if (args is [var attempted, ..] && subcommands.Contains(attempted, StringComparer.Ordinal))
{
    Console.Error.WriteLine($"`{attempted}` was not given the arguments it takes.");
    Console.Error.WriteLine();
    Console.Error.WriteLine(usage);
    Environment.Exit(2);
    return;
}

// First, before anything reads the remote address.
//
// Every way this server is deployed puts a proxy in front of it - Cloud Run's front end, or
// Caddy on the compose file - and both hand the application a connection from themselves.
// Without this, `RemoteIpAddress` is the proxy on every request, and `LoginThrottle`'s
// per-source limit puts the entire deployment in one bucket. Its own options say so:
//
//     behind a reverse proxy or a load balancer that does not populate it is the *proxy's*
//     address - so every user in the deployment shares one bucket, thirty attempts across all
//     of them exhausts it, and the per-source limit becomes an outage
//
// That was written in the library and never done in the host, which is a rule that exists on
// one surface and not the other. It was live on Cloud Run too, not only on a self-hosted path.
//
// The options come from ProxyHeaders.BehindOneProxy rather than an object literal here, and
// that is not tidying. Written inline, the two lines that clear the known-proxy lists were
// `KnownIPNetworks = { }` and `KnownProxies = { }` -- collection initializers, meaning "call Add
// zero times", clearing nothing. The defaults survived, the proxy check stayed on, Caddy's bridge
// address failed it, and every forwarded header was dropped. Nothing caught it because no test
// project references this host: the only thing that ever compiled this file was the Docker build,
// and compiling a no-op tells you nothing.
//
// The rest of what was written here is now on the function, where a test can hold it.
// The hop count is a deployment's topology, not this image's. BehindOneProxy has taken it as a
// parameter all along and its own XML doc calls it "the number to change if a CDN is ever put in
// front" - nothing here read a value for it, so the sentence described a knob no operator could
// reach. Getting it wrong is silent: behind a CDN plus a proxy, a limit of 1 attributes every
// request to the proxy's neighbour and the per-source login limit degrades to per-deployment.
app.UseForwardedHeaders(ProxyHeaders.BehindOneProxy(Hops(config)));

// The stylesheet the pages link, served from this origin because `default-src 'self'` is the
// only place it can come from. Files only - this serves what exists under wwwroot and never
// falls back to an index, which matters more here than it sounds: a SPA-style fallback would
// answer `200 text/html` for an unmatched `/.well-known/*`, and an MCP client probing discovery
// URLs in sequence ends at a parse error instead of moving on from a 404.
//
// A deployment with its own design mounts a volume over /app/wwwroot/css and points
// UI_STYLESHEETS at what it put there. No rebuild, no fork.
app.UseStaticFiles();

app.UseAuthentication();

// The bearer gate, after routing and before the endpoints. On this server every route is
// AllowAnonymous - the admin surface gates itself, because an authorization policy would
// authenticate against whichever scheme the host made default and that is how a session cookie ends
// up authenticating the directory (N-17) - so what this does here is populate the principal when a
// token is presented, and challenge nothing. See BearerAuthenticationMiddleware.
//
// Behind the same flag as the registration above, and `bearerSurface` exists so the two cannot
// disagree again. With neither bearer surface routed there is nothing on this server that reads a
// bearer principal, so the middleware would be validating tokens for no reader - and, before this
// was a shared variable, failing to resolve its options and taking the whole process down with it.
app.UseRouting();

if (bearerSurface)
{
    app.UseBoltwayProtectedResource();
}

// Before the endpoints, because the pages read `CultureInfo.CurrentUICulture` while they render and
// this is what sets it. After UseAuthentication only because nothing here depends on the order;
// what matters is that it is upstream of MapBoltwayAuthorizationServer.
//
// Registered unconditionally: with no translations configured the options hold one culture and the
// middleware resolves it on every request, which is the same answer the pages gave before this
// existed.
app.UseRequestLocalization();

app.MapBoltwayAuthorizationServer();

// The RFC 9728 document for the administrative resource, which this server's own 401s point at.
//
// Behind `bearerSurface` because `MapProtectedResourceMetadata` resolves `ProtectedResource` from
// the container, and that is registered under the same flag - mapping it unconditionally is the
// startup failure `bearerSurface` was introduced to end, reached from the other direction.
//
// It was never mapped. Every challenge this server sent carried
// `resource_metadata="…/.well-known/oauth-protected-resource/admin"` and that URL answered 404,
// which is N-06 - advertised and absent - on the discovery surface CLAUDE.md says belongs to this
// library rather than to any connector. A client doing the thing the challenge tells it to do
// reached a dead end, and the only reason nobody hit it is that the admin BFF is configured with
// its authority rather than discovering it. Measured on the running server, both halves: the header
// names that URL, and the URL 404s.
if (bearerSurface)
{
    app.MapProtectedResourceMetadata();
}

// Liveness only. Deliberately not a readiness probe that touches the database: a probe that
// fails when Postgres blinks takes the whole server out of rotation for a dependency that
// most requests here do not need.
// `build` is the sha the image was built from, baked in by the Dockerfile's BUILD_SHA arg, and it
// is here so that "is the thing serving the thing we deployed" is answerable from outside the
// host. Without it a deploy that pinned an old tag, or one where the container was never
// recreated, is indistinguishable from a correct one: every other check - the issuer, the scopes,
// the policy, the challenge - passes identically on both. That happened, and cost an hour of
// looking at a green deploy while a two-commit-old build served the pages.
//
// Omitted rather than guessed when the image was built without it, because a health endpoint
// inventing a version is worse than one that admits it does not know.
var build = config["BUILD_SHA"];

// The ordered half of `build`: commits behind it on the first-parent chain, from ci.yml's
// `git rev-list --count`. The sha identifies a build and orders nothing; this orders builds and
// identifies nothing - "prod serves b1230, main built b1234" says behind by four merges, which
// no pair of shas can. An int on the wire because comparison is its whole job, and a value that
// does not parse is omitted under the same rule as `build`.
int? buildNumber = int.TryParse(
    config["BUILD_NUMBER"],
    System.Globalization.NumberStyles.None,
    System.Globalization.CultureInfo.InvariantCulture,
    out var counted) ? counted : null;

// `AllowAnonymous` is load-bearing, and it was missing for as long as this endpoint has existed.
//
// The bearer middleware challenges any endpoint that does not carry it - see
// BearerAuthenticationMiddleware, where that is the deliberate design, because an authorization
// policy would authenticate against whichever scheme the host made default and that is how a
// session cookie ends up authenticating the directory (N-17). The comment at `UseRouting` above
// asserts "on this server every route is AllowAnonymous". That was true of every route the library
// maps and false of the two lines below it, and nothing said so, because no bearer surface was ever
// turned on in a deployment that also had a healthcheck.
//
// Turning `ADMIN_API=true` on in production is what found it: `/health` answered 401 with a Bearer
// challenge, `verify.sh` failed with "never answered", and the container's own HEALTHCHECK -
// `curl -fsS /health` - had begun failing on the same response, so the authorization server was
// serving every page correctly while reporting itself unhealthy. A liveness probe that a
// configuration flag can silently make private is worse than no probe: it does not fail loudly, it
// reports the wrong answer to whatever is deciding whether to keep the process.
//
// `MapStoreReadiness` below already carries it, in the library, which is why `/health/ready` kept
// answering 200 through all of this.
app.MapGet("/health", () =>
{
    // A dictionary rather than the anonymous-object ternary this grew from: with two optional
    // fields that was becoming a truth table repeating the constant fields in every branch.
    var health = new Dictionary<string, object>(StringComparer.Ordinal)
    {
        ["ok"] = true,
        ["issuer"] = issuer,
    };

    if (build is { Length: > 0 })
    {
        health["build"] = build;
    }

    if (buildNumber is { } n)
    {
        health["number"] = n;
    }

    return Results.Json(health);
})
    .AllowAnonymous();

// And the other question, on its own route, because the sentence above is about a consumer that
// *rotates* - Docker, a load balancer - while a monitor rotates nothing and pages a person. With
// only the line above, an uptime check stays green through a total database outage while every
// sign-in fails, which is the shape of monitoring that is worse than none.
//
// One line here on purpose: everything it does is in StoreReadiness, in the library, under twelve
// tests. Nothing in this file is reachable from a test project - the Docker build is the only thing
// that compiles it - so logic that lands here is logic nobody can check.
app.MapStoreReadiness();

// Not a refusal, because the whole point of this path is a developer running the host with no
// database server. A warning, because the previous wording - "a file, for a single instance" -
// read as a supported deployment, and a single instance still serves concurrent requests. The
// message names the failure so that whoever meets it in production logs recognises it.
if (sqlite is { Length: > 0 })
{
    app.Logger.LogWarning(
        "Storage is SQLite at {Path}. This is a development configuration: the SQLite provider does "
        + "not meet the concurrent-redemption requirement and intermittently fails a redemption with "
        + "'cannot start a transaction within a transaction' under concurrent load. Set DATABASE_URL "
        + "for anything a person other than you will sign in to.",
        sqlite);
}

if (app.Logger.IsEnabled(LogLevel.Information))
{
    var store = postgres is { Length: > 0 } ? "postgres" : $"sqlite {sqlite}";
    var google = googleClientId is { Length: > 0 } ? "on" : "off";

    app.Logger.LogInformation(
        "boltway authorization server · issuer {Issuer} · {Store} · {Resources} resource(s) · google {Google}",
        issuer, store, resources.Count, google);
}

await app.RunAsync();

// ─────────────────────────────────────────────────────────────────────────────

string Required(string key, string what)
{
    var value = config[key];
    if (value is { Length: > 0 }) return value;

    // Named individually rather than collected, because the first thing anyone does with a
    // startup failure is read one line of it.
    throw new InvalidOperationException($"{key} is not set. It is {what}.");
}

// `true` or `false`, and nothing else. The lenient reading - anything that is not "false" is the
// default - fails in the one direction that matters: an operator who typed `flase` to turn an
// endpoint off gets it left on and advertised, having done the work and been told nothing. This
// host refuses to start rather than starting wrong, and a flag is not the place to stop doing
// that.
static bool Flag(IConfiguration config, string key, bool @default)
{
    var value = config[key];
    if (value is not { Length: > 0 }) return @default;

    if (bool.TryParse(value, out var parsed)) return parsed;

    throw new InvalidOperationException($"{key} is `{value}`. It is `true` or `false`.");
}

// Named values rather than a boolean, and refused rather than guessed, on the same reasoning as
// Flag: an operator who typed `cloud_logging` and got the default back has configured nothing and
// been told nothing.
static string LogFormat(IConfiguration config)
{
    var value = config["LOG_FORMAT"];
    if (value is not { Length: > 0 }) return "json";

    return value.Trim().ToLowerInvariant() switch
    {
        "json" => "json",
        "simple" => "simple",
        "cloud-logging" or "cloudlogging" or "gcp" => "cloud-logging",
        _ => throw new InvalidOperationException(
            $"LOG_FORMAT is `{value}`. It is `json` (the default, structured and vendor-neutral), "
            + "`cloud-logging` (the same fields under Google Cloud Logging's names), or `simple` "
            + "(the framework's human-readable console)."),
    };
}

// How many proxies stand in front, for X-Forwarded-For. Refused rather than clamped: a value that
// does not parse is a topology somebody meant to describe, and silently using 1 is how the
// per-source login limit becomes per-deployment without anybody being told.
static int Hops(IConfiguration config)
{
    var value = config["FORWARDED_HOPS"];
    if (value is not { Length: > 0 }) return 1;

    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var hops) || hops < 1)
    {
        throw new InvalidOperationException(
            $"FORWARDED_HOPS is `{value}`. It is a whole number of proxies in front of this server, "
            + "at least 1 — the default. Behind a CDN and a reverse proxy it is 2.");
    }

    return hops;
}

// A duration, or null when unset. One spelling only - a count and a unit, `30s`, `15m`, `24h`,
// `30d` - because the two obvious alternatives each have a silent failure: a bare number leaves
// "seconds or minutes" to whoever reads it next, and TimeSpan.Parse takes `30` as thirty *days*.
static TimeSpan? Duration(IConfiguration config, string key)
{
    var value = config[key];
    if (value is not { Length: > 0 }) return null;

    var text = value.Trim();
    var unit = text.Length > 0 ? char.ToLowerInvariant(text[^1]) : ' ';
    var count = text[..^1];

    if (int.TryParse(count, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0)
    {
        switch (unit)
        {
            case 's': return TimeSpan.FromSeconds(n);
            case 'm': return TimeSpan.FromMinutes(n);
            case 'h': return TimeSpan.FromHours(n);
            case 'd': return TimeSpan.FromDays(n);
            default: break;
        }
    }

    throw new InvalidOperationException(
        $"{key} is `{value}`. It is a positive whole number and a unit — `30s`, `15m`, `24h`, `30d`.");
}

// Named values rather than a boolean, and refused rather than guessed, for the reason above: a
// misspelling here decides whether a password lands on the wire in the clear, and the lenient
// reading resolves it to whichever branch the typo happens to miss.
static SmtpSecurity ParseSmtpSecurity(string? value)
{
    if (value is not { Length: > 0 }) return SmtpSecurity.Auto;

    return value.Trim().ToLowerInvariant() switch
    {
        "auto" => SmtpSecurity.Auto,
        "starttls" => SmtpSecurity.StartTls,
        "implicit" or "implicittls" or "tls" or "ssl" => SmtpSecurity.ImplicitTls,
        "none" => SmtpSecurity.None,
        _ => throw new InvalidOperationException(
            $"SMTP_SECURITY is `{value}`. It is `auto`, `starttls`, `implicit` or `none`. "
            + "Unset is `auto`, which reads the port: 465 is implicit TLS and anything else is "
            + "STARTTLS."),
    };
}

// Every refusal names the client, because a deployment configuring several has to be told which
// line to fix - the whole reason RESOURCES' errors name their key too.
static ConfiguredClient ParseClient(KeyValuePair<string, ClientEntry> entry)
{
    var (id, value) = entry;

    if (!ClientIdentifier.TryParseFromRequest(id, out var clientId))
    {
        throw new InvalidOperationException(
            $"CLIENTS entry `{id}` is not a usable client id. RFC 6749 Appendix A.1: printable "
            + "ASCII, and not longer than the wire allows.");
    }

    List<RegisteredRedirectUri> redirects = [];

    foreach (var raw in (value.RedirectUris ?? string.Empty)
        .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (!RegisteredRedirectUri.TryRegister(raw, out var registered, out var error))
        {
            throw new InvalidOperationException(
                $"CLIENTS entry `{id}` has a redirect URI this server will not register: {raw} ({error}).");
        }

        redirects.Add(registered.Value);
    }

    // A service account never reaches /authorize, so it has no redirect URI and requiring one would
    // mean inventing a URL that must never be used. An ordinary client with none is still refused:
    // for that one, no authorization could ever complete.
    //
    // **And a resource server is a third kind, which this refused outright until it was measured.**
    // RFC 7662 §2.1 requires the introspection endpoint to be authorized, so a resource server that
    // wants revocation to take effect needs a confidential client here - and that client authorizes
    // nobody and acts as nobody. It has no redirect URI for the same reason a service account has
    // none, and no owner because it is not entitled to anybody's token. Neither of the two escape
    // hatches was safe to borrow: a redirect URI that must never be used is a live authorization
    // target for whoever steals the secret, and `owner` would turn a credential whose only job is
    // to ask "is this token live" into one that acts as a person.
    //
    // So the deployment says which it meant, and the guard keeps refusing the mistake.
    if (value.IntrospectionOnly)
    {
        if (redirects.Count > 0)
        {
            throw new InvalidOperationException(
                $"CLIENTS entry `{id}` sets both introspectionOnly and redirectUris. A client that "
                + "only introspects never reaches /authorize, so a redirect URI on it is a target "
                + "nothing needs and anybody holding the secret could aim at. Drop one.");
        }

        if (value.Owner is { Length: > 0 })
        {
            throw new InvalidOperationException(
                $"CLIENTS entry `{id}` sets both introspectionOnly and owner. Asking whether a token "
                + "is still live and acting as an account are different powers, and a client that "
                + "holds the second does not need the first to be granted quietly alongside it. "
                + "Drop one.");
        }
    }
    else if (redirects.Count == 0 && value.Owner is not { Length: > 0 })
    {
        throw new InvalidOperationException(
            $"CLIENTS entry `{id}` registers no redirect URI, so no authorization could ever "
            + "complete for it. Set redirectUris, space separated — or set owner, if this is meant "
            + "to be a service account, or introspectionOnly, if this is a resource server that "
            + "only calls /introspect.");
    }

    if (redirects.Count > 0 && value.Owner is { Length: > 0 })
    {
        throw new InvalidOperationException(
            $"CLIENTS entry `{id}` sets both owner and redirectUris. A client that names an owner "
            + "acts as that account through client_credentials and never reaches /authorize, so a "
            + "redirect URI on it is a promise nothing keeps. Drop one.");
    }

    Sha256Hash? secret = null;

    if (value.SecretSha256 is { Length: > 0 } encoded)
    {
        if (!Sha256Hash.TryFromBytes(Convert.FromBase64String(encoded), out var parsed))
        {
            throw new InvalidOperationException(
                $"CLIENTS entry `{id}` has a secretSha256 that is not 32 bytes. It is base64 of the "
                + "SHA-256 of the secret, not the secret: "
                + "printf %s \"$SECRET\" | openssl dgst -sha256 -binary | base64");
        }

        secret = parsed;
    }

    // Without one there is nothing to authenticate with, and §2.1 is the whole reason this client
    // exists. A public client here would make the endpoint reachable by anybody who learned the id,
    // which is a way to test whether a stolen token is still worth using.
    if (value.IntrospectionOnly && secret is null)
    {
        throw new InvalidOperationException(
            $"CLIENTS entry `{id}` sets introspectionOnly but has no secretSha256. RFC 7662 §2.1 "
            + "requires the introspection endpoint to be authorized, so this client would be unable "
            + "to call the one endpoint it exists for. Mint one with `new-client-secret`.");
    }

    if (value.Owner is not { Length: > 0 } owner)
    {
        return new ConfiguredClient(clientId, value.Name, redirects, secret);
    }

    // Validated here rather than left to AddConfiguredClients, so the message names the CLIENTS
    // entry a person can edit instead of a client id they then have to go and find.
    if (secret is null)
    {
        throw new InvalidOperationException(
            $"CLIENTS entry `{id}` names an owner but has no secretSha256. A client that acts as an "
            + "account must authenticate, or anybody who knows its id can be issued that account's "
            + "token. Mint one with `new-client-secret`.");
    }

    if (!ScopeSet.TryParse(value.Scopes ?? string.Empty, out var scopes, out var scopeError)
        || scopes.IsEmpty)
    {
        throw new InvalidOperationException(
            $"CLIENTS entry `{id}` names an owner but no usable scopes ({scopeError ?? "empty"}). A "
            + "service account is issued exactly these and nothing widens them, so an empty set is a "
            + "client that could never obtain a token.");
    }

    return new ConfiguredClient(clientId, value.Name, redirects, secret)
    {
        Owner = SubjectId.FromStorage(owner),
        Scopes = scopes,
    };
}

static ScopeSet ParseScopes(string resource, string? wire)
{
    if (!ScopeSet.TryParse(wire ?? string.Empty, out var parsed, out var error))
        throw new InvalidOperationException($"Resource `{resource}` declares scopes this cannot read: {error}");

    return parsed;
}

// SEED_ROLES='{"founder":{"name":"Founder","permissions":"docs_read docs_write"},"member":{}}'
// The same map-of-objects shape RESOURCES uses, space-separated words inside for the same reason.
// An entry with no body is a role that stands for nothing yet, which RoleDefinition allows on
// purpose. Read only by the migrate verb; the serving process never parses this.
static IReadOnlyList<RoleSeed> ParseRoleSeeds(string json)
{
    var entries = JsonSerializer.Deserialize<Dictionary<string, RoleSeedEntry>>(
        json, JsonSerializerOptions.Web)
        ?? throw new InvalidOperationException("SEED_ROLES is not a JSON object.");

    // The ADMIN_ROLES lesson again: set-but-empty is never what anyone meant, and accepting it
    // silently turns a quoting mistake into a seeding step that reports nothing forever.
    if (entries.Count == 0)
    {
        throw new InvalidOperationException(
            "SEED_ROLES is set and defines no role. Unset it, or define one.");
    }

    return entries.Select(entry => new RoleSeed(
        entry.Key,
        entry.Value?.Name,
        (entry.Value?.Permissions ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
        .ToArray();
}

// SCOPE_DESCRIPTIONS='{"docs:read":"Read the knowledge base."}'
static IEnumerable<KeyValuePair<string, string>> ScopeDescriptions(IConfiguration config)
{
    var json = config["SCOPE_DESCRIPTIONS"];
    if (json is not { Length: > 0 }) return [];

    return JsonSerializer.Deserialize<Dictionary<string, string>>(json, JsonSerializerOptions.Web)
        ?? [];
}

// Platforms hand out `postgres://user:pass@host/db`; Npgsql wants key/value pairs. Converting
// here rather than asking an operator to rewrite a string their provider gave them.
static string Normalise(string connectionString)
{
    if (!connectionString.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) &&
        !connectionString.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
    {
        return connectionString;
    }

    var uri = new Uri(connectionString);
    var credentials = uri.UserInfo.Split(':', 2);

    return string.Join(';',
        $"Host={uri.Host}",
        $"Port={(uri.Port > 0 ? uri.Port : 5432)}",
        $"Database={uri.AbsolutePath.TrimStart('/')}",
        $"Username={Uri.UnescapeDataString(credentials[0])}",
        $"Password={Uri.UnescapeDataString(credentials.Length > 1 ? credentials[1] : string.Empty)}",
        "SSL Mode=Require");
}

internal sealed class ResourceEntry
{
    public string? Name { get; set; }
    public string? Scopes { get; set; }
}

/// <summary>One entry in SEED_ROLES. See the migrate verb.</summary>
internal sealed class RoleSeedEntry
{
    /// <summary>What a person reads. Defaults to the id, and stays free to be reworded later.</summary>
    public string? Name { get; set; }

    /// <summary>Space separated, in the resource server's vocabulary. Absent is a role that stands
    /// for nothing yet.</summary>
    public string? Permissions { get; set; }
}

/// <summary>One entry in CLIENTS. See "Clients this deployment registered by hand".</summary>
internal sealed class ClientEntry
{
    public string? Name { get; set; }

    /// <summary>Space separated, matched exactly, never by prefix.</summary>
    public string? RedirectUris { get; set; }

    /// <summary>Base64 of the SHA-256 of the secret. Absent for a public client.</summary>
    public string? SecretSha256 { get; set; }

    /// <summary>
    /// A resource server that only authenticates to <c>/introspect</c>, and authorizes nobody.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The third kind of client, after the one a person authorizes and the one that acts as an
    /// account. It carries a secret and nothing else: no redirect URI, so no authorization can
    /// complete for it, and no owner, so it is entitled to no account's token. What it buys is the
    /// right to ask whether a token somebody already handed it is still live.
    /// </para>
    /// <para>
    /// <b>Set it rather than borrowing one of the other two.</b> Both were tried and both are
    /// worse: a placeholder <c>redirectUris</c> is a live authorization target for whoever steals
    /// the secret, and <c>owner</c> makes the client able to act as that account through
    /// <c>client_credentials</c> - a much larger power than the one being asked for, granted as a
    /// side effect of getting past a validation rule.
    /// </para>
    /// </remarks>
    public bool IntrospectionOnly { get; set; }

    /// <summary>
    /// The subject of the account this client acts as. Present only for a service account.
    /// </summary>
    /// <remarks>
    /// Setting it changes what kind of client this is: it stops being one a person authorizes and
    /// becomes one that holds a standing credential for this account. It then uses
    /// <c>client_credentials</c> and nothing else, needs a secret, needs scopes, and must not carry
    /// a redirect URI.
    ///
    /// The owner's roles are the ceiling on what its token can do, which is the reason to give a
    /// service account its own narrow-role account rather than hanging one off an account that
    /// holds every role.
    /// </remarks>
    public string? Owner { get; set; }

    /// <summary>
    /// Space separated. What a service account is issued, exactly - nothing widens it.
    /// </summary>
    public string? Scopes { get; set; }
}
