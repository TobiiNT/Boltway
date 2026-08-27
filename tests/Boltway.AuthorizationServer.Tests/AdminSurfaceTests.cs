using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>/admin/*</c> - the highest-value target in the system, and the rules that keep it survivable.
/// </summary>
/// <remarks>
/// A flaw here is not a leaked document, it is the directory. Everything in this file that looks
/// paranoid is paying for the decision to have an HTTP admin surface at all.
/// </remarks>
public sealed class AdminSurfaceTests
{
    private const string Handle = "ada";

    /// <summary>
    /// A principal the test controls, standing in for the resource server's bearer middleware.
    /// </summary>
    /// <remarks>
    /// The AS does not validate tokens - <c>Boltway.ResourceServer</c> does, in the host - so
    /// what these tests exercise is what this library decides about an already-validated principal.
    /// The scheme name matters and is asserted: "bearer" is not a cookie, and that is the whole of
    /// <c>N-17</c>'s input.
    /// </remarks>
    private sealed class FakePrincipalMiddleware
    {
        internal static string? Scheme { get; set; }

        internal static string Scopes { get; set; } = string.Empty;

        internal static string Subject { get; set; } = "01J8XKQ7M3N4P5R6S7T8V9W0AD";
    }

    private static Task<FlowFixture> StartAsync(bool administration = true) =>
        FlowFixture.StartAsync(seed =>
        {
            var roles = new InMemoryRoleStore();

            // Defined before anything can hold them - creation does not assign, and assignment refuses
            // an id the realm does not define.
            if (roles.FindAsync(RealmId.Default, "founder", CancellationToken.None).GetAwaiter().GetResult() is null)
            {
                roles.StoreAsync(new RoleDefinition("founder", "founder", []), CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            if (roles.FindAsync(RealmId.Default, "operator", CancellationToken.None).GetAwaiter().GetResult() is null)
            {
                roles.StoreAsync(new RoleDefinition("operator", "operator", []), CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
            if (roles.FindAsync(RealmId.Default, "employee", CancellationToken.None).GetAwaiter().GetResult() is null)
            {
                roles.StoreAsync(new RoleDefinition("employee", "employee", []), CancellationToken.None)
                    .GetAwaiter().GetResult();
            }

        var users = new InMemoryUserStore(roles);
            var audit = new InMemoryAdminAuditStore();

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());
                services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));
                services.AddSingleton<IAdminAuditStore>(audit);
            };

            seed.ConfigureOptions = o =>
            {
                o.AdministrationEnabled = administration;

                // On here even though this file is about `/admin`, because the N-17 tests below scan
                // the routing table for all three prefixes and an unmapped surface is a surface they
                // cannot find a violation on. The behavioural tests for these routes are in
                // AccountSurfaceTests and MeSurfaceTests; what they contribute here is existing.
                o.SelfServiceEnabled = true;
                o.SelfServicePagesEnabled = true;

                // Advertised because the endpoints authorize on them. Startup refuses the pair
                // otherwise: a scope this server does not publish is one no client will ever put in
                // an authorization request, so the surface would be routed and unreachable.
                o.ScopesSupported.Add(AdminScopes.Read);
                o.ScopesSupported.Add(AdminScopes.Write);
                o.ScopesSupported.Add(AdminScopes.Self);

                // The narrow pair. Optional in a deployment - users:read/users:write alone keep the
                // whole surface reachable - advertised here because the tests below mint tokens
                // carrying them.
                o.ScopesSupported.Add(AdminScopes.RolesRead);
                o.ScopesSupported.Add(AdminScopes.RolesWrite);
            };

            seed.ConfigureApp = app => app.Use(async (http, next) =>
            {
                if (FakePrincipalMiddleware.Scheme is { } scheme)
                {
                    var identity = new ClaimsIdentity(
                        [
                            new Claim("sub", FakePrincipalMiddleware.Subject),
                            new Claim("scope", FakePrincipalMiddleware.Scopes),
                        ],
                        scheme);

                    http.User = new ClaimsPrincipal(identity);
                }

                await next(http);
            });
        });

    private static void SignedInAs(string? scheme, string scopes)
    {
        FakePrincipalMiddleware.Scheme = scheme;
        FakePrincipalMiddleware.Scopes = scopes;
    }

    // ─────────────────────────────────────────────────────────────────── N-17

    /// <summary>
    /// No route under <c>/admin/</c> or <c>/account/</c> names a cookie scheme.
    /// </summary>
    /// <remarks>
    /// The structural half of <c>N-17</c>, over the routing table rather than over a handler. What it
    /// catches is the well-meaning change - "it would be so much easier to call this from the consent
    /// page" - which arrives as an attribute rather than as an <c>if</c>, and which no unit test of a
    /// handler would ever see.
    /// </remarks>
    [Fact]
    public async Task No_administrative_route_carries_a_cookie_scheme()
    {
        await using var fixture = await StartAsync();

        var sources = fixture.Services.GetRequiredService<EndpointDataSource>();

        var administrative = sources.Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => "/" + e.RoutePattern.RawText!.TrimStart('/') is var path
                && (path.StartsWith(AuthorizationServerPaths.AdminPrefix, StringComparison.Ordinal)
                    || path.StartsWith(AuthorizationServerPaths.AccountPrefix, StringComparison.Ordinal)
                    // `/account` itself, which has no trailing slash and so matches no prefix. It
                    // is E-33, the one route on that surface a prefix scan would have skipped.
                    || string.Equals(path, AuthorizationServerPaths.Account, StringComparison.Ordinal)))
            .ToList();

        // The control. An empty list would pass every assertion below and prove nothing, and the
        // whole surface being unmapped is exactly the state this file will be in one day.
        Assert.NotEmpty(administrative);

        foreach (var endpoint in administrative)
        {
            var schemes = endpoint.Metadata
                .OfType<Microsoft.AspNetCore.Authorization.IAuthorizeData>()
                .Select(data => data.AuthenticationSchemes)
                .Where(s => !string.IsNullOrEmpty(s))
                .SelectMany(s => s!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .ToList();

            foreach (var cookie in AdminAuthorization.CookieSchemes)
            {
                Assert.DoesNotContain(cookie, schemes, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>
    /// No route under <c>/me/</c> names a bearer scheme.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>N-17</c>'s other half, and the reason the rule survived meeting a page that has to be
    /// cookie-authenticated. §7.2: read literally the rule would mean a user changing their own
    /// password runs an OAuth client, and the way out is a third prefix rather than a softened rule.
    /// The prefixes are disjoint, so both directions are mechanical and neither needs judgement.
    /// </para>
    /// <para>
    /// What this catches is the change that goes the other way from the one above - "these pages
    /// should also accept a token, so the CLI can drive them" - which would put a bearer-authenticated
    /// state-changing form on the origin that carries the session cookie, and give the pages two ways
    /// in where the whole design has one.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task No_self_service_page_carries_a_bearer_scheme()
    {
        await using var fixture = await StartAsync();

        var sources = fixture.Services.GetRequiredService<EndpointDataSource>();

        var pages = sources.Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => "/" + e.RoutePattern.RawText!.TrimStart('/') is var path
                && (path.StartsWith(AuthorizationServerPaths.MePrefix, StringComparison.Ordinal)
                    || string.Equals(path, AuthorizationServerPaths.Me, StringComparison.Ordinal)))
            .ToList();

        // The control, for the reason the one above has it: an unmapped surface passes every
        // assertion below and proves nothing.
        Assert.NotEmpty(pages);

        foreach (var endpoint in pages)
        {
            var schemes = endpoint.Metadata
                .OfType<Microsoft.AspNetCore.Authorization.IAuthorizeData>()
                .Select(data => data.AuthenticationSchemes)
                .Where(s => !string.IsNullOrEmpty(s))
                .SelectMany(s => s!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .ToList();

            Assert.DoesNotContain("Bearer", schemes, StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// The three prefixes do not overlap, which is what makes the two rules above decidable.
    /// </summary>
    /// <remarks>
    /// Both assertions read the routing table and sort by prefix. A path that matched two of them
    /// would be governed by two contradictory rules, and whichever test ran first would decide -
    /// so the disjointness is asserted rather than assumed from the strings looking different.
    /// </remarks>
    [Fact]
    public void The_three_surface_prefixes_are_disjoint()
    {
        string[] prefixes =
        [
            AuthorizationServerPaths.AdminPrefix,
            AuthorizationServerPaths.AccountPrefix,
            AuthorizationServerPaths.MePrefix,
        ];

        foreach (var one in prefixes)
        {
            foreach (var other in prefixes)
            {
                if (!ReferenceEquals(one, other))
                {
                    Assert.False(
                        one.StartsWith(other, StringComparison.Ordinal),
                        $"'{one}' is under '{other}', so a route could be governed by both rules.");
                }
            }
        }

        // And the two bare paths sort the way the prefix scans assume: `/account` is not under
        // `/me/`, `/me` is not under `/account/`. Each is picked up by its own equality check.
        Assert.False(
            AuthorizationServerPaths.Me.StartsWith(AuthorizationServerPaths.AccountPrefix, StringComparison.Ordinal));
        Assert.False(
            AuthorizationServerPaths.Account.StartsWith(AuthorizationServerPaths.MePrefix, StringComparison.Ordinal));
    }

    /// <summary>
    /// A real session cookie does not open the admin API.
    /// </summary>
    /// <remarks>
    /// The behavioural half, and the one that would still fail if somebody satisfied the structural
    /// one by renaming a scheme. A principal authenticated by a cookie is refused whatever claims it
    /// carries - including, as here, exactly the scope the endpoint wants.
    /// </remarks>
    [Fact]
    public async Task A_cookie_principal_is_refused_even_carrying_the_right_scope()
    {
        await using var fixture = await StartAsync();

        SignedInAs(CookieAuthenticationDefaults.AuthenticationScheme, AdminScopes.Read + " " + AdminScopes.Write);

        var response = await fixture.Client.GetAsync(new Uri("/admin/users/ada", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Contains("bearer-only", problem.GetProperty("error_description").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_anonymous_request_is_refused()
    {
        await using var fixture = await StartAsync();

        SignedInAs(null, string.Empty);

        var response = await fixture.Client.GetAsync(new Uri("/admin/users/ada", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Authenticated and unentitled is 403, not 401.
    /// </summary>
    /// <remarks>
    /// Answering 401 would tell a caller who is already authenticated to authenticate again, which is
    /// a loop that cannot terminate - they would present the same token and be told the same thing.
    /// </remarks>
    [Fact]
    public async Task A_token_without_the_scope_is_forbidden_rather_than_unauthorized()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", "openid");

        var response = await fixture.Client.GetAsync(new Uri("/admin/users/ada", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// <c>users:read</c> does not permit a write.
    /// <summary>
    /// A role is defined, listed, reworded, given to somebody, and removed.
    /// </summary>
    /// <remarks>
    /// One test rather than five, because the interesting part is the sequence: a role has to exist
    /// before an account can hold it, and removing it has to take the assignment with it. Five tests
    /// would each seed the state the one before it produced, and none of them would cover the order.
    /// </remarks>
    private static readonly string[] AnalystPermissions = ["docs_read", "read_ledgers"];
    private static readonly string[] Analyst = ["analyst"];
    private static readonly string[] Mistyped = ["analsyt"];

    [Fact]
    public async Task A_role_is_defined_listed_reworded_assigned_and_removed()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        var created = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/roles", UriKind.Relative),
            new { id = "analyst", permissions = AnalystPermissions });

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();

        // The name defaults to the id rather than to null or an empty string: every surface that
        // shows a role has something to show before anybody has written one.
        Assert.Equal("analyst", createdBody.GetProperty("name").GetString());

        // Add-only, the same as accounts, and for the same reason: replacing one would change what
        // every token issued under it turns out to have meant.
        var again = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/roles", UriKind.Relative), new { id = "analyst" });

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        var listed = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/roles", UriKind.Relative));

        Assert.Contains(
            listed.GetProperty("roles").EnumerateArray(),
            r => r.GetProperty("id").GetString() == "analyst");

        // Rewording is the operation the id/name split exists for, and it changes no token.
        var reworded = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/roles/analyst", UriKind.Relative), new { name = "Nhà phân tích" });

        Assert.Equal(HttpStatusCode.OK, reworded.StatusCode);
        Assert.Equal(
            "Nhà phân tích",
            (await reworded.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("name").GetString());

        await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        var assigned = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/users/" + Handle, UriKind.Relative), new { roles = Analyst });

        Assert.Equal(HttpStatusCode.OK, assigned.StatusCode);
        Assert.Equal(
            "analyst",
            (await assigned.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("role")[0].GetString());

        // An id nothing defines is refused rather than stored, and the message names it.
        var mistyped = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/users/" + Handle, UriKind.Relative), new { roles = Mistyped });

        Assert.Equal(HttpStatusCode.Conflict, mistyped.StatusCode);

        // Two ways to say one thing, refused rather than ranked.
        var both = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/users/" + Handle, UriKind.Relative),
            new { role = "analyst", roles = Analyst });

        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);

        var removed = await fixture.Client.DeleteAsync(new Uri("/admin/roles/analyst", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);

        // The assignment went with it. An account left holding nothing is the least-privileged
        // outcome, which is the direction to be wrong in.
        var after = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/users/" + Handle, UriKind.Relative));

        Assert.Empty(after.GetProperty("role").EnumerateArray());
    }

    /// </summary>
    [Fact]
    public async Task Read_scope_cannot_write()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read);

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = "grace" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// The role endpoints accept their own narrow pair, read and write kept apart.
    /// </summary>
    /// <remarks>
    /// The whole point of the pair existing: a credential can hold the role vocabulary without
    /// holding the directory. <see cref="A_role_is_defined_listed_reworded_assigned_and_removed"/>
    /// runs the same surface under <c>users:read users:write</c>, and staying green there is the
    /// other half of this contract - the broad pair keeps covering everything.
    /// </remarks>
    [Fact]
    public async Task The_role_surface_accepts_its_dedicated_scopes()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.RolesWrite);

        var created = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/roles", UriKind.Relative), new { id = "scoped" });

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var reworded = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/roles/scoped", UriKind.Relative), new { name = "Scoped" });

        Assert.Equal(HttpStatusCode.OK, reworded.StatusCode);

        SignedInAs("Bearer", AdminScopes.RolesRead);

        var listed = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/roles", UriKind.Relative));

        Assert.Contains(
            listed.GetProperty("roles").EnumerateArray(),
            r => r.GetProperty("id").GetString() == "scoped");

        // The read half cannot write - the same split the users pair has.
        var refused = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/roles", UriKind.Relative), new { id = "denied" });

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        SignedInAs("Bearer", AdminScopes.RolesWrite);

        var removed = await fixture.Client.DeleteAsync(new Uri("/admin/roles/scoped", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
    }

    /// <summary>
    /// The roles pair reaches no account: not the listing, not a creation, not the audit log.
    /// </summary>
    /// <remarks>
    /// The boundary that makes the narrow pair worth issuing. If <c>roles:*</c> ever satisfied a
    /// user endpoint, a credential scoped to the vocabulary would silently hold the directory -
    /// which is the exact over-grant the pair exists to end.
    /// </remarks>
    [Fact]
    public async Task Role_scopes_grant_nothing_about_accounts()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.RolesRead + " " + AdminScopes.RolesWrite);

        var listed = await fixture.Client.GetAsync(new Uri("/admin/users", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Forbidden, listed.StatusCode);

        var created = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = "grace" });
        Assert.Equal(HttpStatusCode.Forbidden, created.StatusCode);

        var audited = await fixture.Client.GetAsync(new Uri("/admin/audit", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Forbidden, audited.StatusCode);
    }

    /// <summary>
    /// A refusal on the role surface names every scope that would have done.
    /// </summary>
    /// <remarks>
    /// Two scopes satisfy each role endpoint, so a message naming only one sends the caller for a
    /// broader grant than they need - the refusal is the one place the narrow pair gets advertised
    /// to the person holding the wrong token.
    /// </remarks>
    [Fact]
    public async Task A_role_refusal_names_every_scope_that_would_do()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", "openid");

        var refused = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/roles", UriKind.Relative), new { id = "denied" });

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        var body = await refused.Content.ReadAsStringAsync();

        Assert.Contains(AdminScopes.RolesWrite, body, StringComparison.Ordinal);
        Assert.Contains(AdminScopes.Write, body, StringComparison.Ordinal);
    }

    // ────────────────────────────────────────────────────────────── the surface

    [Fact]
    public async Task It_is_absent_unless_a_deployment_asked_for_it()
    {
        await using var fixture = await StartAsync(administration: false);

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        var response = await fixture.Client.GetAsync(new Uri("/admin/users/ada", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task An_account_can_be_created_read_patched_and_reset()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        var created = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative),
            new { handle = Handle, email = "ada@example.com", role = "founder" });

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        var password = createdBody.GetProperty("password").GetString();

        Assert.False(string.IsNullOrEmpty(password));

        var read = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/users/" + Handle, UriKind.Relative));

        Assert.Equal("founder", read.GetProperty("role")[0].GetString());
        Assert.True(read.GetProperty("has_password").GetBoolean());

        // The hash never leaves the process, not even as a length. An API that returned one would
        // make every reader of its logs a candidate for an offline attack.
        Assert.False(read.TryGetProperty("password_hash", out _));

        var patched = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/users/" + Handle, UriKind.Relative),
            new { role = "employee", enabled = false });

        var patchedBody = await patched.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, patched.StatusCode);
        Assert.Equal("employee", patchedBody.GetProperty("role")[0].GetString());
        Assert.False(patchedBody.GetProperty("disabled_at").ValueKind is JsonValueKind.Null);

        var reset = await fixture.Client.PostAsync(
            new Uri($"/admin/users/{Handle}/password", UriKind.Relative), content: null);

        var resetBody = await reset.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.NotEqual(password, resetBody.GetProperty("password").GetString());
    }

    /// <summary>
    /// A patch that mentions nothing this server knows is refused, not silently accepted.
    /// </summary>
    /// <remarks>
    /// A client sending a field this version does not have would otherwise get 200 and believe the
    /// change landed. That is the failure mode nobody notices until the account behaves as it always
    /// did.
    /// </remarks>
    [Fact]
    public async Task A_patch_that_changes_nothing_is_refused()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Write);

        await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        var response = await fixture.Client.PatchAsJsonAsync(
            new Uri("/admin/users/" + Handle, UriKind.Relative), new { nickname = "ada" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// There is no way to send a password to this API.
    /// </summary>
    /// <remarks>
    /// The reset endpoint takes no body, and the create request has no such field. A password
    /// arriving over HTTP lands in a proxy log, an access log and whatever traced the request - so
    /// the control is the absence, and this is what notices it coming back.
    /// </remarks>
    [Fact]
    public void No_admin_request_type_accepts_a_password()
    {
        var properties = new[] { typeof(CreateUserRequest), typeof(PatchUserRequest) }
            .SelectMany(type => type.GetProperties())
            .ToList();

        Assert.Contains(properties, p => p.Name == "Handle");

        Assert.DoesNotContain(
            properties,
            p => p.Name.Contains("password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Every_administrative_call_reaches_the_audit_log()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        await fixture.Client.PostAsync(
            new Uri($"/admin/users/{Handle}/password", UriKind.Relative), content: null);

        var entries = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/audit", UriKind.Relative));

        var actions = entries.EnumerateArray().Select(e => e.GetProperty("action").GetString()).ToList();

        Assert.Equal(["user.password.reset", "user.create"], actions);

        // The client acted for a subject, so the trail says which one - unlike the CLI, whose actor
        // is honestly null.
        Assert.All(
            entries.EnumerateArray(),
            e => Assert.Equal("client", e.GetProperty("actor_kind").GetString()));
    }

    /// <summary>
    /// No audit entry carries a password, including the one that just generated one.
    /// </summary>
    [Fact]
    public async Task The_audit_log_never_carries_a_password()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        var created = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        var password = (await created.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("password").GetString()!;

        var raw = await fixture.Client.GetStringAsync(new Uri("/admin/audit", UriKind.Relative));

        Assert.DoesNotContain(password, raw, StringComparison.Ordinal);
    }

    /// <summary>
    /// The list pages with a cursor, and says where the next page starts.
    /// </summary>
    /// <remarks>
    /// <c>next_after</c> is null on the last page rather than pointing at nothing, so a client stops
    /// by reading the field rather than by making one more request and finding it empty.
    /// </remarks>
    [Fact]
    public async Task Accounts_can_be_listed_a_page_at_a_time()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        foreach (var name in new[] { "ada", "grace", "hedy" })
        {
            await fixture.Client.PostAsJsonAsync(
                new Uri("/admin/users", UriKind.Relative), new { handle = name });
        }

        var first = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/users?limit=2", UriKind.Relative));

        var firstNames = first.GetProperty("users").EnumerateArray()
            .Select(u => u.GetProperty("handle").GetString()).ToList();

        Assert.Equal(2, firstNames.Count);

        var cursor = first.GetProperty("next_after").GetString();

        Assert.False(string.IsNullOrEmpty(cursor));

        var second = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/users?limit=2&after=" + cursor, UriKind.Relative));

        var secondNames = second.GetProperty("users").EnumerateArray()
            .Select(u => u.GetProperty("handle").GetString()).ToList();

        // Every account exactly once across the two pages, and no overlap - the property a keyset
        // cursor has and an offset does not once anything is being created while somebody pages.
        Assert.Equal(["ada", "grace", "hedy"], firstNames.Concat(secondNames).Order(StringComparer.Ordinal));
        Assert.Null(second.GetProperty("next_after").GetString());
    }

    [Fact]
    public async Task Listing_needs_only_the_read_scope()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read);

        var response = await fixture.Client.GetAsync(new Uri("/admin/users", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A_handle_nobody_has_is_a_404()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read);

        var response = await fixture.Client.GetAsync(new Uri("/admin/users/nobody", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ─────────────────────────────────────────────────────── E-30, E-31

    /// <summary>Create an account and give it <paramref name="grants"/> live grants.</summary>
    private static async Task<SubjectId> WithGrantsAsync(FlowFixture fixture, int grants)
    {
        var created = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        var subject = SubjectId.FromStorage(
            (await created.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("subject").GetString()!);

        var store = fixture.Services.GetRequiredService<Abstractions.Stores.IGrantStore>();
        var now = DateTimeOffset.UnixEpoch;

        for (var i = 0; i < grants; i++)
        {
            await store.StoreAsync(
                new Abstractions.Grants.GrantRecord(
                    "grant-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    subject,
                    ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata"),
                    OAuth.Primitives.Scopes.ScopeSet.FromStorage("openid"),
                    ["https://mcp.example.com/mcp"],
                    now,
                    now),
                CancellationToken.None);
        }

        return subject;
    }

    /// <summary>
    /// Revoking sessions revokes every grant and says how many.
    /// </summary>
    /// <remarks>
    /// The count is the response body rather than a 204, because "there was nothing live" and
    /// "three sessions ended" are different answers an operator acts on differently - and because
    /// running it twice to be sure should say zero the second time.
    /// </remarks>
    [Fact]
    public async Task Revoking_sessions_revokes_every_grant_and_reports_the_count()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        await WithGrantsAsync(fixture, 3);

        var response = await fixture.Client.DeleteAsync(
            new Uri($"/admin/users/{Handle}/sessions", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(3, body.GetProperty("revoked").GetInt32());

        var grants = fixture.Services.GetRequiredService<Abstractions.Stores.IGrantStore>();

        Assert.True(await grants.IsRevokedAsync("grant-0", CancellationToken.None));
        Assert.True(await grants.IsRevokedAsync("grant-2", CancellationToken.None));

        // Twice, because that is what somebody does when they are not sure the first one worked.
        var again = await fixture.Client.DeleteAsync(
            new Uri($"/admin/users/{Handle}/sessions", UriKind.Relative));

        Assert.Equal(
            0,
            (await again.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetInt32());
    }

    /// <summary>
    /// Revoking sessions leaves the account able to sign in.
    /// </summary>
    /// <remarks>
    /// Three separate operations for three separate questions. Somebody who still knows the
    /// password signs straight back in, and an operator who believes this locked the account out is
    /// holding the wrong belief during an incident.
    /// </remarks>
    [Fact]
    public async Task Revoking_sessions_does_not_disable_the_account()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        await WithGrantsAsync(fixture, 1);

        await fixture.Client.DeleteAsync(new Uri($"/admin/users/{Handle}/sessions", UriKind.Relative));

        var account = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri($"/admin/users/{Handle}", UriKind.Relative));

        Assert.Equal(JsonValueKind.Null, account.GetProperty("disabled_at").ValueKind);
        Assert.True(account.GetProperty("has_password").GetBoolean());
    }

    /// <summary>
    /// Anonymising replaces the handle, revokes the sessions, and keeps the subject.
    /// </summary>
    /// <remarks>
    /// The subject surviving is the design: audit entries and grant history keep their referent,
    /// and an audit trail that empties when the audited party asks is not an audit trail.
    /// </remarks>
    [Fact]
    public async Task Anonymising_tombstones_the_handle_and_keeps_the_subject()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        var subject = await WithGrantsAsync(fixture, 2);

        var response = await fixture.Client.PostAsync(
            new Uri($"/admin/users/{Handle}/anonymise", UriKind.Relative), content: null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(subject.Value, body.GetProperty("subject").GetString());
        Assert.Equal(UserAdministration.TombstonePrefix + subject.Value, body.GetProperty("handle").GetString());
        Assert.Equal(2, body.GetProperty("revoked").GetInt32());

        // The old handle is gone from the directory and the tombstone is there in its place,
        // carrying no address, no credential and no role.
        var old = await fixture.Client.GetAsync(new Uri($"/admin/users/{Handle}", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, old.StatusCode);

        var tombstone = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/users/" + body.GetProperty("handle").GetString(), UriKind.Relative));

        Assert.Equal(subject.Value, tombstone.GetProperty("subject").GetString());
        Assert.Equal(JsonValueKind.Null, tombstone.GetProperty("email").ValueKind);
        // An empty array rather than null. `role` is always an array now - a consumer that had to
        // branch on the JSON type to read it would read it wrong the day somebody holds two - so
        // "this tombstone holds nothing" is an empty one, not an absent field.
        Assert.Empty(tombstone.GetProperty("role").EnumerateArray());
        Assert.False(tombstone.GetProperty("has_password").GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, tombstone.GetProperty("disabled_at").ValueKind);
    }

    /// <summary>
    /// The handle an anonymised account released can be used by a new one.
    /// </summary>
    /// <remarks>
    /// The directory's half of the operation, and the one that fails if a store sets the username
    /// without moving the normalized index - invisible until somebody re-uses a handle, which is
    /// months later and looks like a different bug.
    /// </remarks>
    [Fact]
    public async Task An_anonymised_handle_can_be_taken_by_somebody_new()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        var first = await WithGrantsAsync(fixture, 0);

        await fixture.Client.PostAsync(
            new Uri($"/admin/users/{Handle}/anonymise", UriKind.Relative), content: null);

        var again = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        Assert.Equal(HttpStatusCode.Created, again.StatusCode);

        var second = (await again.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("subject").GetString();

        // A different account under the same name - not the old one brought back.
        Assert.NotEqual(first.Value, second);
    }

    /// <summary>Both write operations refuse a read-only token.</summary>
    [Theory]
    [InlineData("DELETE", "sessions")]
    [InlineData("POST", "anonymise")]
    public async Task Ending_a_session_needs_the_write_scope(string method, string segment)
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read);

        using var request = new HttpRequestMessage(
            new HttpMethod(method), new Uri($"/admin/users/{Handle}/{segment}", UriKind.Relative));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Both refuse a handle nobody has, without saying anything else about it.</summary>
    [Theory]
    [InlineData("DELETE", "sessions")]
    [InlineData("POST", "anonymise")]
    public async Task Ending_the_sessions_of_a_handle_nobody_has_is_a_404(string method, string segment)
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        using var request = new HttpRequestMessage(
            new HttpMethod(method), new Uri($"/admin/users/nobody/{segment}", UriKind.Relative));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Both write an audit entry, and anonymise writes the handle it destroyed.
    /// </summary>
    /// <remarks>
    /// The entry is the only place the handle survives - the account no longer carries it. That is
    /// the boundary of what anonymise promises: the directory stops naming the person, and the
    /// record of who was administered stays readable, because otherwise nobody can answer whether
    /// it was done properly.
    /// </remarks>
    [Fact]
    public async Task Both_operations_are_in_the_audit_log()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Read + " " + AdminScopes.Write);

        await WithGrantsAsync(fixture, 1);

        await fixture.Client.DeleteAsync(new Uri($"/admin/users/{Handle}/sessions", UriKind.Relative));
        await fixture.Client.PostAsync(
            new Uri($"/admin/users/{Handle}/anonymise", UriKind.Relative), content: null);

        var entries = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/admin/audit", UriKind.Relative));

        var actions = entries.EnumerateArray()
            .Select(e => e.GetProperty("action").GetString())
            .ToList();

        Assert.Contains("user.sessions.revoke", actions);
        Assert.Contains("user.anonymise", actions);

        var anonymise = entries.EnumerateArray()
            .Single(e => e.GetProperty("action").GetString() == "user.anonymise");

        Assert.Equal(Handle, anonymise.GetProperty("target_handle").GetString());
        Assert.Equal("succeeded", anonymise.GetProperty("outcome").GetString());
    }

    [Fact]
    public async Task A_duplicate_handle_is_a_conflict()
    {
        await using var fixture = await StartAsync();

        SignedInAs("Bearer", AdminScopes.Write);

        await fixture.Client.PostAsJsonAsync(new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        var again = await fixture.Client.PostAsJsonAsync(
            new Uri("/admin/users", UriKind.Relative), new { handle = Handle });

        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }
}
