using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Creating a service account over HTTP and then obtaining a token with it, over HTTP.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this file exists.</b> Every part of this feature had unit tests and shipped two defects
/// anyway, both of the same shape: the code was right and the route did not reach it. The admin UI
/// posted <c>role</c> where the API had started reading <c>roles</c>, and cleared every role on an
/// unrelated save. <c>client_credentials</c> was advertised only on the configured-clients path, so
/// a deployment holding its clients in the store had the grant working and undiscoverable. Both
/// passed the whole suite.
/// </para>
/// <para>
/// So nothing here reaches into a store or calls an administration method directly. It goes in at
/// <c>POST /admin/users/{handle}/service-account</c> and comes out at <c>POST /token</c>, and what
/// it proves is the wiring between them: that the client the administrator created is one the token
/// endpoint can resolve, that the secret it printed is one the authenticator accepts, and that the
/// scopes it was given are the scopes that come back.
/// </para>
/// <para>
/// The fixture registers <see cref="IClientStore"/> and calls <c>AddStoredClients</c>, which is the
/// arrangement a real deployment has and the one neither the resolver tests nor the grant tests
/// use - they seed a client into <c>TestClientResolver</c>, which is the half that was already
/// working when the grant went undiscoverable in production.
/// </para>
/// </remarks>
public sealed class ServiceAccountEndToEndTests
{
    private const string Handle = "grace";
    private const string Scope = "mcp:tools";

    /// <summary>The secret the fixture's own configured client authenticates with.</summary>
    /// <remarks>
    /// A real minted secret rather than a literal, because the server parses before it compares.
    /// It exists so this file can prove the composition production shipped broken the other way
    /// around: turning stored clients on must not take configured clients' secrets away.
    /// </remarks>
    private static readonly string ConfiguredSecret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

    /// <summary>A server holding its clients in a store, with an administrator signed in.</summary>
    /// <param name="registry">
    /// The resources this server serves. The fixture's own pair both define <c>mcp:tools</c>, which
    /// is the ambiguous case; a test about scopes choosing a resource supplies a pair that differ.
    /// </param>
    private static Task<FlowFixture> StartAsync(
        TestResourceRegistry? registry = null,
        IScopeEntitlementPolicy? policy = null,
        string ownerRole = "founder")
    {
        // Per fixture rather than static: two tests running in parallel must not share a directory,
        // and xUnit runs the methods of one class sequentially but its classes concurrently.
        var roles = new InMemoryRoleStore();
        roles.StoreAsync(new RoleDefinition("founder", "founder", []), CancellationToken.None)
            .GetAwaiter().GetResult();

        // Assignment refuses an id the realm does not define, so a fixture that wants an owner
        // holding a narrow role has to define it first.
        if (ownerRole != "founder")
        {
            roles.StoreAsync(new RoleDefinition(ownerRole, ownerRole, []), CancellationToken.None)
                .GetAwaiter().GetResult();
        }

        return FlowFixture.StartAsync(seed =>
        {
            // The fixture's own client becomes a configured confidential client that authenticates
            // with a secret, standing in for the deployment's admin UI. It is here so the suite can
            // prove the composition that shipped broken: AddStoredClients chains the secret stores,
            // and turning the table on must not take this client's secret away.
            seed.Client = Build.Client("https://admin.example.com/client", ClientType.Confidential)
                with { TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic };
            seed.ClientSecrets["https://admin.example.com/client"] = ConfiguredSecret;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IUserStore>(new InMemoryUserStore(roles));
                services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());
                services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));
                services.AddSingleton<IAdminAuditStore>(new InMemoryAdminAuditStore());

                // The two lines that make this a service-account deployment. Without the store the
                // administration surface refuses to hold one; without AddStoredClients the client it
                // creates exists and cannot be resolved at /token - which is a failure no test in
                // this assembly could previously have seen.
                services.AddSingleton<IClientStore>(new InMemoryClientStore());
                services.AddStoredClients();

                // After the fixture's own, so this wins. Only a test that cares about which resource
                // the scopes select passes one.
                if (registry is not null)
                {
                    services.AddSingleton<IResourceRegistry>(registry);
                }

                // Only the tests about the owner's ceiling register one. Without a policy the
                // shipped default cannot narrow anything, which is every deployment that has not
                // set ADMIN_ROLES.
                if (policy is not null)
                {
                    services.AddSingleton(policy);
                }
            };

            seed.ConfigureOptions = o =>
            {
                o.AdministrationEnabled = true;
                o.ScopesSupported.Add(AdminScopes.Read);
                o.ScopesSupported.Add(AdminScopes.Write);

                // The scopes the alternate registry declares. Harmless on the default fixture and
                // required on the other: a resource declaring a scope this server does not publish
                // is a scope no client could ever ask for.
                o.ScopesSupported.Add("docs:read");
                o.ScopesSupported.Add("docs:write");

                // The default set is authorization_code and refresh_token, so a deployment holding
                // service accounts has to say this - the host does, keyed on whether an IClientStore
                // is registered. Written out here rather than defaulted in the fixture because it is
                // half of what "advertised only for the path nobody would use" was about: the grant
                // and the storage have to be turned on together, and a fixture that did it silently
                // would be proving something the deployment does not have to get right.
                o.GrantTypesSupported.Add("client_credentials");
            };

            // Stands in for the resource server's bearer middleware, exactly as AdminSurfaceTests
            // does: this library does not validate tokens, it decides about a validated principal.
            seed.ConfigureApp = app => app.Use(async (http, next) =>
            {
                http.User = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim("sub", "01J8XKQ7M3N4P5R6S7T8V9W0AD"),
                        new Claim("scope", $"{AdminScopes.Read} {AdminScopes.Write}"),
                    ],
                    "bearer"));

                await next(http);
            });
        });
    }

    /// <summary>Create the account the service account will act as.</summary>
    private static async Task CreateAccountAsync(FlowFixture server, string role = "founder")
    {
        var created = await server.Client.PostAsJsonAsync(
            AuthorizationServerPaths.AdminUsers,
            new CreateUserRequest(Handle, "grace@example.com", role));

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    /// <summary>
    /// Grants the administrative scopes only to holders of one role - `AdminRoleScopePolicy`, as a
    /// double, and the shape every deployment that sets `ADMIN_ROLES` is running.
    /// </summary>
    private sealed class AdminScopesForRole(string role) : IScopeEntitlementPolicy
    {
        public ValueTask<ScopeSet> FilterAsync(
            UserAccount user, ScopeSet requested, CancellationToken cancellationToken)
        {
            if (user.Roles.Contains(role, StringComparer.Ordinal))
            {
                return ValueTask.FromResult(requested);
            }

            _ = ScopeSet.TryParse(
                string.Join(' ', requested.Values.Where(s => s != AdminScopes.Read && s != AdminScopes.Write)),
                out var narrowed,
                out _);

            return ValueTask.FromResult(narrowed);
        }
    }

    /// <summary>Create or rotate the service account, returning what the operator is shown.</summary>
    private static async Task<(string ClientId, string Secret)> CreateServiceAccountAsync(
        FlowFixture server, params string[] scopes)
    {
        var response = await server.Client.PostAsJsonAsync(
            $"/admin/users/{Handle}/service-account",
            new CreateServiceAccountRequest(scopes.Length > 0 ? scopes : [Scope]));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        return (body.GetProperty("client_id").GetString()!,
                body.GetProperty("client_secret").GetString()!);
    }

    /// <summary>Ask for a token the way a service configured with these two strings would.</summary>
    /// <remarks>
    /// RFC 6749 §2.3.1 Basic, with both halves form-urlencoded before the base64 - the same
    /// construction the admin BFF uses against this server, rather than the shortcut that happens to
    /// work while no credential contains a colon.
    /// </remarks>
    private static async Task<HttpResponseMessage> TokenAsync(
        FlowFixture server, string clientId, string secret, params (string Key, string Value)[] extra)
    {
        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",

            // RFC 8707, and required here rather than optional: this fixture registers two
            // resources, so the server refuses to guess which one a token is for. A caller may
            // override it through `extra` - including with nothing, which is
            // A_service_account_must_name_its_resource below.
            ["resource"] = Build.Resource,
        };

        foreach (var (key, value) in extra)
        {
            if (value.Length == 0)
            {
                form.Remove(key);
                continue;
            }

            form[key] = value;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, AuthorizationServerPaths.Token)
        {
            Content = new FormUrlEncodedContent(form),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                Uri.EscapeDataString(clientId) + ":" + Uri.EscapeDataString(secret))));

        return await server.Client.SendAsync(request);
    }

    /// <summary>
    /// Assert a status, and say what the server actually answered when it is not that.
    /// </summary>
    /// <remarks>
    /// The token endpoint refuses with a JSON body naming the reason, and a bare status comparison
    /// throws that away - "expected OK, actual BadRequest" over a response that said
    /// <c>unsupported_grant_type</c> costs a round of guessing to get back.
    /// </remarks>
    private static async Task ShouldBeAsync(HttpResponseMessage response, HttpStatusCode expected)
    {
        if (response.StatusCode == expected)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync();

        Assert.Fail($"expected {expected}, got {response.StatusCode}: {body}");
    }

    /// <summary>
    /// The whole path: an administrator creates one, and it obtains a token.
    /// </summary>
    /// <remarks>
    /// The test the feature never had. Everything else in this file is a way this can stop being
    /// true.
    /// </remarks>
    [Fact]
    public async Task A_created_service_account_obtains_a_token()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server);

        // Derived from the handle, so a person reading a config file can tell whose account it acts
        // as. Asserted because it is the string an operator copies into a deployed service, and
        // changing it would make rotating a secret a redeploy.
        Assert.Equal($"svc-{Handle}", clientId);

        using var token = await TokenAsync(server, clientId, secret);

        await ShouldBeAsync(token, HttpStatusCode.OK);

        var body = await token.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("access_token").GetString()));
        Assert.Equal(Scope, body.GetProperty("scope").GetString());

        // No refresh token, and that is the design rather than an omission: a service account holds
        // its own credential and can ask again whenever it likes, so a refresh token would be a
        // second long-lived secret bought for nothing. It is also what bounds "disabled" below to
        // one access-token lifetime.
        Assert.False(body.TryGetProperty("refresh_token", out _));
    }

    /// <summary>The scopes ticked on the form are the scopes in the token, and only those.</summary>
    /// <remarks>
    /// The property the scope picker depends on. If the grant widened or reordered what it was
    /// given, choosing scopes on a form would be choosing something else.
    /// </remarks>
    [Fact]
    public async Task The_token_carries_exactly_the_scopes_it_was_created_with()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server, "mcp:tools", "openid");

        using var token = await TokenAsync(server, clientId, secret);
        await ShouldBeAsync(token, HttpStatusCode.OK);

        var granted = (await token.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("scope").GetString()!
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(["mcp:tools", "openid"], granted.Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// A <c>scope</c> parameter on the request is refused rather than honoured.
    /// </summary>
    /// <remarks>
    /// RFC 6749 §4.4.2 permits one, and this server refuses it: scope is fixed on the client, so a
    /// request that could name its own would let a service account widen itself past what the
    /// administrator ticked. Asserted over HTTP because that is where a client would send it.
    /// </remarks>
    // ── The owner's roles are the ceiling ───────────────────────────────────
    //
    // `UserAdministration` says so when it creates one of these, and the CLI prints it to the
    // operator: "It acts as `<handle>` and can do whatever that account's roles allow." It was
    // true of nowhere. This grant read scope straight off the client record, and the surface that
    // consumes the token deliberately never reads the role - correctly, because that is the
    // authorization server's job, and the authorization server was not doing it on this one path.
    //
    // Measured before the fix: an account holding a role that is not in ADMIN_ROLES got a service
    // account with `users:write`, read the entire directory including every email, and promoted
    // its own owner to founder. The same subject going through /authorize for the same scopes was
    // cut back to `openid` by the same policy - so the policy was registered and running, and this
    // grant was simply not asking it.

    /// <summary>An owner who may not hold the scope means the token is refused, not narrowed.</summary>
    [Fact]
    public async Task A_service_account_is_refused_when_its_owner_may_not_hold_the_scope()
    {
        await using var server = await StartAsync(
            policy: new AdminScopesForRole("founder"), ownerRole: "boring");

        await CreateAccountAsync(server, "boring");

        var (clientId, secret) = await CreateServiceAccountAsync(server, AdminScopes.Write, "mcp:tools");

        using var token = await TokenAsync(server, clientId, secret);
        await ShouldBeAsync(token, HttpStatusCode.BadRequest);

        var body = await token.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// The control, and the reason the test above is about the ceiling rather than about every
    /// service account failing.
    /// </summary>
    [Fact]
    public async Task An_entitled_owner_still_gets_the_token()
    {
        await using var server = await StartAsync(policy: new AdminScopesForRole("founder"));
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server, AdminScopes.Write, "mcp:tools");

        using var token = await TokenAsync(server, clientId, secret);
        await ShouldBeAsync(token, HttpStatusCode.OK);

        var granted = (await token.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("scope").GetString()!
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        Assert.Contains(AdminScopes.Write, granted);
    }

    /// <summary>
    /// A second control: with no policy registered nothing narrows, which is every deployment that
    /// has not set `ADMIN_ROLES`. Without this, a filter that refused everything would pass the
    /// test above and look like a working ceiling.
    /// </summary>
    [Fact]
    public async Task With_no_policy_registered_nothing_is_narrowed()
    {
        await using var server = await StartAsync(ownerRole: "boring");
        await CreateAccountAsync(server, "boring");

        var (clientId, secret) = await CreateServiceAccountAsync(server, AdminScopes.Write, "mcp:tools");

        using var token = await TokenAsync(server, clientId, secret);
        await ShouldBeAsync(token, HttpStatusCode.OK);
    }

    /// <summary>
    /// The scope that was withheld is named, because the operator has to be able to tell this
    /// apart from a wrong secret or a revoked grant.
    /// </summary>
    [Fact]
    public async Task The_refusal_names_the_scope_the_owner_could_not_hold()
    {
        await using var server = await StartAsync(
            policy: new AdminScopesForRole("founder"), ownerRole: "boring");

        await CreateAccountAsync(server, "boring");

        var (clientId, secret) = await CreateServiceAccountAsync(server, AdminScopes.Write, "mcp:tools");

        using var token = await TokenAsync(server, clientId, secret);
        await ShouldBeAsync(token, HttpStatusCode.BadRequest);

        var rejection = Assert.Single(
            server.Logs.Rejections, l => l.Message.Contains("withheld=", StringComparison.Ordinal));

        Assert.Contains(AdminScopes.Write, rejection.Message, StringComparison.Ordinal);

        // And not the one the owner could have had, or the line reads as though everything failed.
        Assert.DoesNotContain("withheld=mcp:tools", rejection.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_scope_parameter_is_refused()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server);

        using var token = await TokenAsync(server, clientId, secret, ("scope", "mcp:tools"));

        await ShouldBeAsync(token, HttpStatusCode.BadRequest);

        var body = await token.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// When two resources could both serve the scopes, the request still has to say which.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The limit of the derivation above, and the case A-02 is about: both of the default fixture's
    /// resources define <c>mcp:tools</c>, so a service account holding it has genuinely not said
    /// which one its tokens are for, and picking one would make the audience depend on registration
    /// order. Refusing is correct here in a way it was not when the scopes chose.
    /// </para>
    /// <para>
    /// It is worth keeping a test on the refusal rather than only on the new path: the narrowing is
    /// allowed to make more requests succeed and is not allowed to start guessing, and only this
    /// direction catches the difference.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_service_account_must_name_its_resource_when_two_could_serve_it()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server);

        using var without = await TokenAsync(server, clientId, secret, ("resource", string.Empty));

        await ShouldBeAsync(without, HttpStatusCode.BadRequest);

        var body = await without.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_target", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// When the client's own scopes name one resource, no <c>resource</c> parameter is needed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The production shape: two resources, one defining the connector's scopes and one the admin
    /// API's, and a service account pinned to the connector's. Nothing in the request says which -
    /// the client record already did, because scope is fixed on the client for this grant.
    /// </para>
    /// <para>
    /// The default fixture cannot show this: both of its resources define <c>mcp:tools</c>, so the
    /// scopes genuinely do not choose between them and the request must still say. That case is
    /// <see cref="A_service_account_must_name_its_resource_when_two_could_serve_it"/> below.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_service_account_whose_scopes_name_one_resource_needs_no_resource_parameter()
    {
        await using var server = await StartAsync(registry: new TestResourceRegistry()
            .Add(Build.Resource, "docs:read docs:write")
            .Add(Build.OtherResource, "users:read users:write"));

        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server, "docs:read", "docs:write");

        using var token = await TokenAsync(server, clientId, secret, ("resource", string.Empty));

        await ShouldBeAsync(token, HttpStatusCode.OK);

        var body = await token.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("docs:read docs:write", body.GetProperty("scope").GetString());
    }

    /// <summary>
    /// A scope the registry declares for nothing does not stop that.
    /// </summary>
    /// <remarks>
    /// <c>openid</c> and <c>offline_access</c> belong to the server rather than to any resource, so
    /// requiring a candidate to define them would match nothing and put the refusal back - for a
    /// service account whose only sin is holding a scope the picker offers.
    /// </remarks>
    [Fact]
    public async Task A_scope_no_resource_defines_does_not_make_it_ambiguous()
    {
        await using var server = await StartAsync(registry: new TestResourceRegistry()
            .Add(Build.Resource, "docs:read docs:write")
            .Add(Build.OtherResource, "users:read users:write"));

        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server, "docs:read", "openid");

        using var token = await TokenAsync(server, clientId, secret, ("resource", string.Empty));

        await ShouldBeAsync(token, HttpStatusCode.OK);
    }

    /// <summary>
    /// Turning stored clients on does not take the configured clients' secrets away.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The composition production shipped without: <c>ClientAuthenticator</c> takes one secret
    /// store, each source answers only for its own clients, and before the stores chained,
    /// <c>AddStoredClients</c> replaced the configured store outright - so the fix for "service
    /// accounts cannot authenticate" would have arrived as "the configured clients cannot".
    /// </para>
    /// <para>
    /// The grant refusing this client is the proof its authentication <b>succeeded</b>: a wrong
    /// or unfindable secret dies earlier as <c>invalid_client</c>, and <c>unauthorized_client</c>
    /// ("not registered to act as an account") is only ever said to a client that authenticated
    /// and has no owner. Asserting a full authorization-code exchange here would prove the same
    /// thing at ten times the length.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_configured_client_still_authenticates_beside_the_store()
    {
        await using var server = await StartAsync();

        using var right = await TokenAsync(server, "https://admin.example.com/client", ConfiguredSecret);

        await ShouldBeAsync(right, HttpStatusCode.BadRequest);
        Assert.Equal(
            "unauthorized_client",
            (await right.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());

        // And the wrong secret still dies as authentication, not as the grant: the chain must not
        // have made "no store answered" look like "authenticated, but unauthorized".
        using var wrong = await TokenAsync(server, "https://admin.example.com/client", "not-the-secret");

        await ShouldBeAsync(wrong, HttpStatusCode.Unauthorized);
    }

    /// <summary>The wrong secret is refused, and the client id alone is not enough.</summary>
    /// <remarks>
    /// The failure this kills is a confidential client authenticating as public: every layer behaves
    /// correctly and anybody knowing a derived, guessable client id mints the owner's token.
    /// </remarks>
    [Fact]
    public async Task A_wrong_secret_is_refused()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, _) = await CreateServiceAccountAsync(server);

        using var token = await TokenAsync(server, clientId, "not-the-secret");

        await ShouldBeAsync(token, HttpStatusCode.Unauthorized);
    }

    /// <summary>Unticking "may obtain tokens" stops the next one.</summary>
    /// <remarks>
    /// <b>Not revocation, and the page says so.</b> What this asserts is the half that is true
    /// immediately: no new token is issued. One already out lives until it expires, which is why the
    /// caveat under the checkbox has to keep saying it.
    /// </remarks>
    [Fact]
    public async Task A_disabled_service_account_is_refused_a_new_token()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server);

        using (var before = await TokenAsync(server, clientId, secret))
        {
            await ShouldBeAsync(before, HttpStatusCode.OK);
        }

        var patched = await server.Client.PatchAsJsonAsync(
            $"/admin/users/{Handle}/service-account", new PatchServiceAccountRequest(Enabled: false));

        Assert.Equal(HttpStatusCode.NoContent, patched.StatusCode);

        using var after = await TokenAsync(server, clientId, secret);

        Assert.NotEqual(HttpStatusCode.OK, after.StatusCode);

        // And back on again, because a switch that only goes one way is a switch that quietly
        // becomes a delete.
        await server.Client.PatchAsJsonAsync(
            $"/admin/users/{Handle}/service-account", new PatchServiceAccountRequest(Enabled: true));

        using var again = await TokenAsync(server, clientId, secret);
        await ShouldBeAsync(again, HttpStatusCode.OK);
    }

    /// <summary>Deleting it stops the credential working.</summary>
    [Fact]
    public async Task A_deleted_service_account_stops_obtaining_tokens()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, secret) = await CreateServiceAccountAsync(server);

        var deleted = await server.Client.DeleteAsync($"/admin/users/{Handle}/service-account");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        using var after = await TokenAsync(server, clientId, secret);

        Assert.NotEqual(HttpStatusCode.OK, after.StatusCode);
    }

    /// <summary>
    /// Creating one again rotates the secret: the id survives and the old secret stops working.
    /// </summary>
    /// <remarks>
    /// Both halves matter and they pull in opposite directions. The id is reused so that rotating a
    /// secret is not a redeploy of everything configured with it; the old secret must die so that
    /// rotation is a response to a leak rather than a second working credential. A rotation that
    /// left the old one valid would look identical from the page that performed it.
    /// </remarks>
    [Fact]
    public async Task Rotating_keeps_the_id_and_kills_the_old_secret()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, first) = await CreateServiceAccountAsync(server);
        var (again, second) = await CreateServiceAccountAsync(server);

        Assert.Equal(clientId, again);
        Assert.NotEqual(first, second);

        using (var withNew = await TokenAsync(server, clientId, second))
        {
            await ShouldBeAsync(withNew, HttpStatusCode.OK);
        }

        using var withOld = await TokenAsync(server, clientId, first);

        await ShouldBeAsync(withOld, HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// Recreated with different scopes, it is audienced at what those scopes name now.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Measured in production 2026-09-01.</b> A service account holding the administrative
    /// scopes was deleted and recreated holding a resource server's. Every token afterwards carried
    /// the new scopes and the OLD audience, so the resource server refused all of them with "the
    /// access token was not issued for this resource" while this server logged a clean 200. Naming
    /// the new resource explicitly failed too, with <c>invalid_target</c>. Half a day went into the
    /// resource registry, which was correct the whole time.
    /// </para>
    /// <para>
    /// <b>Why deleting did not clear it.</b> The client id is derived from the owner's handle and
    /// the grant id from (client, owner), so both came back identical and the grant row survived
    /// the delete. That row is written once - <c>StoreAsync</c> is an insert and refuses a
    /// duplicate - so reading its resources back is a cache with no invalidation, for a value that
    /// was itself derived from the scopes the client held at the time.
    /// </para>
    /// <para>
    /// The first token matters and is not decoration: the row is written on first use, not at
    /// creation, so an account that was never used has nothing stale to inherit.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_recreated_service_account_is_audienced_at_what_its_new_scopes_name()
    {
        await using var server = await StartAsync(registry: new TestResourceRegistry()
            .Add(Build.Resource, "docs:read docs:write")
            .Add(Build.OtherResource, "users:read users:write"));

        await CreateAccountAsync(server);

        // Used once, which is what writes the grant row.
        var (firstId, firstSecret) = await CreateServiceAccountAsync(server, "users:read", "users:write");

        using (var first = await TokenAsync(server, firstId, firstSecret, ("resource", Build.OtherResource)))
        {
            await ShouldBeAsync(first, HttpStatusCode.OK);
        }

        var deleted = await server.Client.DeleteAsync($"/admin/users/{Handle}/service-account");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        var (secondId, secondSecret) = await CreateServiceAccountAsync(server, "docs:read", "docs:write");

        // The same credential id, which is the whole reason the row is found again.
        Assert.Equal(firstId, secondId);

        using var token = await TokenAsync(server, secondId, secondSecret, ("resource", Build.Resource));

        await ShouldBeAsync(token, HttpStatusCode.OK);

        var body = await token.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("docs:read docs:write", body.GetProperty("scope").GetString());
    }

    /// <summary>
    /// And not at the one it left behind.
    /// </summary>
    /// <remarks>
    /// The control for the test above, and the reason it is not enough on its own: recomputing the
    /// audience would also "pass" if it resolved to every registered resource. This says the new
    /// set is narrower than that - the resource the old scopes named is refused now, which is what
    /// makes the recomputation a derivation rather than a widening.
    /// </remarks>
    [Fact]
    public async Task A_recreated_service_account_is_not_audienced_at_what_it_left_behind()
    {
        await using var server = await StartAsync(registry: new TestResourceRegistry()
            .Add(Build.Resource, "docs:read docs:write")
            .Add(Build.OtherResource, "users:read users:write"));

        await CreateAccountAsync(server);

        var (firstId, firstSecret) = await CreateServiceAccountAsync(server, "users:read", "users:write");

        using (var first = await TokenAsync(server, firstId, firstSecret, ("resource", Build.OtherResource)))
        {
            await ShouldBeAsync(first, HttpStatusCode.OK);
        }

        var deleted = await server.Client.DeleteAsync($"/admin/users/{Handle}/service-account");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        var (secondId, secondSecret) = await CreateServiceAccountAsync(server, "docs:read", "docs:write");

        using var stale = await TokenAsync(server, secondId, secondSecret, ("resource", Build.OtherResource));

        await ShouldBeAsync(stale, HttpStatusCode.BadRequest);

        var body = await stale.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_target", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// A service account never reaches <c>/authorize</c>, whatever it sends.
    /// </summary>
    /// <remarks>
    /// The two grant sets do not overlap by design: a client that could do both would be one a
    /// person can authorize <i>and</i> one holding a standing credential for somebody else's
    /// account, with the answer decided by which endpoint the caller used. Asserted here rather than
    /// on the resolver because a redirect URI it never registered is the thing an attacker would
    /// supply.
    /// </remarks>
    [Fact]
    public async Task A_service_account_cannot_start_an_authorization()
    {
        await using var server = await StartAsync();
        await CreateAccountAsync(server);

        var (clientId, _) = await CreateServiceAccountAsync(server);

        using var response = await server.Client.GetAsync(
            AuthorizationServerPaths.Authorize
            + "?response_type=code"
            + "&client_id=" + Uri.EscapeDataString(clientId)
            + "&redirect_uri=" + Uri.EscapeDataString("https://attacker.example/cb")
            + "&scope=" + Uri.EscapeDataString(Scope)
            + "&state=xyz");

        Assert.NotEqual(HttpStatusCode.Found, response.StatusCode);
    }
}
