using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>/account/*</c> — the surface a person points at their own account. E-33 to E-38.
/// </summary>
/// <remarks>
/// The property under test throughout is §1.6: <b>no handler here has a code path that reaches
/// another account.</b> That is a claim about absence, so most of these tests are shaped as "put
/// somebody else's thing in the request and watch it not work" rather than as "the happy path
/// returns 200".
/// </remarks>
public sealed class AccountSurfaceTests
{
    private const string Mine = "01J8XKQ7M3N4P5R6S7T8V9W0AD";
    private const string Theirs = "01J8XKQ7M3N4P5R6S7T8V9W0ZZ";

    private sealed class Caller
    {
        internal static string? Scheme { get; set; }

        internal static string Scopes { get; set; } = string.Empty;

        internal static string? Subject { get; set; } = Mine;
    }

    private sealed record World(
        FlowFixture Fixture, InMemoryUserStore Users, InMemoryRoleStore Roles, SharedStores Stores, InMemoryAdminAuditStore Audit);

    private static async Task<World> StartAsync(bool selfService = true)
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        // Defined before anything can hold them. Creation does not assign and assignment refuses an
        // id the realm does not define, so a directory with no roles in it is a directory where
        // nobody can be given one — which is the rule, stated as a fixture.
        if (await roles.FindAsync(RealmId.Default, "founder", CancellationToken.None) is null)
        {
            await roles.StoreAsync(new RoleDefinition("founder", "founder", []), CancellationToken.None);
        }
        if (await roles.FindAsync(RealmId.Default, "operator", CancellationToken.None) is null)
        {
            await roles.StoreAsync(new RoleDefinition("operator", "operator", []), CancellationToken.None);
        }
        if (await roles.FindAsync(RealmId.Default, "employee", CancellationToken.None) is null)
        {
            await roles.StoreAsync(new RoleDefinition("employee", "employee", []), CancellationToken.None);
        }
        var audit = new InMemoryAdminAuditStore();
        var stores = new SharedStores();

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Stores = stores;

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
                o.SelfServiceEnabled = selfService;
                o.ScopesSupported.Add(AdminScopes.Self);
            };

            seed.ConfigureApp = app => app.Use(async (http, next) =>
            {
                if (Caller.Scheme is { } scheme)
                {
                    List<Claim> claims = [new Claim("scope", Caller.Scopes)];

                    if (Caller.Subject is { } subject)
                    {
                        claims.Add(new Claim("sub", subject));
                    }

                    http.User = new ClaimsPrincipal(new ClaimsIdentity(claims, scheme));
                }

                await next(http);
            });
        });

        return new World(fixture, users, roles, stores, audit);
    }

    private static void SignedIn(string? scheme = "Bearer", string? scopes = null, string? subject = Mine)
    {
        Caller.Scheme = scheme;
        Caller.Scopes = scopes ?? AdminScopes.Self;
        Caller.Subject = subject;
    }

    private static async Task<UserAccount> SeedAccountAsync(
        World world, string subject, string handle, string? password = "correct horse")
    {
        var account = new UserAccount(
            SubjectId.FromStorage(subject),
            handle,
            handle + "@example.com",
            EmailVerified: true,
            password is null ? null : new Argon2idPasswordHasher().Hash(password)) { Roles = ["founder"] };

        await world.Users.StoreAsync(account with { Roles = [] }, CancellationToken.None);
        await world.Users.SetRolesAsync(account.Subject, account.Roles, CancellationToken.None);

        return account;
    }

    private static async Task<GrantRecord> SeedGrantAsync(
        World world, string subject, string clientId, string grantId)
    {
        var grant = new GrantRecord(
            grantId,
            SubjectId.FromStorage(subject),
            ClientIdentifier.ForPreRegistered(clientId),
            ScopeSet.FromStorage("kb:read"),
            ["https://api.example.com"],
            DateTimeOffset.UnixEpoch.AddDays(1),
            DateTimeOffset.UnixEpoch.AddDays(1));

        await world.Stores.Grants.StoreAsync(grant, CancellationToken.None);

        return grant;
    }

    // ─────────────────────────────────────────────────────────────── the surface

    /// <summary>
    /// It is absent unless a deployment asked for it, the same as <c>/admin</c>.
    /// </summary>
    [Fact]
    public async Task It_is_absent_unless_a_deployment_asked_for_it()
    {
        var world = await StartAsync(selfService: false);
        await using var fixture = world.Fixture;

        SignedIn();

        var response = await fixture.Client.GetAsync(new Uri("/account", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// A cookie principal is refused, carrying the right scope. <c>N-17</c>.
    /// </summary>
    /// <remarks>
    /// The same rule as the admin surface and a weaker justification, which is why it is asserted
    /// rather than assumed: the blast radius here is one account, so "it is only your own data" is
    /// an argument somebody will one day make for letting the consent page call this. The answer is
    /// that <c>/me</c> exists for that, with antiforgery, and this surface stays bearer-only.
    /// </remarks>
    [Fact]
    public async Task A_cookie_principal_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        SignedIn(CookieAuthenticationDefaults.AuthenticationScheme);

        var response = await fixture.Client.GetAsync(new Uri("/account", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// A token with the scope and no <c>sub</c> is refused rather than run against nobody.
    /// </summary>
    /// <remarks>
    /// A client-credentials token, or one minted by something that dropped the claim. Every handler
    /// here reads its subject from the principal, so without this check they would all run against a
    /// default <see cref="SubjectId"/> — which is not an account, but is a value that compares equal
    /// to any other default and would make "whose row is this" answerable by accident.
    /// </remarks>
    [Fact]
    public async Task A_token_carrying_no_subject_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        SignedIn(subject: null);

        var response = await fixture.Client.GetAsync(new Uri("/account", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>Without <c>users:self</c>, nothing here answers.</summary>
    [Fact]
    public async Task The_self_scope_is_required()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        SignedIn(scopes: AdminScopes.Read + " " + AdminScopes.Write);

        var response = await fixture.Client.GetAsync(new Uri("/account", UriKind.Relative));

        // Deliberately including the two admin scopes: holding authority over everyone is not
        // holding authority over yourself, and the surfaces do not imply each other.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ────────────────────────────────────────────────────────────────────── E-33

    /// <summary>
    /// <c>GET /account</c> answers from the directory, not from the token.
    /// </summary>
    /// <remarks>
    /// The role is changed after the principal is minted and before the request. A handler
    /// projecting the token's claims would return the stale one, which is the defect this asserts
    /// against — and the reason it matters is <c>disabled_at</c>, which a token cannot carry at all.
    /// </remarks>
    [Fact]
    public async Task It_reads_the_account_from_the_directory_rather_than_the_token()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await world.Users.SetRolesAsync(SubjectId.FromStorage(Mine), ["operator"], CancellationToken.None);

        SignedIn();

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>(new Uri("/account", UriKind.Relative));

        Assert.Equal("ada", body.GetProperty("handle").GetString());
        Assert.Equal("operator", body.GetProperty("role")[0].GetString());
        Assert.True(body.GetProperty("has_password").GetBoolean());

        // The hash is a credential's shadow and is not on this surface at any depth.
        Assert.DoesNotContain("password_hash", body.ToString(), StringComparison.Ordinal);
    }

    // ────────────────────────────────────────────────────────────────────── E-34

    /// <summary>
    /// A password change needs the current password, even with a valid token. <c>S-49</c>.
    /// </summary>
    /// <remarks>
    /// The whole reason the endpoint exists in this shape. Without the check, half an hour of stolen
    /// access becomes permanent access and every rotation the token design pays for is wasted.
    /// </remarks>
    [Fact]
    public async Task A_wrong_current_password_is_refused_and_changes_nothing()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var before = await SeedAccountAsync(world, Mine, "ada");
        SignedIn();

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password", UriKind.Relative),
            new { current_password = "not it", new_password = "a new one entirely" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        // 403 rather than 401: the caller authenticated fine, so inviting them to get a new token
        // would be a loop that cannot terminate.
        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);
        Assert.Equal(before.PasswordHash, after!.PasswordHash);

        // And it is audited. A run of these against one subject is somebody working through a stolen
        // token, and no sign-in happened, so the sign-in log will not show it.
        var entries = await world.Audit.ReadAsync(new AuditQuery(RealmId.Default), CancellationToken.None);
        var refusal = Assert.Single(entries, e => e.Action == "user.password.change");
        Assert.Equal(AdminAuditOutcome.Refused, refusal.Outcome);
    }

    /// <summary>The right current password changes it, and leaves sessions alone by default.</summary>
    /// <remarks>
    /// §1.10: revocation is asked for, not inferred. The server cannot tell a routine change from a
    /// response to a compromise, so it does what the caller said and reports the number.
    /// </remarks>
    [Fact]
    public async Task A_change_leaves_other_sessions_running_unless_asked()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var before = await SeedAccountAsync(world, Mine, "ada");
        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        SignedIn();

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password", UriKind.Relative),
            new { current_password = "correct horse", new_password = "battery staple stapler" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(0, body.GetProperty("sessions_revoked").GetInt32());

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);
        Assert.NotEqual(before.PasswordHash, after!.PasswordHash);

        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));
    }

    /// <summary>Asking for revocation ends every session, including this one.</summary>
    /// <remarks>
    /// Sparing the caller's own session would mean identifying which grant this request came from,
    /// from a token this service is not given — and getting that wrong leaves the compromised
    /// session alive, which is the one case the flag exists for.
    /// </remarks>
    [Fact]
    public async Task Asking_for_revocation_ends_every_session()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Mine, "client-b", "grant-2");
        await SeedGrantAsync(world, Theirs, "client-a", "grant-other");

        SignedIn();

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password", UriKind.Relative),
            new
            {
                current_password = "correct horse",
                new_password = "battery staple stapler",
                revoke_sessions = true,
            });

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, body.GetProperty("sessions_revoked").GetInt32());

        Assert.True(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));
        Assert.True(await world.Stores.Grants.IsRevokedAsync("grant-2", CancellationToken.None));

        // The control, and the point of the whole file: somebody else's grant is untouched.
        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-other", CancellationToken.None));
    }

    /// <summary>An account with no local password says so rather than "wrong password".</summary>
    /// <remarks>
    /// A federated-only account. The caller is the account holder, so this is not an oracle about
    /// somebody else, and "wrong password" would send them hunting for one that does not exist.
    /// </remarks>
    [Fact]
    public async Task An_account_with_no_password_says_so()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada", password: null);
        SignedIn();

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password", UriKind.Relative),
            new { current_password = "anything", new_password = "something else" });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("no_password", body.GetProperty("error").GetString());
    }

    /// <summary>A blank new password is refused before it locks somebody out.</summary>
    [Fact]
    public async Task A_blank_new_password_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        SignedIn();

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password", UriKind.Relative),
            new { current_password = "correct horse", new_password = "   " });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ────────────────────────────────────────────────────────────────── E-35, E-36

    /// <summary>The session list is this account's, and only this account's.</summary>
    [Fact]
    public async Task The_session_list_holds_only_your_own()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Theirs, "client-a", "grant-other");

        SignedIn();

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/account/sessions", UriKind.Relative));

        var ids = body.EnumerateArray().Select(e => e.GetProperty("id").GetString()).ToList();

        Assert.Equal(["grant-1"], ids);
    }

    /// <summary>A revoked grant is not a session.</summary>
    [Fact]
    public async Task An_ended_session_leaves_the_list()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Mine, "client-b", "grant-2");

        SignedIn();

        var ended = await fixture.Client.DeleteAsync(new Uri("/account/sessions/grant-1", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, ended.StatusCode);
        Assert.True((await ended.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetBoolean());

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/account/sessions", UriKind.Relative));

        Assert.Equal(["grant-2"], body.EnumerateArray().Select(e => e.GetProperty("id").GetString()));

        // Ending it twice is not an error. The row is still there — rows are never deleted on
        // revocation — so the second call finds it, sees it is not the caller's problem any more,
        // and says the honest thing.
        var again = await fixture.Client.DeleteAsync(new Uri("/account/sessions/grant-1", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.False((await again.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("revoked").GetBoolean());
    }

    /// <summary>
    /// Somebody else's grant id is 404, and their session survives.
    /// </summary>
    /// <remarks>
    /// <b>The single most important assertion in this file.</b> <c>IGrantStore.RevokeAsync</c> takes
    /// an id and no subject, so a handler that passed the route value straight through would let
    /// anyone holding <c>users:self</c> — which is everyone — end any session in the deployment.
    /// 404 rather than 403 because a 403 confirms the id exists, which turns this into an oracle for
    /// guessing grant ids.
    /// </remarks>
    [Fact]
    public async Task Another_accounts_session_cannot_be_ended_and_is_not_confirmed_to_exist()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await SeedGrantAsync(world, Theirs, "client-a", "grant-other");

        SignedIn();

        var response = await fixture.Client.DeleteAsync(
            new Uri("/account/sessions/grant-other", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-other", CancellationToken.None));

        // Indistinguishable from an id that was never issued. If these two answers ever differ, the
        // endpoint has become a way to enumerate the deployment's grants.
        var absent = await fixture.Client.DeleteAsync(
            new Uri("/account/sessions/no-such-grant", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);
        Assert.Equal(
            await response.Content.ReadAsStringAsync(),
            await absent.Content.ReadAsStringAsync());
    }

    // ────────────────────────────────────────────────────────────────── E-37, E-38

    /// <summary>Consents list, and withdrawing one does not end the session it authorized.</summary>
    /// <remarks>
    /// Two operations because they are two intentions. "Ask me again next time" is not "sign me
    /// out", and doing the second quietly would make the button lie about what it did.
    /// </remarks>
    [Fact]
    public async Task Withdrawing_consent_forgets_the_approval_and_leaves_the_session()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        await world.Stores.Consents.GrantAsync(
            SubjectId.FromStorage(Mine),
            ClientIdentifier.ForPreRegistered("client-a"),
            ScopeSet.FromStorage("kb:read"),
            ["https://api.example.com"],
            DateTimeOffset.UnixEpoch.AddDays(1),
            CancellationToken.None);

        SignedIn();

        var listed = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/account/consents", UriKind.Relative));

        Assert.Equal(
            ["client-a"],
            listed.EnumerateArray().Select(e => e.GetProperty("client_id").GetString()));

        var withdrawn = await fixture.Client.DeleteAsync(
            new Uri("/account/consents/client-a", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, withdrawn.StatusCode);
        Assert.False(
            (await withdrawn.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("sessions_revoked").GetBoolean());

        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));

        var after = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/account/consents", UriKind.Relative));

        Assert.Empty(after.EnumerateArray());
    }

    /// <summary>
    /// A client id that is a URL survives the round trip.
    /// </summary>
    /// <remarks>
    /// The reason <c>AccountConsent</c> is a catch-all segment. This server supports client ID
    /// metadata documents, so the id an MCP client is known by is
    /// <c>https://claude.ai/oauth/mcp-oauth-client-metadata</c> — a scheme and several path
    /// segments. A <c>{clientId}</c> template matches none of it, and percent-encoding the slashes
    /// makes the answer depend on whether the proxy in front normalises <c>%2F</c>.
    /// </remarks>
    [Fact]
    public async Task A_url_shaped_client_id_can_be_withdrawn()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        const string cimd = "https://claude.ai/oauth/mcp-oauth-client-metadata";

        await SeedAccountAsync(world, Mine, "ada");
        await world.Stores.Consents.GrantAsync(
            SubjectId.FromStorage(Mine),
            ClientIdentifier.ForCimd(cimd),
            ScopeSet.FromStorage("kb:read"),
            [],
            DateTimeOffset.UnixEpoch.AddDays(1),
            CancellationToken.None);

        SignedIn();

        var response = await fixture.Client.DeleteAsync(
            new Uri("/account/consents/" + cimd, UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await fixture.Client.GetFromJsonAsync<JsonElement>(
            new Uri("/account/consents", UriKind.Relative));

        Assert.Empty(body.EnumerateArray());
    }

    /// <summary>Withdrawing a consent that is not yours is 404, and theirs survives.</summary>
    [Fact]
    public async Task Another_accounts_consent_cannot_be_withdrawn()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAccountAsync(world, Mine, "ada");
        await world.Stores.Consents.GrantAsync(
            SubjectId.FromStorage(Theirs),
            ClientIdentifier.ForPreRegistered("client-a"),
            ScopeSet.FromStorage("kb:read"),
            [],
            DateTimeOffset.UnixEpoch.AddDays(1),
            CancellationToken.None);

        SignedIn();

        var response = await fixture.Client.DeleteAsync(
            new Uri("/account/consents/client-a", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        Assert.NotNull(await world.Stores.Consents.FindAsync(
            SubjectId.FromStorage(Theirs),
            ClientIdentifier.ForPreRegistered("client-a"),
            CancellationToken.None));
    }
}
