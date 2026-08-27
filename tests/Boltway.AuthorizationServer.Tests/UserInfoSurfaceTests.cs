using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>/userinfo</c>: what an OIDC client is told about the person who just signed in.
/// </summary>
/// <remarks>
/// <para>
/// The interesting assertions here are the two asymmetries, because both are decisions rather than
/// defaults: personal data follows the granted scopes, and the role does not. The second is what
/// makes this endpoint useful to a client that maps a directory onto its own permissions - behind a
/// scope, a client that forgot to ask would get a login that succeeds and grants nothing, which
/// reaches a person as "my account is broken".
/// </para>
/// <para>
/// And that the answer comes from the store rather than the token, which is the difference between
/// a demotion taking effect at the next sign-in and at the next token expiry.
/// </para>
/// </remarks>
public sealed class UserInfoSurfaceTests
{
    private const string Mine = "01J8XKQ7M3N4P5R6S7T8V9W0AD";

    private sealed class Caller
    {
        internal static string? Scheme { get; set; }

        internal static string Scopes { get; set; } = string.Empty;

        internal static string? Subject { get; set; } = Mine;
    }

    private sealed record World(FlowFixture Fixture, InMemoryUserStore Users);

    private static async Task<World> StartAsync(bool userInfo = true)
    {
        var roles = new InMemoryRoleStore();
        foreach (var id in new[] { "founder", "operator", "employee" })
        {
            // Defined before anything can hold them - creation does not assign, and assignment
            // refuses an id the realm does not define.
            if (await roles.FindAsync(RealmId.Default, id, CancellationToken.None) is null)
            {
                await roles.StoreAsync(new RoleDefinition(id, id, []), CancellationToken.None);
            }
        }

        var users = new InMemoryUserStore(roles);

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
            };

            seed.ConfigureOptions = o => o.UserInfoEnabled = userInfo;

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

        return new World(fixture, users);
    }

    private static void SignedIn(string? scheme = "Bearer", string? scopes = "openid", string? subject = Mine)
    {
        Caller.Scheme = scheme;
        Caller.Scopes = scopes ?? string.Empty;
        Caller.Subject = subject;
    }

    private static async Task SeedAsync(World world, string? role = "founder")
    {
        await world.Users.StoreAsync(
            new UserAccount(
                SubjectId.FromStorage(Mine),
                "ada",
                "ada@example.com",
                EmailVerified: true,
                PasswordHash: null),
            CancellationToken.None);

        if (role is { Length: > 0 })
        {
            await world.Users.SetRolesAsync(SubjectId.FromStorage(Mine), [role], CancellationToken.None);
        }
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();

    // ─────────────────────────────────────────────────────────────── the surface

    /// <summary>`sub` is in every response, whatever was granted. OIDC Core §5.3.2.</summary>
    [Fact]
    public async Task The_subject_is_always_present()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAsync(world);
        SignedIn(scopes: "openid");

        var body = await BodyAsync(await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative)));

        Assert.Equal(Mine, body.GetProperty("sub").GetString());
    }

    /// <summary>
    /// The address follows the grant; the handle and the role do not.
    /// </summary>
    /// <remarks>
    /// One test rather than three, because the point is the *difference* between them: asserting
    /// each separately would let the asymmetry be broken in one direction without a failure that
    /// says what was lost.
    /// </remarks>
    [Fact]
    public async Task Personal_data_follows_the_scopes_and_the_role_does_not()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAsync(world);
        SignedIn(scopes: "openid");

        var bare = await BodyAsync(await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative)));

        Assert.False(bare.TryGetProperty("email", out _));

        // Both ungated, and both for the reason the access token already applies: the address is
        // data the subject consents to release, while the handle and the role are what a client
        // needs to name and place this person at all. `UserAccountClaims` releases
        // `preferred_username` into the token with no scope either - this asserts the two surfaces
        // agree, which is the part that would otherwise drift.
        Assert.Equal("ada", bare.GetProperty("preferred_username").GetString());
        Assert.Equal("founder", bare.GetProperty("role")[0].GetString());

        SignedIn(scopes: "openid email");

        var full = await BodyAsync(await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative)));

        Assert.Equal("ada@example.com", full.GetProperty("email").GetString());
        Assert.True(full.GetProperty("email_verified").GetBoolean());
    }

    /// <summary>
    /// The role is read from the directory, not from the token that reached this endpoint.
    /// </summary>
    /// <remarks>
    /// The failure this pins: a client mapping roles onto its own permissions on every sign-in
    /// would keep granting the old ones for as long as an access token lives - up to half an hour
    /// after somebody was deliberately demoted.
    /// </remarks>
    [Fact]
    public async Task The_role_is_the_one_the_directory_holds_now()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAsync(world, role: "founder");
        SignedIn(scopes: "openid");

        var before = await BodyAsync(await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative)));
        Assert.Equal("founder", before.GetProperty("role")[0].GetString());

        // The token in hand is unchanged and still says `founder` - only the directory moved.
        // `SetRoleAsync` rather than storing the account again: accounts are add-only in this store,
        // deliberately, because overwriting one would replace its credentials.
        await world.Users.SetRolesAsync(SubjectId.FromStorage(Mine), ["employee"], CancellationToken.None);

        var after = await BodyAsync(await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative)));
        Assert.Equal("employee", after.GetProperty("role")[0].GetString());
    }

    /// <summary>Bearer only. <c>N-17</c>.</summary>
    /// <remarks>
    /// The sign-in pages share this origin, so a cookie-authenticated read of who somebody is turns
    /// any XSS on the login page into that read.
    /// </remarks>
    [Fact]
    public async Task A_cookie_principal_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAsync(world);
        SignedIn(CookieAuthenticationDefaults.AuthenticationScheme);

        var response = await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Without <c>openid</c> it does not answer, whatever else the token carries.</summary>
    [Fact]
    public async Task The_openid_scope_is_required()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAsync(world);
        SignedIn(scopes: "email profile");

        var response = await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// A token that verifies and names nobody is refused rather than answered with an empty person.
    /// </summary>
    /// <remarks>
    /// Anonymised, or deleted out from under an outstanding token. <c>invalid_token</c> rather than
    /// a 404, because the subject is not a resource this endpoint locates - it is who the credential
    /// says you are, and the honest answer is that the credential no longer identifies anybody.
    /// </remarks>
    [Fact]
    public async Task A_token_naming_no_account_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        SignedIn(scopes: "openid");

        var response = await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Turned off, it is neither routed nor advertised.</summary>
    [Fact]
    public async Task It_is_absent_when_a_deployment_turns_it_off()
    {
        var world = await StartAsync(userInfo: false);
        await using var fixture = world.Fixture;

        await SeedAsync(world);
        SignedIn(scopes: "openid");

        var response = await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>POST answers too. OIDC Core §5.3.1 says a server SHOULD support it.</summary>
    [Fact]
    public async Task It_answers_a_post_as_well_as_a_get()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedAsync(world);
        SignedIn(scopes: "openid");

        var response = await fixture.Client.PostAsync(
            new Uri("/userinfo", UriKind.Relative), new StringContent(string.Empty));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
