using System.Net;
using System.Text.RegularExpressions;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Identity.Passwords;
using Boltway.Notifications;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>/me/*</c> — the pages a person uses on their own account. E-46.
/// </summary>
/// <remarks>
/// The mirror of <see cref="AccountSurfaceTests"/>: same account, same rules, opposite
/// authentication. §7.2 — <c>N-17</c> read literally would mean a founder changing their own
/// password runs an OAuth client, so these are cookie-authenticated with antiforgery and refuse a
/// bearer, and the prefixes are disjoint so both halves are mechanical.
/// </remarks>
public sealed partial class MeSurfaceTests
{
    private const string Mine = "01J8XKQ7M3N4P5R6S7T8V9W0AD";
    private const string Theirs = "01J8XKQ7M3N4P5R6S7T8V9W0ZZ";
    private const string Password = "correct horse battery";

    private sealed record World(
        FlowFixture Fixture,
        InMemoryUserStore Users,
        SharedStores Stores,
        RecordingSignIn SignIn,
        RecoverySurfaceTests.Outbox Mail);

    /// <summary>
    /// An <see cref="IUserSignIn"/> that records rather than touching a cookie.
    /// </summary>
    /// <remarks>
    /// The fixture pairs <c>TestUserSession</c> with no ASP.NET Core authentication, so the shipped
    /// <c>CookieUserSignIn</c> would throw looking for <c>IAuthenticationService</c>. That is the
    /// fixture being half a deployment rather than a defect — the two seams are documented as one
    /// decision, and a deployment replacing the session replaces the sign-out with it. What is worth
    /// asserting here is that the page <i>calls</i> it, which is the decision this step made.
    /// </remarks>
    internal sealed class RecordingSignIn : IUserSignIn
    {
        internal int SignOuts { get; private set; }

        public Task SignInAsync(HttpContext context, AuthenticatedUser user) => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context)
        {
            SignOuts++;
            return Task.CompletedTask;
        }
    }

    private static async Task<World> StartAsync(
        bool pages = true,
        string? signedInAs = Mine,
        string? password = Password,
        Dictionary<string, string>? scopeDescriptions = null,
        bool recovery = false,
        string? email = "ada@example.com",
        bool emailVerified = false,
        TimeSpan? accessTokenLifetime = null)
    {
        var roles = new InMemoryRoleStore();

        // Defined before anything can hold them — creation does not assign, and assignment refuses
        // an id the realm does not define.
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

        var users = new InMemoryUserStore(roles);
        var stores = new SharedStores();
        var hasher = new Argon2idPasswordHasher();
        var signIn = new RecordingSignIn();
        var mail = new RecoverySurfaceTests.Outbox();

        if (signedInAs is not null)
        {
            await users.StoreAsync(
                new UserAccount(
                    SubjectId.FromStorage(signedInAs),
                    "ada",
                    email,
                    EmailVerified: emailVerified,
                    password is null ? null : hasher.Hash(password)),
                CancellationToken.None);

            if (await roles.FindAsync(RealmId.Default, "founder", CancellationToken.None) is null)
        {
            await roles.StoreAsync(new RoleDefinition("founder", "founder", []), CancellationToken.None);
        }
            await users.SetRolesAsync(SubjectId.FromStorage(signedInAs), ["founder"], CancellationToken.None);
        }

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Stores = stores;

            seed.SignedInUser = signedInAs is null
                ? null
                : new AuthenticatedUser(SubjectId.FromStorage(signedInAs), DateTimeOffset.UnixEpoch);

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IPasswordHasher>(hasher);
                services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));
                services.AddSingleton<IAdminAuditStore>(new InMemoryAdminAuditStore());
                services.AddSingleton<IUserSignIn>(signIn);
                services.AddSingleton<IUserTokenStore>(new InMemoryUserTokenStore());
                services.AddSingleton<INotificationSender>(mail);
            };

            seed.ConfigureOptions = o =>
            {
                o.SelfServicePagesEnabled = pages;
                o.PasswordRecoveryEnabled = recovery;

                if (accessTokenLifetime is { } lifetime)
                {
                    o.AccessTokenLifetime = lifetime;
                }

                foreach (var (scope, description) in scopeDescriptions ?? [])
                {
                    o.ScopeDescriptions[scope] = description;
                }
            };
        });

        return new World(fixture, users, stores, signIn, mail);
    }

    private static async Task<ConsentRecord> SeedConsentAsync(
        World world, string subject, string clientId, string scope)
    {
        return await world.Stores.Consents.GrantAsync(
            SubjectId.FromStorage(subject),
            ClientIdentifier.ForPreRegistered(clientId),
            ScopeSet.FromStorage(scope),
            ["https://api.example.com"],
            DateTimeOffset.UnixEpoch.AddDays(1),
            CancellationToken.None);
    }

    private static async Task<GrantRecord> SeedGrantAsync(
        World world, string subject, string clientId, string grantId, string scope = "kb:read",
        string? userAgent = null)
    {
        var grant = new GrantRecord(
            grantId,
            SubjectId.FromStorage(subject),
            ClientIdentifier.ForPreRegistered(clientId),
            ScopeSet.FromStorage(scope),
            ["https://api.example.com"],
            DateTimeOffset.UnixEpoch.AddDays(1),
            DateTimeOffset.UnixEpoch.AddDays(1),
            RevokedAt: null,
            UserAgent: userAgent);

        await world.Stores.Grants.StoreAsync(grant, CancellationToken.None);

        return grant;
    }

    /// <summary>Give a grant a refresh token issued at a particular moment.</summary>
    /// <remarks>
    /// Straight into the store rather than through a token request: what the page reads is the
    /// newest <c>IssuedAt</c> among a grant's rows, and driving a real rotation to place one at a
    /// chosen moment would be a test about the token endpoint wearing this one's name.
    /// </remarks>
    private static async Task SeedRefreshAsync(
        World world, string grantId, DateTimeOffset issuedAt, string seed = "rt-1")
    {
        await world.Stores.RefreshTokens.StoreAsync(
            new RefreshTokenRecord(
                Sha256Hash.OfString(seed),
                grantId,
                $"family-{grantId}",
                Generation: 0,
                PredecessorHash: null,
                SuccessorHash: null,
                IssuedAt: issuedAt,
                ExpiresAt: issuedAt.AddDays(30)),
            CancellationToken.None);
    }

    [GeneratedRegex("<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"")]
    private static partial Regex HiddenField();

    /// <summary>Post a form, carrying whatever hidden fields the page drew.</summary>
    /// <remarks>
    /// <para>
    /// The antiforgery field name is read out of the HTML rather than assumed. ASP.NET Core chooses
    /// it, and a test that hardcoded it would pass against a page that had stopped drawing one.
    /// </para>
    /// <para>
    /// <paramref name="tokenFrom"/> defaults to the page being posted to and is separate for the one
    /// case where it has to be: the session list draws a form <i>per session</i>, so a person with
    /// none has no form to read a token from. Taking it from another page is not a workaround —
    /// antiforgery tokens are not path-scoped, so it is exactly what a crafted post would do, which
    /// is the threat those tests are about.
    /// </para>
    /// </remarks>
    private static async Task<HttpResponseMessage> SubmitAsync(
        FlowFixture fixture,
        string path,
        (string Name, string Value)[] fields,
        string? tokenFrom = null)
    {
        var html = await fixture.Client.GetStringAsync(new Uri(tokenFrom ?? path, UriKind.Relative));

        // Last one wins rather than Add: the session page repeats the same antiforgery field in
        // every row's form, so a dictionary built with Add throws on the second session.
        var form = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (Match match in HiddenField().Matches(html))
        {
            form[match.Groups[1].Value] = WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        Assert.NotEmpty(form);

        foreach (var (name, value) in fields)
        {
            form[name] = value;
        }

        return await fixture.Client.PostAsync(new Uri(path, UriKind.Relative), new FormUrlEncodedContent(form));
    }

    // ─────────────────────────────────────────────────────────────── the surface

    [Fact]
    public async Task The_pages_are_absent_unless_a_deployment_asked_for_them()
    {
        var world = await StartAsync(pages: false);
        await using var fixture = world.Fixture;

        var response = await fixture.Client.GetAsync(new Uri("/me", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// The issuer's own hostname sends a person to sign in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TryUseReturnUrl</c>'s remarks record the measurement this closes: after signing out,
    /// <c>/</c> was a <c>404</c> and <c>/login</c> was a refusal, "so the two URLs a person would
    /// type to sign back in were both dead ends". Only <c>/login</c> was fixed at the time. This is
    /// the other one, reported from production by somebody who typed the hostname and got nothing.
    /// </para>
    /// <para>
    /// A redirect rather than the page itself, so one URL draws the sign-in form and the address bar
    /// agrees with what is on screen.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_root_sends_a_person_to_sign_in()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var response = await fixture.Client.GetAsync(new Uri("/", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/login", response.Headers.Location?.ToString());
    }

    /// <summary>
    /// With no self-service pages there is nowhere to send them, so the root stays a 404.
    /// </summary>
    /// <remarks>
    /// The same condition the bare-<c>/login</c> default carries: with the pages off there is no
    /// standalone destination, so redirecting would land on a refusal. An authorization server whose
    /// only surface is <c>/authorize</c> and <c>/token</c> genuinely has no page for a person, and a
    /// <c>404</c> says so more honestly than a bounce into a dead end.
    /// </remarks>
    [Fact]
    public async Task Without_self_service_the_root_stays_absent()
    {
        var world = await StartAsync(pages: false);
        await using var fixture = world.Fixture;

        var response = await fixture.Client.GetAsync(new Uri("/", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// An anonymous browser is sent to sign in, and back here afterwards.
    /// </summary>
    /// <remarks>
    /// The <c>returnUrl</c> is the reason <c>/login</c>'s check became a list. It used to accept one
    /// path — <c>/authorize</c> — so before this step a person sent from <c>/me</c> to sign in would
    /// have been refused at the page they were sent to.
    /// </remarks>
    [Fact]
    public async Task An_anonymous_visitor_is_sent_to_sign_in_and_back()
    {
        var world = await StartAsync(signedInAs: null);
        await using var fixture = world.Fixture;

        foreach (var page in new[] { "/me", "/me/password", "/me/sessions" })
        {
            var response = await fixture.Client.GetAsync(new Uri(page, UriKind.Relative));

            // 303, not 302: every redirect this server emits is a See Other (E-20), and a POST
            // that lands here — an expired session mid-form — must not be replayed to /login.
            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.Equal(
                "/login?returnUrl=" + Uri.EscapeDataString(page),
                response.Headers.Location!.OriginalString);
        }
    }

    /// <summary>And the sign-in page accepts that returnUrl rather than refusing it.</summary>
    /// <remarks>
    /// The other half of the previous test, and worth its own assertion: a redirect to a page that
    /// answers 400 is a loop a person cannot get out of, and the two halves live in different files.
    /// </remarks>
    [Fact]
    public async Task The_sign_in_page_accepts_a_me_return_url()
    {
        var world = await StartAsync(signedInAs: null);
        await using var fixture = world.Fixture;

        var response = await fixture.Client.GetAsync(
            new Uri("/login?returnUrl=%2Fme%2Fpassword", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>Anything not on the list is still refused.</summary>
    /// <remarks>
    /// The control on widening the check. If this ever passes, <c>/login</c> has become an open
    /// redirector on the one origin a user has been taught to type a password into.
    /// </remarks>
    [Theory]
    [InlineData("/logout")]
    [InlineData("//evil.example")]
    [InlineData("/me/../admin/users")]
    [InlineData("/mesessions")]
    public async Task The_sign_in_page_still_refuses_everything_else(string returnUrl)
    {
        var world = await StartAsync(signedInAs: null);
        await using var fixture = world.Fixture;

        var response = await fixture.Client.GetAsync(
            new Uri("/login?returnUrl=" + Uri.EscapeDataString(returnUrl), UriKind.Relative));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────── /me

    /// <summary>The front page reads the directory, not the session.</summary>
    /// <remarks>
    /// The session carries a subject and when it was proven, and nothing else. A page that rendered
    /// from it would show a handle that changed hours ago, and could not answer "is there a password
    /// here" at all — which is the field deciding whether it offers a password link.
    /// </remarks>
    [Fact]
    public async Task The_front_page_shows_the_account_as_the_directory_holds_it()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await world.Users.SetRolesAsync(SubjectId.FromStorage(Mine), ["operator"], CancellationToken.None);

        var html = await fixture.Client.GetStringAsync(new Uri("/me", UriKind.Relative));

        Assert.Contains("ada", html, StringComparison.Ordinal);
        Assert.Contains("operator", html, StringComparison.Ordinal);
        Assert.Contains("/me/password", html, StringComparison.Ordinal);
        Assert.Contains("/me/sessions", html, StringComparison.Ordinal);

        // The address is unverified in the fixture, and the page says so beside it rather than
        // presenting it as established.
        Assert.Contains("not verified", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// An account with no local password is offered no password link.
    /// </summary>
    /// <remarks>
    /// Absent, not disabled. A control that cannot work is a question somebody spends time on before
    /// finding out the answer is no.
    /// </remarks>
    [Fact]
    public async Task A_federated_account_is_told_there_is_no_password_rather_than_offered_one()
    {
        var world = await StartAsync(password: null);
        await using var fixture = world.Fixture;

        var html = await fixture.Client.GetStringAsync(new Uri("/me", UriKind.Relative));

        Assert.DoesNotContain("/me/password", html, StringComparison.Ordinal);
        Assert.Contains("no password here", html, StringComparison.Ordinal);
    }

    // ────────────────────────────────────────────────────────────── /me/password

    /// <summary>The current password is required, and a wrong one changes nothing. <c>S-49</c>.</summary>
    [Fact]
    public async Task A_wrong_current_password_is_refused_and_changes_nothing()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var before = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);

        var response = await SubmitAsync(
            fixture,
            "/me/password",
            [("current", "not it"), ("new", "a new one entirely"), ("confirm", "a new one entirely")]);

        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("not your current password", html, StringComparison.Ordinal);

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);
        Assert.Equal(before!.PasswordHash, after!.PasswordHash);
    }

    /// <summary>
    /// A mistyped confirmation is caught before the store is touched.
    /// </summary>
    /// <remarks>
    /// Server-side, because these pages ship no JavaScript and a check that only exists in the
    /// browser is one a form post can skip. A mistyped new password is a lockout.
    /// </remarks>
    [Fact]
    public async Task A_mismatched_confirmation_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var before = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);

        var response = await SubmitAsync(
            fixture,
            "/me/password",
            [("current", Password), ("new", "one thing"), ("confirm", "another thing")]);

        Assert.Contains("do not match", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);
        Assert.Equal(before!.PasswordHash, after!.PasswordHash);
    }

    /// <summary>The right one changes it, and says so.</summary>
    [Fact]
    public async Task The_right_current_password_changes_it()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var before = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);

        var response = await SubmitAsync(
            fixture,
            "/me/password",
            [("current", Password), ("new", "battery staple stapler"), ("confirm", "battery staple stapler")]);

        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("has been changed", html, StringComparison.Ordinal);

        // The form is gone from the success page, and with it any chance of the new password sitting
        // in a value attribute.
        Assert.DoesNotContain("name=\"current\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("battery staple stapler", html, StringComparison.Ordinal);

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Mine), CancellationToken.None);
        Assert.NotEqual(before!.PasswordHash, after!.PasswordHash);
    }

    /// <summary>
    /// Ticking the box ends every grant, and this browser's session with them.
    /// </summary>
    /// <remarks>
    /// Revoking grants does not touch the cookie — a grant and a browser session are different
    /// things — so without the explicit sign-out, "sign me out everywhere, including here" would
    /// answer everywhere but here.
    /// </remarks>
    [Fact]
    public async Task Asking_to_be_signed_out_everywhere_ends_the_grants_and_this_session()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Mine, "client-b", "grant-2");
        await SeedGrantAsync(world, Theirs, "client-a", "grant-other");

        var response = await SubmitAsync(
            fixture,
            "/me/password",
            [
                ("current", Password),
                ("new", "battery staple stapler"),
                ("confirm", "battery staple stapler"),
                ("revoke", "true"),
            ]);

        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("has been changed", html, StringComparison.Ordinal);
        Assert.Contains("2 session(s) were ended", html, StringComparison.Ordinal);

        Assert.True(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));
        Assert.True(await world.Stores.Grants.IsRevokedAsync("grant-2", CancellationToken.None));

        // And this browser's own session, which revoking grants does not touch: a grant and a
        // cookie session are different things, so without the explicit sign-out the checkbox would
        // deliver everywhere but here.
        Assert.Equal(1, world.SignIn.SignOuts);

        // Somebody else's, untouched. The same control AccountSurfaceTests has, because this page
        // reaches the same store by a different route.
        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-other", CancellationToken.None));
    }

    /// <summary>Without the box, other sessions keep running. §1.10.</summary>
    [Fact]
    public async Task A_change_leaves_other_sessions_running_unless_asked()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        await SubmitAsync(
            fixture,
            "/me/password",
            [("current", Password), ("new", "battery staple stapler"), ("confirm", "battery staple stapler")]);

        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));

        // And the browser stays signed in. Signing somebody out of the page they are reading is a
        // surprise, and §1.10's whole point is that it is asked for rather than inferred.
        Assert.Equal(0, world.SignIn.SignOuts);
    }

    /// <summary>A federated account gets a sentence rather than a form it can only fail.</summary>
    [Fact]
    public async Task The_password_page_offers_no_form_when_there_is_no_password()
    {
        var world = await StartAsync(password: null);
        await using var fixture = world.Fixture;

        var html = await fixture.Client.GetStringAsync(new Uri("/me/password", UriKind.Relative));

        Assert.Contains("no password here", html, StringComparison.Ordinal);
        Assert.DoesNotContain("name=\"current\"", html, StringComparison.Ordinal);
    }

    // ────────────────────────────────────────────────────────────── /me/sessions

    [Fact]
    public async Task The_session_page_lists_only_your_own()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Theirs, "client-b", "grant-other");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("client-a", html, StringComparison.Ordinal);
        Assert.DoesNotContain("client-b", html, StringComparison.Ordinal);
        Assert.DoesNotContain("grant-other", html, StringComparison.Ordinal);

        // Said whether or not anything is listed, because "I ended it" must not be read as "it is
        // gone now" — which it may or may not be, depending on whether the application's own server
        // asks this one. The page carries that caveat either way.
        Assert.Contains("until its current token expires", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// "None of this was me" asks before it acts, and asking ends nothing.
    /// </summary>
    /// <remarks>
    /// <b>The assertion that matters is the second one.</b> A confirmation that has already done the
    /// thing is not a confirmation, and this is the control that ends the application the reader is
    /// holding the page in — so pressing it once and changing your mind has to be free.
    /// </remarks>
    [Fact]
    public async Task Ending_everything_asks_first_and_ends_nothing_yet()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Mine, "client-b", "grant-2");

        using var response = await SubmitAsync(fixture, "/me/sessions", [("all", "ask")]);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("End every session above?", html, StringComparison.Ordinal);

        // Still listed, and still live in the store. The page saying so is not evidence on its own —
        // a handler that revoked and then re-rendered a stale list would look identical here.
        Assert.Contains("client-a", html, StringComparison.Ordinal);

        var live = await world.Stores.Grants.ListForSubjectAsync(
            SubjectId.FromStorage(Mine), CancellationToken.None);

        Assert.Equal(2, live.Count);
    }

    /// <summary>Confirming ends every one of them, and says how many.</summary>
    [Fact]
    public async Task Ending_everything_ends_every_one_of_them()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Mine, "client-b", "grant-2");
        await SeedGrantAsync(world, Theirs, "client-c", "grant-other");

        using var response = await SubmitAsync(fixture, "/me/sessions", [("all", "confirm")]);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("2 session(s) were ended.", html, StringComparison.Ordinal);

        // The half revoking cannot do, and it is a link rather than a suggestion.
        Assert.Contains("/me/password", html, StringComparison.Ordinal);
        Assert.Contains("Now change your password", html, StringComparison.Ordinal);

        Assert.Empty(await world.Stores.Grants.ListForSubjectAsync(
            SubjectId.FromStorage(Mine), CancellationToken.None));

        // Somebody else's is untouched. This control is the widest thing on the page and the one
        // where a missing subject predicate would be quietest.
        Assert.Single(await world.Stores.Grants.ListForSubjectAsync(
            SubjectId.FromStorage(Theirs), CancellationToken.None));
    }

    /// <summary>With nothing to end, the control is not offered.</summary>
    /// <remarks>
    /// A button that would end nothing still reads as the response to the message that sent somebody
    /// here, and pressing it teaches them the page does not work.
    /// </remarks>
    [Fact]
    public async Task With_no_sessions_there_is_nothing_to_end()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.DoesNotContain("None of this was me", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A session says which browser approved it, so two grants for one client are tellable apart.
    /// </summary>
    /// <remarks>
    /// The case the whole field exists for: without it these two rows are identical, and telling
    /// them apart is exactly what somebody is trying to do when they open this page.
    /// </remarks>
    [Fact]
    public async Task A_session_says_which_browser_approved_it()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(
            world, Mine, "client-a", "grant-1",
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36");

        await SeedGrantAsync(
            world, Mine, "client-a", "grant-2",
            userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
                + "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("Chrome on macOS", html, StringComparison.Ordinal);
        Assert.Contains("Safari on iPhone", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A grant with no browser recorded says nothing about one.
    /// </summary>
    /// <remarks>
    /// Every grant created before the column existed is in this state. "Unknown device" would report
    /// ordinary history as something wrong, on the page people open when they already suspect it is.
    /// </remarks>
    [Fact]
    public async Task A_session_with_no_browser_recorded_says_nothing_about_one()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("client-a", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Approved from", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The header is encoded, because it is the one value on this page a stranger chose.
    /// </summary>
    /// <remarks>
    /// Everything else here comes from configuration or from the store's own identifiers. This
    /// arrives as a request header, is stored verbatim, and is rendered back to the account owner —
    /// which is the shape of a stored cross-site scripting hole if the encoding is ever dropped.
    /// </remarks>
    [Fact]
    public async Task A_browser_string_containing_markup_is_rendered_as_text()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(
            world, Mine, "client-a", "grant-1", userAgent: "<script>alert('x')</script>");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A session that has renewed says when, and says what a renewal is evidence of.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The caveat is the assertion that matters here.</b> The page people open when they suspect
    /// a session is not theirs is the worst possible place for a timestamp that reads as "somebody
    /// was here twenty minutes ago" when what it means is "this application's own timer fired".
    /// Access tokens are signed rather than looked up, so a person can work for half an hour
    /// without moving this value and the value moves with nobody at the keyboard.
    /// </para>
    /// <para>
    /// Asserted on the word "renew" rather than on the whole sentence: the phrasing is a
    /// deployment's to change, and the distinction between renewal and use is not.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_session_that_has_renewed_says_when_and_says_what_that_means()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedRefreshAsync(world, "grant-1", DateTimeOffset.UnixEpoch.AddDays(9));

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("1970-01-10 00:00:00Z", html, StringComparison.Ordinal);
        Assert.Contains("renew", html, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The newest renewal is the one shown, not the first or the last stored.</summary>
    [Fact]
    public async Task The_session_page_shows_the_most_recent_renewal()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedRefreshAsync(world, "grant-1", DateTimeOffset.UnixEpoch.AddDays(9), "rt-old");
        await SeedRefreshAsync(world, "grant-1", DateTimeOffset.UnixEpoch.AddDays(20), "rt-new");
        await SeedRefreshAsync(world, "grant-1", DateTimeOffset.UnixEpoch.AddDays(15), "rt-middle");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("1970-01-21 00:00:00Z", html, StringComparison.Ordinal);
        Assert.DoesNotContain("1970-01-10 00:00:00Z", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A session that has never renewed shows no renewal line, and no caveat about one.
    /// </summary>
    /// <remarks>
    /// Every session younger than one access-token lifetime is in this state, so "never renewed"
    /// would report ordinary freshness as something wrong — and a caveat explaining a line that is
    /// not on the page sends a reader looking for it.
    /// </remarks>
    [Fact]
    public async Task A_session_that_has_never_renewed_says_nothing_about_renewal()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("client-a", html, StringComparison.Ordinal);
        Assert.DoesNotContain("renew", html, StringComparison.OrdinalIgnoreCase);

        // The page still says the thing it always says, so the absence above is about the renewal
        // line rather than about the page having failed to render.
        Assert.Contains("until its current token expires", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The page names this deployment's access-token lifetime, not a number somebody typed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The sentence said "up to an hour" for as long as the option defaulted to thirty
    /// minutes.</b> Every test passed throughout, because no test had ever read the sentence — and
    /// the failure is invisible from inside the codebase, since the string and the option are both
    /// individually correct and only their pairing is a lie. This is that pairing, asserted.
    /// </para>
    /// <para>
    /// Driven with a configured value rather than the default on purpose. A test that asserted
    /// "30 minutes" against the default would pass just as happily if the renderer went back to
    /// printing a constant, which is the whole defect.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_session_page_names_this_deployments_access_token_lifetime()
    {
        var world = await StartAsync(accessTokenLifetime: TimeSpan.FromMinutes(90));
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("90 minutes", html, StringComparison.Ordinal);
        Assert.DoesNotContain("an hour", html, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A lifetime that is not whole minutes is rounded up, never down.</summary>
    /// <remarks>
    /// Five minutes and one second is the shortest lifetime a deployment may configure, and it is
    /// the case that decides the rounding direction: down prints a ceiling this server does not
    /// honour, and the page is the one somebody opens to find out how long they stay exposed.
    /// Understating that is the direction not to be wrong in.
    /// </remarks>
    [Fact]
    public async Task A_lifetime_that_is_not_whole_minutes_rounds_up()
    {
        var world = await StartAsync(
            accessTokenLifetime: TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("6 minutes", html, StringComparison.Ordinal);
        Assert.DoesNotContain("5 minutes", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The session list describes scopes the way the approvals page does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the assertion that was missing, and its absence is why the defect shipped.</b>
    /// The page rendered <c>g.Scope.ToWireString()</c>, every test passed, and the symptom was only
    /// visible on a deployment with descriptions configured: <c>/me/consents</c> read "Read the
    /// knowledge base" and <c>/me/sessions</c> read <c>kb:read kb:write</c>, one click apart, for
    /// the same client.
    /// </para>
    /// <para>
    /// Differential rather than a fixed string, because what has to be true is that the two pages
    /// agree — a wording change should not have to be made in two tests, and a wording change made
    /// in one page and not the other is exactly what this is for.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_session_page_and_the_approvals_page_describe_a_scope_the_same_way()
    {
        var world = await StartAsync(scopeDescriptions: new()
        {
            ["kb:read"] = "Read the knowledge base",
            ["kb:write"] = "Write to the knowledge base",
        });

        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1", "kb:read kb:write");
        await SeedConsentAsync(world, Mine, "client-a", "kb:read kb:write");

        var sessions = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));
        var consents = await fixture.Client.GetStringAsync(new Uri("/me/consents", UriKind.Relative));

        foreach (var description in new[] { "Read the knowledge base", "Write to the knowledge base" })
        {
            Assert.Contains(description, sessions, StringComparison.Ordinal);
            Assert.Contains(description, consents, StringComparison.Ordinal);
        }

        // And the wire scope is gone from the readable part of the page. It survives in the form's
        // hidden grant id and nowhere a person reads.
        Assert.DoesNotContain("kb:read kb:write", sessions, StringComparison.Ordinal);

        // The resources too, which the session page did not show at all: "what may it do" and
        // "where" are the pair the consent page asks about, so they are the pair both of these
        // answer.
        Assert.Contains("https://api.example.com", sessions, StringComparison.Ordinal);
        Assert.Contains("https://api.example.com", consents, StringComparison.Ordinal);
    }

    /// <summary>
    /// A scope nobody described is raw and flagged on both pages, not just the one.
    /// </summary>
    /// <remarks>
    /// A-14 is decided in <c>ConsentModelBuilder.Describe</c> rather than by each page, which is
    /// the point: a fourth page describing scopes gets this without its author knowing the rule.
    /// </remarks>
    [Fact]
    public async Task An_undescribed_scope_is_raw_and_flagged_on_the_session_page_too()
    {
        var world = await StartAsync(scopeDescriptions: new() { ["kb:read"] = "Read the knowledge base" });
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1", "kb:read kb:write");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("Read the knowledge base", html, StringComparison.Ordinal);
        Assert.Contains("<code>kb:write</code>", html, StringComparison.Ordinal);
        Assert.Contains("no description configured", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The client's host leads the row, with the full id below it.
    /// </summary>
    /// <remarks>
    /// <c>N-14</c>'s reasoning about the consent page applies to every page that names a client, and
    /// the session page used to print the id alone — which for a CIMD client is a URL long enough to
    /// push the rest of the row off a phone.
    /// </remarks>
    [Fact]
    public async Task The_session_page_leads_with_the_clients_host()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "https://claude.ai/oauth/client.json", "grant-1");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/sessions", UriKind.Relative));

        Assert.Contains("<strong>claude.ai</strong>", html, StringComparison.Ordinal);
        Assert.Contains("https://claude.ai/oauth/client.json", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Ending_one_session_leaves_the_others()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");
        await SeedGrantAsync(world, Mine, "client-b", "grant-2");

        var response = await SubmitAsync(fixture, "/me/sessions", [("grant", "grant-1")]);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("session has ended", html, StringComparison.Ordinal);
        Assert.DoesNotContain("client-a", html, StringComparison.Ordinal);
        Assert.Contains("client-b", html, StringComparison.Ordinal);

        Assert.True(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));
        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-2", CancellationToken.None));
    }

    /// <summary>
    /// Somebody else's grant id in the form ends nothing.
    /// </summary>
    /// <remarks>
    /// <b>The assertion this file exists for.</b> <c>IGrantStore.RevokeAsync</c> takes an id and no
    /// subject, and this id arrives in a form field — so a handler that passed it straight through
    /// would let anyone who can sign in end any session in the deployment. The page redraws saying
    /// nothing, which is what a stale form should do and is also not an oracle.
    /// </remarks>
    [Fact]
    public async Task Another_accounts_grant_id_in_the_form_ends_nothing()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Theirs, "client-a", "grant-other");

        // The token comes from /me/password because this account has no session of its own to
        // draw a form — which is the whole point: the id being posted is somebody else's.
        var response = await SubmitAsync(
            fixture, "/me/sessions", [("grant", "grant-other")], tokenFrom: "/me/password");
        var html = await response.Content.ReadAsStringAsync();

        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-other", CancellationToken.None));
        Assert.DoesNotContain("session has ended", html, StringComparison.Ordinal);
    }

    // ────────────────────────────────────────────────────────────── /me/consents

    /// <summary>
    /// The list shows what was approved, in the words it was approved in.
    /// </summary>
    /// <remarks>
    /// The scope descriptions come from the same configuration the consent page reads. A person
    /// agreed to "Read the knowledge base"; a page showing them <c>kb:read</c> asks them to
    /// recognise their own decision from a string nobody promised was legible.
    /// </remarks>
    [Fact]
    public async Task The_consents_page_describes_scopes_the_way_the_consent_page_did()
    {
        var world = await StartAsync(scopeDescriptions: new() { ["kb:read"] = "Read the knowledge base" });
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Mine, "https://claude.ai/oauth/client.json", "kb:read");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/consents", UriKind.Relative));

        Assert.Contains("Read the knowledge base", html, StringComparison.Ordinal);

        // The host is the prominent line — N-14's reasoning about the consent page applies to every
        // page that names a client — and the full id is there too, because that is what the form
        // posts back and what an operator would be asked for.
        Assert.Contains("<strong>claude.ai</strong>", html, StringComparison.Ordinal);
        Assert.Contains("https://claude.ai/oauth/client.json", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// A scope nobody described renders as itself with a warning, never as words derived from it.
    /// </summary>
    /// <remarks>
    /// A-14, and it is reachable here in a way it is not on the consent page: a description can be
    /// removed from configuration <i>after</i> the approval that used it, so this page can be asked
    /// to redescribe an agreement whose words no longer exist. Inventing them is the "read: story
    /// your read" failure the rule is written against.
    /// </remarks>
    [Fact]
    public async Task An_undescribed_scope_is_shown_raw_with_a_warning()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Mine, "client-a", "kb:read");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/consents", UriKind.Relative));

        Assert.Contains("<code>kb:read</code>", html, StringComparison.Ordinal);
        Assert.Contains("no description configured", html, StringComparison.Ordinal);
    }

    /// <summary>Somebody else's approvals are not on the page.</summary>
    [Fact]
    public async Task The_consents_page_lists_only_your_own()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Mine, "client-a", "kb:read");
        await SeedConsentAsync(world, Theirs, "client-b", "kb:read");

        var html = await fixture.Client.GetStringAsync(new Uri("/me/consents", UriKind.Relative));

        Assert.Contains("client-a", html, StringComparison.Ordinal);
        Assert.DoesNotContain("client-b", html, StringComparison.Ordinal);
    }

    /// <summary>Withdrawing removes the approval and says so.</summary>
    [Fact]
    public async Task Withdrawing_one_approval_leaves_the_others()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Mine, "client-a", "kb:read");
        await SeedConsentAsync(world, Mine, "client-b", "kb:read");

        var response = await SubmitAsync(fixture, "/me/consents", [("client", "client-a")]);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Contains("has been withdrawn", html, StringComparison.Ordinal);
        Assert.DoesNotContain("client-a", html, StringComparison.Ordinal);
        Assert.Contains("client-b", html, StringComparison.Ordinal);

        Assert.Null(await world.Stores.Consents.FindAsync(
            SubjectId.FromStorage(Mine), ClientIdentifier.ForPreRegistered("client-a"), CancellationToken.None));
    }

    /// <summary>
    /// Another account's client id in the form withdraws nothing.
    /// </summary>
    /// <remarks>
    /// <b>Structural rather than checked.</b> <c>IConsentStore.RevokeAsync</c> is keyed on
    /// <c>(subject, client)</c> and the subject is the session's, so the id in the form cannot reach
    /// a record that is not the caller's however it is spelled. This asserts the wiring actually
    /// passes the session's subject — the property is only as good as the argument.
    /// </remarks>
    [Fact]
    public async Task Another_accounts_client_id_in_the_form_withdraws_nothing()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Theirs, "client-b", "kb:read");

        // The token comes from /me/password: this account has approved nothing, so /me/consents
        // draws no per-approval form to read one from — which is the point, since the id being
        // posted belongs to somebody else.
        var response = await SubmitAsync(
            fixture, "/me/consents", [("client", "client-b")], tokenFrom: "/me/password");

        Assert.DoesNotContain(
            "has been withdrawn", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        Assert.NotNull(await world.Stores.Consents.FindAsync(
            SubjectId.FromStorage(Theirs), ClientIdentifier.ForPreRegistered("client-b"), CancellationToken.None));
    }

    /// <summary>
    /// Withdrawing does not end the sessions, and the page says which one it did. <c>E-38</c>.
    /// </summary>
    /// <remarks>
    /// "Withdraw" is the word a person reads as "cut it off". It is not: the next authorization asks
    /// again, and a grant already issued keeps working. A page that performed that silently would
    /// leave somebody believing they had stopped something.
    /// </remarks>
    [Fact]
    public async Task Withdrawing_an_approval_does_not_end_the_session_and_the_page_says_so()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Mine, "client-a", "kb:read");
        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        var response = await SubmitAsync(fixture, "/me/consents", [("client", "client-a")]);
        var html = await response.Content.ReadAsStringAsync();

        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));

        Assert.Contains("does not end access it already has", html, StringComparison.Ordinal);
        Assert.Contains("/me/sessions", html, StringComparison.Ordinal);
    }

    /// <summary>A malformed client id changes nothing and does not throw.</summary>
    /// <remarks>
    /// It arrives from a browser and reaches a store key, so it goes through the same
    /// <c>ClientIdentifier.TryParseFromRequest</c> the authorization endpoint runs. A page that
    /// answered 500 here would turn a stale form into an error report.
    /// </remarks>
    [Fact]
    public async Task A_malformed_client_id_redraws_the_page_having_done_nothing()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedConsentAsync(world, Mine, "client-a", "kb:read");

        var response = await SubmitAsync(fixture, "/me/consents", [("client", "not a clientid")]);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var html = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain("has been withdrawn", html, StringComparison.Ordinal);
        Assert.Contains("client-a", html, StringComparison.Ordinal);
    }

    /// <summary>The front page links here, or the page is one nobody finds.</summary>
    [Fact]
    public async Task The_front_page_links_to_the_approvals()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var html = await fixture.Client.GetStringAsync(new Uri("/me", UriKind.Relative));

        Assert.Contains("/me/consents", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every self-service page can be returned to after signing in.
    /// </summary>
    /// <remarks>
    /// <b>Read off the routing table rather than listed by hand.</b> A page reachable while signed
    /// in but missing from <c>LoginReturnTargets</c> works perfectly until the session expires, and
    /// then answers a 400 at <c>/login</c> — which is the worst moment to find out, and is what
    /// happened to <c>/me</c> itself before that check became a list.
    /// </remarks>
    [Fact]
    public async Task Every_self_service_page_can_be_returned_to_after_signing_in()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var pages = fixture.Services
            .GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>()
            .Endpoints
            .OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .Where(e => e.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()
                ?.HttpMethods.Contains("GET") is true)
            .Select(e => "/" + e.RoutePattern.RawText!.TrimStart('/'))
            .Where(path => path.StartsWith(AuthorizationServerPaths.MePrefix, StringComparison.Ordinal)
                || string.Equals(path, AuthorizationServerPaths.Me, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(pages);

        foreach (var page in pages)
        {
            Assert.Contains(page, AuthorizationServerPaths.LoginReturnTargets, StringComparer.Ordinal);
        }
    }


    // ─────────────────────────────────────────────────────────── E-41, the send

    /// <summary>
    /// The button exists, and pressing it produces the mail <c>/verify-email</c> was written to
    /// receive.
    /// </summary>
    /// <remarks>
    /// The gap this closes: <c>AccountRecovery.RequestEmailVerificationAsync</c> minted the token
    /// and composed the message, the page redeemed it, and nothing called the first one — its only
    /// callers in the whole tree were three tests. A deployment could not produce the link, so the
    /// page could not be reached by anybody who had not written C# to get there.
    /// </remarks>
    [Fact]
    public async Task Asking_for_a_confirmation_link_sends_one()
    {
        var world = await StartAsync(recovery: true);
        await using var fixture = world.Fixture;

        var response = await SubmitAsync(
            fixture, AuthorizationServerPaths.MeEmailVerify, [], tokenFrom: AuthorizationServerPaths.Me);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var sent = Assert.Single(world.Mail.Sent);
        var verify = Assert.IsType<VerifyEmail>(sent);

        Assert.Equal("ada@example.com", verify.To);
        Assert.Contains(AuthorizationServerPaths.VerifyEmail, verify.Link, StringComparison.Ordinal);
    }

    /// <summary>The page then says a link is on its way.</summary>
    [Fact]
    public async Task The_account_page_reports_that_a_link_was_sent()
    {
        var world = await StartAsync(recovery: true);
        await using var fixture = world.Fixture;

        var response = await SubmitAsync(
            fixture, AuthorizationServerPaths.MeEmailVerify, [], tokenFrom: AuthorizationServerPaths.Me);

        var page = await fixture.Client.GetStringAsync(response.Headers.Location!);

        Assert.Contains("on its way", page, StringComparison.Ordinal);
    }

    /// <summary>
    /// No offer on a deployment that cannot send it.
    /// </summary>
    /// <remarks>
    /// <c>PasswordRecoveryEnabled</c> is refused at startup without an <c>INotificationSender</c>,
    /// so it is the server's own answer to "can this process send mail". Drawing the button without
    /// it would mint a token and deliver nothing — the failure shape this server refuses to start
    /// into, rebuilt one layer up.
    /// </remarks>
    [Fact]
    public async Task The_offer_is_absent_when_the_email_flows_are_off()
    {
        var world = await StartAsync(recovery: false);
        await using var fixture = world.Fixture;

        var page = await fixture.Client.GetStringAsync(new Uri(AuthorizationServerPaths.Me, UriKind.Relative));

        Assert.DoesNotContain(AuthorizationServerPaths.MeEmailVerify, page, StringComparison.Ordinal);
    }

    /// <summary>And the endpoint refuses too, rather than trusting the page not to have drawn it.</summary>
    [Fact]
    public async Task The_endpoint_sends_nothing_when_the_email_flows_are_off()
    {
        var world = await StartAsync(recovery: false);
        await using var fixture = world.Fixture;

        // The token comes from the password page, because with the offer withdrawn /me draws no form
        // at all and so has no hidden field to read. Not a workaround: antiforgery tokens are not
        // path-scoped, which is exactly why the endpoint cannot rely on the page having drawn it.
        var response = await SubmitAsync(
            fixture,
            AuthorizationServerPaths.MeEmailVerify,
            [],
            tokenFrom: AuthorizationServerPaths.MePassword);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Empty(world.Mail.Sent);
    }

    /// <summary>Nothing to offer, or to send, when the address is already proven.</summary>
    [Fact]
    public async Task An_already_verified_address_is_neither_offered_nor_sent()
    {
        var world = await StartAsync(recovery: true, emailVerified: true);
        await using var fixture = world.Fixture;

        var page = await fixture.Client.GetStringAsync(new Uri(AuthorizationServerPaths.Me, UriKind.Relative));
        Assert.DoesNotContain(AuthorizationServerPaths.MeEmailVerify, page, StringComparison.Ordinal);

        await SubmitAsync(
            fixture,
            AuthorizationServerPaths.MeEmailVerify,
            [],
            tokenFrom: AuthorizationServerPaths.MePassword);

        Assert.Empty(world.Mail.Sent);
    }

    /// <summary>An account with no address has nothing to confirm.</summary>
    [Fact]
    public async Task An_account_with_no_address_is_offered_nothing()
    {
        var world = await StartAsync(recovery: true, email: null);
        await using var fixture = world.Fixture;

        var page = await fixture.Client.GetStringAsync(new Uri(AuthorizationServerPaths.Me, UriKind.Relative));

        Assert.DoesNotContain(AuthorizationServerPaths.MeEmailVerify, page, StringComparison.Ordinal);
    }

    /// <summary>
    /// Signed in is not exempt from the throttle.
    /// </summary>
    /// <remarks>
    /// §3.1. The mail goes to an address the server chooses, so this cannot reach a stranger — but a
    /// held session is still a button that sends on every press, and the counter is what stops a
    /// stuck client filling somebody's inbox. Said rather than swallowed: a page that ignored the
    /// press would have the person pressing it again, which is the thing being bounded.
    /// </remarks>
    [Fact]
    public async Task Asking_repeatedly_is_refused_and_the_page_says_so()
    {
        var world = await StartAsync(recovery: true);
        await using var fixture = world.Fixture;

        HttpResponseMessage? last = null;

        for (var attempt = 0; attempt < 6; attempt++)
        {
            last = await SubmitAsync(
                fixture, AuthorizationServerPaths.MeEmailVerify, [], tokenFrom: AuthorizationServerPaths.Me);
        }

        var page = await fixture.Client.GetStringAsync(last!.Headers.Location!);

        Assert.Contains("wait a few minutes", page, StringComparison.Ordinal);

        // Bounded, not merely reported: fewer messages than presses.
        Assert.True(world.Mail.Sent.Count < 6, $"{world.Mail.Sent.Count} messages for 6 presses.");
    }

    /// <summary>A post without the antiforgery token sends nothing.</summary>
    [Fact]
    public async Task A_verification_post_without_the_antiforgery_token_is_refused()
    {
        var world = await StartAsync(recovery: true);
        await using var fixture = world.Fixture;

        var response = await fixture.Client.PostAsync(
            new Uri(AuthorizationServerPaths.MeEmailVerify, UriKind.Relative),
            new FormUrlEncodedContent(Array.Empty<KeyValuePair<string, string>>()));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(world.Mail.Sent);
    }

    /// <summary>A form post without the antiforgery token is refused.</summary>
    /// <remarks>
    /// These are state-changing forms on the origin that carries the session cookie, so without this
    /// any page on the internet could submit them. <c>UseAntiforgery</c> auto-validates only handlers
    /// that bind form data, and these read <c>Request.Form</c> by hand — so the check is explicit and
    /// this asserts it is actually there.
    /// </remarks>
    [Fact]
    public async Task A_post_without_the_antiforgery_token_is_refused()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SeedGrantAsync(world, Mine, "client-a", "grant-1");

        var response = await fixture.Client.PostAsync(
            new Uri("/me/sessions", UriKind.Relative),
            new FormUrlEncodedContent([new KeyValuePair<string, string>("grant", "grant-1")]));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.False(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));
    }
}
