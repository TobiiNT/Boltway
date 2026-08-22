using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A session cookie stops working when the account says its sessions stopped counting.
/// </summary>
/// <remarks>
/// <para>
/// <b>Driven through the real cookie pipeline, and that is the point of the file.</b> The mechanism
/// is three pieces that each look fine alone: a column, a validator, and one line in the host's
/// <c>AddCookie</c>. Unit-testing the validator would prove the middle piece and leave the two that
/// actually fail — a stamp nobody writes, a callback nobody wires — passing. So these sign in over
/// HTTP, keep the cookie the browser would keep, and ask whether the next request is still signed in.
/// </para>
/// <para>
/// <b>Every test here would have passed before this feature existed except by failing.</b> That is
/// the shape worth having: the old behaviour is not "less secure", it is a different answer to
/// <c>GET /me</c>, and these assert the answer.
/// </para>
/// </remarks>
public sealed partial class SessionRevalidationTests
{
    private const string Username = "ada";
    private const string Password = "correct horse battery";
    private const string Replacement = "a completely different passphrase";

    /// <summary>A cookie from before the stamp is refused, and the browser is signed out.</summary>
    /// <remarks>
    /// The whole feature, in one test. Before this, the second request was a 200 with the account
    /// page on it — for fourteen days, sliding forward on every use.
    /// </remarks>
    [Fact]
    public async Task A_session_from_before_the_stamp_is_refused()
    {
        await using var world = await StartAsync();

        Assert.Equal(HttpStatusCode.OK, (await world.GetAccountAsync()).StatusCode);

        // A second later, so the comparison is strict rather than a tie. Ties are their own test.
        await world.Users.StampSessionsAsync(
            world.Subject, world.Now.AddSeconds(1), CancellationToken.None);

        var after = await world.GetAccountAsync();

        // Redirected to sign in, not served. The account page is behind the same guard everything
        // else on /me is, so this is what "signed out" looks like from outside.
        Assert.True(IsRedirect(after.StatusCode), $"expected a redirect to sign in, got {after.StatusCode}");
        Assert.Contains("/login", after.Headers.Location?.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>A cookie from after the stamp is left alone.</summary>
    /// <remarks>
    /// The control. Without it, a validator that refused everything would pass the test above, and
    /// "signed out for fourteen days" is not the improvement being claimed.
    /// </remarks>
    [Fact]
    public async Task A_session_from_after_the_stamp_stands()
    {
        await using var world = await StartAsync();

        await world.Users.StampSessionsAsync(
            world.Subject, world.Now.AddMinutes(-5), CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, (await world.GetAccountAsync()).StatusCode);
    }

    /// <summary>An account nobody has stamped keeps its sessions.</summary>
    /// <remarks>
    /// Null is not zero. Every account that existed before the column has null in it, and reading
    /// that as "the beginning of time" would sign the whole deployment out on the deploy that added
    /// this — spending every user's trust to buy nothing, since none of those sessions were
    /// suspected of anything.
    /// </remarks>
    [Fact]
    public async Task An_account_that_was_never_stamped_keeps_its_session()
    {
        await using var world = await StartAsync();

        Assert.Null((await world.Users.FindBySubjectAsync(world.Subject, CancellationToken.None))!.SessionsValidFrom);
        Assert.Equal(HttpStatusCode.OK, (await world.GetAccountAsync()).StatusCode);
    }

    /// <summary>A stamp at the same moment as the sign-in does not end it.</summary>
    /// <remarks>
    /// The comparison is strictly-before for this case: the request that signs somebody in can stamp
    /// in the same tick, and a non-strict test would sign them out of the session they are creating.
    /// </remarks>
    [Fact]
    public async Task A_stamp_at_the_moment_of_sign_in_does_not_end_it()
    {
        await using var world = await StartAsync();

        await world.Users.StampSessionsAsync(world.Subject, world.Now, CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, (await world.GetAccountAsync()).StatusCode);
    }

    /// <summary>A disabled account's session goes too.</summary>
    /// <remarks>
    /// Disabling used to stop the next sign-in and nothing else, so somebody already holding a
    /// cookie stayed in. An administrator disabling an account is answering the same question this
    /// class exists for.
    /// </remarks>
    [Fact]
    public async Task A_disabled_account_loses_its_session()
    {
        await using var world = await StartAsync();

        await world.Users.SetEnabledAsync(world.Subject, world.Now, CancellationToken.None);

        var after = await world.GetAccountAsync();

        Assert.True(IsRedirect(after.StatusCode), $"expected a redirect to sign in, got {after.StatusCode}");
    }

    /// <summary>
    /// The account page's sign-out is one press, and the press ends the session.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Written from a real confusion rather than from the spec.</b> This control was a link to
    /// the confirmation page, so pressing it ended nothing until a second press on a second page.
    /// Somebody pressed it, read the question, went to another site two seconds later, and reported
    /// that signing out had not worked — measured in production: <c>GET /logout -&gt; 200</c> with no
    /// <c>POST</c> anywhere after it, and the next request still carrying a live session.
    /// </para>
    /// <para>
    /// So the assertion is the whole round trip: the page offers a form, submitting it once signs
    /// out, and the request after that is refused. A test that only checked for a <c>&lt;form&gt;</c>
    /// would pass on a form that posts somewhere useless.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Signing_out_from_the_account_page_takes_one_press()
    {
        await using var world = await StartAsync();

        var page = await world.Client.GetStringAsync(new Uri("/me", UriKind.Relative));

        // A form, not a link. The old shape would leave this assertion passing only by accident,
        // since /me carries other forms — so the action is asserted too.
        Assert.Contains("action=\"/logout\"", page, StringComparison.Ordinal);

        var token = AntiforgeryField().Match(page);
        Assert.True(token.Success, "the account page rendered no antiforgery field");

        using var signedOut = await world.Client.PostAsync(
            new Uri("/logout", UriKind.Relative),
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, HttpUtility.HtmlDecode(token.Groups[2].Value)),
            ]));

        Assert.True(signedOut.IsSuccessStatusCode, $"the sign-out was refused: {signedOut.StatusCode}");

        // The session is gone, not merely reported gone. This is the assertion the production
        // confusion turned on: the page said something, and the session was still live.
        var after = await world.GetAccountAsync();

        Assert.True(IsRedirect(after.StatusCode), $"expected a redirect to sign in, got {after.StatusCode}");
    }

    /// <summary>
    /// Changing the password ends every other browser, without anybody asking for it separately.
    /// </summary>
    /// <remarks>
    /// The end-to-end claim the mail and the sessions page both make. It is asserted through the
    /// real password route rather than by calling the store, because the defect it guards against is
    /// a route that forgets to stamp — which a store-level test cannot see.
    /// </remarks>
    [Fact]
    public async Task Changing_the_password_ends_the_sessions_that_predate_it()
    {
        await using var world = await StartAsync();

        var page = await world.Client.GetStringAsync(new Uri("/me/password", UriKind.Relative));
        var token = AntiforgeryField().Match(page);
        Assert.True(token.Success, "the password page rendered no antiforgery field");

        using var changed = await world.Client.PostAsync(
            new Uri("/me/password", UriKind.Relative),
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, HttpUtility.HtmlDecode(token.Groups[2].Value)),
                new("current", Password),
                new("new", Replacement),
                new("confirm", Replacement),
            ]));

        // The page it renders, not the status code. A refused change re-renders this form as a 200
        // with a complaint on it, so a status assertion passes on exactly the case worth catching —
        // and then the stamp assertion below fails for a reason nobody would look for here.
        var body = await changed.Content.ReadAsStringAsync();

        Assert.True(
            IsRedirect(changed.StatusCode) || body.Contains("Your password has been changed", StringComparison.Ordinal),
            $"the password change was refused: {changed.StatusCode}");

        var stamped = await world.Users.FindBySubjectAsync(world.Subject, CancellationToken.None);
        Assert.NotNull(stamped!.SessionsValidFrom);

        // The clock has not moved, so this session's auth_time equals the stamp rather than
        // preceding it — the tie case above, and the reason the browser that made the change is
        // still signed in. What the stamp ends is every *other* browser, which is the intent: a
        // person changing their password is not asking to be thrown out of the page they are on.
        Assert.Equal(HttpStatusCode.OK, (await world.GetAccountAsync()).StatusCode);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Any of the redirects this server signs somebody out with.
    /// </summary>
    /// <remarks>
    /// <c>SignInFirst</c> answers 303 and the sign-in itself answers 303, so a test pinned to 302
    /// asserts a status code nothing here produces. What these tests are about is being sent to the
    /// login page rather than served the account, and the Location header carries that.
    /// </remarks>
    private static bool IsRedirect(HttpStatusCode status) =>
        (int)status is >= 300 and <= 399;

    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    private sealed record World(
        FlowFixture Fixture, InMemoryUserStore Users, SubjectId Subject, DateTimeOffset Now)
        : IAsyncDisposable
    {
        public HttpClient Client => Fixture.Client;

        public Task<HttpResponseMessage> GetAccountAsync() =>
            Client.GetAsync(new Uri("/me", UriKind.Relative));

        public ValueTask DisposeAsync() => Fixture.DisposeAsync();
    }

    private static async Task<World> StartAsync()
    {
        var hasher = new Argon2idPasswordHasher(new Argon2idParameters
        {
            MemoryKiB = 64,
            Iterations = 1,
            Parallelism = 1,
        });

        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var subject = new UlidSubjectIdFactory(TimeProvider.System).Mint();

        await users.StoreAsync(
            new UserAccount(
                subject,
                Username,
                "ada@example.com",
                EmailVerified: true,
                PasswordHash: hasher.Hash(Password)),
            CancellationToken.None);

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            // Signed in the way a browser is, by posting the form. A pre-seeded principal would skip
            // the ticket entirely, and the ticket is what these tests are about.
            seed.SignedInUser = null;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IPasswordHasher>(hasher);

                services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie(o =>
                    {
                        o.Cookie.Name = "__Host-boltway-session";
                        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                        o.Cookie.HttpOnly = true;
                        o.Cookie.SameSite = SameSiteMode.Lax;

                        // The line the production host has. Without it every test in this file
                        // fails, which is the property worth having: the wiring is under test and
                        // not assumed.
                        // The line the production host has. Without it every test in this file
                        // fails, which is the property worth having: the wiring is under test and
                        // not assumed.
                        o.Events.OnValidatePrincipal = SessionRevalidation.ValidateAsync;
                    });

                services.AddHttpContextAccessor();
                services.AddScoped<IUserSession, CookieUserSession>();
            };

            // The fixture's default pipeline has no UseAuthentication, because every other suite
            // supplies its session through TestUserSession and nothing reads a cookie back. This
            // one is about the cookie, so the middleware that reads it has to be here.
            seed.ConfigureApp = app => app.UseAuthentication();

            seed.ConfigureOptions = o =>
            {
                o.SelfServicePagesEnabled = true;

                // /logout is routed if and only if this is set, so without it the account page
                // draws no sign-out at all and the test above would assert against a page that
                // never offered one.
                o.EndSessionEnabled = true;

                // Every request, so a test asserts the decision rather than the cache in front of
                // it. The interval has its own test; mixing the two would make every assertion here
                // depend on a clock nobody moved.
                o.SessionRevalidation = TimeSpan.Zero;
            };
        });

        var world = new World(fixture, users, subject, fixture.Clock.GetUtcNow());

        var page = await world.Client.GetStringAsync(new Uri("/login", UriKind.Relative));
        var token = AntiforgeryField().Match(page);
        Assert.True(token.Success, "the login page rendered no antiforgery field");

        using var signedIn = await world.Client.PostAsync(
            new Uri("/login", UriKind.Relative),
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, HttpUtility.HtmlDecode(token.Groups[2].Value)),
                new("username", Username),
                new("password", Password),
            ]));

        // Not merely "a redirect": a refused sign-in also redirects, back to the form. Asserting
        // the destination is what tells the two apart, and a fixture that signs nobody in would
        // otherwise make every test in this file fail for a reason none of them are about.
        var landed = signedIn.Headers.Location?.ToString() ?? string.Empty;

        Assert.True(
            IsRedirect(signedIn.StatusCode) && !landed.Contains("/login", StringComparison.Ordinal),
            $"the sign-in was refused: {signedIn.StatusCode} -> {landed}");

        return world;
    }
}
