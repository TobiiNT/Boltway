using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Reaching the sign-in page by hand, with no authorization request in flight.
/// </summary>
/// <remarks>
/// <para>
/// Found by signing out on a running deployment and trying to sign back in. Measured, in this
/// order: <c>/logout</c> answered <c>200</c> with no link of any kind, <c>/</c> answered
/// <c>404</c> with an empty body, and <c>/login</c> answered <c>400</c> — <i>"This page was opened
/// without a valid authorization request."</i> So signing out was a one-way door, and the two URLs
/// a person would then type were both dead ends.
/// </para>
/// <para>
/// The whole suite was green while that was true, and the reason is worth keeping: every login test
/// starts from <c>/authorize</c>, because that is the flow the specification describes. Nothing
/// arrived at the page the way a person does — which is also how the recovery pages shipped
/// pointing at a bare <c>/login</c> a day earlier. Two defects, one blind spot.
/// </para>
/// </remarks>
public sealed partial class BareSignInTests
{
    private const string Username = "ada";
    private const string Password = "correct horse battery staple";

    /// <summary>
    /// A person types the obvious URL and gets the sign-in page, aimed at their own account.
    /// </summary>
    [Fact]
    public async Task Bare_login_renders_the_page_when_the_self_service_pages_are_routed()
    {
        await using var world = await StartAsync(selfServicePages: true);

        var page = await world.Client.GetAsync("/login");
        var html = await page.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal("/me", ReturnUrlIn(html));
    }

    /// <summary>
    /// With nowhere to land, the refusal stands.
    /// </summary>
    /// <remarks>
    /// A deployment can route password recovery, or nothing but <c>/authorize</c>, without routing
    /// the self-service pages — and then <c>/me</c> is a <c>404</c>. Signing somebody in and
    /// dropping them on a missing page is a worse answer than declining to start, so the default is
    /// routed-or-absent in exactly the way the "go to sign in" link is.
    /// </remarks>
    [Fact]
    public async Task Bare_login_is_still_refused_when_there_is_nowhere_to_land()
    {
        await using var world = await StartAsync(selfServicePages: false);

        var page = await world.Client.GetAsync("/login");

        Assert.Equal(HttpStatusCode.BadRequest, page.StatusCode);
    }

    /// <summary>
    /// The open-redirect guard is untouched: a supplied target that is not on the list is refused.
    /// </summary>
    /// <remarks>
    /// The distinction this change rests on, stated as a test. An attacker chooses a submitted
    /// value; nobody chooses an absent one. If these ever stop being different answers, <c>/login</c>
    /// is an open redirector on the one origin a person has been taught to trust with a password.
    /// </remarks>
    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    [InlineData("/admin/users")]
    [InlineData("/me/../admin/users")]
    public async Task A_supplied_target_that_is_not_allowed_is_still_refused(string returnUrl)
    {
        await using var world = await StartAsync(selfServicePages: true);

        var page = await world.Client.GetAsync("/login?returnUrl=" + Uri.EscapeDataString(returnUrl));

        Assert.Equal(HttpStatusCode.BadRequest, page.StatusCode);
    }

    /// <summary>
    /// And the form on that page works, rather than answering the refusal one click later.
    /// </summary>
    /// <remarks>
    /// The <c>POST</c> reads its <c>returnUrl</c> from the form, so defaulting on the <c>GET</c>
    /// alone would have rendered a page whose own submission answered <c>400</c> — the same dead
    /// end moved to the far side of the password field, where it costs an attempt as well. Asserted
    /// end to end rather than by reading the handler: the page is fetched, the form is submitted as
    /// the browser would submit it, and the destination is the one the person asked for.
    /// </remarks>
    [Fact]
    public async Task Signing_in_from_the_bare_page_lands_on_the_account()
    {
        await using var world = await StartAsync(selfServicePages: true);

        var signedIn = await SubmitAsync(world, Username, Password);

        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);
        Assert.Equal("/me", signedIn.Headers.Location!.ToString());
    }

    /// <summary>A wrong password on that page is still a wrong password, not a bad request.</summary>
    [Fact]
    public async Task A_wrong_password_on_the_bare_page_re_renders_the_form()
    {
        await using var world = await StartAsync(selfServicePages: true);

        var rejected = await SubmitAsync(world, Username, "not-the-password");
        var html = await rejected.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        Assert.Equal("/me", ReturnUrlIn(html));
    }

    /// <summary>
    /// The sign-out page offers a way back in.
    /// </summary>
    /// <remarks>
    /// The other half of the same dead end, and the one that made it a trap: the page a person is
    /// looking at when they want to sign back in had nothing to press. Asserted against the served
    /// page rather than the renderer, because the renderer was already capable of drawing this and
    /// the defect was that nothing asked it to.
    /// </remarks>
    [Fact]
    public async Task The_sign_out_page_offers_a_way_back_in()
    {
        await using var world = await StartAsync(selfServicePages: true);

        var html = await world.Client.GetStringAsync("/logout");

        Assert.Contains("href=\"/login?returnUrl=%2Fme\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"/login\"", html, StringComparison.Ordinal);
    }

    /// <summary>And offers none when there is none, rather than one that lands on the refusal.</summary>
    [Fact]
    public async Task The_sign_out_page_offers_nothing_when_there_is_nowhere_to_go()
    {
        await using var world = await StartAsync(selfServicePages: false);

        var html = await world.Client.GetStringAsync("/logout");

        Assert.DoesNotContain("<a href=", html, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ harness

    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [GeneratedRegex("name=\"returnUrl\" value=\"([^\"]*)\"")]
    private static partial Regex ReturnUrlField();

    private static string ReturnUrlIn(string html)
    {
        var match = ReturnUrlField().Match(html);

        Assert.True(match.Success, "The page rendered no returnUrl field.");

        return HttpUtility.HtmlDecode(match.Groups[1].Value);
    }

    /// <summary>Fetch the bare page and post its form back, the way a browser would.</summary>
    private static async Task<HttpResponseMessage> SubmitAsync(World world, string username, string password)
    {
        var page = await world.Client.GetStringAsync("/login");
        var token = AntiforgeryField().Match(page);

        Assert.True(token.Success, "The page rendered no antiforgery field.");

        return await world.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", ReturnUrlIn(page)),
            new("username", username),
            new("password", password),
        ]));
    }

    private sealed record World(FlowFixture Fixture) : IAsyncDisposable
    {
        public HttpClient Client => Fixture.Client;

        public ValueTask DisposeAsync() => Fixture.DisposeAsync();
    }

    private static async Task<World> StartAsync(bool selfServicePages)
    {
        var hasher = new Argon2idPasswordHasher(new Argon2idParameters
        {
            MemoryKiB = 64,
            Iterations = 1,
            Parallelism = 1,
        });

        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        await users.StoreAsync(
            new UserAccount(
                new UlidSubjectIdFactory(TimeProvider.System).Mint(),
                Username,
                "ada@example.com",
                EmailVerified: true,
                PasswordHash: hasher.Hash(Password)),
            CancellationToken.None);

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            // Nobody is signed in: this suite is about arriving at these pages cold, which is the
            // state the defect lived in.
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
                    });

                services.AddHttpContextAccessor();
                services.AddScoped<IUserSession, CookieUserSession>();
            };

            seed.ConfigureOptions = o =>
            {
                o.SelfServicePagesEnabled = selfServicePages;

                // The sign-out page is behind its own switch, and this suite is about the door back
                // in from it. Off, /logout is not routed at all and these tests would assert on a
                // 404 that says nothing about the link.
                o.EndSessionEnabled = true;
            };
            seed.ConfigureApp = app => app.UseAuthentication();
        });

        return new World(fixture);
    }
}
