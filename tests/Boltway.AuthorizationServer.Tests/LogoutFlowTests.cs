using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>/logout</c> - the endpoint this server advertised for its whole history and never routed.
/// </summary>
/// <remarks>
/// <para>
/// <c>AuthorizationServerPaths.EndSession</c>, <c>AuthorizationServerOptions.EndSessionEnabled</c>
/// and <c>AuthorizationServerMetadata.EndSessionEndpoint</c> all existed, <c>MetadataBuilder</c>
/// published the URL when the flag was set, and nothing mapped the path. A deployment turning the
/// flag on put an <c>end_session_endpoint</c> in both discovery documents pointing at a 404 - the
/// <c>N-06</c> failure, in the shape <c>N-06</c> is written about.
/// </para>
/// <para>
/// So the first two tests here are a pair, and they are the point of the file: the endpoint is
/// routed exactly when it is advertised, in both directions.
/// </para>
/// </remarks>
public sealed partial class LogoutFlowTests
{
    private static readonly AuthenticatedUser SignedIn =
        new(SubjectId.FromStorage("user-1"), new DateTimeOffset(2026, 8, 4, 11, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task It_is_absent_when_it_is_not_advertised()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureOptions = o => o.EndSessionEnabled = false);

        var page = await fixture.Client.GetAsync(new Uri("/logout", UriKind.Relative));
        var metadata = await Metadata(fixture);

        Assert.Equal(HttpStatusCode.NotFound, page.StatusCode);
        Assert.False(metadata.TryGetProperty("end_session_endpoint", out _));
    }

    [Fact]
    public async Task It_is_routed_when_it_is_advertised()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureOptions = o => o.EndSessionEnabled = true);

        var page = await fixture.Client.GetAsync(new Uri("/logout", UriKind.Relative));
        var metadata = await Metadata(fixture);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal(
            "https://auth.example.com/logout",
            metadata.GetProperty("end_session_endpoint").GetString());
    }

    /// <summary>
    /// The <c>GET</c> asks. It does not end anything.
    /// </summary>
    /// <remarks>
    /// A URL that ends a session on <c>GET</c> is one anybody can put in an <c>&lt;img src&gt;</c> on
    /// a page the user merely visits. It is denial of service against a person rather than a server,
    /// which is why OIDC RP-Initiated Logout §2 says the provider SHOULD ask - and why this asserts
    /// the session is still there afterwards rather than only that a form was drawn.
    /// </remarks>
    [Fact]
    public async Task A_get_asks_and_ends_nothing()
    {
        await using var fixture = await SignedInFixture();

        var first = await fixture.Client.GetStringAsync(new Uri("/logout", UriKind.Relative));

        Assert.Contains("<form method=\"post\"", first, StringComparison.Ordinal);
        Assert.Contains("action=\"/logout\"", first, StringComparison.Ordinal);
        Assert.DoesNotContain("Signed out", first, StringComparison.Ordinal);

        // The session is read again from scratch. If the GET had ended it, this one would draw the
        // other half of the page.
        var second = await fixture.Client.GetStringAsync(new Uri("/logout", UriKind.Relative));

        Assert.Contains("<form method=\"post\"", second, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_post_ends_the_session_and_clears_the_cookie()
    {
        await using var fixture = await RealCookieFixture();

        await SignIn(fixture);

        var confirmation = await fixture.Client.GetStringAsync(new Uri("/logout", UriKind.Relative));
        var (field, token) = AntiforgeryOf(confirmation);

        var response = await fixture.Client.PostAsync(
            new Uri("/logout", UriKind.Relative),
            new FormUrlEncodedContent([new KeyValuePair<string, string>(field, token)]));

        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Signed out", body, StringComparison.Ordinal);

        // The header a browser acts on, not an inference from the next page. `expires` in the past
        // is how a cookie is deleted; asserting only that the following request looks signed out
        // would pass against a server that simply stopped reading a cookie it left in place.
        var deletion = Assert.Single(
            response.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith("__Host-boltway-session=;", StringComparison.Ordinal));

        Assert.Contains("expires=Thu, 01 Jan 1970", deletion, StringComparison.Ordinal);

        var after = await fixture.Client.GetStringAsync(new Uri("/logout", UriKind.Relative));

        Assert.Contains("Signed out", after, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_post_is_refused_without_an_antiforgery_token()
    {
        await using var fixture = await RealCookieFixture();

        await SignIn(fixture);

        var response = await fixture.Client.PostAsync(
            new Uri("/logout", UriKind.Relative),
            new FormUrlEncodedContent([]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // And the session survived the refusal, which is the half that matters: a logout CSRF that
        // is refused but still signs the user out has refused nothing.
        var after = await fixture.Client.GetStringAsync(new Uri("/logout", UriKind.Relative));

        Assert.Contains("<form method=\"post\"", after, StringComparison.Ordinal);
    }

    /// <summary>
    /// An anonymous browser gets the answer a just-signed-out one gets.
    /// </summary>
    /// <remarks>
    /// Distinguishing them would tell an unauthenticated caller whether this browser holds a session
    /// for this server, which is a fact about somebody else's browsing. It is also what makes the
    /// endpoint safe to leave anonymous: requiring authentication would send a signed-out visitor to
    /// the sign-in page to prove who they are so they can stop being it.
    /// </remarks>
    [Fact]
    public async Task An_anonymous_browser_is_told_the_same_thing_as_one_that_has_signed_out()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.SignedInUser = null;
            seed.ConfigureOptions = o => o.EndSessionEnabled = true;
        });

        var body = await fixture.Client.GetStringAsync(new Uri("/logout", UriKind.Relative));

        Assert.Contains("Signed out", body, StringComparison.Ordinal);
        Assert.DoesNotContain("<form method=\"post\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_page_carries_the_headers_every_other_page_carries()
    {
        await using var fixture = await SignedInFixture();

        var response = await fixture.Client.GetAsync(new Uri("/logout", UriKind.Relative));

        var csp = Assert.Single(response.Headers.GetValues("Content-Security-Policy"));

        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Contains("form-action 'self'", csp, StringComparison.Ordinal);
        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
    }

    private static Task<FlowFixture> SignedInFixture() =>
        FlowFixture.StartAsync(seed =>
        {
            seed.SignedInUser = SignedIn;
            seed.ConfigureOptions = o => o.EndSessionEnabled = true;
        });

    /// <summary>
    /// A fixture whose session comes from a real cookie, because the POST has to clear one.
    /// </summary>
    /// <remarks>
    /// <see cref="TestUserSession"/> hands a session over regardless of what the browser holds, so a
    /// sign-out test built on it would pass with <c>SignOutAsync</c> deleted - the page would still
    /// say "Signed out" and the cookie would still be there. Only the real handler can be asked
    /// whether the cookie went away.
    /// </remarks>
    private static Task<FlowFixture> RealCookieFixture() =>
        FlowFixture.StartAsync(seed =>
        {
            seed.SignedInUser = null;
            seed.ConfigureOptions = o => o.EndSessionEnabled = true;

            seed.ConfigureServices = services =>
            {
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

                // A route that signs a browser in without going through the login form. The password
                // path is tested next door; what this file needs is a session, and driving the whole
                // flow to get one would make every assertion below depend on it.
                services.AddSingleton<TestSignInRoute>();
            };

            seed.ConfigureApp = app =>
            {
                app.UseAuthentication();

                app.Use(async (http, next) =>
                {
                    if (http.Request.Path == "/test-sign-in")
                    {
                        await http.RequestServices.GetRequiredService<IUserSignIn>()
                            .SignInAsync(http, SignedIn);

                        http.Response.StatusCode = StatusCodes.Status204NoContent;
                        return;
                    }

                    await next(http);
                });
            };
        });

    private static async Task SignIn(FlowFixture fixture)
    {
        var response = await fixture.Client.GetAsync(new Uri("/test-sign-in", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private static async Task<JsonElement> Metadata(FlowFixture fixture)
    {
        var json = await fixture.Client.GetStringAsync(
            new Uri("/.well-known/oauth-authorization-server", UriKind.Relative));

        return JsonDocument.Parse(json).RootElement;
    }

    private static (string Field, string Token) AntiforgeryOf(string html)
    {
        var match = AntiforgeryField().Match(html);

        Assert.True(match.Success, "The confirmation page carried no antiforgery field.");

        return (match.Groups[1].Value, match.Groups[2].Value);
    }

    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    /// <summary>A marker so the sign-in route's registration is visible in the container.</summary>
    private sealed class TestSignInRoute;
}
