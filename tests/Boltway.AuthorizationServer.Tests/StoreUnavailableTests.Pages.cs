using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Identity.Passwords;
using Boltway.Notifications;
using Boltway.OAuth.Primitives.Ids;
using Boltway.Storage.InMemory;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// X-43 on the surfaces a person reaches: the sign-in and recovery pages, and the APIs behind them.
/// </summary>
/// <remarks>
/// <para>
/// <b>The sign-in page is the one this was worth doing for.</b> Everything else in X-43 was a
/// machine being told the wrong thing; here it is a person, on the page where the only thing they
/// can conclude is about themselves. The headline test is the negative one - a directory that
/// cannot be reached must not produce "that username and password did not match", which is the
/// same sentence the outage that started all of this put in front of somebody whose credentials
/// were fine.
/// </para>
/// <para>
/// <b>X-31 is deliberately not re-tested here.</b> Changing which untabled row the HTML writer
/// picks could have broken the rate limit, and <c>ThrottleResponseTests</c> already drives that
/// path end to end on this exact writer. A second copy would not catch anything the first does not.
/// </para>
/// </remarks>
public sealed partial class StoreUnavailableTests
{
    private const string PageUsername = "ada";
    private const string PagePassword = "correct-horse-battery-staple";

    /// <summary>
    /// A server whose directory answers nothing, with the real cookie session and a hasher.
    /// </summary>
    /// <remarks>
    /// The same shape <c>LoginFlowTests</c> builds, minus the seeded account - there is no point
    /// seeding one into a store that cannot be read. The hasher is real rather than a double
    /// because the endpoint verifies against a dummy hash when it has no account, and a fake would
    /// skip the branch under test.
    /// </remarks>
    private static Task<FlowFixture> UnreachableDirectoryPagesAsync() =>
        FlowFixture.StartAsync(seed =>
        {
            seed.SignedInUser = null;

            // So a bare `GET /login` has a returnUrl to default to. `TryUseReturnUrl` sends an
            // absent one to `/me` when the self-service pages are on and refuses at 400 when they
            // are not, and nothing below reads those pages - this is only about the sign-in form
            // being reachable without an authorization request in front of it, which is how a
            // person arrives after following a password-reset link.
            seed.ConfigureOptions = o => o.SelfServicePagesEnabled = true;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(new UnreachableUserStore());
                services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());
            };
        });

    [GeneratedRegex("name=\"([^\"]*Token[^\"]*)\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();

    [GeneratedRegex("name=\"returnUrl\" value=\"([^\"]+)\"")]
    private static partial Regex ReturnUrlField();

    /// <summary>
    /// Sign in for real: fetch the form, then post it.
    /// </summary>
    /// <remarks>
    /// The GET is not a formality. It is what proves the page still renders while the directory is
    /// gone - <c>LoginModel</c> reads no accounts, so a store failure has to wait for the POST -
    /// and it is the only way to obtain the antiforgery token, without which the POST is refused
    /// at 400 and never reaches the code under test.
    /// </remarks>
    private static async Task<HttpResponseMessage> SignInAsync(FlowFixture fixture)
    {
        var page = await fixture.Client.GetStringAsync(new Uri("/login", UriKind.Relative));

        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        Assert.True(token.Success, "The sign-in page rendered no antiforgery field, so the directory outage reached the GET.");
        Assert.True(returnUrl.Success, "The sign-in page rendered no returnUrl field.");

        return await fixture.Client.PostAsync(
            new Uri("/login", UriKind.Relative),
            new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>(token.Groups[1].Value, token.Groups[2].Value),
                new KeyValuePair<string, string>("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
                new KeyValuePair<string, string>("username", PageUsername),
                new KeyValuePair<string, string>("password", PagePassword),
            ]));
    }

    // ── the sign-in page ─────────────────────────────────────────────────────

    /// <summary>
    /// A directory that cannot be read is not a wrong password, and must not be reported as one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without the shed this posts through <c>ResolveAccountAsync</c>, which throws, and the
    /// request ends as an unhandled exception - a bare <c>500</c>, since no
    /// <c>UseExceptionHandler</c> is registered anywhere in this server. That is already wrong. The
    /// failure this asserts against is the worse one a step away: any change that let the lookup
    /// return "no account" instead of throwing would land on the branch below it, which re-renders
    /// the form saying the credentials did not match.
    /// </para>
    /// <para>
    /// So the assertion is on the sentence, not only on the status. <c>200</c> with that text is
    /// what a person must never be shown when the truth is that this server could not look.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_sign_in_whose_directory_is_gone_does_not_say_the_password_was_wrong()
    {
        await using var fixture = await UnreachableDirectoryPagesAsync();

        var response = await SignInAsync(fixture);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        Assert.DoesNotContain("did not match", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("name=\"password\"", body, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And what they do get is a page, not an empty body with a better number on it.
    /// </summary>
    /// <remarks>
    /// The distinction the HTML row exists for. A bare <c>503</c> reaches a browser as the
    /// browser's own error page, which says nothing about coming back - so on this surface the
    /// status is necessary and not sufficient. The correlation id is in the body because A-12 wants
    /// <c>curl -D-</c> to be enough, and because it is what a person can quote when they report it.
    /// </remarks>
    [Fact]
    public async Task The_person_gets_a_rendered_page_and_a_retry_after()
    {
        await using var fixture = await UnreachableDirectoryPagesAsync();

        var response = await SignInAsync(fixture);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("<html", body, StringComparison.OrdinalIgnoreCase);

        Assert.NotNull(response.Headers.RetryAfter?.Delta);
        Assert.True(response.Headers.RetryAfter!.Delta!.Value > TimeSpan.Zero);

        Assert.Contains(
            response.Headers.GetValues("X-Request-Id").Single(), body, StringComparison.Ordinal);
    }

    /// <summary>One line, on the surface that names the half of the server that failed.</summary>
    /// <remarks>
    /// <c>Interaction</c> rather than a borrowed protocol surface. An operator reading a burst of
    /// these needs to know people cannot sign in, which is a different page to open from token
    /// issuance failing - and before this surface existed there was no value that said so.
    /// </remarks>
    [Fact]
    public async Task The_sign_in_load_shed_is_logged_against_the_interaction_surface()
    {
        await using var fixture = await UnreachableDirectoryPagesAsync();

        _ = await SignInAsync(fixture);

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal("Interaction", line.Property("Surface"));
        Assert.Equal("StoreUnavailable", line.Property("Reason"));
        Assert.Equal("X-43", line.Property("RequirementId"));
        Assert.Equal("503", line.Property("Status"));
    }

    /// <summary>
    /// A defect on the same page is still a defect.
    /// </summary>
    /// <remarks>
    /// The negative direction, and it matters more on a filter than on a hand-written <c>catch</c>:
    /// a filter wraps every route in the group at once, so one that classified too broadly would
    /// hide bugs across six files rather than one endpoint. An unhandled
    /// <see cref="InvalidCastException"/> must still reach the host and abort the request.
    /// </remarks>
    [Fact]
    public async Task A_defect_on_the_sign_in_page_is_not_dressed_up_as_come_back_later()
    {
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.SignedInUser = null;

            // So a bare `GET /login` has a returnUrl to default to. `TryUseReturnUrl` sends an
            // absent one to `/me` when the self-service pages are on and refuses at 400 when they
            // are not, and nothing below reads those pages - this is only about the sign-in form
            // being reachable without an authorization request in front of it, which is how a
            // person arrives after following a password-reset link.
            seed.ConfigureOptions = o => o.SelfServicePagesEnabled = true;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(new BrokenUserStore());
                services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());
            };
        });

        await Assert.ThrowsAnyAsync<Exception>(() => SignInAsync(fixture));

        Assert.Empty(fixture.Logs.Rejections);
    }

    /// <summary>A directory with a bug in it, as opposed to one that cannot be reached.</summary>
    private sealed class BrokenUserStore : IUserStore
    {
        public Task<UserAccount?> FindBySubjectAsync(SubjectId subject, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<UserAccount?> FindByUsernameAsync(RealmId realm, string username, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<UserAccount?> FindByVerifiedEmailAsync(RealmId realm, string email, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<UserAccount?> FindByExternalLoginAsync(
            RealmId realm, string upstreamIssuer, string upstreamSubject, CancellationToken cancellationToken) =>
            throw Bug();

        public Task StoreAsync(UserAccount user, CancellationToken cancellationToken) => throw Bug();

        public Task LinkExternalLoginAsync(ExternalLogin link, CancellationToken cancellationToken) => throw Bug();

        public Task<IReadOnlyList<ExternalLogin>> ListExternalLoginsAsync(
            SubjectId subject, CancellationToken cancellationToken) => throw Bug();

        public Task<bool> SetRolesAsync(
            SubjectId subject, IReadOnlyList<string> roles, CancellationToken cancellationToken) => throw Bug();

        public Task<bool> StampSessionsAsync(SubjectId subject, DateTimeOffset at, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<bool> SetPasswordHashAsync(SubjectId subject, string passwordHash, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<bool> SetEnabledAsync(SubjectId subject, DateTimeOffset? disabledAt, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<bool> SetEmailAsync(SubjectId subject, string? email, bool verified, CancellationToken cancellationToken) =>
            throw Bug();

        public Task<IReadOnlyList<UserAccount>> ListAsync(
            RealmId realm, SubjectId? after, int limit, CancellationToken cancellationToken) => throw Bug();

        public Task<bool> AnonymiseAsync(
            SubjectId subject, string tombstoneUsername, DateTimeOffset now, CancellationToken cancellationToken) =>
            throw Bug();

        private static InvalidCastException Bug() => new("a real bug");
    }

    // ── the JSON half of the same file ───────────────────────────────────────

    /// <summary>
    /// The recovery API sheds too, and answers the status alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>RecoveryEndpoints</c> is the one file that maps both halves - three routes under
    /// <c>/account/</c> that a script calls, five pages a person is sent to by an email - so it is
    /// the one place the split could be got wrong without anything else noticing. This drives the
    /// API half and asserts the shape a script needs: no body, and a surface that says which half
    /// of the server it was.
    /// </para>
    /// <para>
    /// <c>/account/password/forgot</c> is anonymous, which is why it is the route used here: it
    /// exercises the split without a fixture that also has to mint an admin token.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_recovery_api_sheds_with_the_status_and_no_body()
    {
        // Both extra registrations are demanded by startup validation rather than by this test:
        // recovery mints links that live in a token store and arrive by mail, and the server
        // refuses to start with the flow on and either one missing. Neither is reached here - the
        // directory fails first - but a fixture cannot decline to be valid.
        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.ConfigureOptions = o => o.PasswordRecoveryEnabled = true;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(new UnreachableUserStore());
                services.AddSingleton<IUserTokenStore>(new InMemoryUserTokenStore());
                services.AddSingleton<INotificationSender>(new RecoverySurfaceTests.Outbox());
            };
        });

        var response = await fixture.Client.PostAsync(
            new Uri("/account/password/forgot", UriKind.Relative),
            new StringContent(
                // `account`, which is the field this endpoint reads - a handle or an address. An
                // unrecognised name parses to null, and null short-circuits the lookup before the
                // store is touched, so the request would answer 202 having proved nothing.
                """{"account":"ada"}""", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());
        Assert.NotNull(response.Headers.RetryAfter?.Delta);

        var line = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal("Administration", line.Property("Surface"));
        Assert.Equal("X-43", line.Property("RequirementId"));
    }
}
