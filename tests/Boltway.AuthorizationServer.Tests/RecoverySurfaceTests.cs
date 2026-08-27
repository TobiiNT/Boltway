using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.Notifications;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.InMemory;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The two flows that reach a person by email. E-39 to E-44.
/// </summary>
/// <remarks>
/// Two rules shape almost every assertion here. <c>S-48</c>: asking for a reset says the same thing
/// whether or not the account exists, so most of these tests are about what the server does
/// <i>not</i> say. <c>S-47</c>: a link is single use, expiring, and dead the moment the password
/// changes by any route - so the rest are about links that must stop working.
/// </remarks>
public sealed partial class RecoverySurfaceTests
{
    private const string Handle = "ada";
    private const string Address = "ada@example.com";
    private const string Subject = "01J8XKQ7M3N4P5R6S7T8V9W0AD";

    /// <summary>An <see cref="INotificationSender"/> that keeps what it was given.</summary>
    /// <remarks>
    /// The only way to observe <c>S-48</c>'s one real difference. The endpoint answers identically
    /// for a known and an unknown address; whether a message was produced is the sole distinguishing
    /// fact, and in production only the mailbox owner can see it.
    /// </remarks>
    internal sealed class Outbox : INotificationSender
    {
        private readonly List<NotificationMessage> _sent = [];

        internal IReadOnlyList<NotificationMessage> Sent
        {
            get { lock (_sent) { return [.. _sent]; } }
        }

        public Task SendAsync(NotificationMessage message, CancellationToken cancellationToken)
        {
            lock (_sent) { _sent.Add(message); }

            return Task.CompletedTask;
        }
    }

    private sealed record World(
        FlowFixture Fixture, InMemoryUserStore Users, SharedStores Stores, Outbox Mail, InMemoryUserTokenStore Tokens);

    private static async Task<World> StartAsync(
        bool recovery = true, string? email = Address, bool withSender = true)
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);
        var stores = new SharedStores();
        var mail = new Outbox();
        var tokens = new InMemoryUserTokenStore();
        var hasher = new Argon2idPasswordHasher();

        await users.StoreAsync(
            new UserAccount(
                SubjectId.FromStorage(Subject), Handle, email, EmailVerified: false, hasher.Hash("old password")),
            CancellationToken.None);

        var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.Stores = stores;

            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSingleton<IPasswordHasher>(hasher);
                services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));
                services.AddSingleton<IAdminAuditStore>(new InMemoryAdminAuditStore());
                services.AddSingleton<IUserTokenStore>(tokens);

                if (withSender)
                {
                    services.AddSingleton<INotificationSender>(mail);
                }
            };

            seed.ConfigureOptions = o => o.PasswordRecoveryEnabled = recovery;
        });

        return new World(fixture, users, stores, mail, tokens);
    }

    [GeneratedRegex("<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"")]
    private static partial Regex HiddenField();

    /// <summary>The token out of the link in the most recent message.</summary>
    private static string TokenFrom(NotificationMessage message)
    {
        var link = message switch
        {
            ResetPassword reset => reset.Link,
            VerifyEmail verify => verify.Link,
            _ => throw new InvalidOperationException("That message carries no link."),
        };

        return System.Web.HttpUtility.ParseQueryString(new Uri(link).Query)["token"]!;
    }

    // ─────────────────────────────────────────────────────────────── the surface

    [Fact]
    public async Task The_flows_are_absent_unless_a_deployment_asked_for_them()
    {
        var world = await StartAsync(recovery: false);
        await using var fixture = world.Fixture;

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// Turning them on without a sender is refused at startup, not at the first request.
    /// </summary>
    /// <remarks>
    /// The endpoints would answer 202, mint a link, and deliver nothing - every signal saying it
    /// worked, and the only thing that does not happen being the one the caller is waiting for.
    /// </remarks>
    [Fact]
    public async Task Recovery_without_a_sender_refuses_to_start()
    {
        var failure = await Assert.ThrowsAsync<
            DependencyInjection.AuthorizationServerConfigurationException>(
            () => StartAsync(withSender: false));

        Assert.Contains("INotificationSender", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The sign-in page offers a reset, and only where there is one to offer.
    /// </summary>
    /// <remarks>
    /// <b>The gap this pair closes.</b> The flow worked before it and nothing pointed at it, so a
    /// deployment that turned recovery on had to tell people the URL by hand - the fifth time in
    /// this library that a capability existed and no deployment could reach it. The negative half
    /// matters as much: <c>/forgot</c> is not routed with recovery off, so an unconditional link
    /// would hand a 404 to the one person least able to recover from it.
    /// </remarks>
    [Fact]
    public async Task The_sign_in_page_offers_a_reset_only_when_the_deployment_can_send_one()
    {
        var on = await StartAsync();
        await using (on.Fixture)
        {
            var html = await on.Fixture.Client.GetStringAsync(new Uri("/login?returnUrl=%2Fauthorize", UriKind.Relative));

            Assert.Contains("href=\"/forgot\"", html, StringComparison.Ordinal);
        }

        var off = await StartAsync(recovery: false);
        await using (off.Fixture)
        {
            var html = await off.Fixture.Client.GetStringAsync(
                new Uri("/login?returnUrl=%2Fauthorize", UriKind.Relative));

            Assert.DoesNotContain("/forgot", html, StringComparison.Ordinal);

            // And it is genuinely not there, which is what makes hiding the link the right answer
            // rather than a cosmetic one.
            var page = await off.Fixture.Client.GetAsync(new Uri("/forgot", UriKind.Relative));

            Assert.Equal(HttpStatusCode.NotFound, page.StatusCode);
        }
    }

    /// <summary>
    /// The page sends the mail, and says the same thing whether or not it did. <c>S-48</c>.
    /// </summary>
    /// <remarks>
    /// The browser half of the assertion this file exists for. <c>E-39</c> answers JSON, so this
    /// page calls <see cref="AccountRecovery"/> in process rather than posting to it - which means
    /// <c>S-48</c> has to hold on a second code path, and this is what says it does.
    /// </remarks>
    [Fact]
    public async Task The_forgot_page_answers_identically_for_a_known_and_an_unknown_account()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var known = await SubmitForgotAsync(fixture, Address);
        var unknown = await SubmitForgotAsync(fixture, "nobody@example.com");

        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);

        var knownHtml = await known.Content.ReadAsStringAsync();

        Assert.Contains("is on its way", knownHtml, StringComparison.Ordinal);
        Assert.Equal(knownHtml, await unknown.Content.ReadAsStringAsync());

        // The submitted identifier is not echoed back - the field the page would be tempted to
        // repopulate is an email address, and a page saying "we looked for X" is one sentence from
        // saying whether X was found.
        Assert.DoesNotContain(Address, knownHtml, StringComparison.Ordinal);

        // And the one real difference, observable in production only by a mailbox owner.
        var sent = Assert.Single(world.Mail.Sent);
        Assert.IsType<ResetPassword>(sent);
        Assert.Equal(Address, sent.To);
    }

    /// <summary>
    /// The link the page mails works, end to end.
    /// </summary>
    /// <remarks>
    /// The two halves are wired by different code - the page calls the service, the link lands on
    /// <c>/reset</c> - and a test of each separately would pass with the mail pointing at a route
    /// that does not exist. §7.3 is that failure in the abstract; this is it in a request.
    /// </remarks>
    [Fact]
    public async Task A_link_asked_for_from_the_page_resets_the_password()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await SubmitForgotAsync(fixture, Handle);

        var token = TokenFrom(Assert.Single(world.Mail.Sent));
        var before = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);

        var page = await fixture.Client.GetStringAsync(
            new Uri("/reset?token=" + Uri.EscapeDataString(token), UriKind.Relative));

        var form = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (Match match in HiddenField().Matches(page))
        {
            form[match.Groups[1].Value] = WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        form["new"] = "battery staple stapler";
        form["confirm"] = "battery staple stapler";

        var posted = await fixture.Client.PostAsync(
            new Uri("/reset", UriKind.Relative), new FormUrlEncodedContent(form));

        Assert.Contains(
            "password has been set", await posted.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);
        Assert.NotEqual(before!.PasswordHash, after!.PasswordHash);
    }

    /// <summary>
    /// A form post without the antiforgery token sends nothing.
    /// </summary>
    /// <remarks>
    /// <c>E-39</c> has no antiforgery - it has no cookie to protect - and this page is on the origin
    /// that carries the session cookie, where every other form has one. A forged request here is not
    /// an escalation; being the page that is the exception is how the next one comes to skip it.
    /// </remarks>
    [Fact]
    public async Task The_forgot_page_refuses_a_post_without_the_antiforgery_token()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var response = await fixture.Client.PostAsync(
            new Uri("/forgot", UriKind.Relative),
            new FormUrlEncodedContent([new KeyValuePair<string, string>("account", Address)]));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(world.Mail.Sent);
    }

    /// <summary>
    /// The page is behind the same throttle as the endpoint, and says so rather than lying. §3.1.
    /// </summary>
    /// <remarks>
    /// Adding a page must not become a way around a limit that exists to stop this server mailing
    /// strangers on somebody else's instruction. And a refused request is told apart from a sent
    /// one: answering "a link is on its way" when the server has decided not to send one leaves a
    /// person waiting for something that will not arrive.
    /// </remarks>
    [Fact]
    public async Task The_forgot_page_is_throttled_like_the_endpoint()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        // Three per identifier in fifteen minutes, so the fourth is refused.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            Assert.Contains(
                "is on its way",
                await (await SubmitForgotAsync(fixture, Address)).Content.ReadAsStringAsync(),
                StringComparison.Ordinal);
        }

        var refused = await SubmitForgotAsync(fixture, Address);
        var html = await refused.Content.ReadAsStringAsync();

        Assert.Contains("Too many requests", html, StringComparison.Ordinal);
        Assert.DoesNotContain("is on its way", html, StringComparison.Ordinal);

        // Retry-After on the page too, so a person reads the sentence and a client reads the header
        // - the JSON endpoint already sets it, and two surfaces disagreeing about a number neither
        // is guessing at is a defect nobody would look for.
        Assert.NotNull(refused.Headers.RetryAfter);

        Assert.Equal(3, world.Mail.Sent.Count);
    }

    /// <summary>Post the forgot-password form, carrying the antiforgery token the page drew.</summary>
    private static async Task<HttpResponseMessage> SubmitForgotAsync(FlowFixture fixture, string account)
    {
        var page = await fixture.Client.GetStringAsync(new Uri("/forgot", UriKind.Relative));

        var form = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (Match match in HiddenField().Matches(page))
        {
            form[match.Groups[1].Value] = WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        Assert.NotEmpty(form);

        form["account"] = account;

        return await fixture.Client.PostAsync(new Uri("/forgot", UriKind.Relative), new FormUrlEncodedContent(form));
    }

    // ────────────────────────────────────────────────────────────────────── E-39

    /// <summary>
    /// A known and an unknown identifier get the same status and the same bytes. <c>S-48</c>.
    /// </summary>
    /// <remarks>
    /// <b>The assertion this file exists for.</b> Any difference - a 404, a different sentence, a
    /// different field - turns this endpoint into a way to test which addresses are registered here,
    /// at whatever rate the throttle allows.
    /// </remarks>
    [Fact]
    public async Task A_reset_request_answers_identically_for_a_known_and_an_unknown_account()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var known = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Address });

        var unknown = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = "nobody@example.com" });

        Assert.Equal(HttpStatusCode.Accepted, known.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, unknown.StatusCode);
        Assert.Equal(await known.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());

        // And the only real difference, which in production only a mailbox owner can observe.
        var sent = Assert.Single(world.Mail.Sent);
        Assert.IsType<ResetPassword>(sent);
        Assert.Equal(Address, sent.To);
    }

    [Fact]
    public async Task A_reset_can_be_asked_for_by_handle_as_well_as_by_address()
    {
        // Somebody who has forgotten their password has usually also forgotten which of the two they
        // signed up with.
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        Assert.Single(world.Mail.Sent);
    }

    [Fact]
    public async Task Asking_again_replaces_the_first_link_rather_than_adding_one()
    {
        // S-47: somebody who clicks "forgot password" three times holds one live link, not three.
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });
        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        Assert.Equal(2, world.Mail.Sent.Count);

        var first = TokenFrom(world.Mail.Sent[0]);
        var second = TokenFrom(world.Mail.Sent[1]);

        var stale = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/reset", UriKind.Relative),
            new { token = first, new_password = "a new one" });

        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);

        var fresh = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/reset", UriKind.Relative),
            new { token = second, new_password = "a new one" });

        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }

    /// <summary>The request is bounded, because it sends mail to an address the caller picks. §3.1.</summary>
    [Fact]
    public async Task Reset_requests_are_throttled()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        HttpStatusCode last = HttpStatusCode.Accepted;

        for (var attempt = 0; attempt < 12 && last is not HttpStatusCode.TooManyRequests; attempt++)
        {
            var response = await fixture.Client.PostAsJsonAsync(
                new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

            last = response.StatusCode;
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, last);

        // Bounded, not merely slowed: the mailbox stops receiving.
        Assert.True(world.Mail.Sent.Count <= 3, $"sent {world.Mail.Sent.Count} messages");
    }

    // ─────────────────────────────────────────────────────────────── E-40, E-43

    /// <summary>
    /// The link resets the password, ends every session, and says so. §1.10.
    /// </summary>
    /// <remarks>
    /// Revocation is unconditional on this route and only on this route. Somebody resetting through
    /// email is usually doing it because they lost control of something, and the sessions an
    /// attacker holds are exactly what a new password does not touch.
    /// </remarks>
    [Fact]
    public async Task Redeeming_a_link_sets_the_password_and_ends_every_session()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await world.Stores.Grants.StoreAsync(
            new GrantRecord(
                "grant-1", SubjectId.FromStorage(Subject), ClientIdentifier.ForPreRegistered("c"),
                ScopeSet.FromStorage("docs:read"), [], DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch),
            CancellationToken.None);

        var before = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        var token = TokenFrom(world.Mail.Sent[0]);

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/reset", UriKind.Relative),
            new { token, new_password = "battery staple stapler" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, body.GetProperty("sessions_revoked").GetInt32());

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);
        Assert.NotEqual(before!.PasswordHash, after!.PasswordHash);

        Assert.True(await world.Stores.Grants.IsRevokedAsync("grant-1", CancellationToken.None));

        // And the message nobody asked for, which is how somebody finds out it was not them.
        Assert.Contains(world.Mail.Sent, m => m is PasswordChanged);
    }

    [Fact]
    public async Task A_link_works_once()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        var token = TokenFrom(world.Mail.Sent[0]);

        Assert.Equal(
            HttpStatusCode.OK,
            (await fixture.Client.PostAsJsonAsync(
                new Uri("/account/password/reset", UriKind.Relative),
                new { token, new_password = "first choice" })).StatusCode);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await fixture.Client.PostAsJsonAsync(
                new Uri("/account/password/reset", UriKind.Relative),
                new { token, new_password = "second choice" })).StatusCode);
    }

    /// <summary>
    /// Changing the password by another route kills an outstanding link. <c>S-47</c>.
    /// </summary>
    /// <remarks>
    /// The clause an implementation forgets, and the one that matters most: a reset link that still
    /// works after the password has changed is a second key, held by whoever asked for it - which on
    /// this path may be the attacker whose access is the reason it was changed.
    /// </remarks>
    [Fact]
    public async Task A_password_change_by_another_route_kills_an_outstanding_link()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        var token = TokenFrom(world.Mail.Sent[0]);

        // The operator's route, in process - the CLI's verb, and the one least likely to be
        // remembered when this rule is being implemented.
        await fixture.Services.CreateScope().ServiceProvider
            .GetRequiredService<UserAdministration>()
            .ResetPasswordAsync(Actor.Cli, RealmId.Default, Handle, CancellationToken.None);

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/reset", UriKind.Relative),
            new { token, new_password = "too late" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>The page walks the same flow, with the token in a hidden field.</summary>
    /// <remarks>
    /// The token arrives in the URL because an email link has nowhere else to put it, and it does
    /// not stay there: a query string is written to access logs, kept in browser history, and sent
    /// in <c>Referer</c> - and this one is a live credential for the account.
    /// </remarks>
    [Fact]
    public async Task The_reset_page_carries_the_token_in_a_hidden_field_and_redeems_it()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        var token = TokenFrom(world.Mail.Sent[0]);
        var page = await fixture.Client.GetStringAsync(
            new Uri("/reset?token=" + Uri.EscapeDataString(token), UriKind.Relative));

        var form = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (Match match in HiddenField().Matches(page))
        {
            form[match.Groups[1].Value] = WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        Assert.Equal(token, form["token"]);
        Assert.Equal(2, form.Count);

        form["new"] = "battery staple stapler";
        form["confirm"] = "battery staple stapler";

        var posted = await fixture.Client.PostAsync(
            new Uri("/reset", UriKind.Relative), new FormUrlEncodedContent(form));

        Assert.Equal(HttpStatusCode.OK, posted.StatusCode);
        Assert.Contains(
            "password has been set", await posted.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    /// <summary>Drawing the form does not consume the link.</summary>
    /// <remarks>
    /// An email client that pre-fetches URLs must not silently destroy the reset it was delivering,
    /// and a person who opens the link and comes back after lunch should still find it working.
    /// </remarks>
    [Fact]
    public async Task Opening_the_reset_page_does_not_consume_the_link()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/forgot", UriKind.Relative), new { account = Handle });

        var token = TokenFrom(world.Mail.Sent[0]);
        var url = new Uri("/reset?token=" + Uri.EscapeDataString(token), UriKind.Relative);

        _ = await fixture.Client.GetStringAsync(url);
        _ = await fixture.Client.GetStringAsync(url);

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/reset", UriKind.Relative),
            new { token, new_password = "still works" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// An unknown link draws the form, and the refusal comes on submit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Deliberate, and a real cost worth stating.</b> The page cannot tell a live link from a
    /// dead one without redeeming it, and <c>IUserTokenStore</c> has no read that does not consume -
    /// on purpose, because a peek plus an act is two statements, and two concurrent presentations of
    /// one link would both pass the peek. So a person following a dead link types a password before
    /// being told, which is worse than being told immediately and much better than an email client's
    /// URL prefetch silently destroying the reset it was delivering.
    /// </para>
    /// <para>
    /// The refusal, when it comes, says the same thing for expired, used and never-issued. §7.3 -
    /// not the oracle <c>S-48</c> is about, because a token is 256 bits of CSPRNG output and there
    /// is nothing to enumerate.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task An_unknown_link_is_refused_on_submit_rather_than_on_arrival()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var page = await fixture.Client.GetStringAsync(
            new Uri("/reset?token=never-issued", UriKind.Relative));

        Assert.Contains("name=\"new\"", page, StringComparison.Ordinal);

        var form = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (Match match in HiddenField().Matches(page))
        {
            form[match.Groups[1].Value] = WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        form["new"] = "hopeful";
        form["confirm"] = "hopeful";

        var posted = await fixture.Client.PostAsync(
            new Uri("/reset", UriKind.Relative), new FormUrlEncodedContent(form));

        Assert.Contains(
            "no longer works", await posted.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    /// <summary>A link with no token at all is refused on arrival, since there is nothing to try.</summary>
    [Fact]
    public async Task A_link_with_no_token_is_refused_immediately()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        var page = await fixture.Client.GetStringAsync(new Uri("/reset", UriKind.Relative));

        Assert.Contains("no longer works", page, StringComparison.Ordinal);
        Assert.DoesNotContain("name=\"new\"", page, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────── E-41, E-44

    [Fact]
    public async Task A_verification_link_marks_the_address_proven()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Services.CreateScope().ServiceProvider
            .GetRequiredService<AccountRecovery>()
            .RequestEmailVerificationAsync(SubjectId.FromStorage(Subject), CancellationToken.None);

        var token = TokenFrom(Assert.Single(world.Mail.Sent));

        var page = await fixture.Client.GetStringAsync(
            new Uri("/verify-email?token=" + Uri.EscapeDataString(token), UriKind.Relative));

        Assert.Contains("confirmed as your address", page, StringComparison.Ordinal);

        var account = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);
        Assert.True(account!.EmailVerified);
    }

    /// <summary>
    /// A verification link stops working when the address changes under it.
    /// </summary>
    /// <remarks>
    /// The link proves control of the mailbox it was sent to and of nothing else. Somebody who asks
    /// for one, changes their address, then clicks the old link must not end up with the new address
    /// marked verified - that would be a way to have any address confirmed by proving control of a
    /// different one.
    /// </remarks>
    [Fact]
    public async Task A_verification_link_does_not_verify_an_address_it_was_not_sent_to()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Services.CreateScope().ServiceProvider
            .GetRequiredService<AccountRecovery>()
            .RequestEmailVerificationAsync(SubjectId.FromStorage(Subject), CancellationToken.None);

        var token = TokenFrom(Assert.Single(world.Mail.Sent));

        await world.Users.SetEmailAsync(
            SubjectId.FromStorage(Subject), "somebody-else@example.com", verified: false, CancellationToken.None);

        var page = await fixture.Client.GetStringAsync(
            new Uri("/verify-email?token=" + Uri.EscapeDataString(token), UriKind.Relative));

        Assert.Contains("no longer works", page, StringComparison.Ordinal);

        var account = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);
        Assert.False(account!.EmailVerified);
    }

    /// <summary>A verification link cannot be redeemed as a reset link.</summary>
    /// <remarks>
    /// The reason the purpose is stored on the token rather than inferred from which endpoint is
    /// asking. A verification mail goes to an address somebody typed, sometimes before anyone has
    /// proven it is theirs - so a link from it that could set the password would be a takeover
    /// primitive.
    /// </remarks>
    [Fact]
    public async Task A_verification_link_cannot_set_a_password()
    {
        var world = await StartAsync();
        await using var fixture = world.Fixture;

        await fixture.Services.CreateScope().ServiceProvider
            .GetRequiredService<AccountRecovery>()
            .RequestEmailVerificationAsync(SubjectId.FromStorage(Subject), CancellationToken.None);

        var token = TokenFrom(Assert.Single(world.Mail.Sent));
        var before = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);

        var response = await fixture.Client.PostAsJsonAsync(
            new Uri("/account/password/reset", UriKind.Relative),
            new { token, new_password = "takeover" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var after = await world.Users.FindBySubjectAsync(SubjectId.FromStorage(Subject), CancellationToken.None);
        Assert.Equal(before!.PasswordHash, after!.PasswordHash);
    }
}
