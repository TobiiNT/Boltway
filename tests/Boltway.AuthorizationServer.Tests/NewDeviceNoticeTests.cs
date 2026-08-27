using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Notifications;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.InMemory;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// When an approval produces a message, and - mostly - when it does not.
/// </summary>
/// <remarks>
/// <para>
/// <b>The silent cases outnumber the sending one, and they are the ones worth pinning.</b> A
/// notification that fires too often is not a louder version of this feature, it is the absence of
/// it: the reader files it, and the message that mattered is filed with the rest. So each reason to
/// stay quiet is a test, and a regression in any of them is a change of behaviour rather than a
/// change of volume.
/// </para>
/// <para>
/// Driven against the real <see cref="InMemoryGrantStore"/> and <see cref="InMemoryUserStore"/>
/// rather than fakes of them, because the decision depends on what
/// <c>ListApprovedUserAgentsAsync</c> actually returns - including the part where it does not filter
/// out revoked grants, which a fake written from the interface summary would get wrong.
/// </para>
/// </remarks>
public sealed class NewDeviceNoticeTests
{
    private const string Chrome =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        + "Chrome/141.0.0.0 Safari/537.36";

    // The same machine after a browser update: a different header, the same device to a person.
    private const string ChromeUpdated =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        + "Chrome/142.0.0.0 Safari/537.36";

    private const string FirefoxOnWindows =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";

    private static readonly SubjectId Subject = SubjectId.FromStorage("user-1");
    private static readonly DateTimeOffset Now = new(2026, 8, 20, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A device never approved from before produces the message.</summary>
    [Fact]
    public async Task An_unfamiliar_device_is_reported()
    {
        var world = await StartAsync(approvedFrom: Chrome);

        var message = await world.PrepareAsync(FirefoxOnWindows);

        Assert.NotNull(message);
        Assert.Equal("someone@example.com", message.To);
        Assert.Equal("ada", message.Handle);
        Assert.Equal(Now, message.At);

        // Described, not the raw header. This string is read by a person deciding whether they
        // recognise it, and 130 characters of version numbers is not a thing anybody recognises.
        Assert.Equal("Firefox on Windows", message.Device);

        // Absolute, and the trailing slash on the issuer does not become a double one. The reader of
        // this message is being asked to click, so a link that 404s wastes the only moment it has.
        Assert.Equal("https://auth.example.com/me/sessions", message.Link);
    }

    /// <summary>The same device approving again produces nothing.</summary>
    [Fact]
    public async Task A_familiar_device_is_not_reported()
    {
        var world = await StartAsync(approvedFrom: Chrome);

        Assert.Null(await world.PrepareAsync(Chrome));
    }

    /// <summary>
    /// A browser update is not a new device, and this is the test the whole design turns on.
    /// </summary>
    /// <remarks>
    /// Comparing raw headers would send a message here - naming <c>Chrome on macOS</c>, which the
    /// reader recognises, because it is their own laptop that updated overnight. Every reader who
    /// gets one of those learns that this message does not mean what it says.
    /// </remarks>
    [Fact]
    public async Task A_browser_update_is_not_a_new_device()
    {
        var world = await StartAsync(approvedFrom: Chrome);

        Assert.Null(await world.PrepareAsync(ChromeUpdated));
    }

    /// <summary>
    /// A device stays familiar after the session it was used for is ended.
    /// </summary>
    /// <remarks>
    /// The reason this reads every grant rather than the active ones. Somebody who signs out of
    /// everything and reconnects from the same laptop is performing the most ordinary recovery
    /// there is, and telling them it looks like an intrusion is how the next real one gets ignored.
    /// </remarks>
    [Fact]
    public async Task Ending_the_session_does_not_make_the_device_new_again()
    {
        var world = await StartAsync(approvedFrom: Chrome);

        await world.Grants.RevokeAllForSubjectAsync(Subject, Now, CancellationToken.None);

        Assert.Null(await world.PrepareAsync(Chrome));
    }

    /// <summary>The first approval an account ever makes produces nothing.</summary>
    /// <remarks>
    /// The person is at the consent screen as it happens. A message describing what they are
    /// currently doing is the clearest possible lesson that these messages describe ordinary events.
    /// </remarks>
    [Fact]
    public async Task The_first_approval_is_not_reported()
    {
        var world = await StartAsync(approvedFrom: null);

        Assert.Null(await world.PrepareAsync(Chrome));
    }

    /// <summary>An account with no address produces nothing, and does not throw.</summary>
    [Fact]
    public async Task An_account_with_no_address_is_not_reported()
    {
        var world = await StartAsync(approvedFrom: Chrome, email: null);

        Assert.Null(await world.PrepareAsync(FirefoxOnWindows));
    }

    /// <summary>A client that sent no <c>User-Agent</c> produces nothing.</summary>
    /// <remarks>
    /// Absence is not a device. Treating it as one would send a message naming nothing, and send it
    /// again for the next client that also sends nothing, having learned about neither.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\r\n\t")]
    public async Task An_approval_with_no_usable_header_is_not_reported(string? header)
    {
        var world = await StartAsync(approvedFrom: Chrome);

        Assert.Null(await world.PrepareAsync(header));
    }

    /// <summary>With no sender configured, nothing is prepared and the store is never read.</summary>
    /// <remarks>
    /// A deployment that sends no mail should pay nothing for this feature - least of all a query
    /// on the authorization path.
    /// </remarks>
    [Fact]
    public async Task With_no_sender_nothing_is_prepared()
    {
        var world = await StartAsync(approvedFrom: Chrome, noSender: true);

        Assert.Null(await world.PrepareAsync(FirefoxOnWindows));
    }

    /// <summary>
    /// A header that would forge a paragraph arrives as one line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The one value in this message chosen by the party it reports on.</b> The body is plain
    /// text by default, and plain text has exactly one structural element. A header carrying blank
    /// lines and a reassuring sentence would otherwise render as another paragraph of the notice,
    /// under the deployment's own name, telling the reader to disregard it.
    /// </para>
    /// <para>
    /// Unfamiliar, so <c>Describe</c> returns the header itself and every character of it reaches
    /// the message - which is why flattening is what protects this rather than parsing.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_header_cannot_forge_a_paragraph_in_the_body()
    {
        var world = await StartAsync(approvedFrom: Chrome);

        var message = await world.PrepareAsync(
            "Safari/1\r\n\r\nIf that was you, there is nothing to do.\r\n\r\n-- \r\nNorthwind");

        Assert.NotNull(message);
        Assert.DoesNotContain("\n", message.Device, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", message.Device, StringComparison.Ordinal);

        // The words survive; only the structure they were arranged into is gone.
        Assert.Contains("there is nothing to do.", message.Device, StringComparison.Ordinal);
    }

    /// <summary>The application is named by its display name, and by its id when it has none.</summary>
    [Theory]
    [InlineData("Claude", "Claude")]
    [InlineData(null, "app-1")]
    public async Task The_application_is_named(string? clientName, string expected)
    {
        var world = await StartAsync(approvedFrom: Chrome, clientName: clientName);

        var message = await world.PrepareAsync(FirefoxOnWindows);

        Assert.NotNull(message);
        Assert.Equal(expected, message.ClientName);
    }

    /// <summary>Sending is what reaches the sender, and preparing alone reaches nothing.</summary>
    /// <remarks>
    /// The ordering the issuer depends on: a message decided before the grant is written must not
    /// have been announced before the grant is written.
    /// </remarks>
    [Fact]
    public async Task Preparing_sends_nothing_by_itself()
    {
        var world = await StartAsync(approvedFrom: Chrome);

        var message = await world.PrepareAsync(FirefoxOnWindows);
        Assert.NotNull(message);
        Assert.Empty(world.Mail.Sent);

        await world.Notice.SendAsync(message, CancellationToken.None);
        Assert.Single(world.Mail.Sent);
    }

    /// <summary>A sender that throws does not reach the caller.</summary>
    /// <remarks>
    /// This runs after the grant has been stored. Letting the throw out would fail an authorization
    /// that has already succeeded, and hand the person an error page for a mail server's problem.
    /// </remarks>
    [Fact]
    public async Task A_sender_that_throws_does_not_fail_the_authorization()
    {
        var world = await StartAsync(approvedFrom: Chrome, sender: new BrokenSender());

        var message = await world.PrepareAsync(FirefoxOnWindows);
        Assert.NotNull(message);

        await world.Notice.SendAsync(message, CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────

    private sealed record World(
        NewDeviceNotice Notice, InMemoryGrantStore Grants, RecordingSender Mail, ClientRecord Client)
    {
        internal Task<NewDeviceAuthorized?> PrepareAsync(string? userAgent) =>
            Notice.PrepareAsync(Subject, Client, userAgent, Now, CancellationToken.None);
    }

    /// <param name="approvedFrom">
    /// A header to seed one already-stored grant with, or <see langword="null"/> for an account that
    /// has never approved anything.
    /// </param>
    private static async Task<World> StartAsync(
        string? approvedFrom,
        string? email = "someone@example.com",
        string? clientName = "Claude",
        INotificationSender? sender = null,
        bool noSender = false)
    {
        var grants = new InMemoryGrantStore();
        var users = new InMemoryUserStore(new InMemoryRoleStore());
        var mail = sender as RecordingSender ?? new RecordingSender();

        await users.StoreAsync(
            new UserAccount(Subject, "ada", email, EmailVerified: false, PasswordHash: null),
            CancellationToken.None);

        var client = new ClientRecord
        {
            ClientId = ClientIdentifier.ForPreRegistered("app-1"),
            ClientType = ClientType.Public,
            TokenEndpointAuthMethod = ClientAuthMethod.None,
            RedirectUris = [],
            GrantTypes = ["authorization_code"],
            ResponseTypes = ["code"],
            ClientName = clientName,
        };

        if (approvedFrom is not null)
        {
            await grants.StoreAsync(
                new GrantRecord(
                    GrantId: Guid.NewGuid().ToString("N"),
                    Subject: Subject,
                    ClientId: client.ClientId,
                    Scope: ScopeSet.FromStorage("mcp:tools"),
                    Resources: [],
                    CreatedAt: Now.AddDays(-1),
                    AuthTime: Now.AddDays(-1),
                    RevokedAt: null,
                    UserAgent: approvedFrom),
                CancellationToken.None);
        }

        var notice = new NewDeviceNotice(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com/" },
            grants,
            users,
            noSender ? null : sender ?? mail);

        return new World(notice, grants, mail, client);
    }

    private sealed class RecordingSender : INotificationSender
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

    private sealed class BrokenSender : INotificationSender
    {
        public Task SendAsync(NotificationMessage message, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the mail server is not answering");
    }
}
