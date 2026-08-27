using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Boltway.Notifications;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>
/// Tells an account holder when an application was authorized from somewhere they have not
/// approved from before.
/// </summary>
/// <remarks>
/// <para>
/// <b>The gap this closes.</b> An attacker who can complete a sign-in can authorize an application
/// and hold access for as long as the grant lives, and every surface that would reveal it is one
/// the account holder has to think to visit. The sessions page answers the question; nothing was
/// asking it. <see cref="NewDeviceAuthorized"/> records the rest of the reasoning, including what
/// this deliberately does not catch.
/// </para>
/// <para>
/// <b>Two methods because the ordering is the correctness.</b> <see cref="PrepareAsync"/> runs
/// before the grant is written and <see cref="SendAsync"/> after. Read afterwards and the grant
/// just written is in its own history, so every device is familiar and no message is ever sent -
/// a feature that is green, silent and useless, which is the failure this codebase keeps finding.
/// Sending before the write would announce an authorization that may not land.
/// </para>
/// <para>
/// <b>Nothing here may fail an authorization.</b> A person is mid-flow at a consent screen; a
/// directory that is slow or a mail server that is down must not turn that into an error page. The
/// send is wrapped for the same reason <c>AccountRecovery</c> wraps its own, and the read is
/// wrapped too, which that one has no need to do - it runs before the operation rather than after,
/// so a throw would reach the caller instead of a log line.
/// </para>
/// </remarks>
public sealed class NewDeviceNotice(
    AuthorizationServerOptions server,
    IGrantStore grants,
    IUserStore? users = null,
    INotificationSender? notifications = null,
    ILogger<NewDeviceNotice>? logger = null)
{
    private readonly AuthorizationServerOptions _server =
        server ?? throw new ArgumentNullException(nameof(server));

    private readonly IGrantStore _grants = grants ?? throw new ArgumentNullException(nameof(grants));

    // Optional, unlike the grant store. A server issuing only client credentials registers no
    // directory, and resolving one that is not there would fail the authorization path for a
    // notification - the tail wagging the request.
    private readonly IUserStore? _users = users;

    /// <summary>
    /// Decide whether this approval deserves a message, before the grant it describes is stored.
    /// </summary>
    /// <param name="subject">Who approved.</param>
    /// <param name="client">What they approved.</param>
    /// <param name="userAgent">The header this approval arrived with, or <see langword="null"/>.</param>
    /// <param name="at">When.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The message to send once the grant has landed, or <see langword="null"/>.</returns>
    /// <remarks>
    /// <para>
    /// <b>Every reason to say nothing is checked before the reason to say something.</b> A
    /// deployment with no sender, a client sending no <c>User-Agent</c>, an account with no address:
    /// each of those means no message can be sent, and each is settled without reading the store,
    /// because this is on the authorization path.
    /// </para>
    /// <para>
    /// <b>A first approval is not a new device.</b> An account whose history is empty is one
    /// approving for the first time, and the person doing it is looking at the consent screen. A
    /// message telling them what they are in the middle of doing teaches them that this notice
    /// describes ordinary events.
    /// </para>
    /// </remarks>
    public async Task<NewDeviceAuthorized?> PrepareAsync(
        SubjectId subject,
        ClientRecord client,
        string? userAgent,
        DateTimeOffset at,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        if (notifications is null || _users is null)
        {
            return null;
        }

        // Described before anything is compared, because the description is what is compared. A
        // header that describes to nothing - absent, blank, or control characters only - cannot be
        // told apart from any other such header, so it can never be evidence of a new device.
        if (ApprovingDevice.DescribeOnOneLine(userAgent) is not { } device)
        {
            return null;
        }

        try
        {
            var account = await _users.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false);

            // Sent to an address that has not been verified, the same as PasswordChanged. Gating on
            // verification would mean the accounts least likely to be watched are the ones that get
            // no security mail at all, and silence is the failure this exists to remove.
            if (account?.Email is not { Length: > 0 } address)
            {
                return null;
            }

            var known = await _grants.ListApprovedUserAgentsAsync(subject, cancellationToken)
                .ConfigureAwait(false);

            // Nothing approved before: this is the first, and the person is watching it happen.
            if (known.Count == 0)
            {
                return null;
            }

            // Compared as descriptions on both sides - see ListApprovedUserAgentsAsync for why the
            // store holds headers and this holds the comparison. Ordinal: these are two renderings
            // of the same parser's output, so anything but an exact match is a different device.
            var familiar = known
                .Select(ApprovingDevice.DescribeOnOneLine)
                .Any(described => string.Equals(described, device, StringComparison.Ordinal));

            return familiar
                ? null
                : new NewDeviceAuthorized(at, Name(client), device, Sessions())
                {
                    To = address,
                    Handle = account.Username,
                };
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            // The authorization is not this method's to fail. A person at a consent screen has no
            // way to act on "the directory was slow", and the grant they are approving is valid
            // whether or not anybody could be told about it.
            logger?.LogError(
                failure,
                "Could not work out whether this approval came from a new device. The authorization "
                + "is unaffected and no notification will be sent for it.");

            return null;
        }
    }

    /// <summary>Send what <see cref="PrepareAsync"/> decided on, once the grant has been stored.</summary>
    /// <param name="message">What it returned.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task SendAsync(NewDeviceAuthorized message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (notifications is null)
        {
            return;
        }

        try
        {
            await notifications.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            // The message type and nothing off the message: the address is personal data and the
            // device came from a header somebody chose. AccountRecovery.SendAsync says the same.
            logger?.LogError(
                failure,
                "Could not send a {Notification} notification. The authorization it describes has "
                + "already completed.",
                message.GetType().Name);
        }
    }

    /// <summary>
    /// What to call the application in a sentence a person reads.
    /// </summary>
    /// <remarks>
    /// The registered name when there is one, and the client id when there is not. The id is worse
    /// to read and better than a blank: this message exists to be recognised or not recognised, and
    /// an empty field can be neither. Chosen here rather than in the sender for the reason
    /// <c>VerifyEmail.Link</c> is: a sender resolving a client id would be a second path to the
    /// client store.
    /// </remarks>
    /// <summary>The absolute address of the sessions page.</summary>
    /// <remarks>
    /// Built the way <c>AccountRecovery</c> builds its links - issuer plus path - because a route
    /// this server serves is this server's to name. It carries no token: see
    /// <see cref="NewDeviceAuthorized"/>.
    /// </remarks>
    private string Sessions() =>
        _server.Issuer!.TrimEnd('/') + AuthorizationServerPaths.MeSessions;

    private static string Name(ClientRecord client) =>
        client.ClientName is { Length: > 0 } name ? name : client.ClientId.Value;
}
