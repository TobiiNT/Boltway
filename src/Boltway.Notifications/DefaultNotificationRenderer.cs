using System.Globalization;

namespace Boltway.Notifications;

/// <summary>
/// English, plain text, and deliberately plain.
/// </summary>
/// <remarks>
/// <para>
/// It exists so that a deployment turning on the email flows gets working mail rather than a
/// <c>NullReferenceException</c>, and it is written to be obviously replaceable: no branding, no
/// signature, no HTML. A product's voice is not something a library can supply, and one that tried
/// would be shipping one customer's tone to every other customer.
/// </para>
/// <para>
/// <b>Plain text on purpose, not as a simplification.</b> A password-reset mail is the message a
/// phishing kit imitates most, and an HTML body trains the recipient to click a styled button
/// whose target they cannot see. A visible URL is one a person can read before they follow it.
/// </para>
/// <para>
/// <b>No token, no address and no link in any exception this can throw</b>, because the caller logs
/// what it catches, and a reset link in a log file is a live credential in a place with different
/// access rules from the mailbox it was meant for.
/// </para>
/// </remarks>
public sealed class DefaultNotificationRenderer : INotificationRenderer
{
    private readonly NotificationText _text;

    /// <summary>The English messages.</summary>
    public DefaultNotificationRenderer()
        : this(new NotificationText())
    {
    }

    /// <summary>The messages, in a deployment's own words.</summary>
    /// <param name="text">
    /// The sentences. Anything left unset stays English, per property - see
    /// <see cref="NotificationText"/> for why that is a record rather than a dictionary.
    /// </param>
    public DefaultNotificationRenderer(NotificationText text)
    {
        ArgumentNullException.ThrowIfNull(text);

        _text = text;
    }

    /// <inheritdoc />
    public RenderedNotification Render(NotificationMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        // The two facts the templates need that only this class knows how to write: when, and
        // where. Formatted here rather than in NotificationText, because a timestamp is not a
        // sentence and a deployment translating its mail should not be able to change what a date
        // means.
        return message switch
        {
            VerifyEmail verify => _text.Render(verify, Utc(verify.ExpiresAt), verify.Link),
            ResetPassword reset => _text.Render(reset, Utc(reset.ExpiresAt), reset.Link),
            PasswordChanged changed => _text.Render(changed, Utc(changed.At), link: null),
            NewDeviceAuthorized device => _text.Render(device, Utc(device.At), device.Link),

            _ => throw new ArgumentOutOfRangeException(
                nameof(message),
                // The type name, and nothing off the message: this string is logged.
                message.GetType().Name,
                "No rendering for this notification. A message was added to Boltway."
                + "Notifications without one here."),
        };
    }

    /// <summary>
    /// A timestamp a person in any timezone can act on.
    /// </summary>
    /// <remarks>
    /// UTC and named as such, rather than the server's local time, which is a fact about where the
    /// container runs and about nothing the reader knows.
    /// </remarks>
    private static string Utc(DateTimeOffset at) =>
        at.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
}
