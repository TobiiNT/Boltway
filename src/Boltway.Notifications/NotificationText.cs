using System.Globalization;

namespace Boltway.Notifications;

/// <summary>
/// The sentences the shipped notifications are made of, and the only ones a deployment may change.
/// </summary>
/// <remarks>
/// <para>
/// The pages a person signs in on can be translated, and until this existed the mail they receive
/// could not. Measured on a running deployment: every page came out in Vietnamese and the reset mail
/// arrived in English - <i>"Hello ada, Somebody asked to reset the password for this account"</i>
/// - which is the message somebody reads while they are locked out and least able to work past a
/// language they do not use.
/// </para>
/// <para>
/// <b>One set of sentences per deployment, not one per request culture, and that is deliberate.</b>
/// <c>InteractionText</c> is resolved through <c>IStringLocalizer</c> because a page is rendered for
/// the person reading it, and the request says who that is. A notification is not: the culture in
/// scope when <c>PasswordChanged</c> is sent belongs to whoever *caused* it, which for an operator's
/// reset is a different person from the recipient, and no account here carries a language. So
/// per-request culture would be right about as often as it was wrong, silently. A deployment whose
/// people share a language says so once; one whose people do not needs a per-recipient preference
/// this library does not have, and should replace <see cref="INotificationRenderer"/>.
/// </para>
/// <para>
/// <b>A record with defaults, not a dictionary.</b> A dictionary can be half-filled by a deploy, and
/// a password-reset mail with an empty body is worse than an English one. Every property here has an
/// English value, binding leaves an unset one alone, and a partial translation is partial rather
/// than blank.
/// </para>
/// <para>
/// <b>Whole messages, not fragments.</b> A letter is not assembled from sentences in English order;
/// a translator needs to move a paragraph, and splitting a body into six keys prevents that. The one
/// exception is the sessions line, which is a whole sentence that is sometimes absent - see
/// <see cref="PasswordChangedOneSessionText"/>.
/// </para>
/// <para>
/// <b>Plain text, and nothing here is encoded.</b> These strings become the body of a mail, so there
/// is no markup to escape and escaping would put <c>&amp;amp;</c> in front of a reader. That is the
/// difference from <c>InteractionText</c>, which encodes because its output lands in HTML.
/// </para>
/// </remarks>
public sealed record NotificationText
{
    /// <summary>The English text, for the fallback in <see cref="Format"/>.</summary>
    private static readonly NotificationText Defaults = new();

    /// <summary>
    /// Whether a broken sentence throws instead of falling back. Only <see cref="Problems"/> sets it.
    /// </summary>
    /// <remarks>
    /// Without it the validation is a no-op that reads like a check: <see cref="Problems"/> renders
    /// through the same path the sender does, and that path swallows <see cref="FormatException"/>
    /// by design.
    /// </remarks>
    private bool Strict { get; init; }

    /// <summary>Subject of the address-confirmation mail.</summary>
    public string VerifyEmailSubjectText { get; init; } = "Confirm your email address";

    /// <summary>
    /// Body of the address-confirmation mail. <c>{0}</c> handle, <c>{1}</c> link, <c>{2}</c> expiry.
    /// </summary>
    public string VerifyEmailBodyText { get; init; } =
        """
        Hello {0},

        Please confirm this address belongs to you by opening this link:

        {1}

        The link stops working at {2}.

        If you did not expect this, you can ignore it. Nothing changes unless the link is
        opened.
        """;

    /// <summary>Subject of the password-reset mail.</summary>
    public string ResetPasswordSubjectText { get; init; } = "Reset your password";

    /// <summary>
    /// Body of the password-reset mail. <c>{0}</c> handle, <c>{1}</c> link, <c>{2}</c> expiry.
    /// </summary>
    /// <remarks>
    /// The last paragraph is the load-bearing one and a translation should keep what it does: it
    /// tells somebody who did not ask for this that they need do nothing, and says why that is safe
    /// rather than only asserting it. A reset mail that says "if this was not you, contact support"
    /// turns every phishing simulation into a support ticket.
    /// </remarks>
    public string ResetPasswordBodyText { get; init; } =
        """
        Hello {0},

        Somebody asked to reset the password for this account. To choose a new one, open
        this link:

        {1}

        The link stops working at {2}, and it can only be used once.

        If it was not you, you do not need to do anything: your password has not changed
        and this link is the only way it could, so ignoring this message leaves the account
        exactly as it is.
        """;

    /// <summary>Subject of the password-changed notice.</summary>
    public string PasswordChangedSubjectText { get; init; } = "Your password was changed";

    /// <summary>
    /// Body of the password-changed notice. <c>{0}</c> handle, <c>{1}</c> when, <c>{2}</c> the
    /// sessions line, which is empty when none were ended and carries its own leading newline.
    /// </summary>
    /// <remarks>
    /// Says what to do rather than only what happened. Somebody reading this who did not change
    /// their password is reading it at the one moment when being told where to go is worth more
    /// than being told what went wrong.
    /// </remarks>
    public string PasswordChangedBodyText { get; init; } =
        """
        Hello {0},

        The password for this account was changed at {1}.{2}

        If that was you, there is nothing to do.

        If it was not, somebody else has access to this account. Reset the password
        immediately and then sign out of every session.
        """;

    /// <summary>One session ended. Carries its own leading newline.</summary>
    /// <remarks>
    /// The newline belongs to the sentence rather than to the body template, because zero is the
    /// ordinary case and a template with the break in it left a stray blank line in every message
    /// where nothing was revoked. Measured in a delivered message.
    /// </remarks>
    public string PasswordChangedOneSessionText { get; init; } =
        "\nOne session was ended at the same time.";

    /// <summary>Several sessions ended. <c>{0}</c> is the count. Carries its own leading newline.</summary>
    public string PasswordChangedManySessionsText { get; init; } =
        "\n{0} sessions were ended at the same time.";

    /// <summary>Subject of the new-device notice.</summary>
    /// <remarks>
    /// Says what happened rather than asking a question. A subject line ending in a question mark
    /// reads like the thing it is warning about, and this one has to survive being seen on a lock
    /// screen next to a dozen others.
    /// </remarks>
    public string NewDeviceAuthorizedSubjectText { get; init; } =
        "An application was authorized from a new device";

    /// <summary>
    /// Body of the new-device notice. <c>{0}</c> handle, <c>{1}</c> when, <c>{2}</c> the
    /// application, <c>{3}</c> the device, <c>{4}</c> the sessions page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What it does not claim.</b> Not "somebody signed in" - an approval is a sign-in that also
    /// granted an application access, and a reader told the smaller thing would go and change their
    /// password while the grant kept working. The two instructions are therefore both here and in
    /// that order: end the access first, because that is the one this message is about.
    /// </para>
    /// <para>
    /// <b>The device is the last field on purpose.</b> It is the one value here that the party being
    /// reported on chose, so it sits after every sentence this deployment wrote rather than inside
    /// one, where a carefully composed header would read as the server talking.
    /// </para>
    /// </remarks>
    public string NewDeviceAuthorizedBodyText { get; init; } =
        """
        Hello {0},

        At {1}, an application was authorized to use this account:

          Application: {2}
          Device:      {3}

        If that was you, there is nothing to do.

        If it was not, somebody else can sign in as you. Open your sessions page and press
        "None of this was me", then change your password — in that order, because ending the
        sessions is what stops the access that was already granted.

          {4}
        """;

    /// <summary>The subject and body for one message.</summary>
    internal RenderedNotification Render(NotificationMessage message, string expiryOrWhen, string? link)
    {
        ArgumentNullException.ThrowIfNull(message);

        var handle = message.Handle ?? string.Empty;

        return message switch
        {
            VerifyEmail => new RenderedNotification(
                Format(VerifyEmailSubjectText, Defaults.VerifyEmailSubjectText),
                Format(VerifyEmailBodyText, Defaults.VerifyEmailBodyText, handle, link ?? string.Empty, expiryOrWhen)),

            ResetPassword => new RenderedNotification(
                Format(ResetPasswordSubjectText, Defaults.ResetPasswordSubjectText),
                Format(ResetPasswordBodyText, Defaults.ResetPasswordBodyText, handle, link ?? string.Empty, expiryOrWhen)),

            PasswordChanged changed => new RenderedNotification(
                Format(PasswordChangedSubjectText, Defaults.PasswordChangedSubjectText),
                Format(
                    PasswordChangedBodyText,
                    Defaults.PasswordChangedBodyText,
                    handle,
                    expiryOrWhen,
                    Sessions(changed.SessionsRevoked))),

            NewDeviceAuthorized device => new RenderedNotification(
                Format(NewDeviceAuthorizedSubjectText, Defaults.NewDeviceAuthorizedSubjectText),
                Format(
                    NewDeviceAuthorizedBodyText,
                    Defaults.NewDeviceAuthorizedBodyText,
                    handle,
                    expiryOrWhen,
                    device.ClientName,
                    device.Device,
                    link ?? string.Empty)),

            _ => throw new ArgumentOutOfRangeException(
                nameof(message),
                // The type name, and nothing off the message: this string is logged.
                message.GetType().Name,
                "No rendering for this notification. A message was added to Boltway."
                + "Notifications without one here."),
        };
    }

    /// <summary>The sessions line, or nothing at all.</summary>
    private string Sessions(int revoked) => revoked switch
    {
        0 => string.Empty,
        1 => Format(PasswordChangedOneSessionText, Defaults.PasswordChangedOneSessionText),
        _ => Format(
            PasswordChangedManySessionsText,
            Defaults.PasswordChangedManySessionsText,
            revoked.ToString(CultureInfo.InvariantCulture)),
    };

    /// <summary>
    /// Every sentence that will not render, named by its property.
    /// </summary>
    /// <remarks>
    /// A configured string with a placeholder the message does not supply - a stray <c>{3}</c>, or
    /// <c>{0}</c> in a subject that takes none - throws <see cref="FormatException"/> at
    /// <see cref="string.Format(IFormatProvider, string, object?[])"/>. Left to the sender, that
    /// surfaces as a caught-and-logged failure at the moment somebody is waiting for a reset link,
    /// and the message they needed silently does not arrive. A host calls this at startup instead
    /// and refuses to run, which is the same trade every other configuration check here makes.
    /// </remarks>
    public IReadOnlyList<string> Problems()
    {
        var strict = this with { Strict = true };

        (string Property, Func<string> Render)[] checks =
        [
            (nameof(VerifyEmailSubjectText), () => strict.Format(strict.VerifyEmailSubjectText, "")),
            (nameof(VerifyEmailBodyText), () => strict.Format(strict.VerifyEmailBodyText, "", "a", "b", "c")),
            (nameof(ResetPasswordSubjectText), () => strict.Format(strict.ResetPasswordSubjectText, "")),
            (nameof(ResetPasswordBodyText), () => strict.Format(strict.ResetPasswordBodyText, "", "a", "b", "c")),
            (nameof(PasswordChangedSubjectText), () => strict.Format(strict.PasswordChangedSubjectText, "")),
            (nameof(PasswordChangedBodyText), () => strict.Format(strict.PasswordChangedBodyText, "", "a", "b", "c")),
            (nameof(PasswordChangedOneSessionText), () => strict.Format(strict.PasswordChangedOneSessionText, "")),
            (nameof(PasswordChangedManySessionsText), () => strict.Format(strict.PasswordChangedManySessionsText, "", "2")),
            (nameof(NewDeviceAuthorizedSubjectText), () => strict.Format(strict.NewDeviceAuthorizedSubjectText, "")),
            (nameof(NewDeviceAuthorizedBodyText),
                () => strict.Format(strict.NewDeviceAuthorizedBodyText, "", "a", "b", "c", "d", "e")),
        ];

        var problems = new List<string>();

        foreach (var (property, render) in checks)
        {
            try
            {
                render();
            }
            catch (FormatException failure)
            {
                problems.Add($"{property}: {failure.Message}");
            }
        }

        return problems;
    }

    /// <summary>The configured sentence, or English if it will not render.</summary>
    private string Format(string configured, string fallback, params string[] arguments)
    {
        if (Strict)
        {
            return string.Format(CultureInfo.InvariantCulture, configured, arguments);
        }

        try
        {
            return string.Format(CultureInfo.InvariantCulture, configured, arguments);
        }
        catch (FormatException)
        {
            return string.Format(CultureInfo.InvariantCulture, fallback, arguments);
        }
    }
}
