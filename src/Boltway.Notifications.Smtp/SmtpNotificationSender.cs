using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Boltway.Notifications.Smtp;

/// <summary>How the connection to the mail server is secured.</summary>
/// <remarks>
/// One setting rather than two booleans. The pair it replaces — a port and a
/// <c>UseStartTls</c> flag — could express "465 with STARTTLS", which is not a thing any server
/// does, and could not express implicit TLS at all.
/// </remarks>
public enum SmtpSecurity
{
    /// <summary>Decide from the port: 465 is implicit TLS, anything else is STARTTLS.</summary>
    /// <remarks>
    /// The default, and the reason is that the port and the mechanism are not independent facts.
    /// RFC 8314 assigns 465 to implicit TLS and 587 to submission with STARTTLS, so a deployment
    /// that has said which port it uses has already said which mechanism, and asking again is
    /// asking it to repeat itself into a second setting that can disagree with the first.
    /// </remarks>
    Auto = 0,

    /// <summary>Connect in the clear, then require STARTTLS. Submission, port 587.</summary>
    StartTls,

    /// <summary>TLS from the first byte. Port 465, and what Cloudflare Email Service requires.</summary>
    ImplicitTls,

    /// <summary>No TLS. For a mail server on the same host and nothing else.</summary>
    None,
}

/// <summary>How to reach a mail server.</summary>
public sealed class SmtpNotificationOptions
{
    /// <summary>The mail server's hostname. Required.</summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>The port. 587 — submission with STARTTLS — rather than 25.</summary>
    /// <remarks>
    /// 25 is server-to-server relay and is blocked outbound by most hosting providers, so a
    /// deployment that leaves this alone gets the port that works.
    /// </remarks>
    public int Port { get; set; } = 587;

    /// <summary>How the connection is secured. Derived from <see cref="Port"/> by default.</summary>
    public SmtpSecurity Security { get; set; } = SmtpSecurity.Auto;

    /// <summary>The username to authenticate with, or null for a server that wants none.</summary>
    public string? Username { get; set; }

    /// <summary>The password. A long-lived credential of the deployment's own.</summary>
    public string? Password { get; set; }

    /// <summary>What the mail is from. Required.</summary>
    /// <remarks>
    /// A real, deliverable address rather than <c>no-reply@</c> where that can be helped: the reply
    /// to a password-reset mail is usually somebody saying "this was not me", which is the single
    /// most useful message a deployment can receive and the one <c>no-reply</c> discards.
    /// </remarks>
    public string From { get; set; } = string.Empty;

    /// <summary>The display name beside <see cref="From"/>.</summary>
    public string? FromName { get; set; }

    /// <summary>How long to wait for the server. Ten seconds.</summary>
    /// <remarks>
    /// Short, because the call happens on a request thread — see the class remarks. The cost of a
    /// timeout is a message that did not send and an operation that already succeeded; the cost of
    /// no timeout is a request held open for as long as somebody else's server feels like.
    /// </remarks>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>The socket options this configuration means.</summary>
    /// <remarks>
    /// <b><see cref="SecureSocketOptions.StartTls"/>, never
    /// <c>StartTlsWhenAvailable</c>.</b> The opportunistic variant falls back to plaintext against
    /// a server that does not advertise the extension, which is a credential sent in the clear
    /// decided by whoever is on the other end of the socket — including whoever is in the middle
    /// of it, since stripping the advertisement is the whole attack.
    /// </remarks>
    public SecureSocketOptions SocketOptions => Security switch
    {
        SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
        SmtpSecurity.ImplicitTls => SecureSocketOptions.SslOnConnect,
        SmtpSecurity.None => SecureSocketOptions.None,
        _ => Port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls,
    };
}

/// <summary>
/// <see cref="INotificationSender"/> over SMTP.
/// </summary>
/// <remarks>
/// <para>
/// <b>It sends inline, which means it holds a request thread for the length of an SMTP
/// conversation.</b> That is acceptable for the volume these flows produce — a password reset is
/// rare and a person is already waiting — and it is not acceptable for anything higher. A
/// deployment sending more than occasionally should put a queue behind
/// <see cref="INotificationSender"/> and make this the queue's worker. Said here because the
/// alternative is discovering it under load.
/// </para>
/// <para>
/// <b>Built on MailKit, and it used to be built on <c>System.Net.Mail.SmtpClient</c>.</b> The
/// argument for the base class library was that this package exists to keep a mail client out of
/// <c>Boltway.AuthorizationServer</c>, so it should not add a dependency of its own. What
/// settled it the other way is that <c>SmtpClient</c> cannot do implicit TLS at all — the old
/// remarks here said so, as a limitation nobody had hit — and Cloudflare Email Service offers
/// submission on 465 with implicit TLS and nothing else. A mail client that cannot talk to a mail
/// provider is not a smaller dependency, it is a missing feature with a footnote. MailKit is MIT,
/// which the licence rule requires, and it is what Microsoft's own obsoletion notice points at.
/// </para>
/// </remarks>
/// <param name="options">Where the mail server is.</param>
/// <param name="renderer">What the messages say.</param>
public sealed class SmtpNotificationSender(
    SmtpNotificationOptions options, INotificationRenderer renderer) : INotificationSender
{
    /// <inheritdoc />
    public async Task SendAsync(NotificationMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(renderer);

        if (string.IsNullOrWhiteSpace(options.Host) || string.IsNullOrWhiteSpace(options.From))
        {
            throw new InvalidOperationException(
                "SmtpNotificationOptions needs a Host and a From. Both are the deployment's, and "
                + "neither has a default this library could invent.");
        }

        var rendered = renderer.Render(message);

        var mail = new MimeMessage
        {
            Subject = rendered.Subject,
            Body = new TextPart(rendered.IsHtml ? "html" : "plain") { Text = rendered.Body },
        };

        mail.From.Add(new MailboxAddress(options.FromName, options.From));
        mail.To.Add(MailboxAddress.Parse(message.To));

        using var client = new SmtpClient { Timeout = (int)options.Timeout.TotalMilliseconds };

        await client.ConnectAsync(options.Host, options.Port, options.SocketOptions, cancellationToken)
            .ConfigureAwait(false);

        // A username and no password authenticates with an empty one, which is what the previous
        // client did through NetworkCredential and what a server asking for AUTH with no secret
        // expects. MailKit's signature is non-nullable, so the coalesce is the same behaviour
        // written down — the compiler noticing is how this difference surfaced at all.
        if (options.Username is { Length: > 0 })
        {
            await client
                .AuthenticateAsync(options.Username, options.Password ?? string.Empty, cancellationToken)
                .ConfigureAwait(false);
        }

        await client.SendAsync(mail, cancellationToken).ConfigureAwait(false);

        // QUIT rather than dropping the socket. A server that never sees it holds the connection
        // open to its own timeout, and some providers count those against a concurrency limit —
        // so the failure would arrive as refused connections during the next incident, not here.
        await client.DisconnectAsync(quit: true, cancellationToken).ConfigureAwait(false);
    }
}
