using Boltway.Notifications.Smtp;
using MailKit.Security;

namespace Boltway.Notifications.Tests;

/// <summary>
/// Which TLS mechanism a configuration means.
/// </summary>
/// <remarks>
/// <para>
/// This decides whether an SMTP password goes onto the wire encrypted, so the interesting rows are
/// the ones where a plausible configuration could silently resolve to plaintext.
/// </para>
/// <para>
/// The setting it replaced was a boolean, and the reason it had to go is the last row here: there
/// was no value of <c>UseStartTls</c> that produced implicit TLS, so there was no way to configure
/// this against a provider offering 465 and nothing else.
/// </para>
/// </remarks>
public sealed class SmtpSecurityTests
{
    private static SmtpNotificationOptions Options(int port, SmtpSecurity security) =>
        new() { Host = "mail.example.com", From = "hello@example.com", Port = port, Security = security };

    /// <summary>
    /// Unset reads the port, so a deployment names one thing and gets the mechanism that goes
    /// with it.
    /// </summary>
    [Theory]
    [InlineData(587, SecureSocketOptions.StartTls)]
    [InlineData(25, SecureSocketOptions.StartTls)]
    [InlineData(2525, SecureSocketOptions.StartTls)]
    [InlineData(465, SecureSocketOptions.SslOnConnect)]
    public void Auto_reads_the_port(int port, SecureSocketOptions expected) =>
        Assert.Equal(expected, Options(port, SmtpSecurity.Auto).SocketOptions);

    /// <summary>The default is Auto, so an options object nobody configured behaves the same way.</summary>
    [Fact]
    public void Auto_is_the_default()
    {
        var options = new SmtpNotificationOptions { Host = "mail.example.com", From = "a@example.com" };

        Assert.Equal(SmtpSecurity.Auto, options.Security);
        Assert.Equal(587, options.Port);
        Assert.Equal(SecureSocketOptions.StartTls, options.SocketOptions);
    }

    /// <summary>An explicit choice wins, including one that disagrees with the port.</summary>
    /// <remarks>
    /// Deliberately not validated against the port. A provider on a non-standard port is a real
    /// deployment, and refusing it would trade a rare misconfiguration for a configuration that
    /// cannot be expressed at all.
    /// </remarks>
    [Theory]
    [InlineData(587, SmtpSecurity.ImplicitTls, SecureSocketOptions.SslOnConnect)]
    [InlineData(465, SmtpSecurity.StartTls, SecureSocketOptions.StartTls)]
    [InlineData(1025, SmtpSecurity.None, SecureSocketOptions.None)]
    public void An_explicit_choice_wins(int port, SmtpSecurity security, SecureSocketOptions expected) =>
        Assert.Equal(expected, Options(port, security).SocketOptions);

    /// <summary>
    /// STARTTLS is the mandatory variant, never the opportunistic one.
    /// </summary>
    /// <remarks>
    /// <c>StartTlsWhenAvailable</c> falls back to plaintext against a server that does not
    /// advertise the extension — and stripping that advertisement is the whole attack, so the
    /// fallback is chosen by whoever is in the middle of the socket. The assertion is written
    /// against the exact enum member rather than "not None" because the difference between the two
    /// StartTls values is the entire point.
    /// </remarks>
    [Fact]
    public void Starttls_is_required_rather_than_opportunistic()
    {
        Assert.Equal(SecureSocketOptions.StartTls, Options(587, SmtpSecurity.StartTls).SocketOptions);
        Assert.Equal(SecureSocketOptions.StartTls, Options(587, SmtpSecurity.Auto).SocketOptions);

        Assert.NotEqual(
            SecureSocketOptions.StartTlsWhenAvailable, Options(587, SmtpSecurity.Auto).SocketOptions);
    }

    /// <summary>
    /// Cloudflare Email Service, which is why this whole seam changed shape.
    /// </summary>
    /// <remarks>
    /// It offers submission on 465 with implicit TLS and nothing else — no STARTTLS on 587, no
    /// plaintext on 25 — so this row is the one the old boolean could not reach with any value.
    /// </remarks>
    [Fact]
    public void Cloudflare_needs_nothing_but_the_port()
    {
        var options = new SmtpNotificationOptions
        {
            Host = "smtp.cloudflare.com",
            From = "hello@example.com",
            Port = 465,
        };

        Assert.Equal(SecureSocketOptions.SslOnConnect, options.SocketOptions);
    }
}
