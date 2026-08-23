using Boltway.Notifications;

namespace Boltway.Notifications.Tests;

/// <summary>
/// The sentences the mail is made of.
/// </summary>
/// <remarks>
/// The gap these cover was live: a deployment with <c>UI_DEFAULT_LOCALE=vi</c> served every page in
/// Vietnamese and sent the password-reset mail in English, because the pages resolve through
/// <c>InteractionText</c> and the mail resolved through nothing at all.
/// </remarks>
public sealed class NotificationTextTests
{
    [Fact]
    public void Problems_checks_every_string_a_deployment_can_replace()
    {
        // The check-list was hand-maintained and had drifted: NewDeviceAuthorizedSubjectText and
        // NewDeviceAuthorizedBodyText were missing, and the body takes five arguments — the most of
        // any message here, so the likeliest to be mis-edited. What that costs is narrow and bad:
        // Problems() is why a host refuses to start rather than failing to deliver mail, and for
        // the one message that is a security alert the bad translation instead fell back to English
        // at send time with nothing reporting it.
        //
        // Reflection rather than a second list, so adding a message cannot repeat this: a property
        // nothing checks reports no problem, and this goes red.
        var properties = typeof(NotificationText)
            .GetProperties()
            .Where(p => p.PropertyType == typeof(string) && p.CanWrite)
            .ToList();

        Assert.NotEmpty(properties);

        var unchecked_ = new List<string>();

        foreach (var property in properties)
        {
            // A placeholder no caller can supply. Every check renders with fewer arguments than
            // this, so a property that is checked at all reports a problem, and one that is not
            // reports nothing.
            var broken = new NotificationText();
            property.SetValue(broken, "sentinel {9}");

            if (!broken.Problems().Any(p => p.StartsWith(property.Name, StringComparison.Ordinal)))
            {
                unchecked_.Add(property.Name);
            }
        }

        Assert.True(
            unchecked_.Count == 0,
            "Problems() does not check these, so a deployment can break them and start anyway: "
            + string.Join(", ", unchecked_));
    }

    private static readonly DateTimeOffset At =
        new(2026, 8, 12, 7, 37, 0, TimeSpan.Zero);

    private static RenderedNotification Reset(NotificationText? text = null) =>
        new DefaultNotificationRenderer(text ?? new NotificationText())
            .Render(new ResetPassword("https://auth.example.com/reset?token=x", At)
            {
                To = "someone@example.com",
                Handle = "ada",
            });

    [Fact]
    public void Unconfigured_is_the_English_it_always_was()
    {
        var mail = Reset();

        Assert.Equal("Reset your password", mail.Subject);
        Assert.Contains("Hello ada,", mail.Body, StringComparison.Ordinal);
        Assert.Contains("https://auth.example.com/reset?token=x", mail.Body, StringComparison.Ordinal);
        Assert.Contains("2026-08-12 07:37 UTC", mail.Body, StringComparison.Ordinal);
        Assert.False(mail.IsHtml);
    }

    /// <summary>The whole point.</summary>
    [Fact]
    public void A_deployments_own_words_reach_the_reader()
    {
        var mail = Reset(new NotificationText
        {
            ResetPasswordSubjectText = "Đặt lại mật khẩu",
            ResetPasswordBodyText = "Chào {0},\n\nMở liên kết này: {1}\n\nHết hạn lúc {2}.",
        });

        Assert.Equal("Đặt lại mật khẩu", mail.Subject);
        Assert.StartsWith("Chào ada,", mail.Body, StringComparison.Ordinal);
        Assert.Contains("https://auth.example.com/reset?token=x", mail.Body, StringComparison.Ordinal);
        Assert.Contains("2026-08-12 07:37 UTC", mail.Body, StringComparison.Ordinal);
    }

    /// <summary>
    /// A record and not a dictionary, so half a translation is half a translation.
    /// </summary>
    [Fact]
    public void An_unset_sentence_stays_English()
    {
        var mail = Reset(new NotificationText { ResetPasswordSubjectText = "Đặt lại mật khẩu" });

        Assert.Equal("Đặt lại mật khẩu", mail.Subject);
        Assert.Contains("Hello ada,", mail.Body, StringComparison.Ordinal);
    }

    /// <summary>
    /// The timestamp is not a sentence, so a translation cannot change what a date means.
    /// </summary>
    [Fact]
    public void The_timestamp_is_not_translatable()
    {
        var mail = Reset(new NotificationText { ResetPasswordBodyText = "{2}" });

        Assert.Equal("2026-08-12 07:37 UTC", mail.Body);
    }

    /// <summary>Zero sessions is no line at all, not a blank one.</summary>
    [Theory]
    [InlineData(0, "")]
    [InlineData(1, "One session was ended at the same time.")]
    [InlineData(4, "4 sessions were ended at the same time.")]
    public void The_sessions_line_appears_only_when_there_were_sessions(int revoked, string expected)
    {
        var mail = new DefaultNotificationRenderer()
            .Render(new PasswordChanged(At, revoked) { To = "someone@example.com", Handle = "ada" });

        if (expected.Length == 0)
        {
            Assert.DoesNotContain("ended at the same time", mail.Body, StringComparison.Ordinal);
            Assert.DoesNotContain("\n\n\n", mail.Body, StringComparison.Ordinal);
        }
        else
        {
            Assert.Contains(expected, mail.Body, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A sentence that cannot render is named at startup, not discovered when somebody is waiting.
    /// </summary>
    /// <remarks>
    /// The sender catches and logs a failed send by design — throwing would turn "your password was
    /// reset and we could not tell you" into "your password was not reset". So a broken template
    /// produces a mail that silently never arrives, on the one flow where not arriving is the whole
    /// problem. <c>Problems()</c> is what lets a host refuse instead.
    /// </remarks>
    [Fact]
    public void A_placeholder_the_message_does_not_supply_is_reported()
    {
        var problems = new NotificationText { ResetPasswordBodyText = "Chào {0}, {7}" }.Problems();

        Assert.Single(problems);
        Assert.Contains(nameof(NotificationText.ResetPasswordBodyText), problems[0], StringComparison.Ordinal);
    }

    /// <summary>And the shipped English has none.</summary>
    [Fact]
    public void The_defaults_render()
    {
        Assert.Empty(new NotificationText().Problems());
    }

    /// <summary>
    /// A broken sentence still sends, in English, rather than throwing at the reader.
    /// </summary>
    /// <remarks>
    /// The startup check is the place to refuse. If one gets past it — a host that never called
    /// <c>Problems()</c> — the fallback keeps the mail arriving, because an English reset link is
    /// worth more than a correctly-translated silence.
    /// </remarks>
    [Fact]
    public void A_broken_sentence_falls_back_rather_than_throwing()
    {
        var mail = Reset(new NotificationText { ResetPasswordBodyText = "Chào {0}, {7}" });

        Assert.Contains("Hello ada,", mail.Body, StringComparison.Ordinal);
    }
}
