using System.Globalization;
using System.Security.Claims;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// Refuses a session cookie that was issued before the account said its sessions stopped counting.
/// </summary>
/// <remarks>
/// <para>
/// <b>Without this, nothing a person can do ends somebody else's browser session.</b> The cookie is
/// self-contained, so there was no list to revoke from: changing the password left every browser
/// already holding one signed in, and so did ending every application's access. Those are the two
/// controls somebody reaches for when they believe another party is in their account, and both left
/// that party able to sign a new application in the moment the page finished loading.
/// </para>
/// <para>
/// <b>It compares <c>auth_time</c>, not the ticket's issue time, and the difference is the whole
/// mechanism.</b> With sliding expiration the cookie handler rewrites <c>IssuedUtc</c> on every
/// renewal, so a session in daily use climbs forward and would never fall behind a stamp — the
/// sessions this is for are exactly the ones being used. <c>CookieUserSignIn</c> writes
/// <c>auth_time</c> once, as a claim, and claims survive renewal.
/// </para>
/// <para>
/// <b>Fails open, on the precedent this repository already set for revocation.</b> A store that
/// cannot be read leaves the session alone rather than signing everybody out: an outage that logs
/// out every user is a worse day than one that leaves a window open, and the window it leaves is
/// the one that existed before this class. Every fail-open is a warning, for the reason
/// <c>ResourceServerMetrics</c> gives about a risk nobody is counting.
/// </para>
/// </remarks>
public sealed partial class SessionRevalidation(
    IUserStore users,
    AuthorizationServerOptions options,
    TimeProvider timeProvider,
    ILogger<SessionRevalidation>? logger = null)
{
    /// <summary>
    /// Where the last check's time is kept, inside the ticket.
    /// </summary>
    /// <remarks>
    /// In the ticket rather than in memory on the server: a deployment behind two instances would
    /// otherwise re-check on every hop between them, and a restart would re-check everything at
    /// once. The value is a moment this server wrote and only this server reads, in a cookie the
    /// browser cannot forge — the data protection key that signs the ticket covers it.
    /// </remarks>
    private const string CheckedAt = "boltway.session.checked";

    /// <summary>Wire this into <c>AddCookie</c>. Resolves itself from the request's services.</summary>
    /// <remarks>
    /// A static entry point because <c>CookieAuthenticationOptions.Events</c> is configured once at
    /// startup, before any scope exists, while this needs a store that is scoped to the request.
    /// </remarks>
    public static Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var validator = context.HttpContext.RequestServices.GetService<SessionRevalidation>();

        // Nothing registered means a host that did not opt in. Not an error: the check is worth
        // nothing without a store that records the stamp, and a throw here would take down every
        // authenticated request on a deployment that simply does not use this.
        return validator is null ? Task.CompletedTask : validator.CheckAsync(context);
    }

    /// <summary>Decide whether this ticket still belongs to the account it names.</summary>
    public async Task CheckAsync(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var now = timeProvider.GetUtcNow();

        // Ordered cheapest first, and every one of these means "not this class's business" rather
        // than "allowed": a ticket with no subject or no auth_time is one this server did not write.
        if (context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value is not { Length: > 0 } subject
            || AuthTimeOf(context.Principal) is not { } authTime)
        {
            return;
        }

        if (!IsDue(context, now))
        {
            return;
        }

        UserAccount? account;

        try
        {
            account = await users.FindBySubjectAsync(SubjectId.FromStorage(subject), context.HttpContext.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            // See the class remarks: the session stands. Warned rather than swallowed, because a
            // directory that is always failing here is a revocation that silently never happens.
            logger?.LogWarning(
                failure,
                "Could not revalidate a session cookie against the directory. The session stands, "
                + "which leaves it usable until it expires even if it has been invalidated.");

            return;
        }

        // An account that no longer exists cannot have a valid session, and unlike a store failure
        // this is an answer rather than the absence of one.
        if (account is null)
        {
            await RejectAsync(context, "the account no longer exists").ConfigureAwait(false);
            return;
        }

        if (account.DisabledAt is not null)
        {
            await RejectAsync(context, "the account is disabled").ConfigureAwait(false);
            return;
        }

        // Strictly before: a sign-in and a stamp in the same tick is a stamp written by the request
        // that signed in, and signing somebody out of the session they are creating is a loop.
        if (account.SessionsValidFrom is { } validFrom && authTime < validFrom)
        {
            await RejectAsync(context, "the account's sessions were invalidated after this one began")
                .ConfigureAwait(false);
            return;
        }

        // Only on the path that actually asked the store. Renewing marks the ticket as checked now,
        // which is what makes the interval an interval rather than a delay before checking always.
        context.Properties.Items[CheckedAt] = now.UtcTicks.ToString(CultureInfo.InvariantCulture);
        context.ShouldRenew = true;
    }

    /// <summary>Whether enough time has passed since the last check on this ticket.</summary>
    /// <remarks>
    /// <para>
    /// An interval rather than a check per request, because this reads the directory and the
    /// alternative puts a query in front of every authenticated page load. What it costs is stated
    /// where a person can act on it: <see cref="AuthorizationServerOptions.SessionRevalidation"/>
    /// is how long an invalidated session can still be used.
    /// </para>
    /// <para>
    /// <b>An unreadable or absent marker means due now.</b> A ticket written before this feature has
    /// none, and a ticket carrying something unparseable is not one to extend the benefit of the
    /// doubt to — both are answered by checking rather than by trusting.
    /// </para>
    /// </remarks>
    private bool IsDue(CookieValidatePrincipalContext context, DateTimeOffset now)
    {
        if (options.SessionRevalidation <= TimeSpan.Zero)
        {
            return true;
        }

        if (!context.Properties.Items.TryGetValue(CheckedAt, out var raw)
            || !long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks))
        {
            return true;
        }

        var last = new DateTimeOffset(ticks, TimeSpan.Zero);

        // A marker in the future is a clock that moved backwards, not a check that has not happened
        // yet. Treated as due, so a corrected clock cannot park a session past its next check.
        return last > now || now - last >= options.SessionRevalidation;
    }

    private async Task RejectAsync(CookieValidatePrincipalContext context, string because)
    {
        // Both, and in this order. RejectPrincipal makes this request anonymous; SignOutAsync
        // deletes the cookie, without which every subsequent request would be refused again and the
        // browser would carry a ticket nothing will ever accept.
        context.RejectPrincipal();

        // The reason, and no identifier. This line says a session ended; which account it was is on
        // the audit record, which has different access rules from a log.
        if (logger is not null)
        {
            SessionRefused(logger, because);
        }

        // Awaited rather than discarded: the response has to carry the delete-cookie header, and a
        // fire-and-forget here would race the request finishing.
        await context.HttpContext.SignOutAsync(context.Scheme.Name).ConfigureAwait(false);
    }

    /// <summary>
    /// Source-generated, so the message is not formatted when this level is off.
    /// </summary>
    [LoggerMessage(EventId = 0, Level = LogLevel.Information, Message = "A session cookie was refused: {Reason}.")]
    private static partial void SessionRefused(ILogger logger, string reason);

    /// <summary>When the person behind this ticket actually authenticated.</summary>
    private static DateTimeOffset? AuthTimeOf(ClaimsPrincipal principal)
    {
        if (principal.FindFirst(CookieUserSignIn.AuthTimeClaim)?.Value is not { Length: > 0 } raw
            || !long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            // A claim outside the representable range. CookieUserSession guards the same conversion
            // for the same reason: this value arrives from a cookie, and a cookie is a file on
            // somebody else's computer.
            return null;
        }
    }
}
