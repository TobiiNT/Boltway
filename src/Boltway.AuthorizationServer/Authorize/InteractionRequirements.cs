using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>
/// Whether an authorization request still needs the user to do something. Stage 9.
/// </summary>
/// <remarks>
/// <para>
/// <b>One implementation, because two is how the bypass happened.</b> This logic lived inline in
/// the authorization endpoint, and the consent POST re-ran stages 1 to 8 and then checked only that
/// <i>some</i> user was signed in. An adversarial review measured the consequence: with a session
/// authenticated an hour earlier, <c>/authorize?…&amp;max_age=60</c> correctly redirected to
/// <c>/login</c> — and posting the same <c>returnUrl</c> straight to <c>/consent</c> returned an
/// authorization code, carrying the hour-old <c>auth_time</c>. The same held for
/// <c>prompt=login</c>. OIDC Core §3.1.2.1 makes the re-authentication a MUST, and a relying party
/// asking for it is told it happened.
/// </para>
/// <para>
/// The comment on the consent path claimed at the time that the session was re-checked "against
/// this request's <c>max_age</c>". It was not. Splitting a security decision across two call sites
/// and describing it once is how a comment ends up true of the code it sits next to and false of
/// the system.
/// </para>
/// </remarks>
public static class InteractionRequirements
{
    /// <summary>Whether the user must authenticate again before this request can be answered.</summary>
    /// <param name="context">The validated request.</param>
    /// <param name="user">The current session, or <see langword="null"/>.</param>
    /// <param name="freshness">
    /// How recently an authentication satisfies any re-authentication demand. See the remarks: this
    /// is the loop-breaker, not a leniency.
    /// </param>
    public static bool MustReauthenticate(AuthorizeContext context, AuthenticatedUser? user, TimeSpan freshness)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (user is null)
        {
            return true;
        }

        // `prompt=login`, `prompt=select_account` and `max_age` all mean "re-authenticate", and all
        // three are satisfied by an authentication that just happened. Without that floor each is an
        // infinite loop: the parameter survives in the returnUrl and is still set when the browser
        // comes back, so /authorize sends to /login, the user authenticates, /authorize sees the same
        // parameter and sends to /login again. `max_age=0` is the certain case — any elapsed time
        // exceeds zero, so a user who authenticated microseconds ago is already stale, and under
        // `prompt=none` that is a `login_required` nothing can ever satisfy. OIDC defines `max_age=0`
        // as "re-authenticate", once, not forever.
        if (context.Now - user.Value.AuthenticatedAt <= freshness)
        {
            return false;
        }

        return context.Prompt.Contains("login", StringComparer.Ordinal)
            || context.Prompt.Contains("select_account", StringComparer.Ordinal)
            || IsStale(user.Value, context);
    }

    /// <summary>
    /// Whether the session is too old for this request's <c>max_age</c>.
    /// </summary>
    /// <remarks>
    /// OIDC Core §3.1.2.1: "If the elapsed time is greater than this value, the OP MUST attempt to
    /// actively re-authenticate the End-User." Measured against when the user actually presented
    /// credentials, which is why <see cref="AuthenticatedUser.AuthenticatedAt"/> is stored rather
    /// than stamped per request — re-deriving it from the cookie's issuance makes every session
    /// permanently fresh and the parameter a no-op.
    /// </remarks>
    public static bool IsStale(AuthenticatedUser user, AuthorizeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.MaxAge is { } maxAge && context.Now - user.AuthenticatedAt > maxAge;
    }
}
