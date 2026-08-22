using System.Security.Claims;
using Boltway.AuthorizationServer.Abstractions.Users;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Interaction;

/// <summary>
/// Establishes a session after the user proves who they are.
/// </summary>
/// <remarks>
/// <para>
/// The write half of <see cref="IUserSession"/>, and it lives <b>here</b> rather than in the
/// abstractions assembly because it needs <see cref="HttpContext"/> and a scheme name — and that
/// assembly's whole promise is that it has no ASP.NET Core reference.
/// </para>
/// <para>
/// Kept separate from <see cref="IUserSession"/> rather than merged into it: a seam that could both
/// read and write a session would let an <see cref="IUserSession"/> implementation establish one
/// <i>during</i> an authorization request, which is how "the connector signed me in as someone
/// else" happens.
/// </para>
/// </remarks>
public interface IUserSignIn
{
    /// <summary>Sign the user in, recording when they proved it.</summary>
    /// <param name="context">The request.</param>
    /// <param name="user">Who, and when they authenticated.</param>
    Task SignInAsync(HttpContext context, AuthenticatedUser user);

    /// <summary>End the session this seam created.</summary>
    /// <param name="context">The request.</param>
    /// <remarks>
    /// <para>
    /// <b>Required rather than defaulted, unlike the page added to
    /// <see cref="IInteractionRenderer"/> at the same time</b>, and the difference is what a wrong
    /// answer costs. A default here could only call <c>SignOutAsync</c> with the framework's default
    /// scheme; an implementation that signs in under its own scheme would then have a sign-out that
    /// silently ends nothing, and the page would say "your session has ended" while the cookie was
    /// still there. A missing page is visible. A sign-out that does not sign out is not.
    /// </para>
    /// <para>
    /// It belongs on this interface rather than beside it because sign-in decides the scheme, and
    /// only the thing that decided it can end it.
    /// </para>
    /// </remarks>
    Task SignOutAsync(HttpContext context);
}

/// <summary>Cookie authentication, with an explicit authentication time.</summary>
/// <remarks>
/// <para>
/// <c>auth_time</c> is written as a claim rather than derived from the ticket's issue time, and that
/// is load-bearing. Sliding expiration rewrites the issue time on every request, so a session
/// derived from it is permanently fresh — and <c>max_age</c>, which the relying party believes it is
/// enforcing, silently becomes a no-op.
/// </para>
/// <para>
/// Nothing is carried over from before sign-in. <c>SignInAsync</c> writes a new ticket, so classic
/// fixation is structurally absent — but it returns the moment a pre-login cookie survives and is
/// later treated as identity-bearing. This flow sets no pre-login cookie at all, which is the
/// property that makes that true rather than merely likely.
/// </para>
/// </remarks>
public sealed class CookieUserSignIn(string scheme = CookieAuthenticationDefaults.AuthenticationScheme) : IUserSignIn
{
    /// <summary>The claim carrying when the user actually authenticated.</summary>
    public const string AuthTimeClaim = "auth_time";

    /// <inheritdoc />
    public Task SignInAsync(HttpContext context, AuthenticatedUser user)
    {
        ArgumentNullException.ThrowIfNull(context);

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Subject.Value),
                new Claim(AuthTimeClaim, user.AuthenticatedAt.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ],
            scheme,
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role);

        return context.SignInAsync(scheme, new ClaimsPrincipal(identity));
    }

    /// <inheritdoc />
    public Task SignOutAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // The same scheme the ticket was written under. Calling the no-argument overload would sign
        // out whichever scheme the host happens to have made default, which is the same scheme here
        // and would not be in a host that also uses cookies for something else.
        return context.SignOutAsync(scheme);
    }
}

/// <summary>Reads the session cookie back.</summary>
/// <remarks>
/// The cookie must be <c>SameSite=Lax</c>, not <c>Strict</c>, and that is not a preference. The
/// browser arrives at <c>/authorize</c> by a top-level cross-site navigation from
/// <c>claude.ai</c> or <c>chatgpt.com</c>; a <c>Strict</c> cookie is not sent on that navigation, so
/// every user looks signed out on every connect and is shown a login page they should not see. The
/// antiforgery cookie may stay <c>Strict</c> — it is only needed on the same-site form POST.
/// </remarks>
public sealed class CookieUserSession(IHttpContextAccessor accessor) : IUserSession
{
    /// <summary>The range <see cref="DateTimeOffset.FromUnixTimeSeconds"/> will accept.</summary>
    /// <remarks>
    /// Taken from the method's own documented bounds rather than computed, so this does not depend
    /// on a runtime that might widen them.
    /// </remarks>
    private const long MinAuthTimeSeconds = -62135596800;

    /// <inheritdoc cref="MinAuthTimeSeconds" />
    private const long MaxAuthTimeSeconds = 253402300799;

    private readonly IHttpContextAccessor _accessor = accessor ?? throw new ArgumentNullException(nameof(accessor));

    /// <inheritdoc />
    public ValueTask<AuthenticatedUser?> GetAsync(CancellationToken cancellationToken)
    {
        var principal = _accessor.HttpContext?.User;

        if (principal?.Identity is not { IsAuthenticated: true })
        {
            return ValueTask.FromResult<AuthenticatedUser?>(null);
        }

        var subject = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var authTime = principal.FindFirstValue(CookieUserSignIn.AuthTimeClaim);

        // Both or neither. A principal with a subject and no authentication time cannot answer
        // `max_age`, and inventing one — "now", or the ticket's issue time — answers it wrongly in
        // the direction that always says yes.
        if (string.IsNullOrEmpty(subject)
            || !long.TryParse(authTime, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var seconds)
            || seconds < MinAuthTimeSeconds
            || seconds > MaxAuthTimeSeconds)
        {
            // The range check is not belt-and-braces. `long.TryParse` happily returns
            // 9223372036854775807, and `DateTimeOffset.FromUnixTimeSeconds` throws
            // ArgumentOutOfRangeException on it — measured — from a method with no exception
            // boundary above it, on the path every authenticated request takes. Treating it as "not
            // a session" is the same answer this method already gives to every other unreadable
            // claim, and it fails in the safe direction: the user is asked to sign in.
            //
            // Not reachable from a cookie this server issued, since it writes the value itself. It
            // is reachable when data-protection keys are shared with another application that also
            // writes an `auth_time` claim, which is an ordinary way to deploy and not an attack.
            return ValueTask.FromResult<AuthenticatedUser?>(null);
        }

        return ValueTask.FromResult<AuthenticatedUser?>(
            new AuthenticatedUser(
                Boltway.OAuth.Primitives.Ids.SubjectId.FromStorage(subject),
                DateTimeOffset.FromUnixTimeSeconds(seconds)));
    }
}
