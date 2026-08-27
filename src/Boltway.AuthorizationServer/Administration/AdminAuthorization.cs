using System.Security.Claims;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Administration;

/// <summary>The scopes the administrative surface authorizes on.</summary>
/// <remarks>
/// <para>
/// Few, and deliberately so - each one is a thing a customer has to reason about. They are also the
/// only vocabulary this library ships: the <b>role</b> stays an opaque string it never compares to a
/// constant, and turning a role into an entitlement is <c>IScopeEntitlementPolicy</c>'s job, in the
/// deployment.
/// </para>
/// <para>
/// <b>The directory pair covers everything; the roles pair narrows the domain, not the danger.</b>
/// <see cref="Read"/> and <see cref="Write"/> satisfy every endpoint here, the role endpoints
/// included, so nothing that held them loses anything by the narrower pair existing.
/// <see cref="RolesRead"/> earns its place because reading the role vocabulary is genuinely less
/// sensitive than reading the account directory - a definitions list holds no person, and a
/// credential that only ever needed the vocabulary was being handed every address in the
/// organisation for it. <see cref="RolesWrite"/> is <i>not</i> a lesser tier of <see cref="Write"/>:
/// redefining what a role stands for changes what every holder's next token may do, which is
/// privilege escalation through another door. It is separate so a credential can be scoped to the
/// role domain, and it is gated exactly as hard - see <see cref="Administrative"/>.
/// </para>
/// </remarks>
public static class AdminScopes
{
    /// <summary>Read accounts and the audit log. Satisfies every read here, roles included.</summary>
    public const string Read = "users:read";

    /// <summary>Every mutation. Satisfies every write here, roles included.</summary>
    public const string Write = "users:write";

    /// <summary>Act on your own account, and nobody else's.</summary>
    public const string Self = "users:self";

    /// <summary>Read the role definitions, and nothing about any account.</summary>
    public const string RolesRead = "roles:read";

    /// <summary>Define, reword and delete roles - and nothing about any account.</summary>
    public const string RolesWrite = "roles:write";

    /// <summary>
    /// The role-gated scopes: what an administrative role may hold and everybody else is refused.
    /// </summary>
    /// <remarks>
    /// The one list <c>AdminRoleScopePolicy</c> and the host's admin-resource registration both
    /// read, so a scope added here is gated and advertised in the same commit or not at all.
    /// <see cref="Self"/> is deliberately absent - acting on your own account is not an
    /// administrative privilege.
    /// </remarks>
    public static IReadOnlyList<string> Administrative { get; } = [Read, Write, RolesRead, RolesWrite];
}

/// <summary>Why an administrative request was refused.</summary>
public enum AdminAuthorizationFailure
{
    /// <summary>It was not refused.</summary>
    None,

    /// <summary>No authenticated principal at all.</summary>
    Unauthenticated,

    /// <summary>A cookie principal. <c>N-17</c>.</summary>
    CookiePrincipal,

    /// <summary>Authenticated, without the scope this endpoint needs.</summary>
    InsufficientScope,
}

/// <summary>
/// The gate on every <c>/admin</c> and <c>/account</c> request.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>N-17</c>: a cookie principal is refused, whatever claims it carries.</b> The sign-in pages
/// live on the same origin, so if the session cookie authenticated this surface, any XSS on the
/// login page - or any CSRF against it - would be takeover of the entire directory rather than of
/// one session. Bearer-only also makes CSRF structurally impossible here: there is no ambient
/// credential for a browser to attach.
/// </para>
/// <para>
/// <b>The refusal is by authentication scheme, not by "is there a cookie header".</b> What matters
/// is what authenticated the principal this handler would act on, and that is
/// <see cref="ClaimsIdentity.AuthenticationType"/>. A request may carry a session cookie and a
/// bearer token at once - a browser-based admin UI on the same origin would - and the bearer is the
/// one being honoured.
/// </para>
/// <para>
/// <b>This library does not validate the token.</b> The principal arrives from whatever the host
/// wired, which for an authorization server hosting its own admin API is
/// <c>Boltway.ResourceServer</c>'s bearer middleware - the same code every other resource
/// server runs, so the two cannot come to disagree about <c>typ</c>, <c>alg</c> or <c>aud</c>. This
/// decides what a validated principal may do.
/// </para>
/// </remarks>
public static class AdminAuthorization
{
    /// <summary>
    /// Which authentication schemes are a cookie, and therefore refused.
    /// </summary>
    /// <remarks>
    /// The framework's default plus this server's own name for it. A deployment that renamed its
    /// scheme is not covered by a name list, which is why the architecture test asserts over the
    /// routing table rather than trusting this: a route that never carries a cookie scheme cannot be
    /// reached by one regardless of what it is called.
    /// </remarks>
    public static IReadOnlyList<string> CookieSchemes { get; } =
        [CookieAuthenticationDefaults.AuthenticationScheme, "Boltway.Session"];

    /// <summary>Whether this request may run an endpoint needing <paramref name="scope"/>.</summary>
    /// <param name="http">The request.</param>
    /// <param name="scope">What the endpoint needs.</param>
    /// <param name="subject">The caller, when there is one.</param>
    /// <returns><see cref="AdminAuthorizationFailure.None"/> when it may.</returns>
    public static AdminAuthorizationFailure Check(HttpContext http, string scope, out SubjectId subject) =>
        Check(http, [scope], out subject);

    /// <summary>
    /// Whether this request may run an endpoint that any one of <paramref name="anyOf"/> allows.
    /// </summary>
    /// <param name="http">The request.</param>
    /// <param name="anyOf">
    /// The scopes that each individually allow the endpoint. Any-of rather than all-of, because the
    /// alternatives exist for the caller's sake: the role endpoints accept their own narrow scope
    /// <i>or</i> the directory-wide one, so a token holding either is enough and holding both buys
    /// nothing.
    /// </param>
    /// <param name="subject">The caller, when there is one.</param>
    /// <returns><see cref="AdminAuthorizationFailure.None"/> when it may.</returns>
    public static AdminAuthorizationFailure Check(
        HttpContext http, IReadOnlyList<string> anyOf, out SubjectId subject)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(anyOf);

        subject = default;

        if (http.User.Identity is not { IsAuthenticated: true } identity)
        {
            return AdminAuthorizationFailure.Unauthenticated;
        }

        if (identity.AuthenticationType is { } type
            && CookieSchemes.Contains(type, StringComparer.Ordinal))
        {
            return AdminAuthorizationFailure.CookiePrincipal;
        }

        _ = ScopeSet.TryParse(http.User.FindFirst("scope")?.Value, out var scopes, out _);

        if (!anyOf.Any(scopes.Contains))
        {
            return AdminAuthorizationFailure.InsufficientScope;
        }

        var value = http.User.FindFirst("sub")?.Value
            ?? http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (!string.IsNullOrEmpty(value))
        {
            subject = SubjectId.FromStorage(value);
        }

        return AdminAuthorizationFailure.None;
    }
}
