using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>OpenID Connect's UserInfo endpoint. E-17.</summary>
/// <remarks>
/// <para>
/// <b>This existed as a path constant and a flag for a long time before it existed as an
/// endpoint.</b> <see cref="AuthorizationServerOptions.UserInfoEnabled"/> sat beside
/// <c>RevocationEnabled</c> and <c>IntrospectionEnabled</c> with the note "flags for endpoints that
/// do not exist yet… flip a flag when the endpoint exists". This is that flip.
/// </para>
/// <para>
/// <b>What it is for, concretely.</b> An OIDC client that is not a resource server has no business
/// reading an access token - it is not the audience, and the claims in it are not addressed to it.
/// So a client that needs to know who signed in, and what they are allowed to be in its own
/// application, has exactly two channels: the ID token, and here. The ID token deliberately carries
/// neither the address nor the role - see <c>UserAccountClaims</c>, which says a client "has no
/// business routing on somebody's role" out of a token whose job is to prove who signed in. That
/// argument is about the ID token and does not reach this endpoint: this one is called <i>with</i>
/// the access token, which already carries the role, so nothing here is disclosed that the caller
/// could not already have been told.
/// </para>
/// <para>
/// <b>Read from the store, not projected from the token's claims</b> - the same decision
/// <c>AccountEndpoints</c> makes and for the same reason. A token is a snapshot taken up to half an
/// hour ago, so a role changed since would be answered with the old value by the endpoint whose
/// entire job is to say what the account holds now. A client that maps roles onto its own
/// permissions on every sign-in is the case this matters most for: demoting somebody in the
/// directory should reach their next login, not their next token expiry.
/// </para>
/// <para>
/// <b>Bearer only, like every other API surface here - <c>N-17</c>.</b> The sign-in pages share this
/// origin, so a cookie-authenticated API turns any XSS on the login page into a read of every
/// account the browser can reach. The gate is inside the handler rather than an
/// <c>.RequireAuthorization()</c> policy, for the reason <c>AdminEndpoints</c> gives: a policy
/// authenticates against whatever schemes it is told to, and "whichever scheme the host made
/// default" is how a cookie ends up authenticating this.
/// </para>
/// <para>
/// <b>Scopes decide the fields, and <c>sub</c> is not one of them.</b> OIDC Core §5.3.2 requires
/// <c>sub</c> in every response; the rest follow the grant, so a client that asked for
/// <c>openid</c> alone learns an identifier and nothing about the person. That is the same
/// asymmetry <c>UserAccountClaims</c> already applies to the access token.
/// </para>
/// </remarks>
public static class UserInfoEndpoint
{
    /// <summary>Map <c>/userinfo</c>.</summary>
    /// <param name="endpoints">The route builder.</param>
    public static IEndpointRouteBuilder MapUserInfo(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // GET and POST both, which is OIDC Core §5.3.1: a server MUST support GET and SHOULD
        // support POST. Supporting only GET is the shape that works everywhere until it meets the
        // one client that posts, and then fails as a 405 nobody expects from a standard endpoint.
        endpoints.MapGet(AuthorizationServerPaths.UserInfo, GetAsync)
            .AllowAnonymous().WithName("boltway-userinfo-get");

        endpoints.MapPost(AuthorizationServerPaths.UserInfo, GetAsync)
            .AllowAnonymous().WithName("boltway-userinfo-post");

        return endpoints;
    }

    /// <summary>
    /// Answer, or shed if the directory cannot be reached. X-43.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The reason this surface needs it is sharper than elsewhere: the plausible wrong answer
    /// destroys a good credential.</b> RFC 6750 registers no code meaning "come back shortly", and
    /// the nearest one to reach for is <c>invalid_token</c> - which every conforming client treats as
    /// "this token is dead", so it discards a token that is perfectly valid and sends the person
    /// back through a sign-in they did not need. A store that is briefly unreachable would then cost
    /// a re-authorization on every session that happened to call during it.
    /// </para>
    /// <para>
    /// So the refusal carries no <c>error</c> at all, the same as at <c>/token</c>: a status and a
    /// <c>Retry-After</c>, which every HTTP client already understands without being taught an OAuth
    /// code. The 401s and 403s below are unchanged - they are about the credential, and they are
    /// still the right answers when the store can be reached.
    /// </para>
    /// <para>
    /// This is also the only refusal on this endpoint that travels the rejection writer. The others
    /// predate it and answer with their own JSON body; that is worth correcting and is not this
    /// change, which would otherwise alter the shape of four responses while claiming to add one.
    /// </para>
    /// </remarks>
    private static async Task<IResult> GetAsync(HttpContext http, CancellationToken cancellationToken)
    {
        try
        {
            return await ReadAsync(http, cancellationToken);
        }
        catch (Exception unreachable) when (TransientStoreFailure.Describes(unreachable))
        {
            return StoreLoadShed.Answer(http, OAuthSurface.ResourceServer, unreachable);
        }
    }

    private static async Task<IResult> ReadAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        // `openid` rather than a scope of this library's own invention. It is the scope that makes a
        // request an OpenID Connect one at all, so a token granted it is a token whose holder was
        // told they were signing in - which is precisely the consent this endpoint answers on.
        var failure = AdminAuthorization.Check(http, "openid", out var subject);

        if (failure is AdminAuthorizationFailure.None && subject.Value is null)
        {
            // Correctly scoped and carrying no `sub`: a client-credentials token, or one minted by
            // something that dropped the claim. There is no person for this to be about, and
            // proceeding would run the lookup against a default SubjectId.
            failure = AdminAuthorizationFailure.InsufficientScope;
        }

        if (failure is not AdminAuthorizationFailure.None)
        {
            http.RequestServices
                .GetService<ILoggerFactory>()
                ?.CreateLogger("Boltway.AuthorizationServer.UserInfo")
                .LogWarning(
                    new EventId(103, "UserInfoRefused"),
                    "UserInfo request refused: {Failure}; correlation_id={CorrelationId}",
                    failure,
                    http.TraceIdentifier);

            return Refusal(failure);
        }

        var users = http.RequestServices.GetRequiredService<IUserStore>();
        var account = await users.FindBySubjectAsync(subject, cancellationToken);

        if (account is null)
        {
            // The token verifies and names an account the directory no longer has - anonymised, or
            // deleted out from under an outstanding token. `invalid_token` rather than 404: the
            // subject is not a resource this endpoint locates, it is who the credential says you
            // are, and the honest answer is that the credential no longer identifies anybody.
            return Challenge(StatusCodes.Status401Unauthorized, "invalid_token",
                "The token names an account this directory no longer has.");
        }

        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            // OIDC Core §5.3.2. Always present, never gated: a response without it is not a UserInfo
            // response, and a client that cannot key on anything is worse off than one refused.
            ["sub"] = account.Subject.Value,
        };

        var scopes = Scopes(http);

        // **Not behind `profile`, and that is a correction rather than a shortcut.** The obvious
        // reading of OIDC puts the handle behind `profile` - but `UserAccountClaims` already
        // releases `preferred_username` into the access token with no scope at all, gating only the
        // address. Gating it here would mean the same fact about the same person is governed by two
        // different rules depending on which surface asked, which is not a rule.
        //
        // It would also be a gate that never opens on the deployment this was measured against: `profile` is not a
        // scope this server knows anywhere - `ScopesSupported` is whatever a deployment configures,
        // and nothing here treats `profile` specially - so a client asking for it gets
        // `invalid_scope`, and one that does not ask gets a person named by ULID.
        //
        // Sending it under `preferred_username` rather than inventing a name is what lets a client
        // map it without being told: it is the claim OIDC defines for "what this person is called
        // here".
        if (account.Username is { Length: > 0 } handle)
        {
            claims["preferred_username"] = handle;
        }

        if (scopes.Contains("email") && account.Email is { Length: > 0 } email)
        {
            claims["email"] = email;

            // Shipped alongside, never alone - the same rule UserAccountClaims applies to the token.
            // An absent `email_verified` reads as false to some clients and as unknown to others,
            // and a client deciding anything on an address wants to know which it is looking at.
            claims["email_verified"] = account.EmailVerified;
        }

        // Not gated on a scope, and the asymmetry is the same one the access token makes: `email` is
        // personal data the subject consents to release, while a role is what the client needs in
        // order to decide what this person may do at all. Behind a scope, a client that forgot to
        // ask gets a login that succeeds and then grants nothing - which surfaces to a person as
        // "my account is broken" rather than as a missing scope.
        //
        // Nothing is disclosed here that the caller was not already holding: this endpoint is
        // reached with an access token, and that token carries `role` already.
        // An array now, and it stays an array with one element rather than collapsing to a string:
        // a consumer that has to branch on the JSON type to read a claim is one that will read it
        // wrong on the day somebody is given a second role.
        if (account.Roles.Count > 0)
        {
            claims["role"] = account.Roles;
        }

        return Results.Json(claims);
    }

    /// <summary>The granted scopes, from the token this request carries.</summary>
    private static OAuth.Primitives.Scopes.ScopeSet Scopes(HttpContext http)
    {
        _ = OAuth.Primitives.Scopes.ScopeSet.TryParse(
            http.User.FindFirst("scope")?.Value, out var scopes, out _);

        return scopes;
    }

    /// <summary>
    /// The refusal, in the shape a bearer-protected resource owes its caller.
    /// </summary>
    /// <remarks>
    /// RFC 6750 §3: the challenge goes in <c>WWW-Authenticate</c>, and the error code distinguishes
    /// "you sent nothing" from "you sent something that does not carry enough". A client that cannot
    /// tell those apart retries the same token forever.
    /// </remarks>
    private static IResult Refusal(AdminAuthorizationFailure failure) => failure switch
    {
        AdminAuthorizationFailure.InsufficientScope => Challenge(
            StatusCodes.Status403Forbidden,
            "insufficient_scope",
            "This endpoint needs a token granted the `openid` scope."),

        // A cookie principal is refused as if unauthenticated rather than as a distinct error, and
        // deliberately: `N-17` is that this surface has no cookie path at all, so naming one in a
        // response would document a door that does not exist.
        _ => Challenge(
            StatusCodes.Status401Unauthorized,
            "invalid_token",
            "This endpoint is bearer-only. Present an access token."),
    };

    /// <summary>The same JSON body shape the other API surfaces here refuse with.</summary>
    private static IResult Challenge(int status, string error, string description) =>
        Results.Json(new ProblemView(error, description), statusCode: status);
}
