using System.Text.Json.Serialization;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
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

/// <summary>The self-service surface. E-33 to E-38.</summary>
/// <remarks>
/// <para>
/// <b>A different surface from <see cref="AdminEndpoints"/>, not the same one with a guard.</b>
/// §1.6. The alternative - one set of handlers that act on a target "unless the target is yourself"
/// - is how an authorization bug is written: the guard is correct on the day it is added and
/// acquires an exception the first time somebody needs a support tool. Here there is no target
/// parameter at all. Every handler reads its subject from
/// <see cref="AdminAuthorization.Check(HttpContext, string, out SubjectId)"/> and there is nothing
/// in a request that could name another account.
/// </para>
/// <para>
/// <b>Bearer only - <c>N-17</c>, the same as <c>/admin</c>, and the same architecture test covers
/// both prefixes.</b> The scope is <see cref="AdminScopes.Self"/>, which the default entitlement
/// policy grants to everyone because it conveys no authority over anyone else.
/// </para>
/// <para>
/// <b>These are the API, and the pages are <c>/me/*</c>.</b> Taken literally <c>N-17</c> would mean
/// a user changing their own password needs an OAuth client, which is absurd; the way out is a
/// second surface with cookies and antiforgery, calling the same service in process, not a softened
/// rule here. §7.2, and it is why nothing below reads a cookie.
/// </para>
/// <para>
/// <b>What ending a session reaches.</b> Revoking a grant kills every refresh chain descended from
/// it. It does not reach an access token already issued: those are signed rather than looked up.
/// So the responses carry counts and never say "signed out" - the gap is one access-token lifetime
/// long, and the person reading this page is the one deciding whether that is good enough.
/// </para>
/// </remarks>
public static class AccountEndpoints
{
    /// <summary>Map the self-service endpoints.</summary>
    /// <param name="endpoints">The route builder.</param>
    public static IEndpointRouteBuilder MapAccount(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Every route below answers a script in a page, which can use the status and nothing else.
        // X-43.
        var api = endpoints.ShedsOnStoreFailure(OAuthSurface.Administration, rendered: false);


        // No `.RequireAuthorization()` and no scheme, for the reason spelled out on
        // `AdminEndpoints.MapAdministration`: a policy authenticates against whatever schemes it is
        // told to, and "whichever one the host made default" is how a cookie reaches this.
        api.MapGet(AuthorizationServerPaths.Account, GetAccountAsync)
            .AllowAnonymous().WithName("boltway-account-get");

        api.MapPost(AuthorizationServerPaths.AccountPassword, PostPasswordAsync)
            .AllowAnonymous().WithName("boltway-account-password");

        api.MapGet(AuthorizationServerPaths.AccountSessions, GetSessionsAsync)
            .AllowAnonymous().WithName("boltway-account-sessions");

        api.MapDelete(AuthorizationServerPaths.AccountSession, DeleteSessionAsync)
            .AllowAnonymous().WithName("boltway-account-session-delete");

        api.MapGet(AuthorizationServerPaths.AccountConsents, GetConsentsAsync)
            .AllowAnonymous().WithName("boltway-account-consents");

        api.MapDelete(AuthorizationServerPaths.AccountConsent, DeleteConsentAsync)
            .AllowAnonymous().WithName("boltway-account-consent-delete");

        return endpoints;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-33  GET /account
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Who this token says you are, as the directory currently has it.
    /// </summary>
    /// <remarks>
    /// <b>Read from the store rather than projected from the token's claims.</b> A token is a
    /// snapshot taken up to thirty minutes ago, so a role or an address changed since would be
    /// reported as the old value by an endpoint whose entire job is to say what the account holds
    /// now. It is also what makes <c>disabled_at</c> answerable at all: a disabled account's
    /// outstanding tokens keep working until they expire, and this is where their holder can find
    /// out.
    /// </remarks>
    private static async Task<IResult> GetAccountAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (Refuse(http, out var subject) is { } refusal)
        {
            return refusal;
        }

        var account = await Users(http).FindBySubjectAsync(subject, cancellationToken);

        return account is null ? NoAccount() : Results.Json(AccountView.Of(account));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-34  POST /account/password
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Change your own password. The current one is required. <c>S-49</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A valid token is not enough, and that is the endpoint's whole point.</b> An access token
    /// expires; a password does not. Without this check, half an hour of stolen access converts into
    /// permanent access and every rotation the token design pays for is wasted.
    /// </para>
    /// <para>
    /// <b>A wrong current password is 403, not 401.</b> The caller authenticated fine - a 401 would
    /// invite them to get a new token, which is a loop that cannot terminate because the token was
    /// never the problem.
    /// </para>
    /// </remarks>
    private static async Task<IResult> PostPasswordAsync(
        HttpContext http, ChangePasswordRequest? body, CancellationToken cancellationToken)
    {
        if (Refuse(http, out var subject) is { } refusal)
        {
            return refusal;
        }

        if (body is null
            || string.IsNullOrEmpty(body.CurrentPassword)
            || string.IsNullOrEmpty(body.NewPassword))
        {
            return Problem(
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "Send current_password and new_password.");
        }

        // The one rule this library imposes on a chosen password, and it is a well-formedness check
        // rather than a strength policy: a password that is entirely whitespace is almost always a
        // client sending an empty field it did not notice was empty, and accepting it locks somebody
        // out of their own account with a credential they cannot retype. Anything about length or
        // composition is a decision a deployment makes, and this library ships no vocabulary for it
        // - the same reason the role is an opaque string.
        if (string.IsNullOrWhiteSpace(body.NewPassword))
        {
            return Problem(
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "The new password is blank.");
        }

        var result = await Administration(http).ChangePasswordAsync(
            Actor(http, subject),
            subject,
            body.CurrentPassword,
            body.NewPassword,
            body.RevokeSessions ?? false,
            cancellationToken);

        return result.Status switch
        {
            AdministrationStatus.Ok => Results.Json(new PasswordChangedView(result.Revoked)),

            AdministrationStatus.WrongPassword => Problem(
                StatusCodes.Status403Forbidden,
                "wrong_password",
                "The current password does not match."),

            AdministrationStatus.NoPassword => Problem(
                StatusCodes.Status409Conflict,
                "no_password",
                "This account signs in through an upstream provider and has no password here, so "
                + "there is nothing to change."),

            AdministrationStatus.NoSuchAccount => NoAccount(),

            _ => Problem(
                StatusCodes.Status409Conflict,
                "gone",
                "The account was there a moment ago and is not now."),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-35  GET /account/sessions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// What you are currently signed in to.
    /// </summary>
    /// <remarks>
    /// One entry per grant, which is one per (client, authorization). A client authorized twice
    /// appears twice, because it is two things a person can end separately - collapsing them by
    /// client id would make the list shorter and the delete ambiguous.
    /// </remarks>
    private static async Task<IResult> GetSessionsAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (Refuse(http, out var subject) is { } refusal)
        {
            return refusal;
        }

        var grants = await Grants(http).ListForSubjectAsync(subject, cancellationToken);

        return Results.Json(grants.Select(SessionView.Of).ToList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-36  DELETE /account/sessions/{grant}
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// End one of your own sessions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The grant is loaded and its subject checked before anything is revoked.</b> The id comes
    /// from the URL, so without this the endpoint revokes any grant in the deployment for anyone
    /// holding <c>users:self</c> - which is everyone. <c>IGrantStore.RevokeAsync</c> takes an id and
    /// no subject; it is the caller's job to have earned the right to name that id, and this is that
    /// caller.
    /// </para>
    /// <para>
    /// <b>Load-then-revoke is safe here, unlike on the admin sweep.</b> A grant's subject is set when
    /// it is created and never changes, so there is no interleaving in which the row checked and the
    /// row revoked belong to different people. What the window can produce is a revocation of a
    /// grant somebody else revoked first, which answers 404 on the second call and is the honest
    /// answer.
    /// </para>
    /// <para>
    /// <b>Somebody else's grant is 404, not 403.</b> A 403 would confirm the id exists, which turns
    /// this into an oracle for guessing grant ids across the whole deployment. The caller cannot see
    /// it, so as far as this surface is concerned it is not there.
    /// </para>
    /// </remarks>
    private static async Task<IResult> DeleteSessionAsync(
        HttpContext http, string grant, CancellationToken cancellationToken)
    {
        if (Refuse(http, out var subject) is { } refusal)
        {
            return refusal;
        }

        var store = Grants(http);
        var record = await store.FindAsync(grant, cancellationToken);

        if (record is null || record.Subject != subject)
        {
            return NoSession();
        }

        var revoked = await store.RevokeAsync(grant, Clock(http).GetUtcNow(), cancellationToken);

        // False means it was already revoked between the read and the write, or by the read's own
        // staleness. Not an error and not a lie either: the session is over, and saying so twice is
        // what makes a retried request safe.
        return Results.Json(new SessionEndedView(grant, revoked));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-37  GET /account/consents
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetConsentsAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (Refuse(http, out var subject) is { } refusal)
        {
            return refusal;
        }

        var consents = await Consents(http).ListAsync(subject, cancellationToken);

        return Results.Json(consents.Select(ConsentView.Of).ToList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-38  DELETE /account/consents/{clientId}
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Withdraw what you approved for one client.
    /// </summary>
    /// <remarks>
    /// <b>This forgets the approval; it does not end the sessions.</b> A grant already issued keeps
    /// working - the next authorization will ask again rather than proceeding silently, which is
    /// what withdrawing consent means. Ending the access is <c>E-36</c>, and a person who wants both
    /// wants both. Saying so in the response rather than doing the second one quietly: revoking
    /// grants from here would make "I want to be asked again" also mean "sign me out", and only one
    /// of those is what the button said.
    /// </remarks>
    private static async Task<IResult> DeleteConsentAsync(
        HttpContext http, string clientId, CancellationToken cancellationToken)
    {
        if (Refuse(http, out var subject) is { } refusal)
        {
            return refusal;
        }

        // The same parse the authorization endpoint runs on a `client_id` off the wire, and for the
        // same reason: this one arrives in a URL segment, so it is untrusted input that reaches a
        // store key and a log line. It also settles the kind - `Unknown`, because whoever sent it
        // does not get to say what kind of client they are, and the store compares on the value.
        if (!ClientIdentifier.TryParseFromRequest(clientId, out var client))
        {
            return Problem(
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "That is not a well-formed client id.");
        }

        // Keyed on (subject, client), and the subject is the caller's, so this cannot reach another
        // account's record however the id is spelled.
        var withdrawn = await Consents(http).RevokeAsync(subject, client, cancellationToken);

        return withdrawn
            ? Results.Json(new ConsentWithdrawnView(clientId))
            : Problem(
                StatusCodes.Status404NotFound,
                "no_such_consent",
                "You have no recorded approval for that client.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The refusal, or <see langword="null"/> when the caller may proceed.</summary>
    /// <remarks>
    /// <b>The subject is an out-parameter and every handler uses it as its only identifier.</b> That
    /// is the mechanical half of §1.6: a handler that never receives a target cannot act on one.
    /// </remarks>
    private static IResult? Refuse(HttpContext http, out SubjectId subject)
    {
        SecurityHeaders.Apply(http);

        var failure = AdminAuthorization.Check(http, AdminScopes.Self, out subject);

        if (failure is AdminAuthorizationFailure.None && subject.Value is null)
        {
            // Scoped correctly and carrying no `sub`. A client-credentials token, or one minted by
            // something that forgot the claim - either way there is no account for this surface to
            // be about, and proceeding would run every handler against a default SubjectId.
            failure = AdminAuthorizationFailure.InsufficientScope;
        }

        if (failure is not AdminAuthorizationFailure.None)
        {
            // Logged for the reason AdminEndpoints.Refuse logs: it never reaches the service, so it
            // never reaches the audit log, and a run of them against one account is somebody working
            // through a token that is not theirs.
            http.RequestServices
                .GetService<Microsoft.Extensions.Logging.ILoggerFactory>()
                ?.CreateLogger("Boltway.AuthorizationServer.Account")
                .LogWarning(
                    new Microsoft.Extensions.Logging.EventId(102, "AccountRefused"),
                    "Self-service request refused: {Failure}; path={Path}; correlation_id={CorrelationId}",
                    failure,
                    http.Request.Path.Value,
                    http.TraceIdentifier);
        }

        return failure switch
        {
            AdminAuthorizationFailure.None => null,

            AdminAuthorizationFailure.Unauthenticated => Problem(
                StatusCodes.Status401Unauthorized,
                "unauthorized",
                "This endpoint requires an access token."),

            AdminAuthorizationFailure.CookiePrincipal => Problem(
                StatusCodes.Status401Unauthorized,
                "unauthorized",
                "This endpoint is bearer-only. The sign-in pages share this origin, so a session "
                + "cookie never authenticates an API here. The cookie-authenticated pages are "
                + "under /me."),

            _ => Problem(
                StatusCodes.Status403Forbidden,
                "insufficient_scope",
                $"This token does not carry the '{AdminScopes.Self}' scope for an account."),
        };
    }

    /// <summary>The caller, for the audit trail.</summary>
    /// <remarks>
    /// <see cref="ActorKind.Client"/> with the caller's own subject: the person and the target are
    /// the same account here, which is what an entry for a self-service change should read as.
    /// </remarks>
    private static Actor Actor(HttpContext http, SubjectId subject) =>
        new(ActorKind.Client, subject)
        {
            Client = http.User.FindFirst("client_id")?.Value,
            CorrelationId = http.TraceIdentifier,
        };

    /// <summary>The token named a subject the directory does not have.</summary>
    /// <remarks>
    /// A signed token for an account that has since been anonymised, or one minted by a different
    /// deployment against the same keys. 404 rather than 401: the token is valid, and there is
    /// nothing to authenticate again as.
    /// </remarks>
    private static IResult NoAccount() =>
        Problem(
            StatusCodes.Status404NotFound,
            "no_such_account",
            "This token names an account that is not in the directory.");

    private static IResult NoSession() =>
        Problem(StatusCodes.Status404NotFound, "no_such_session", "You have no session with that id.");

    private static IResult Problem(int status, string error, string description) =>
        Results.Json(new ProblemView(error, description), statusCode: status);

    private static IUserStore Users(HttpContext http) =>
        http.RequestServices.GetRequiredService<IUserStore>();

    private static IGrantStore Grants(HttpContext http) =>
        http.RequestServices.GetRequiredService<IGrantStore>();

    private static IConsentStore Consents(HttpContext http) =>
        http.RequestServices.GetRequiredService<IConsentStore>();

    private static UserAdministration Administration(HttpContext http) =>
        http.RequestServices.GetRequiredService<UserAdministration>();

    private static TimeProvider Clock(HttpContext http) =>
        http.RequestServices.GetRequiredService<TimeProvider>();
}

/// <summary>What a password change carries.</summary>
/// <param name="CurrentPassword">What is on the account now. Required - <c>S-49</c>.</param>
/// <param name="NewPassword">What to replace it with.</param>
/// <param name="RevokeSessions">
/// Whether to end every session on the way, including the one this request was made from. Absent
/// means no, the same default <c>set-password</c> has, and §1.10 is why it is a question rather than
/// an inference.
/// </param>
public sealed record ChangePasswordRequest(
    [property: JsonPropertyName("current_password")] string CurrentPassword,
    [property: JsonPropertyName("new_password")] string NewPassword,
    [property: JsonPropertyName("revoke_sessions")] bool? RevokeSessions = null);

/// <summary>An account, as its owner sees it.</summary>
/// <remarks>
/// <b>The same fields <c>AdminUserView</c> carries, minus the realm.</b> Not because a realm is a
/// secret - the caller is in it - but because it is an answer to "which directory is this
/// deployment serving", which is an operator's question and not a thing an account holder can act
/// on. No password hash here for the reason there is none there: a hash is a credential's shadow.
/// </remarks>
/// <param name="Subject">The <c>sub</c> in your tokens.</param>
/// <param name="Handle">What you type at the sign-in page.</param>
/// <param name="Email">Your address, if the directory has one.</param>
/// <param name="EmailVerified">Whether it has been proven.</param>
/// <param name="Roles">What your tokens claim you are. Every one the account holds, in id order.</param>
/// <param name="DisabledAt">When the account was disabled, if it is.</param>
/// <param name="HasPassword">Whether a password exists here at all - not what it is.</param>
public sealed record AccountView(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("handle")] string Handle,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("email_verified")] bool EmailVerified,
    [property: JsonPropertyName("role")] IReadOnlyList<string> Roles,
    [property: JsonPropertyName("disabled_at")] DateTimeOffset? DisabledAt,
    [property: JsonPropertyName("has_password")] bool HasPassword)
{
    /// <summary>Project an account for its owner.</summary>
    /// <param name="account">The account.</param>
    public static AccountView Of(UserAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);

        return new AccountView(
            account.Subject.Value,
            account.Username,
            account.Email,
            account.EmailVerified,
            account.Roles,
            account.DisabledAt,
            account.PasswordHash is not null);
    }
}

/// <summary>What changing a password reports.</summary>
/// <param name="Revoked">
/// How many sessions ended, when the caller asked for that. Zero otherwise, and the response says
/// nothing about the ones still running: they are, and <c>GET /account/sessions</c> is where to see
/// them.
/// </param>
public sealed record PasswordChangedView(
    [property: JsonPropertyName("sessions_revoked")] int Revoked);

/// <summary>One session, as its owner sees it.</summary>
/// <remarks>
/// <b>No token, no hash and no family id.</b> What a person needs to recognise a session is which
/// client, what it may do, and when it started - and anything more here is a credential-shaped value
/// in a response that a browser extension can read.
/// </remarks>
/// <param name="Id">The grant id. What <c>DELETE /account/sessions/{id}</c> takes.</param>
/// <param name="ClientId">Which client holds it.</param>
/// <param name="Scope">What it may do.</param>
/// <param name="Resources">Which resources it may reach.</param>
/// <param name="CreatedAt">When it was authorized.</param>
/// <param name="AuthTime">When the person actually signed in for it.</param>
public sealed record SessionView(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("resources")] IReadOnlyList<string> Resources,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("auth_time")] DateTimeOffset AuthTime)
{
    /// <summary>Project a grant for its owner.</summary>
    /// <param name="grant">The grant.</param>
    public static SessionView Of(GrantRecord grant)
    {
        ArgumentNullException.ThrowIfNull(grant);

        return new SessionView(
            grant.GrantId,
            grant.ClientId.Value,
            grant.Scope.ToWireString(),
            grant.Resources,
            grant.CreatedAt,
            grant.AuthTime);
    }
}

/// <summary>What ending a session reports.</summary>
/// <param name="Id">Which one.</param>
/// <param name="Revoked">
/// Whether <b>this call</b> ended it. False means it was already over, which is the honest answer to
/// a retry rather than an error.
/// </param>
public sealed record SessionEndedView(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("revoked")] bool Revoked);

/// <summary>One standing approval.</summary>
/// <param name="ClientId">Who you approved.</param>
/// <param name="Scope">What you approved.</param>
/// <param name="Resources">Which resources it covers.</param>
/// <param name="GrantedAt">When you last approved it.</param>
public sealed record ConsentView(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("resources")] IReadOnlyList<string> Resources,
    [property: JsonPropertyName("granted_at")] DateTimeOffset GrantedAt)
{
    /// <summary>Project a consent record for its owner.</summary>
    /// <param name="consent">The record.</param>
    public static ConsentView Of(ConsentRecord consent)
    {
        ArgumentNullException.ThrowIfNull(consent);

        return new ConsentView(
            consent.ClientId.Value,
            consent.Scope.ToWireString(),
            consent.Resources,
            consent.GrantedAt);
    }
}

/// <summary>What withdrawing an approval reports.</summary>
/// <param name="ClientId">Which client will be asked about again.</param>
/// <param name="SessionsRevoked">
/// Always false, and present so that nobody has to guess. Withdrawing consent means the next
/// authorization asks again; it does not end access already granted. That is
/// <c>DELETE /account/sessions/{id}</c>.
/// </param>
public sealed record ConsentWithdrawnView(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("sessions_revoked")] bool SessionsRevoked = false);
