using System.Text.Json.Serialization;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Clients;
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

/// <summary>The administrative surface. E-25 to E-32.</summary>
/// <remarks>
/// <para>
/// <b>Mapped only when a deployment asks for it</b>, because an admin API on an authorization server
/// is the highest-value target in the system: a flaw here is not a leaked document, it is the
/// directory. A deployment managing accounts over ssh should not be serving this at all, and
/// "routed or absent" is <c>N-06</c> besides.
/// </para>
/// <para>
/// <b>Bearer only — <c>N-17</c>.</b> Every route here refuses a cookie principal, and an
/// architecture test asserts over the routing table that none of them carries a cookie scheme. The
/// reasoning is on <see cref="AdminAuthorization"/>; the short version is that the sign-in pages
/// share this origin, so a cookie-authenticated admin API turns any XSS on the login page into
/// takeover of everyone.
/// </para>
/// <para>
/// <b>What revoking sessions reaches, since two endpoints here claim to do it.</b> Revoking a
/// grant kills every refresh chain descended from it — the refresh handler loads the grant and
/// refuses when it is not active. It does <b>not</b> reach an access token already issued: those are
/// signed rather than looked up, and <c>IGrantStore.IsRevokedAsync</c>, which exists for a resource
/// server to consult, is called by nothing in this repository. The responses say counts and never
/// "signed out", because the gap is one access-token lifetime long and an operator acting on an
/// incident is the person who most needs to know that.
/// </para>
/// </remarks>
public static class AdminEndpoints
{
    /// <summary>Map the administrative endpoints.</summary>
    /// <param name="endpoints">The route builder.</param>
    public static IEndpointRouteBuilder MapAdministration(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Every route below answers a script in a page, which can use the status and nothing else.
        // X-43.
        var api = endpoints.ShedsOnStoreFailure(OAuthSurface.Administration, rendered: false);


        // No `.RequireAuthorization()` and no auth scheme on any of these. The gate is inside each
        // handler, and that is deliberate: an ASP.NET Core authorization policy authenticates
        // against whatever schemes it is told to, and "whichever scheme the host made default" is
        // how a cookie ends up authenticating this surface. The architecture test asserts the
        // absence, so adding one is a failing build rather than a review comment.
        api.MapGet(AuthorizationServerPaths.AdminUsers, ListUsersAsync)
            .AllowAnonymous().WithName("boltway-admin-user-list");

        api.MapGet(AuthorizationServerPaths.AdminUser, GetUserAsync)
            .AllowAnonymous().WithName("boltway-admin-user-get");

        api.MapPost(AuthorizationServerPaths.AdminUsers, PostUserAsync)
            .AllowAnonymous().WithName("boltway-admin-user-create");

        endpoints.MapPatch(AuthorizationServerPaths.AdminUser, PatchUserAsync)
            .AllowAnonymous().WithName("boltway-admin-user-patch");

        api.MapPost(AuthorizationServerPaths.AdminUserPassword, PostPasswordAsync)
            .AllowAnonymous().WithName("boltway-admin-user-password");

        api.MapDelete(AuthorizationServerPaths.AdminUserSessions, DeleteSessionsAsync)
            .AllowAnonymous().WithName("boltway-admin-user-sessions");

        api.MapPost(AuthorizationServerPaths.AdminUserAnonymise, PostAnonymiseAsync)
            .AllowAnonymous().WithName("boltway-admin-user-anonymise");

        api.MapGet(AuthorizationServerPaths.AdminUserServiceAccount, GetServiceAccountAsync)
            .WithName("AdminGetServiceAccount");

        api.MapPost(AuthorizationServerPaths.AdminUserServiceAccount, PostServiceAccountAsync)
            .WithName("AdminPostServiceAccount");

        endpoints.MapPatch(AuthorizationServerPaths.AdminUserServiceAccount, PatchServiceAccountAsync)
            .WithName("AdminPatchServiceAccount");

        api.MapDelete(AuthorizationServerPaths.AdminUserServiceAccount, DeleteServiceAccountAsync)
            .WithName("AdminDeleteServiceAccount");

        api.MapGet(AuthorizationServerPaths.AdminRoles, ListRolesAsync)
            .AllowAnonymous().WithName("boltway-admin-role-list");

        api.MapPost(AuthorizationServerPaths.AdminRoles, PostRoleAsync)
            .AllowAnonymous().WithName("boltway-admin-role-create");

        endpoints.MapPatch(AuthorizationServerPaths.AdminRole, PatchRoleAsync)
            .AllowAnonymous().WithName("boltway-admin-role-patch");

        api.MapDelete(AuthorizationServerPaths.AdminRole, DeleteRoleAsync)
            .AllowAnonymous().WithName("boltway-admin-role-delete");

        api.MapGet(AuthorizationServerPaths.AdminAudit, GetAuditAsync)
            .AllowAnonymous().WithName("boltway-admin-audit");

        return endpoints;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-25  GET /admin/users
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A page of accounts, oldest first.
    /// </summary>
    /// <remarks>
    /// <b>Keyset, and the cursor is the last subject on the page.</b> <c>?after=<![CDATA[<subject>]]></c>
    /// rather than <c>?page=3</c>: subjects are ULIDs so ordering by subject is ordering by creation, and
    /// an offset would make the last page read every page before it — on the one table that grows
    /// for the life of the deployment, paged through exactly when somebody is trying to find
    /// something out.
    /// </remarks>
    private static async Task<IResult> ListUsersAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Read, out _) is { } refusal)
        {
            return refusal;
        }

        var limit = int.TryParse(http.Request.Query["limit"], out var requested)
            ? Math.Clamp(requested, 1, 200)
            : 50;

        var after = http.Request.Query["after"].ToString();

        var page = await Users(http).ListAsync(
            Realm(http),
            string.IsNullOrEmpty(after) ? null : SubjectId.FromStorage(after),
            limit,
            cancellationToken);

        // The cursor for the next call, or null when this page is the end. A total would be a second
        // query over the whole table for a number that is stale before it renders.
        return Results.Json(new UserPageView(
            [.. page.Select(AdminUserView.Of)],
            page.Count == limit ? page[^1].Subject.Value : null));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-26  GET /admin/users/{handle}
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetUserAsync(
        HttpContext http, string handle, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Read, out _) is { } refusal)
        {
            return refusal;
        }

        var account = await Users(http).FindByUsernameAsync(Realm(http), handle, cancellationToken);

        return account is null ? NotFound() : Results.Json(AdminUserView.Of(account));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-27  POST /admin/users
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> PostUserAsync(
        HttpContext http, CreateUserRequest? body, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal)
        {
            return refusal;
        }

        if (body is null || string.IsNullOrWhiteSpace(body.Handle))
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", "A handle is required.");
        }

        try
        {
            var created = await Administration(http).CreateAsync(
                actor, Realm(http), body.Handle, body.Email, body.Role, cancellationToken);

            // 201 with the password in the body, once. It is never stored in this form and there is
            // no endpoint that can show it again — the caller hands it to a person or loses it.
            return Results.Json(
                new CreatedUserView(
                    created.Subject.Value, created.Handle, created.Email, created.Role, created.Password),
                statusCode: StatusCodes.Status201Created);
        }
        catch (InvalidOperationException taken)
        {
            // The store's message, which already says accounts are add-only and why. 409 rather than
            // 400: the request was well-formed and the directory disagreed.
            return Problem(StatusCodes.Status409Conflict, "handle_taken", taken.Message);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-28  PATCH /admin/users/{handle}
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Change a role, an address, or whether the account may sign in.
    /// </summary>
    /// <remarks>
    /// <b>Absent means unchanged, and that is why every field is nullable with a sentinel.</b> A PATCH
    /// where a missing field meant "clear it" would turn "disable this account" into "disable it and
    /// remove its role and its email", which is the kind of thing discovered a week later. Clearing a
    /// role or an address is asked for explicitly with <c>"-"</c>, the same convention the CLI uses.
    /// </remarks>
    private static async Task<IResult> PatchUserAsync(
        HttpContext http, string handle, PatchUserRequest? body, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal)
        {
            return refusal;
        }

        if (body is null)
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", "A body is required.");
        }

        var service = Administration(http);
        var realm = Realm(http);
        var applied = 0;

        if (body.Role is not null)
        {
            var role = body.Role == "-" ? null : body.Role;
            var result = await service.SetRoleAsync(actor, realm, handle, role, cancellationToken);

            if (result.Status is AdministrationStatus.NoSuchAccount)
            {
                return NotFound();
            }

            applied++;
        }

        if (body.Roles is not null)
        {
            // Both fields are accepted and `roles` is the general one. Sending both is refused
            // rather than ranked: they are two ways to say the same thing, and picking a winner
            // would make `{"role":"founder","roles":[]}` mean whichever this file checks first.
            if (body.Role is not null)
            {
                return Problem(
                    StatusCodes.Status400BadRequest,
                    "invalid_request",
                    "Send `role` or `roles`, not both. They are two ways to set the same thing and there "
                    + "is no correct way to merge them.");
            }

            try
            {
                var result = await service.SetRolesAsync(actor, realm, handle, body.Roles, cancellationToken);

                if (result.Status is AdministrationStatus.NoSuchAccount)
                {
                    return NotFound();
                }
            }
            catch (InvalidOperationException undefined)
            {
                // The store's message names the id that does not exist, which is the caller's next
                // move. 409 rather than 404: the account was found and the directory disagreed
                // about the role.
                return Problem(StatusCodes.Status409Conflict, "no_such_role", undefined.Message);
            }

            applied++;
        }

        if (body.Email is not null)
        {
            var email = body.Email == "-" ? null : body.Email;
            var result = await service.SetEmailAsync(
                actor, realm, handle, email, body.EmailVerified ?? false, cancellationToken);

            if (result.Status is AdministrationStatus.NoSuchAccount)
            {
                return NotFound();
            }

            applied++;
        }

        if (body.Enabled is { } enabled)
        {
            var result = await service.SetEnabledAsync(
                actor, realm, handle, enabled, Clock(http).GetUtcNow(), cancellationToken);

            if (result.Status is AdministrationStatus.NoSuchAccount)
            {
                return NotFound();
            }

            applied++;
        }

        if (applied == 0)
        {
            // A PATCH that changed nothing is almost always a client sending a field this server does
            // not know about. Answering 200 would let it believe the change landed.
            return Problem(
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "No known field was present. Send role, email or enabled.");
        }

        var account = await Users(http).FindByUsernameAsync(realm, handle, cancellationToken);

        return account is null ? NotFound() : Results.Json(AdminUserView.Of(account));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-29  POST /admin/users/{handle}/password
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Generate a new password. <b>It takes none.</b>
    /// </summary>
    /// <remarks>
    /// There is no request body, because <see cref="UserAdministration"/> has no parameter for a
    /// password and adding one here would mean deleting a line the CLI depends on. A chosen password
    /// arriving over HTTP lands in a proxy log, an access log and whatever traced the request.
    /// </remarks>
    private static async Task<IResult> PostPasswordAsync(
        HttpContext http, string handle, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal)
        {
            return refusal;
        }

        var reset = await Administration(http)
            .ResetPasswordAsync(actor, Realm(http), handle, cancellationToken);

        return reset.Status switch
        {
            AdministrationStatus.Ok =>
                Results.Json(new PasswordView(reset.Subject.Value, reset.Password!)),
            AdministrationStatus.NoSuchAccount => NotFound(),
            _ => Problem(
                StatusCodes.Status409Conflict,
                "gone",
                "The account was there a moment ago and is not now. Something else changed the "
                + "directory while this ran."),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-30  DELETE /admin/users/{handle}/sessions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Revoke every grant this account holds.
    /// </summary>
    /// <remarks>
    /// <b>200 with a count, not 204.</b> How many were live is the thing the caller wants and cannot
    /// get any other way, and zero — "there was nothing to revoke" — is a different answer from "3
    /// sessions ended" that a no-content response would collapse. It is also what makes running this
    /// twice legible: the second call says zero.
    /// </remarks>
    private static async Task<IResult> DeleteSessionsAsync(
        HttpContext http, string handle, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal)
        {
            return refusal;
        }

        var result = await Administration(http).RevokeSessionsAsync(
            actor, Realm(http), handle, Clock(http).GetUtcNow(), cancellationToken);

        return result.Status switch
        {
            AdministrationStatus.Ok =>
                Results.Json(new SessionsRevokedView(result.Subject.Value!, result.Revoked)),
            AdministrationStatus.NoSuchAccount => NotFound(),
            _ => Gone(),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-31  POST /admin/users/{handle}/anonymise
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Anonymise an account. Irreversible, and it takes no body.
    /// </summary>
    /// <remarks>
    /// <b>No confirmation field, deliberately.</b> A <c>{"confirm": true}</c> in the body is a
    /// speed bump for a program and no protection at all — the thing that makes this hard to do by
    /// accident is that it is a distinct verb on a distinct path requiring <c>users:write</c>, not a
    /// flag somebody could pass to an update. What it does provide is a response that says what
    /// happened, so an accidental call is visible immediately rather than at the next sign-in.
    /// </remarks>
    private static async Task<IResult> PostAnonymiseAsync(
        HttpContext http, string handle, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal)
        {
            return refusal;
        }

        var result = await Administration(http).AnonymiseAsync(
            actor, Realm(http), handle, Clock(http).GetUtcNow(), cancellationToken);

        return result.Status switch
        {
            AdministrationStatus.Ok =>
                Results.Json(new AnonymisedView(result.Subject.Value!, result.Handle!, result.Revoked)),
            AdministrationStatus.NoSuchAccount => NotFound(),
            _ => Gone(),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-32  GET /admin/audit
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> GetAuditAsync(
        HttpContext http, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Read, out _) is { } refusal)
        {
            return refusal;
        }

        if (http.RequestServices.GetService<IAdminAuditStore>() is not { } audit)
        {
            // A deployment can run without an audit store — the service skips the entry rather than
            // refusing the operation. Saying so is better than an empty list, which reads as "nothing
            // has ever happened".
            return Problem(
                StatusCodes.Status501NotImplemented,
                "no_audit_store",
                "This deployment has no audit store registered, so no administrative action has been "
                + "recorded. Register an IAdminAuditStore.");
        }

        var limit = int.TryParse(http.Request.Query["limit"], out var requested)
            ? Math.Clamp(requested, 1, 500)
            : 100;

        var entries = await audit.ReadAsync(
            new AuditQuery(Realm(http), Limit: limit), cancellationToken);

        return Results.Json(entries.Select(AuditEntryView.Of).ToList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The refusal, or <see langword="null"/> when the caller may proceed.</summary>
    /// <remarks>
    /// <b>The three refusals are three different answers, and collapsing them would be wrong in both
    /// directions.</b> No principal is 401 with a challenge — the caller can fix it by
    /// authenticating. A cookie principal is 401 <i>without</i> inviting a retry with the same
    /// cookie, because no cookie will ever work here. Insufficient scope is 403: the caller is who
    /// they say and may not do this, and telling them to authenticate again would send them round a
    /// loop that cannot terminate.
    /// </remarks>
    private static IResult? Refuse(HttpContext http, string scope, out Actor actor) =>
        Refuse(http, [scope], out actor);

    /// <summary>
    /// The same gate for an endpoint that several scopes each allow — the role surface, where the
    /// narrow <c>roles:*</c> scope and the directory-wide <c>users:*</c> one are both enough.
    /// </summary>
    private static IResult? Refuse(HttpContext http, IReadOnlyList<string> anyOf, out Actor actor)
    {
        SecurityHeaders.Apply(http);

        var failure = AdminAuthorization.Check(http, anyOf, out var subject);

        if (failure is not AdminAuthorizationFailure.None)
        {
            // Logged here, with the correlation id, rather than through the rejection writer.
            //
            // A-09's requirement is that a refusal is visible and joinable — not that it travels
            // through one particular type — and this one is not an OAuth protocol error: it has no
            // row in the error table, no `error` code a client branches on, and no redirect. Minting
            // a table row for it would put an admin-API concern in the shared OAuth error surface.
            //
            // What matters is that it is not silent. A 401 on this endpoint is somebody probing the
            // directory with a cookie, or with a token minted for something else, and it never
            // reaches the audit log because it never reaches the service — so if it is not written
            // here it is written nowhere.
            http.RequestServices
                .GetService<Microsoft.Extensions.Logging.ILoggerFactory>()
                ?.CreateLogger("Boltway.AuthorizationServer.Admin")
                .LogWarning(
                    new Microsoft.Extensions.Logging.EventId(101, "AdminRefused"),
                    "Administrative request refused: {Failure}; scope={Scope}; path={Path}; "
                    + "correlation_id={CorrelationId}",
                    failure,
                    string.Join(' ', anyOf),
                    http.Request.Path.Value,
                    http.TraceIdentifier);
        }

        actor = new Actor(ActorKind.Client, subject.Value is null ? null : subject)
        {
            Client = http.User.FindFirst("client_id")?.Value,
            CorrelationId = http.TraceIdentifier,
        };

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
                "This endpoint is bearer-only. A session cookie authenticates the sign-in pages and "
                + "never this surface, so that any flaw in a page cannot become a change to the "
                + "directory."),

            // Every scope that would have done, so a caller holding the wrong token is sent for
            // the narrowest grant that works rather than for the only name the message happened
            // to say.
            _ => Problem(
                StatusCodes.Status403Forbidden,
                "insufficient_scope",
                anyOf.Count == 1
                    ? $"This token does not carry the '{anyOf[0]}' scope."
                    : "This token does not carry any of the scopes that allow this: "
                      + string.Join(", ", anyOf.Select(s => $"'{s}'")) + "."),
        };
    }

    /// <summary>
    /// A refusal that says nothing about whether the handle exists.
    /// </summary>
    /// <remarks>
    /// The caller already holds <c>users:read</c> or <c>users:write</c>, so "does this account exist"
    /// is not a secret from them — this is 404 because it is a 404, not to hide anything.
    /// </remarks>
    private static IResult NotFound() =>
        Problem(StatusCodes.Status404NotFound, "no_such_account", "No account with that handle.");

    /// <summary>Found, then not there when the write ran.</summary>
    private static IResult Gone() =>
        Problem(
            StatusCodes.Status409Conflict,
            "gone",
            "The account was there a moment ago and is not now. Something else changed the "
            + "directory while this ran.");

    private static IResult Problem(int status, string error, string description) =>
        Results.Json(new ProblemView(error, description), statusCode: status);

    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Every role this realm defines.</summary>
    /// <remarks>
    /// Behind <c>roles:read</c> — or <c>users:read</c>, which covers everything here — rather than
    /// open. A role list is the directory's own vocabulary and says what the deployment can grant,
    /// which is not something an unauthenticated caller has any business enumerating — and it is
    /// the list an admin page renders as choices, so the page is already holding a scope for it.
    /// The narrow one exists so a credential can read the vocabulary without being able to read a
    /// single account.
    /// </remarks>
    private static async Task<IResult> ListRolesAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (Refuse(http, [AdminScopes.RolesRead, AdminScopes.Read], out _) is { } refusal) return refusal;

        var roles = await Administration(http).ListRolesAsync(Realm(http), cancellationToken);

        return Results.Json(new { roles = roles.Select(AdminRoleView.Of).ToList() });
    }

    /// <summary>Define a role.</summary>
    /// <summary>Whether this account has a service account, and what it may do.</summary>
    private static async Task<IResult> GetServiceAccountAsync(
        HttpContext http, string handle, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Read, out _) is { } refusal) return refusal;

        var (account, client) = await Administration(http)
            .FindServiceAccountAsync(Realm(http), handle, cancellationToken);

        if (account is null) return NotFound();

        // 200 with a null body rather than 404 when the account exists and holds none. The question
        // "does this person have one" has the answer "no", and a 404 would say "no such person".
        return client is null
            ? Results.Json<AdminServiceAccountView?>(null)
            : Results.Json(AdminServiceAccountView.Of(client));
    }

    /// <summary>Create the service account, or rotate its secret.</summary>
    /// <remarks>
    /// <b>The response carries the plaintext secret and is the only time it exists.</b> It is not
    /// stored, so it cannot be fetched again — a caller that does not show it has destroyed it, and
    /// the recovery is to POST again, which rotates rather than refusing.
    /// </remarks>
    private static async Task<IResult> PostServiceAccountAsync(
        HttpContext http, string handle, CreateServiceAccountRequest? body,
        CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal) return refusal;

        try
        {
            var result = await Administration(http).CreateServiceAccountAsync(
                actor, Realm(http), handle, body?.Scopes ?? [], cancellationToken);

            if (result.Status is AdministrationStatus.NoSuchAccount) return NotFound();

            return Results.Json(
                new CreatedServiceAccountView(result.ClientId!, result.Secret!),
                statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException malformed)
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", malformed.Message);
        }
    }

    /// <summary>Turn it off or back on.</summary>
    private static async Task<IResult> PatchServiceAccountAsync(
        HttpContext http, string handle, PatchServiceAccountRequest? body,
        CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal) return refusal;

        if (body?.Enabled is not { } enabled)
        {
            return Problem(
                StatusCodes.Status400BadRequest, "invalid_request", "Send `enabled`, true or false.");
        }

        var result = await Administration(http)
            .SetServiceAccountEnabledAsync(actor, Realm(http), handle, enabled, cancellationToken);

        return result.Status is AdministrationStatus.NoSuchAccount ? NotFound() : Results.NoContent();
    }

    /// <summary>Remove it. The credential is gone; tokens already issued are not.</summary>
    private static async Task<IResult> DeleteServiceAccountAsync(
        HttpContext http, string handle, CancellationToken cancellationToken)
    {
        if (Refuse(http, AdminScopes.Write, out var actor) is { } refusal) return refusal;

        var result = await Administration(http)
            .DeleteServiceAccountAsync(actor, Realm(http), handle, cancellationToken);

        return result.Status is AdministrationStatus.NoSuchAccount ? NotFound() : Results.NoContent();
    }

    private static async Task<IResult> PostRoleAsync(
        HttpContext http, CreateRoleRequest? body, CancellationToken cancellationToken)
    {
        // roles:write or users:write — the narrow scope is a narrower domain, not a lesser danger;
        // AdminScopes has the argument. The same pair gates the two mutations below.
        if (Refuse(http, [AdminScopes.RolesWrite, AdminScopes.Write], out var actor) is { } refusal)
        {
            return refusal;
        }

        if (body is null || string.IsNullOrWhiteSpace(body.Id))
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", "A role needs an `id`.");
        }

        try
        {
            var role = await Administration(http).CreateRoleAsync(
                actor, Realm(http), body.Id, body.Name, body.Permissions ?? [], cancellationToken);

            return Results.Json(AdminRoleView.Of(role), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException malformed)
        {
            // RoleDefinition's own rules — blank, too long, or carrying whitespace. 400 rather than
            // 409: the request is wrong, not the directory's state.
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", malformed.Message);
        }
        catch (InvalidOperationException taken)
        {
            // The store's message, which already says roles are add-only and why. 409 for the same
            // reason a taken handle is: the request was well-formed and the directory disagreed.
            return Problem(StatusCodes.Status409Conflict, "role_exists", taken.Message);
        }
    }

    /// <summary>Reword a role, or replace what it stands for.</summary>
    /// <remarks>
    /// Absent means unchanged, the same convention <c>PATCH /admin/users/{handle}</c> uses. There is
    /// no clearing sentinel for permissions because an empty list already says it: a role that
    /// stands for nothing is a legitimate thing to define, unlike an account with no address.
    /// </remarks>
    private static async Task<IResult> PatchRoleAsync(
        HttpContext http, string id, PatchRoleRequest? body, CancellationToken cancellationToken)
    {
        if (Refuse(http, [AdminScopes.RolesWrite, AdminScopes.Write], out var actor) is { } refusal)
        {
            return refusal;
        }

        if (body is null)
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", "No body.");
        }

        var service = Administration(http);
        var realm = Realm(http);
        var applied = 0;

        if (body.Name is { Length: > 0 })
        {
            if (!await service.SetRoleNameAsync(actor, realm, id, body.Name, cancellationToken))
            {
                return NotFound();
            }

            applied++;
        }

        if (body.Permissions is not null)
        {
            try
            {
                if (!await service.SetRolePermissionsAsync(actor, realm, id, body.Permissions, cancellationToken))
                {
                    return NotFound();
                }
            }
            catch (ArgumentException malformed)
            {
                return Problem(StatusCodes.Status400BadRequest, "invalid_request", malformed.Message);
            }

            applied++;
        }

        if (applied == 0)
        {
            // The same refusal the user patch makes, and for the same reason: a PATCH that changed
            // nothing is almost always a client sending a field this server does not know about,
            // and answering 200 would let it believe the change landed.
            return Problem(
                StatusCodes.Status400BadRequest, "invalid_request", "No known field was present. Send name or permissions.");
        }

        var role = await service.FindRoleAsync(realm, id, cancellationToken);

        return role is null ? NotFound() : Results.Json(AdminRoleView.Of(role));
    }

    /// <summary>Remove a role, and every assignment of it.</summary>
    private static async Task<IResult> DeleteRoleAsync(
        HttpContext http, string id, CancellationToken cancellationToken)
    {
        if (Refuse(http, [AdminScopes.RolesWrite, AdminScopes.Write], out var actor) is { } refusal)
        {
            return refusal;
        }

        return await Administration(http).DeleteRoleAsync(actor, Realm(http), id, cancellationToken)
            ? Results.NoContent()
            : NotFound();
    }

    private static IUserStore Users(HttpContext http) =>
        http.RequestServices.GetRequiredService<IUserStore>();

    private static UserAdministration Administration(HttpContext http) =>
        http.RequestServices.GetRequiredService<UserAdministration>();

    private static TimeProvider Clock(HttpContext http) =>
        http.RequestServices.GetRequiredService<TimeProvider>();

    private static RealmId Realm(HttpContext http) =>
        http.RequestServices.GetRequiredService<AuthorizationServerOptions>().Realm;
}

/// <summary>What a create request may say.</summary>
/// <param name="Handle">What they will type at the login page.</param>
/// <param name="Email">Their address, or null.</param>
/// <param name="Role">What its tokens should claim, or null. Every one the account holds, in id order.</param>
/// <remarks>
/// <b>No password field, and its absence is the control.</b> The service generates one and has no
/// parameter for anything else; a field here would be the first half of adding one there.
/// </remarks>
public sealed record CreateUserRequest(
    [property: JsonPropertyName("handle")] string Handle,
    [property: JsonPropertyName("email")] string? Email = null,
    [property: JsonPropertyName("role")] string? Role = null);

/// <summary>What to create a service account with.</summary>
/// <param name="Scopes">
/// Exactly what its tokens will carry. Required, and not derivable.
/// </param>
/// <remarks>
/// A role holds <i>permissions</i> in the resource server's vocabulary and a token carries
/// <i>scopes</i> in OAuth's; nothing maps one to the other, so this cannot default from the owner's
/// roles and the caller names them.
/// </remarks>
public sealed record CreateServiceAccountRequest(
    [property: JsonPropertyName("scopes")] IReadOnlyList<string>? Scopes = null);

/// <summary>Whether a service account may obtain tokens.</summary>
/// <param name="Enabled">True to allow, false to stop.</param>
public sealed record PatchServiceAccountRequest(
    [property: JsonPropertyName("enabled")] bool? Enabled = null);

/// <summary>A service account, as the admin API returns it.</summary>
/// <param name="ClientId">What it presents as.</param>
/// <param name="Scopes">Exactly what its tokens carry.</param>
/// <param name="Enabled">Whether it may obtain tokens.</param>
/// <remarks>
/// <b>No secret, ever.</b> Only the digest is stored and even that stays here — an API returning a
/// credential's shadow makes every reader of its logs a candidate for an offline attack, the same
/// rule <see cref="AdminUserView"/> follows for password hashes.
/// </remarks>
public sealed record AdminServiceAccountView(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("scopes")] IReadOnlyList<string> Scopes,
    [property: JsonPropertyName("enabled")] bool Enabled)
{
    /// <summary>Project a client for the wire.</summary>
    /// <param name="client">The client.</param>
    public static AdminServiceAccountView Of(ClientRecord client)
    {
        ArgumentNullException.ThrowIfNull(client);

        return new AdminServiceAccountView(
            client.ClientId.Value ?? string.Empty, client.AllowedScopes.Values, client.IsEnabled);
    }
}

/// <summary>A service account just created, with the one copy of its secret.</summary>
/// <param name="ClientId">What it presents as.</param>
/// <param name="Secret">
/// The plaintext, <b>which exists only in this response</b>. Not stored, not recoverable, and
/// rotated by POSTing again.
/// </param>
public sealed record CreatedServiceAccountView(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("client_secret")] string Secret);

/// <summary>A role to define.</summary>
/// <param name="Id">The immutable id a token will carry. Matched ordinally and exactly.</param>
/// <param name="Name">What to call it. Defaults to the id when absent.</param>
/// <param name="Permissions">What it stands for, in the resource server's vocabulary.</param>
public sealed record CreateRoleRequest(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string? Name = null,
    [property: JsonPropertyName("permissions")] IReadOnlyList<string>? Permissions = null);

/// <summary>What a role patch may change. Absent means unchanged.</summary>
/// <param name="Name">The new name, or null to leave it alone.</param>
/// <param name="Permissions">
/// The new permissions, replacing all of them, or null to leave them alone. An empty list is a role
/// that stands for nothing, which is a thing a directory may legitimately hold — so there is no
/// clearing sentinel here, unlike an address.
/// </param>
public sealed record PatchRoleRequest(
    [property: JsonPropertyName("name")] string? Name = null,
    [property: JsonPropertyName("permissions")] IReadOnlyList<string>? Permissions = null);

/// <summary>A role, as the admin API returns it.</summary>
/// <param name="Id">What a token carries.</param>
/// <param name="Name">What a person reads.</param>
/// <param name="Permissions">What it stands for, in id order.</param>
public sealed record AdminRoleView(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("permissions")] IReadOnlyList<string> Permissions)
{
    /// <summary>Project a role for the wire.</summary>
    /// <param name="role">The role.</param>
    public static AdminRoleView Of(RoleDefinition role)
    {
        ArgumentNullException.ThrowIfNull(role);

        return new AdminRoleView(
            role.Id, role.Name, [.. role.Permissions.Order(StringComparer.Ordinal)]);
    }
}

/// <summary>What a patch may change. Absent means unchanged; <c>"-"</c> means cleared.</summary>
/// <param name="Role">The new role, <c>"-"</c> to clear, or null to leave alone.</param>
/// <param name="Roles">
/// Every role the account should hold, replacing all of them, or null to leave them alone. An empty
/// list clears them, which is what <c>"-"</c> means on the single-valued field. Sending both is
/// refused rather than ranked.
/// </param>
/// <param name="Email">The new address, <c>"-"</c> to clear, or null to leave alone.</param>
/// <param name="EmailVerified">Whether the address has been proven. Only read with an address.</param>
/// <param name="Enabled">Whether the account may sign in, or null to leave alone.</param>
public sealed record PatchUserRequest(
    [property: JsonPropertyName("role")] string? Role = null,
    [property: JsonPropertyName("roles")] IReadOnlyList<string>? Roles = null,
    [property: JsonPropertyName("email")] string? Email = null,
    [property: JsonPropertyName("email_verified")] bool? EmailVerified = null,
    [property: JsonPropertyName("enabled")] bool? Enabled = null);

/// <summary>An account, as the admin API returns it.</summary>
/// <remarks>
/// <b>No password hash, ever.</b> Not the stored value and not its length: a hash is a credential's
/// shadow, and an API that returns one has made every reader of its logs a candidate for an offline
/// attack.
/// </remarks>
/// <param name="Subject">The <c>sub</c>.</param>
/// <param name="Handle">What they type at the login page.</param>
/// <param name="Realm">Which directory.</param>
/// <param name="Email">Their address, if any.</param>
/// <param name="EmailVerified">Whether it has been proven.</param>
/// <param name="Roles">What its tokens claim. Every one the account holds, in id order.</param>
/// <param name="DisabledAt">When it was disabled, if it is.</param>
/// <param name="HasPassword">Whether a local password exists at all — not what it is.</param>
public sealed record AdminUserView(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("handle")] string Handle,
    [property: JsonPropertyName("realm")] string Realm,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("email_verified")] bool EmailVerified,
    [property: JsonPropertyName("role")] IReadOnlyList<string> Roles,
    [property: JsonPropertyName("disabled_at")] DateTimeOffset? DisabledAt,
    [property: JsonPropertyName("has_password")] bool HasPassword)
{
    /// <summary>Project an account for the wire.</summary>
    /// <param name="account">The account.</param>
    public static AdminUserView Of(UserAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);

        return new AdminUserView(
            account.Subject.Value,
            account.Username,
            account.Realm.OrDefault.Value,
            account.Email,
            account.EmailVerified,
            account.Roles,
            account.DisabledAt,
            account.PasswordHash is not null);
    }
}

/// <summary>A newly created account, and its password once.</summary>
/// <param name="Subject">The <c>sub</c> minted for it.</param>
/// <param name="Handle">What they type at the login page.</param>
/// <param name="Email">Their address, if one was given.</param>
/// <param name="Role">What its tokens will claim. Every one the account holds, in id order.</param>
/// <param name="Password">Generated here and returned once. Nothing can show it again.</param>
public sealed record CreatedUserView(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("handle")] string Handle,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("role")] string? Role,
    [property: JsonPropertyName("password")] string Password);

/// <summary>A reset password, once.</summary>
/// <param name="Subject">Whose.</param>
/// <param name="Password">The new one.</param>
public sealed record PasswordView(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("password")] string Password);

/// <summary>One audit entry, as the API returns it.</summary>
/// <param name="At">When.</param>
/// <param name="ActorKind">What sort of caller.</param>
/// <param name="ActorSubject">Which account acted, if one did.</param>
/// <param name="Action">What was done.</param>
/// <param name="TargetSubject">Whose account, if the handle resolved.</param>
/// <param name="TargetHandle">The handle as typed.</param>
/// <param name="Outcome">Whether it landed.</param>
/// <param name="Detail">What changed, in one short string.</param>
public sealed record AuditEntryView(
    [property: JsonPropertyName("at")] DateTimeOffset At,
    [property: JsonPropertyName("actor_kind")] string ActorKind,
    [property: JsonPropertyName("actor_subject")] string? ActorSubject,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("target_subject")] string? TargetSubject,
    [property: JsonPropertyName("target_handle")] string? TargetHandle,
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("detail")] string? Detail)
{
    /// <summary>Project an entry for the wire.</summary>
    /// <param name="entry">The entry.</param>
    public static AuditEntryView Of(AdminAuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return new AuditEntryView(
            entry.At,
            entry.ActorKind,
            entry.ActorSubject?.Value,
            entry.Action,
            entry.TargetSubject?.Value,
            entry.TargetHandle,
            entry.Outcome is AdminAuditOutcome.Succeeded ? "succeeded" : "refused",
            entry.Detail);
    }
}

/// <summary>What revoking an account's sessions did.</summary>
/// <param name="Subject">Whose.</param>
/// <param name="Revoked">
/// How many grants this call revoked. Zero means nothing was live, not that it failed.
/// </param>
/// <remarks>
/// <b>There is no "signed out" flag, because it would not be true.</b> Refresh chains die with the
/// grant; access tokens already issued are signed rather than looked up and keep working until they
/// expire. A field claiming otherwise is the kind of reassurance an operator acts on during an
/// incident.
/// </remarks>
public sealed record SessionsRevokedView(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("revoked")] int Revoked);

/// <summary>What anonymising an account did.</summary>
/// <param name="Subject">Which account — it still exists, which is the point.</param>
/// <param name="Handle">The tombstone the username became.</param>
/// <param name="Revoked">How many grants were revoked on the way.</param>
public sealed record AnonymisedView(
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("handle")] string Handle,
    [property: JsonPropertyName("revoked")] int Revoked);

/// <summary>One page of accounts, and where the next one starts.</summary>
/// <param name="Users">The accounts, oldest first.</param>
/// <param name="NextAfter">
/// The cursor for the next page, or <see langword="null"/> when this was the last one.
/// </param>
public sealed record UserPageView(
    [property: JsonPropertyName("users")] IReadOnlyList<AdminUserView> Users,
    [property: JsonPropertyName("next_after")] string? NextAfter);

/// <summary>A refusal, in the shape the OAuth endpoints already use.</summary>
/// <param name="Error">A stable code.</param>
/// <param name="Description">What to do about it.</param>
public sealed record ProblemView(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string Description);
