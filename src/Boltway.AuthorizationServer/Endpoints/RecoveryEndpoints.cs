using System.Text.Json.Serialization;
using Boltway.AuthorizationServer.Administration;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>The two flows that reach a person by email. E-39 to E-44.</summary>
/// <remarks>
/// <para>
/// <b>Public — no cookie, no bearer, no session.</b> Everything else on this server is reached by
/// somebody who can already prove who they are; these are reached by somebody who cannot, which is
/// the whole point and the source of every rule below.
/// </para>
/// <para>
/// <b>Three endpoints and three pages, shipped together.</b> <c>E-40</c> and <c>E-41</c> on their
/// own are a design that mails somebody a URL answering 405 — §7.3. The pages are where a link in an
/// email actually lands; the endpoints are for a caller driving the flow programmatically. The third
/// page, <c>/forgot</c>, is the same argument at the other end of the flow: <c>E-39</c> answers JSON,
/// so without it the sign-in page's "I have forgotten my password" link has nowhere to go and a
/// deployment has to tell people the URL by hand.
/// </para>
/// <para>
/// <b><c>S-48</c>: asking for a reset says the same thing whether or not the account exists</b>, and
/// <see cref="AccountRecovery.RequestPasswordResetAsync"/> does the same work either way, so neither
/// the body nor the timing distinguishes them. This handler cannot break that rule by accident,
/// because the method it calls returns nothing there is to report.
/// </para>
/// <para>
/// <b>§3.1: this is an outbound spam vector and it is bounded.</b> <c>E-39</c> sends mail to an
/// address the caller chooses, so the cost of an unbounded request lands on somebody who is not
/// making it. <see cref="RecoveryThrottle"/> counts per submitted identifier and per source, and
/// like every limit here it is per process — <c>X-31</c>.
/// </para>
/// </remarks>
public static class RecoveryEndpoints
{
    /// <summary>Map the recovery endpoints and their pages.</summary>
    /// <param name="endpoints">The route builder.</param>
    public static IEndpointRouteBuilder MapPasswordRecovery(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // **This is the one file that maps both halves, so it declares both.** The three routes
        // under `/account/` are the JSON API a script calls; the five below them are the pages a
        // person is sent to by an email. They share a file because they share the token logic, not
        // because they answer the same caller — and on a store failure the difference is the whole
        // answer: a script can use a status, and somebody who has just clicked a reset link cannot.
        // X-43.
        var api = endpoints.ShedsOnStoreFailure(OAuthSurface.Administration, rendered: false);
        var pages = endpoints.ShedsOnStoreFailure(OAuthSurface.Interaction, rendered: true);

        api.MapPost(AuthorizationServerPaths.AccountPasswordForgot, (Delegate)PostForgotAsync)
            .AllowAnonymous().WithName("boltway-password-forgot");

        api.MapPost(AuthorizationServerPaths.AccountPasswordReset, PostResetApiAsync)
            .AllowAnonymous().WithName("boltway-password-reset");

        api.MapPost(AuthorizationServerPaths.AccountEmailVerify, PostVerifyApiAsync)
            .AllowAnonymous().WithName("boltway-email-verify");

        pages.MapGet(AuthorizationServerPaths.Reset, GetResetPage)
            .AllowAnonymous().WithName("boltway-reset-page");

        pages.MapPost(AuthorizationServerPaths.Reset, (Delegate)PostResetPageAsync)
            .AllowAnonymous().WithName("boltway-reset-page-post");

        pages.MapGet(AuthorizationServerPaths.VerifyEmail, GetVerifyPageAsync)
            .AllowAnonymous().WithName("boltway-verify-page");

        pages.MapGet(AuthorizationServerPaths.Forgot, GetForgotPage)
            .AllowAnonymous().WithName("boltway-forgot-page");

        pages.MapPost(AuthorizationServerPaths.Forgot, (Delegate)PostForgotPageAsync)
            .AllowAnonymous().WithName("boltway-forgot-page-post");

        return endpoints;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-39  POST /account/password/forgot
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Ask for a reset link. <c>S-48</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>202 with the same body every time</b>, and the sentence is deliberately about what will
    /// happen rather than about what was found: "if that account exists, a link is on its way". A
    /// 404 for an unknown address, or a different sentence, would make this endpoint a way to test
    /// which addresses are registered, at whatever rate the throttle allows.
    /// </para>
    /// <para>
    /// <b>202 rather than 200</b>, because nothing has been delivered yet and the server does not
    /// know whether it will be. A mail server accepting a message is not a person receiving one.
    /// </para>
    /// <para>
    /// <b>A missing or empty identifier is answered the same way</b>, and still costs a throttle
    /// slot. Refusing it with a 400 would be a free probe: an attacker learns nothing from it, but
    /// they also spend nothing, and the counter is the thing standing between them and the mailbox.
    /// </para>
    /// </remarks>
    private static async Task<IResult> PostForgotAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        var body = await ReadIdentifierAsync(http, cancellationToken);

        // Charged before anything is looked up, so the counter cannot depend on whether the account
        // exists — the same ordering LoginThrottle uses and for the same reason.
        var admission = Throttle(http).Admit(body, http);

        if (!admission.Allowed)
        {
            return TooManyRequests(http, admission);
        }

        await Recovery(http).RequestPasswordResetAsync(body ?? string.Empty, cancellationToken);

        return Results.Json(
            new AcceptedView(
                "If an account matches, a link to reset its password is on its way. The link "
                + "expires, and can only be used once."),
            statusCode: StatusCodes.Status202Accepted);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-40  POST /account/password/reset
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> PostResetApiAsync(
        HttpContext http, ResetPasswordRequest? body, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (body is null || string.IsNullOrEmpty(body.Token))
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", "Send token and new_password.");
        }

        // Redemption is throttled on the token rather than on an identifier: the thing being bounded
        // here is guessing, not mail. 256 bits makes that hopeless anyway, and the counter costs
        // nothing to keep.
        var admission = Throttle(http).Admit(body.Token, http);

        if (!admission.Allowed)
        {
            return TooManyRequests(http, admission);
        }

        var result = await Recovery(http).RedeemPasswordResetAsync(
            body.Token, body.NewPassword ?? string.Empty, cancellationToken);

        return result.Outcome switch
        {
            RecoveryOutcome.Ok => Results.Json(new ResetDoneView(result.SessionsRevoked)),

            RecoveryOutcome.BlankPassword => Problem(
                StatusCodes.Status400BadRequest, "invalid_request", "The new password is blank."),

            // Expired, used and never-issued are one answer. §7.3 — there is nothing to enumerate,
            // and a person not told their link expired clicks it again rather than asking for a new
            // one.
            _ => Problem(
                StatusCodes.Status400BadRequest,
                "invalid_token",
                "This link no longer works. A reset link can only be used once, and it expires."),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-41  POST /account/email/verify
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<IResult> PostVerifyApiAsync(
        HttpContext http, VerifyEmailRequest? body, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (body is null || string.IsNullOrEmpty(body.Token))
        {
            return Problem(StatusCodes.Status400BadRequest, "invalid_request", "Send token.");
        }

        var admission = Throttle(http).Admit(body.Token, http);

        if (!admission.Allowed)
        {
            return TooManyRequests(http, admission);
        }

        var result = await Recovery(http).VerifyEmailAsync(body.Token, cancellationToken);

        return result.Outcome is RecoveryOutcome.Ok
            ? Results.Json(new VerifiedView(result.Email!))
            : Problem(
                StatusCodes.Status400BadRequest,
                "invalid_token",
                "This link no longer works. A confirmation link can only be used once, and it expires.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-42, E-43  /reset
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The form a reset link lands on.
    /// </summary>
    /// <remarks>
    /// <b>The token is not redeemed here.</b> Drawing the form does not consume it, so a person who
    /// opens the link, gets distracted and comes back still has a working link — and, more to the
    /// point, an email client that pre-fetches URLs does not silently destroy the reset it was
    /// delivering. Redemption happens on the POST, which is what a scanner does not do.
    /// </remarks>
    private static IResult GetResetPage(HttpContext http)
    {
        SecurityHeaders.Apply(http);

        var token = http.Request.Query["token"].ToString();

        return ResetPage(
            http,
            string.IsNullOrEmpty(token) ? ResetPasswordState.Expired : ResetPasswordState.Form,
            token);
    }

    private static async Task<IResult> PostResetPageAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);
        var token = form["token"].ToString();
        var replacement = form["new"].ToString();

        var admission = Throttle(http).Admit(token, http);

        if (!admission.Allowed)
        {
            return TooManyRequests(http, admission);
        }

        // Checked before redemption, so a mistyped confirmation does not consume the link and leave
        // somebody asking for a second one to fix a typo.
        if (!string.Equals(replacement, form["confirm"].ToString(), StringComparison.Ordinal))
        {
            return ResetPage(http, ResetPasswordState.Mismatch, token);
        }

        var result = await Recovery(http).RedeemPasswordResetAsync(token, replacement, cancellationToken);

        return result.Outcome switch
        {
            RecoveryOutcome.Ok => ResetPage(http, ResetPasswordState.Done, token, result.SessionsRevoked),
            RecoveryOutcome.BlankPassword => ResetPage(http, ResetPasswordState.Blank, token),
            _ => ResetPage(http, ResetPasswordState.Expired, token),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-44  /verify-email
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Where a verification link lands, and the one page here that acts on a GET.
    /// </summary>
    /// <remarks>
    /// <b>A GET that changes state, deliberately.</b> The alternative is a page with a button, and
    /// the thing being protected is an address the reader already controls — the worst outcome of a
    /// pre-fetching mail client following this is that the address gets marked as theirs, which is
    /// what they were being asked to confirm. Weighed against a confirmation step everybody clicks
    /// through, this is the better trade. <c>/reset</c> makes the opposite call because what it
    /// changes is a credential.
    /// </remarks>
    private static async Task<IResult> GetVerifyPageAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        var token = http.Request.Query["token"].ToString();
        var result = await Recovery(http).VerifyEmailAsync(token, cancellationToken);
        var renderer = http.RequestServices.GetRequiredService<IInteractionRenderer>();

        return Html(renderer.RenderVerifyEmail(new VerifyEmailPageModel(
            result.Outcome is RecoveryOutcome.Ok,
            result.Email,
            SecurityHeaders.NonceFor(http))));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E-39, in a browser  /forgot
    // ─────────────────────────────────────────────────────────────────────────

    private static IResult GetForgotPage(HttpContext http)
    {
        SecurityHeaders.Apply(http);

        return ForgotPage(http, ForgotPasswordState.Form);
    }

    /// <summary>
    /// Ask for a reset link, from a browser.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The same service <c>E-39</c> calls, in process</b> — §1.13, the pattern <c>/me/*</c>
    /// already follows. Posting the form to <c>E-39</c> itself would be the smaller diff and would
    /// show a person a line of JSON; content-negotiating that endpoint would put a branch on the one
    /// surface whose whole design is that it answers identically every time.
    /// </para>
    /// <para>
    /// <b>Every rule <c>E-39</c> holds to, this holds to.</b> <c>S-48</c>: one answer, whether or
    /// not an account matched, because <see cref="AccountRecovery.RequestPasswordResetAsync"/>
    /// returns nothing there is to report. §3.1: the same throttle, charged before any lookup, so
    /// the counter cannot depend on whether the account exists — and adding a page must not become
    /// a way around a limit that exists to stop this server mailing strangers.
    /// </para>
    /// <para>
    /// <b>Antiforgery, unlike <c>E-39</c>.</b> Not because a forged request here is an escalation —
    /// it makes somebody's browser ask for a mail to an address the attacker already knows — but
    /// because it is a state-changing form on the origin that carries the session cookie, and the
    /// other forms on it are protected. A page that is the exception is the one somebody copies.
    /// </para>
    /// </remarks>
    private static async Task<IResult> PostForgotPageAsync(HttpContext http, CancellationToken cancellationToken)
    {
        SecurityHeaders.Apply(http);

        if (!await InteractionEndpoints.IsAntiforgeryValidAsync(http))
        {
            return InteractionEndpoints.AntiforgeryFailure(http);
        }

        var form = await http.Request.ReadFormAsync(cancellationToken);
        var account = form["account"].ToString();

        var admission = Throttle(http).Admit(account, http);

        if (!admission.Allowed)
        {
            // Retry-After on the page too. A person reads the sentence and a client reads the
            // header, and the endpoint that answers JSON already sets it — a page that dropped it
            // would make the two surfaces disagree about a fact neither of them is guessing at.
            http.Response.Headers.RetryAfter = ((int)Math.Ceiling(admission.RetryAfter.TotalSeconds))
                .ToString(System.Globalization.CultureInfo.InvariantCulture);

            return ForgotPage(http, ForgotPasswordState.Throttled);
        }

        await Recovery(http).RequestPasswordResetAsync(account, cancellationToken);

        return ForgotPage(http, ForgotPasswordState.Sent);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // shared
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The identifier out of a JSON body or a form post.
    /// </summary>
    /// <remarks>
    /// Both, because this endpoint has two callers with different habits: a program sending JSON and
    /// a sign-in page's "forgot password" form. Accepting one and refusing the other would push the
    /// second into building a JSON request from a browser, which needs script on a page whose whole
    /// design is that it has none.
    /// </remarks>
    private static async Task<string?> ReadIdentifierAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (http.Request.HasFormContentType)
        {
            var form = await http.Request.ReadFormAsync(cancellationToken);

            return form["account"].ToString();
        }

        try
        {
            var body = await http.Request.ReadFromJsonAsync<ForgotPasswordRequest>(cancellationToken);

            return body?.Account;
        }
        catch (System.Text.Json.JsonException)
        {
            // Unparseable is the same as absent. It still costs a throttle slot and still gets the
            // 202 — a 400 here would tell a caller their request reached the handler, which is one
            // bit more than the endpoint means to give away.
            return null;
        }
    }

    /// <summary>
    /// Where "go to sign in" goes, or <see langword="null"/> when nowhere does.
    /// </summary>
    /// <remarks>
    /// One implementation, in <see cref="InteractionEndpoints"/>, because the sign-out page needs
    /// the same answer and two copies of "where does a person go when they are finished" is how the
    /// pages come to disagree. This copy was the original and lived here for a day.
    /// <para>
    /// <c>/me</c> is an allowed return target and the natural one after a reset — sign in, see the
    /// account you just recovered — but it exists only when the self-service pages are routed, so
    /// when they are not this is null and the pages draw no link rather than one that fails.
    /// </para>
    /// </remarks>
    private static string? SignInUrlFor(HttpContext http) => InteractionEndpoints.SignInUrlFor(http);

    private static IResult ResetPage(
        HttpContext http, ResetPasswordState state, string token, int revoked = 0)
    {
        var tokens = InteractionEndpoints.AntiforgeryTokensFor(http);
        var renderer = http.RequestServices.GetRequiredService<IInteractionRenderer>();

        return Html(renderer.RenderResetPassword(new ResetPasswordPageModel(
            state,
            token,
            revoked,
            tokens.FormFieldName,
            tokens.RequestToken!,
            SecurityHeaders.NonceFor(http),
            SignInUrlFor(http))));
    }

    private static IResult ForgotPage(HttpContext http, ForgotPasswordState state)
    {
        var tokens = InteractionEndpoints.AntiforgeryTokensFor(http);
        var renderer = http.RequestServices.GetRequiredService<IInteractionRenderer>();

        return Html(renderer.RenderForgotPassword(new ForgotPasswordPageModel(
            state,
            tokens.FormFieldName,
            tokens.RequestToken!,
            SecurityHeaders.NonceFor(http),
            SignInUrlFor(http))));
    }

    private static IResult Html(string html) => Results.Content(html, "text/html; charset=utf-8");

    private static IResult TooManyRequests(HttpContext http, LoginAdmission admission)
    {
        http.Response.Headers.RetryAfter = ((int)Math.Ceiling(admission.RetryAfter.TotalSeconds))
            .ToString(System.Globalization.CultureInfo.InvariantCulture);

        return Problem(StatusCodes.Status429TooManyRequests, "too_many_requests", admission.Description);
    }

    private static IResult Problem(int status, string error, string description) =>
        Results.Json(new ProblemView(error, description), statusCode: status);

    private static AccountRecovery Recovery(HttpContext http) =>
        http.RequestServices.GetRequiredService<AccountRecovery>();

    private static RecoveryThrottle Throttle(HttpContext http) =>
        http.RequestServices.GetRequiredService<RecoveryThrottle>();
}

/// <summary>What a reset request carries.</summary>
/// <param name="Account">A handle or an email address — whichever the person remembers.</param>
public sealed record ForgotPasswordRequest(
    [property: JsonPropertyName("account")] string? Account);

/// <summary>What a reset redemption carries.</summary>
/// <param name="Token">The value out of the link.</param>
/// <param name="NewPassword">What to set.</param>
public sealed record ResetPasswordRequest(
    [property: JsonPropertyName("token")] string Token,
    [property: JsonPropertyName("new_password")] string? NewPassword);

/// <summary>What a verification redemption carries.</summary>
/// <param name="Token">The value out of the link.</param>
public sealed record VerifyEmailRequest(
    [property: JsonPropertyName("token")] string Token);

/// <summary>The one answer <c>E-39</c> ever gives. <c>S-48</c>.</summary>
/// <param name="Message">What will happen, said without reference to what was found.</param>
public sealed record AcceptedView(
    [property: JsonPropertyName("message")] string Message);

/// <summary>What a successful reset reports.</summary>
/// <param name="SessionsRevoked">
/// How many sessions ended. Always every one of them on this route — §1.10, because somebody
/// resetting through email is usually doing it because they lost control of something.
/// </param>
public sealed record ResetDoneView(
    [property: JsonPropertyName("sessions_revoked")] int SessionsRevoked);

/// <summary>What a successful verification reports.</summary>
/// <param name="Email">The address now recorded as proven.</param>
public sealed record VerifiedView(
    [property: JsonPropertyName("email")] string Email);
