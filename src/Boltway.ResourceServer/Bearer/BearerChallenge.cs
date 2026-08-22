using System.Text.Json;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Http;
using Boltway.ResourceServer.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Boltway.ResourceServer.Bearer;

/// <summary>
/// Writes the <c>400</c>, <c>401</c> and <c>403</c> of X-32 through X-35, and logs every one.
/// </summary>
/// <remarks>
/// <para>
/// The status code is the protocol signal and the header is the payload; the body is advisory.
/// Three rules from the vendor research decide the shape of every response here.
/// </para>
/// <list type="number">
/// <item><description>
/// <b>It has to be a real <c>401</c>.</b> "Claude does not honor a <c>WWW-Authenticate</c> header
/// on a <c>200</c> response", and a <c>200</c> carrying <c>isError: true</c> produces no
/// authentication prompt at all — the text is handed to the model as a tool result and the
/// conversation moves on. That is the failure users report as "it told me to sign in instead of
/// showing a Connect button" (C-25).
/// </description></item>
/// <item><description>
/// <b><c>error</c> is emitted even when RFC 6750 §3.1 says to omit it.</b> §3.1 says a challenge
/// answering a request that carried no credentials at all should not include an error code. OpenAI
/// requires both <c>error</c> and <c>error_description</c> to trigger its authentication UI, and
/// Claude is content either way, so <c>invalid_token</c> is emitted in the no-credentials case too
/// (X-32). A challenge one vendor ignores is worse than a slightly over-specified one.
/// </description></item>
/// <item><description>
/// <b>A <c>403</c> without <c>error="insufficient_scope"</c> is terminal for Claude</b> — no
/// re-authentication prompt, permanently, for that user and server. So the only <c>403</c> this
/// type can produce is the scope one, and it always carries the full scope list (X-34).
/// </description></item>
/// </list>
/// <para>
/// Every <c>error_description</c> written here is a compile-time constant. The header builder in
/// Primitives strips <c>"</c>, <c>\</c> and control characters — an unescaped quote would terminate
/// the quoted string early and eat the <c>resource_metadata</c> that follows it, which is the
/// client's only route to discovering the authorization server — but the way to be certain no
/// attacker-chosen byte reaches a response header is never to put a request-derived one there.
/// </para>
/// <para>
/// <b>A-09, and this is where it matters most.</b> Four descriptions leave this type and one of them
/// covers everything: an unparseable JWT, a signature that does not verify, a <c>kid</c> that names
/// no key, an <c>alg</c> off the allow-list, a <c>typ</c> that is not <c>at+jwt</c> and an
/// <c>iss</c> mismatch are all "The access token is not valid." That is correct on the wire — none
/// of it is the client's business, and several of them tell an attacker which of their guesses was
/// closest — and it used to be the whole of what existed. The discriminating
/// <c>SecurityTokenException</c> was computed and dropped. A customer who rotates a signing key and
/// forgets <c>ProtectedResourceOptions.SigningKeys</c> got a wall of identical 401s with
/// <c>IDX10500: No security keys were provided</c> written nowhere. It now goes in the log, with the
/// exception type, next to the correlation id that is on the response they are holding.
/// </para>
/// </remarks>
internal static class BearerChallenge
{
    internal const string InvalidRequest = "invalid_request";
    internal const string InvalidToken = "invalid_token";
    internal const string InsufficientScope = "insufficient_scope";

    private const string AuthenticationRequired = "Authentication is required to access this resource.";
    private const string Expired = "The access token is expired.";
    private const string WrongAudience = "The access token was not issued for this resource.";
    private const string NotValid = "The access token is not valid.";

    /// <summary>What a caller whose session was ended is told.</summary>
    /// <remarks>
    /// Says what happened and what fixes it, because unlike every other description here this is a
    /// state the caller can act on and will otherwise misread: their token is not corrupt, their
    /// clock is not wrong, and re-authorizing genuinely works. It reveals nothing they do not
    /// already know — they are holding the token, and somebody ended its session on purpose.
    /// </remarks>
    private const string Revoked = "The access token's authorization has been ended. Authorize again.";
    private const string ScopeRequired = "The access token does not carry a scope this operation requires.";

    /// <summary>
    /// X-32: no credentials. <c>401</c>.
    /// </summary>
    /// <param name="context">The request being refused.</param>
    /// <param name="metadataUrl">The RFC 9728 §5.1 pointer. Present on every response this type writes.</param>
    /// <param name="scopes">
    /// What the client should ask for. The MCP scope-selection strategy reads this first and falls
    /// back to the metadata document's <c>scopes_supported</c> only when it is absent, so naming the
    /// scopes the endpoint actually needs here is what keeps a grant minimal.
    /// </param>
    internal static Task NoCredentialsAsync(
        HttpContext context, string metadataUrl, IReadOnlyList<string> scopes) =>
        WriteAsync(
            context,
            Rejection.Of(
                ReasonCode.BearerCredentialAbsent,
                OAuthErrorCode.InvalidToken,
                AuthenticationRequired,
                $"path={context.Request.Path}; required_scope={string.Join(' ', scopes)}"),
            metadataUrl,
            scopes);

    /// <summary>X-35: the credential was presented in a way that does not parse. <c>400</c>.</summary>
    /// <remarks>
    /// <c>400</c>, not <c>401</c>, and the requirement is emphatic about the direction: a <c>401</c>
    /// tells a client to refresh its token and try again, and a fresh token presented through the
    /// same broken header fails identically — "getting this backwards makes clients retry-loop
    /// forever on refresh".
    /// </remarks>
    internal static Task MalformedAsync(HttpContext context, string metadataUrl, string reason) =>
        WriteAsync(
            context,
            Rejection.Of(
                ReasonCode.BearerCredentialMalformed,
                OAuthErrorCode.InvalidRequest,
                reason,

                // The reason is already a constant from a closed set, so the client and the log get
                // the same sentence here. What the log adds is the path, which is what turns "one
                // client is broken" into "one route is behind a proxy that rewrites the header".
                $"path={context.Request.Path}"),
            metadataUrl,
            scopes: []);

    /// <summary>X-33: the token did not validate. <c>401</c>.</summary>
    /// <remarks>
    /// Including <see cref="AccessTokenFailure.WrongAudience"/>, which is N-01's second leg: a token
    /// minted for resource A and presented at resource B is <b>not</b> a <c>403</c>. It is a token
    /// this resource cannot accept, and the client's correct response is to obtain one that names
    /// this resource — which is what a <c>401</c> plus a metadata pointer asks it to do. A
    /// <c>403</c> here would be terminal for Claude and would leave the user with no way forward.
    /// </remarks>
    /// <param name="context">The request being refused.</param>
    /// <param name="metadataUrl">The RFC 9728 §5.1 pointer.</param>
    /// <param name="result">
    /// The validator's verdict, carrying the discriminating detail the response must not.
    /// </param>
    /// <param name="scopes">What the client should ask for.</param>
    internal static Task InvalidTokenAsync(
        HttpContext context, string metadataUrl, AccessTokenResult result, IReadOnlyList<string> scopes) =>
        WriteAsync(
            context,
            Rejection.Of(
                result.Failure switch
                {
                    AccessTokenFailure.Expired => ReasonCode.AccessTokenExpired,
                    AccessTokenFailure.WrongAudience => ReasonCode.AccessTokenWrongAudience,
                    AccessTokenFailure.Revoked => ReasonCode.AccessTokenRevoked,
                    _ => ReasonCode.AccessTokenRejected,
                },
                OAuthErrorCode.InvalidToken,
                result.Failure switch
                {
                    AccessTokenFailure.Expired => Expired,
                    AccessTokenFailure.WrongAudience => WrongAudience,
                    AccessTokenFailure.Revoked => Revoked,
                    _ => NotValid,
                },

                // The half the client never sees. `Diagnosis` is the validation exception's type and
                // message — "IDX10500: No security keys were provided", or an issuer mismatch naming
                // both issuers — which is the entire content of the answer to "why is every call
                // returning 401 since the deploy".
                $"path={context.Request.Path}; {result.Diagnosis}"),
            metadataUrl,
            scopes);

    /// <summary>X-34: valid token, missing scope. <c>403</c>.</summary>
    /// <param name="context">The request being refused.</param>
    /// <param name="metadataUrl">The RFC 9728 §5.1 pointer. X-34 requires it on this challenge too.</param>
    /// <param name="granted">The scopes the token actually carries. For the log only.</param>
    /// <param name="scopes">
    /// <b>Every</b> scope the operation needs, not only the missing ones. Claude requests the union
    /// of the challenge's scopes and its discovery-time scope, and it does not reliably carry
    /// forward scopes granted by an earlier step-up — so a challenge naming only the delta produces
    /// a re-authorization that drops the scopes the user already had.
    /// </param>
    internal static Task InsufficientScopeAsync(
        HttpContext context, string metadataUrl, IReadOnlyList<string> granted, IReadOnlyList<string> scopes) =>
        WriteAsync(
            context,
            Rejection.Of(
                ReasonCode.InsufficientScope,
                OAuthErrorCode.InsufficientScope,
                ScopeRequired,

                // Both lists. The challenge names what is required and says nothing about what was
                // presented, so from the client's side "I asked for that scope" and "the token does
                // not have it" are the same 403 — and the difference is a consent page that dropped
                // a scope versus an endpoint whose RequireScope is wrong.
                $"path={context.Request.Path}; required={string.Join(' ', scopes)}; granted={string.Join(' ', granted)}"),
            metadataUrl,
            scopes);

    /// <summary>
    /// The one place a rejection becomes a response on this server. A-09.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Private, and every entry point above goes through it, so writing the challenge and emitting
    /// the log are the same act. The status and the <c>error</c> value come from
    /// <see cref="OAuthErrors"/> rather than from constants here — this is the only
    /// <c>OAuthErrors.Resolve</c> call site in the assembly and an architecture rule says so, which
    /// is what makes "a 4xx from this assembly was logged" checkable rather than reviewed.
    /// </para>
    /// <para>
    /// Reading the status from the table is also a small correctness gain that came free: the
    /// 401/403/400 split and the three wire strings now have one definition shared with the
    /// authorization server, instead of a copy here that could drift from the one a client compares
    /// against.
    /// </para>
    /// </remarks>
    private static async Task WriteAsync(
        HttpContext context,
        Rejection rejection,
        string metadataUrl,
        IReadOnlyList<string> scopes)
    {
        var spec = OAuthErrors.Resolve(OAuthSurface.ResourceServer, rejection.Error);
        var response = context.Response;

        var logger = context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(RejectionLog.LoggerCategory);

        RejectionLog.Rejected(
            logger,
            // Every refusal here is 4xx: the client's request, not our fault. An operator who wants
            // to page on these is asking about a rate, which is a query over this event, not a level.
            LogLevel.Warning,
            OAuthSurface.ResourceServer,
            context.TraceIdentifier,
            rejection.Reason,
            spec.RequirementId,
            spec.Status,
            spec.Wire,
            rejection.Description,
            rejection.PrivateDetail,
            rejection.Cause);

        response.StatusCode = spec.Status;
        response.Headers.WWWAuthenticate =
            WwwAuthenticate.Bearer(spec.Wire, rejection.Description, metadataUrl, scopes);

        // A-09's other half: the id has to be in the response, not only in the log. Every challenge
        // this server writes carries it, which is what makes a screenshot of a failing `curl` enough
        // to find the line that says which key was missing.
        response.Headers[DiagnosticHeaders.RequestId] = context.TraceIdentifier;

        // A challenge is about this request's credentials and must never be reused for another's.
        response.Headers.CacheControl = "no-store";

        ExposeChallengeToTheBrowser(response);

        // RFC 6750 §3 puts the protocol signal in the header; this body is the advisory copy from
        // the canonical example, and it is what a human sees in a terminal. It is deliberately the
        // same two fields as the header carries — nothing here is a second source of truth.
        var body = JsonSerializer.SerializeToUtf8Bytes(
            new BearerErrorBody { Error = spec.Wire, ErrorDescription = rejection.Description },
            BearerErrorJsonContext.Default.BearerErrorBody);

        response.ContentType = "application/json";
        response.ContentLength = body.Length;

        // Writing a body to a HEAD response is a protocol error the framework papers over by
        // discarding it; returning early makes the Content-Length above the whole answer.
        if (HttpMethods.IsHead(context.Request.Method))
        {
            return;
        }

        await response.Body.WriteAsync(body, context.RequestAborted);
    }

    /// <summary>
    /// Let a cross-origin caller read <c>WWW-Authenticate</c>, but only if the host allowed it in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A browser hides every response header from script except a short safelist, and
    /// <c>WWW-Authenticate</c> is not on it. So a cross-origin client that the host has deliberately
    /// permitted still cannot read the one header the whole flow turns on, and sees an opaque
    /// failure instead of a discovery pointer.
    /// </para>
    /// <para>
    /// Conditional on <c>Access-Control-Allow-Origin</c> already being present, which means the
    /// host's own CORS policy has run and admitted this request. This adds nothing to a resource
    /// that is not cross-origin readable and grants nothing that was not already granted — the
    /// endpoint table gives E-24 no CORS at all, and that decision stays the host's to make.
    /// </para>
    /// <para>
    /// <c>X-Request-Id</c> is exposed alongside it, and for the same reason: a browser-based client
    /// that can see the challenge but not the correlation id can report "it failed" and nothing an
    /// operator can search for.
    /// </para>
    /// </remarks>
    private static void ExposeChallengeToTheBrowser(HttpResponse response)
    {
        if (response.Headers.ContainsKey(HeaderNames.AccessControlAllowOrigin)
            && !response.Headers.ContainsKey(HeaderNames.AccessControlExposeHeaders))
        {
            response.Headers[HeaderNames.AccessControlExposeHeaders] =
                HeaderNames.WWWAuthenticate + ", " + DiagnosticHeaders.RequestId;
        }
    }
}
