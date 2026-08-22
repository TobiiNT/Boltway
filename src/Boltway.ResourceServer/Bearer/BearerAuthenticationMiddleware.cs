using Boltway.ResourceServer.Authorization;
using Boltway.ResourceServer.Configuration;
using Boltway.ResourceServer.Revocation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Boltway.ResourceServer.Bearer;

/// <summary>
/// The gate: turns a missing, malformed, invalid or under-scoped access token into X-32..X-35.
/// </summary>
/// <remarks>
/// <para>
/// <b>Placed before the endpoint runs, and that placement is the requirement.</b> Once a handler has
/// executed, whatever it returns is already destined for a <c>200</c> — and a <c>200</c> carrying an
/// error is precisely what produces no authentication prompt in Claude. The gate has to be
/// upstream of the application's own code, which for an MCP server means upstream of the JSON-RPC
/// message ever reaching the SDK.
/// </para>
/// <para>
/// It runs <i>after</i> routing, because what it does depends on the endpoint: whether the endpoint
/// is anonymous, and which scopes it declares. A request that matched no endpoint is left alone —
/// see <see cref="ProtectedResourceOptions.RequireBearerByDefault"/> for why a 404 is the better
/// answer there than a challenge.
/// </para>
/// <para>
/// The middleware is written by hand rather than as an
/// <c>AuthenticationHandler&lt;TOptions&gt;</c>. The stock JWT bearer handler's challenge does not
/// include <c>resource_metadata</c>, so every deployment has to reach into <c>OnChallenge</c>,
/// suppress the default header and rebuild it — and a deployment that forgets emits a challenge
/// with no discovery pointer, which is the one failure that leaves a client with nowhere to go. The
/// pointer is not an option here; it is on every response this type writes.
/// </para>
/// </remarks>
internal sealed class BearerAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ProtectedResource _resource;
    private readonly AccessTokenValidator _validator;
    private readonly ProtectedResourceOptions _options;

    public BearerAuthenticationMiddleware(
        RequestDelegate next,
        ProtectedResource resource,
        AccessTokenValidator validator,
        IOptions<ProtectedResourceOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _next = next;
        _resource = resource;
        _validator = validator;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var endpoint = context.GetEndpoint();

        if (endpoint is null)
        {
            await _next(context);
            return;
        }

        if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            // Anonymous means "credentials are not required", not "credentials are ignored". An
            // endpoint that decides for itself still has to be told who is asking, so a token
            // presented here is validated and the principal set — and nothing is ever challenged,
            // because the endpoint said it does not need one.
            //
            // **This gap was measured rather than reasoned about.** The authorization server's own
            // `/admin/*` routes are AllowAnonymous on purpose — an authorization policy would
            // authenticate against whichever scheme the host made default, which is how a session
            // cookie ends up authenticating the directory (N-17) — and they read `HttpContext.User`
            // inside each handler. With the early return above covering them, that principal was
            // never populated: every bearer token was answered "Unauthenticated", and the admin API
            // had never worked from the deployable image. Found by pointing the admin BFF at it.
            await AuthenticateWithoutChallengingAsync(context);
            await _next(context);
            return;
        }

        var required = RequiredScopes(endpoint.Metadata);

        var protectedEndpoint =
            _options.RequireBearerByDefault
            || endpoint.Metadata.GetMetadata<RequireBearerMetadata>() is not null
            || required.Count > 0;

        if (!protectedEndpoint)
        {
            await _next(context);
            return;
        }

        // The scopes named in a 401. The endpoint's own list when it has one, so the client asks
        // for the minimum; the whole advertised set otherwise, which mirrors the fallback the MCP
        // scope-selection strategy applies when a challenge carries no `scope` at all.
        var challengeScopes = required.Count > 0 ? (IReadOnlyList<string>)required : _resource.ScopesSupported;

        var credential = BearerCredential.Read(context.Request);

        switch (credential.Kind)
        {
            case BearerCredentialKind.Absent:
                await BearerChallenge.NoCredentialsAsync(context, _resource.MetadataUrl, challengeScopes);
                return;

            case BearerCredentialKind.Malformed:
                await BearerChallenge.MalformedAsync(context, _resource.MetadataUrl, credential.Reason!);
                return;

            case BearerCredentialKind.Present:
                break;

            default:
                // Unreachable: the enum is closed and every member is handled above. Refusing
                // rather than falling through, because the alternative shape of this switch — a
                // default that continues to _next — turns any future member into an authentication
                // bypass that compiles cleanly.
                await BearerChallenge.NoCredentialsAsync(context, _resource.MetadataUrl, challengeScopes);
                return;
        }

        var result = await _validator.ValidateAsync(credential.Token!);

        if (result.Failure is not AccessTokenFailure.None)
        {
            // The whole result, not just the kind. The kind picks one of three constant descriptions
            // for the client; the diagnosis that came with it is what the log needs and the client
            // must not have.
            await BearerChallenge.InvalidTokenAsync(
                context, _resource.MetadataUrl, result, challengeScopes);
            return;
        }

        if (!HasEveryScope(result.Scopes.Values, required))
        {
            await BearerChallenge.InsufficientScopeAsync(
                context, _resource.MetadataUrl, result.Scopes.Values, required);
            return;
        }

        // The one question the signature cannot answer: has somebody ended this session since the
        // token was minted. Asked after every offline check has passed, so the round trip is spent
        // only on tokens that were going to be accepted — and skipped entirely on a deployment that
        // has registered no check, which is what every deployment had before this seam existed.
        //
        // Resolved from the request's container rather than injected into the constructor: this
        // middleware is built once from the root provider, and an implementation that wants a
        // scoped dependency — an HttpContext-aware client, a per-request cache — would otherwise be
        // a captive dependency held for the life of the process.
        if (context.RequestServices.GetService<IAccessTokenRevocationCheck>() is { } revocation
            && await revocation.IsRevokedAsync(credential.Token!, result.Principal!, context.RequestAborted))
        {
            // The same 401 shape as any other invalid token, which is RFC 6750 §3.1: `invalid_token`
            // covers "revoked" explicitly, and it is the answer that makes a client re-authorize
            // rather than retry. The description differs and the reason code differs; the status,
            // the error and the `resource_metadata` pointer do not.
            await BearerChallenge.InvalidTokenAsync(
                context,
                _resource.MetadataUrl,
                result with
                {
                    Failure = AccessTokenFailure.Revoked,
                    Diagnosis = "the authorization behind this token has been revoked",
                },
                challengeScopes);
            return;
        }

        context.Features.Set(new BearerTokenFeature(result.Principal!, result.Scopes.Values));
        context.User = result.Principal!;

        await _next(context);
    }

    /// <summary>
    /// Set the principal if a valid token was presented, and do nothing otherwise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Silent on every failure.</b> A missing token on an anonymous endpoint is the ordinary
    /// case; a malformed or invalid one is a caller's problem to discover from the endpoint's own
    /// answer, which is written to say what that endpoint needs. Challenging here would override a
    /// refusal somebody wrote deliberately — <c>AdminEndpoints</c>' 401 explains that the surface is
    /// bearer-only and why, which is more use than a generic <c>invalid_token</c>.
    /// </para>
    /// <para>
    /// <b>Scopes are not checked here either.</b> An anonymous endpoint declares none — it is
    /// deciding for itself — and inventing a requirement would refuse a caller the endpoint would
    /// have admitted.
    /// </para>
    /// </remarks>
    private async Task AuthenticateWithoutChallengingAsync(HttpContext context)
    {
        var credential = BearerCredential.Read(context.Request);

        if (credential.Kind is not BearerCredentialKind.Present)
        {
            return;
        }

        var result = await _validator.ValidateAsync(credential.Token!);

        if (result.Failure is not AccessTokenFailure.None)
        {
            return;
        }

        context.Features.Set(new BearerTokenFeature(result.Principal!, result.Scopes.Values));
        context.User = result.Principal!;
    }

    /// <summary>
    /// Every scope declared on the endpoint, unioned.
    /// </summary>
    /// <remarks>
    /// <c>GetOrderedMetadata</c> rather than <c>GetMetadata</c>, because the latter returns only the
    /// last instance. Two <c>RequireScope</c> calls — one on a route group and one on the route —
    /// is the ordinary way to express "everything under here needs <c>mcp:tools</c>, and this one
    /// also needs <c>story:write</c>", and taking only the last silently drops the group's.
    /// </remarks>
    private static List<string> RequiredScopes(EndpointMetadataCollection metadata)
    {
        var declarations = metadata.GetOrderedMetadata<RequiredScopeMetadata>();

        if (declarations.Count == 0)
        {
            return [];
        }

        var scopes = new List<string>();

        foreach (var declaration in declarations)
        {
            foreach (var scope in declaration.Scopes)
            {
                if (!scopes.Contains(scope, StringComparer.Ordinal))
                {
                    scopes.Add(scope);
                }
            }
        }

        return scopes;
    }

    private static bool HasEveryScope(IReadOnlyList<string> granted, IReadOnlyList<string> required)
    {
        foreach (var scope in required)
        {
            if (!granted.Contains(scope, StringComparer.Ordinal))
            {
                return false;
            }
        }

        return true;
    }
}
