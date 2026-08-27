using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Requests;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// E-10, the token endpoint.
/// </summary>
/// <remarks>
/// <para>
/// <b>POST only, form-encoded only, and never <c>415</c>.</b> A <c>[FromBody]</c>-bound record here
/// answers <c>415 Unsupported Media Type</c> to a JSON request, which is defensible HTTP and fatal
/// in practice: it carries no <c>error</c> member, so neither vendor's client parses it, and the
/// flow dies with nothing to debug. Every rejection from this endpoint is an OAuth JSON body.
/// </para>
/// <para>
/// CORS is <c>*</c> here, unlike <c>/authorize</c> which must have none. The difference is who
/// makes the request: a browser-based client calls this endpoint directly with <c>fetch</c>, and is
/// merely redirected to the other one.
/// </para>
/// </remarks>
public static class TokenEndpoint
{
    /// <summary>Map <c>POST /token</c>.</summary>
    /// <remarks>
    /// <c>MapPost</c> rather than <c>MapMethods</c>, so routing answers <c>405</c> for every other
    /// method by itself. <c>MapGet</c> would additionally serve HEAD, and a HEAD that reaches a
    /// grant handler is a token exchange whose response the client never sees.
    /// </remarks>
    public static IEndpointRouteBuilder MapToken(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints
            .MapPost(AuthorizationServerPaths.Token, HandleAsync)
            .AllowAnonymous()
            .WithName("boltway-token");

        return endpoints;
    }

    /// <summary>
    /// Run the exchange, and turn a store that cannot be reached into a load-shed rather than a crash.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The catch is here and not in middleware</b> because middleware writing a status would be a
    /// second response writer, and A-09 holds precisely because <see cref="RejectionResult"/> is the
    /// only one. The answer still travels that chokepoint: <see cref="StoreLoadShed"/> builds a
    /// <see cref="Rejection"/> and hands it to a result, so the 503 is logged, counted and given an
    /// <c>X-Request-Id</c> by the same code that does it for every 400.
    /// </para>
    /// <para>
    /// <b>This endpoint was the first to shed and is no longer the only one.</b> <c>/introspect</c>
    /// and <c>/userinfo</c> answer the same 503 through the same helper; <c>/authorize</c> sheds
    /// differently, because it already had an exception boundary and the code it may emit is
    /// registered - see there.
    /// </para>
    /// </remarks>
    private static async Task<IResult> HandleAsync(HttpContext http, CancellationToken cancellationToken)
    {
        // Outside the try: a browser client needs these on the 503 as much as on the 200, and
        // nothing about setting a header can raise the failure this is guarding against.
        //
        // Browser-based clients call this endpoint directly. Written here rather than through
        // RequireCors for the same reason discovery does: the metadata without the middleware is a 500.
        DiscoveryHeaders.AllowAnyOrigin(http.Response);

        try
        {
            return await ExchangeAsync(http, cancellationToken);
        }
        catch (Exception unreachable) when (TransientStoreFailure.Describes(unreachable))
        {
            return StoreLoadShed.Answer(http, OAuthSurface.Token, unreachable);
        }
    }

    private static async Task<IResult> ExchangeAsync(HttpContext http, CancellationToken cancellationToken)
    {
        var services = http.RequestServices;

        if (!FormBody.TryRead(http, "token", out var parameters, out var formRejection))
        {
            return Error(http, formRejection!);
        }

        if (!parameters!.TrySingle("grant_type", out var grantType))
        {
            return Error(http, Rejection.Of(
                ReasonCode.RepeatedParameter,
                OAuthErrorCode.InvalidRequest,
                "The 'grant_type' parameter appeared more than once.",
                "parameter=grant_type"));
        }

        if (string.IsNullOrEmpty(grantType))
        {
            return Error(http, Rejection.Of(
                ReasonCode.GrantTypeMissing,
                OAuthErrorCode.InvalidRequest,
                "The 'grant_type' parameter is required."));
        }

        var options = services.GetRequiredService<AuthorizationServerOptions>();

        // An unknown grant is `unsupported_grant_type`, never `invalid_request`. §3.2.4 carves it
        // out explicitly - invalid_request covers "an unsupported parameter value (other than grant
        // type)" - and the two send a client looking in different places.
        if (!options.GrantTypesSupported.Contains(grantType, StringComparer.Ordinal))
        {
            return Error(http, Rejection.Of(
                ReasonCode.GrantTypeUnsupported,
                OAuthErrorCode.UnsupportedGrantType,
                $"The grant type '{grantType}' is not supported.",
                $"grant_type={grantType}; supported={string.Join(' ', options.GrantTypesSupported)}"));
        }

        var authenticator = services.GetRequiredService<ClientAuthenticator>();

        var authentication = await authenticator.AuthenticateAsync(
            new ClientAuthenticationContext(parameters, http.Request.Headers.Authorization), cancellationToken);

        if (authentication is ClientAuthentication.Failed failure)
        {
            return OAuthJsonResults.Error(
                OAuthSurface.Token,
                failure.Rejection,
                http.TraceIdentifier,
                failure.UsedAuthorizationHeader,
                failure.ChallengeScheme);
        }

        var client = ((ClientAuthentication.Authenticated)authentication).Client;

        // X-20. The server supports this grant; the question here is whether THIS client declared
        // it. `/authorize` makes the equivalent check for `authorization_code` and nothing made it
        // at `/token`, so a client whose metadata document declared only ["authorization_code"]
        // could use `refresh_token` freely.
        //
        // An empty list means "did not say", which C-14 requires be read as permission rather than
        // refusal - a client that declares nothing is one that also works against other servers.
        if (client.GrantTypes.Count > 0 && !client.GrantTypes.Contains(grantType, StringComparer.Ordinal))
        {
            return Error(
                http,
                Rejection.Of(
                    ReasonCode.ClientNotRegisteredForGrantType,
                    OAuthErrorCode.UnauthorizedClient,
                    $"This client is not registered for the '{grantType}' grant.",
                    $"client_id={client.ClientId.Value}; grant_type={grantType}; grant_types={string.Join(' ', client.GrantTypes)}"),
                authentication);
        }

        var outcome = grantType switch
        {
            "authorization_code" => await services.GetRequiredService<AuthorizationCodeGrant>()
                .HandleAsync(parameters, client, cancellationToken),
            "refresh_token" => await services.GetRequiredService<RefreshTokenGrant>()
                .HandleAsync(parameters, client, cancellationToken),
            "client_credentials" => await services.GetRequiredService<ClientCredentialsGrant>()
                .HandleAsync(parameters, client, cancellationToken),

            // Reachable only if GrantTypesSupported names a grant with no handler, which options
            // validation refuses - so this is a wiring error, not a client error.
            _ => new GrantOutcome.Failed(Rejection.Of(
                ReasonCode.GrantTypeHasNoHandler,
                OAuthErrorCode.UnsupportedGrantType,
                $"The grant type '{grantType}' has no handler.",
                $"grant_type={grantType}")),
        };

        return outcome switch
        {
            GrantOutcome.Issued issued => Success(issued.Tokens, services.GetRequiredService<TimeProvider>()),
            GrantOutcome.Failed failed => Error(http, failed.Rejection),
            _ => throw new InvalidOperationException($"Unhandled outcome {outcome.GetType().Name}."),
        };
    }

    private static IResult Success(IssuedTokens tokens, TimeProvider time)
    {
        // The injected provider. ExpiresAt comes from it, and subtracting the system clock instead
        // produced expires_in values that disagreed with the token's own exp: measured at 37799 for
        // a token whose exp - iat was 1800, and clamped to 0 with the offset reversed - a client
        // trusting either refreshes at exactly the wrong time.
        var lifetime = tokens.ExpiresAt - time.GetUtcNow();

        return OAuthJsonResults.Token(new TokenResponseBody
        {
            AccessToken = tokens.AccessToken.Wire,

            // Exactly "Bearer". RFC 6750 makes the comparison case-insensitive, and enough relying
            // parties compare it literally that the capitalisation is worth pinning.
            TokenType = "Bearer",

            // A JSON number, not a string. `"expires_in": "1800"` is a documented interop failure.
            ExpiresIn = (int)Math.Max(0, lifetime.TotalSeconds),

            RefreshToken = tokens.RefreshToken?.Wire,
            IdToken = tokens.IdToken,

            // Always emitted. §3.2.3 makes it REQUIRED when it differs from what was asked for and
            // RECOMMENDED otherwise - "optional when identical" asks the client to compare, and one
            // that assumes it got what it asked for finds out from a 403 much later.
            Scope = tokens.Scope.ToWireString(),
        });
    }


    private static IResult Error(HttpContext http, Rejection rejection) =>
        OAuthJsonResults.Error(OAuthSurface.Token, rejection, http.TraceIdentifier);

    /// <summary>
    /// An error raised after the client authenticated, carrying how it did so.
    /// </summary>
    /// <remarks>
    /// The challenge scheme has to survive past authentication. RFC 6749 §5.2 requires a 401's
    /// <c>WWW-Authenticate</c> to match the scheme the client used, and a failure raised later -
    /// an unauthorized grant, say - still went through Basic or private_key_jwt to get here.
    /// </remarks>
    private static IResult Error(HttpContext http, Rejection rejection, ClientAuthentication authentication)
    {
        var authenticated = (ClientAuthentication.Authenticated)authentication;

        return OAuthJsonResults.Error(
            OAuthSurface.Token,
            rejection,
            http.TraceIdentifier,
            authenticated.UsedAuthorizationHeader,
            ClientAuthentication.Authenticated.ChallengeScheme);
    }
}
