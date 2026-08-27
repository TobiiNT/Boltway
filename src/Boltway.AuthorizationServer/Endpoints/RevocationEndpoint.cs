using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.OAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// RFC 7009 token revocation. E-16.
/// </summary>
/// <remarks>
/// <para>
/// <b>The success answer is an empty 200, and so is almost every failure.</b> RFC 7009 §2.2 makes
/// that a MUST: a token that is unknown, malformed, already revoked or not this client's has, from
/// the caller's point of view, exactly the property they asked for - it does not work. X-39 adds the
/// case the RFC leaves implicit and this server has to decide: a token belonging to a <i>different
/// client</i> is also a 200, and nothing is revoked. Saying "that is not yours" would turn this
/// endpoint into an oracle that confirms a stolen token is real and tells the holder whose it is.
/// </para>
/// <para>
/// <b>Revoking any token here revokes the grant behind it, which is broader than the letter.</b>
/// RFC 7009 §2.1 permits it - an access token's revocation MAY take the refresh token with it - and
/// the structure of this server makes it the only coherent reading: the denylist a resource server
/// consults is <c>IGrantStore.IsRevokedAsync</c>, keyed on the grant, and access tokens are signed
/// rather than stored, so there is no per-token row to mark. "Revoke this access token and leave the
/// session running" is not a state this server can represent, and pretending otherwise would answer
/// 200 while the token kept working until it expired.
/// </para>
/// <para>
/// <b>A store failure is a 503, not a 200.</b> X-41. This is the one place the empty-200 rule stops:
/// every other negative answer here means the token does not work, and a failed write means nobody
/// knows whether it does. A 200 there is the confidence rule broken on a security operation - the
/// client is told the credential is dead and stops trying, which is the worst available outcome. The
/// caller must assume the token still exists, and <c>Retry-After</c> says when to ask again.
/// </para>
/// <para>
/// <b>Confidential clients only</b>, the same as introspection: <c>MetadataBuilder</c> advertises
/// <c>revocation_endpoint_auth_methods_supported</c> from the confidential set, so <c>none</c> is
/// never offered. RFC 7009 §2.1 requires client authentication for a confidential client and this
/// server has no public-client revocation path - a public client that wants its grant gone signs in
/// and withdraws consent at <c>/me/consents</c>.
/// </para>
/// </remarks>
public static class RevocationEndpoint
{
    /// <summary>Map <c>POST /revoke</c>.</summary>
    /// <remarks>
    /// <c>MapPost</c> alone, so routing answers 405 to every other method by itself - and for the
    /// reason introspection has: RFC 7009 §2.1 specifies POST, and a GET would put a live credential
    /// in access logs and browser history.
    /// </remarks>
    public static IEndpointRouteBuilder MapRevocation(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints
            .MapPost(AuthorizationServerPaths.Revoke, HandleAsync)
            .AllowAnonymous()
            .WithName("boltway-revoke");

        return endpoints;
    }

    /// <summary>
    /// One handler for the process, like <c>IntrospectionEndpoint</c> keeps.
    /// </summary>
    /// <remarks>
    /// Thread-safe for validation, and it caches the reflection it uses to read claims.
    /// </remarks>
    private static readonly JsonWebTokenHandler Handler = new();

    /// <summary>Revoke, or shed if the store could not be reached. X-41.</summary>
    private static async Task<IResult> HandleAsync(HttpContext http, CancellationToken cancellationToken)
    {
        try
        {
            return await RevokeAsync(http, cancellationToken);
        }
        catch (Exception unreachable) when (TransientStoreFailure.Describes(unreachable))
        {
            return StoreLoadShed.Answer(http, OAuthSurface.Revocation, unreachable);
        }
    }

    private static async Task<IResult> RevokeAsync(HttpContext http, CancellationToken cancellationToken)
    {
        var services = http.RequestServices;

        if (!FormBody.TryRead(http, "revocation", out var parameters, out var formRejection))
        {
            return OAuthJsonResults.Error(OAuthSurface.Revocation, formRejection!, http.TraceIdentifier);
        }

        // Client authentication before the token parameter is read, the same order introspection
        // uses and for the same reason: an unauthenticated caller told "the token parameter is
        // missing" has learned that this endpoint is live and takes that parameter.
        var authentication = await services.GetRequiredService<ClientAuthenticator>()
            .AuthenticateAsync(
                new ClientAuthenticationContext(parameters!, http.Request.Headers.Authorization),
                cancellationToken);

        if (authentication is ClientAuthentication.Failed failure)
        {
            return OAuthJsonResults.Error(
                OAuthSurface.Revocation,
                failure.Rejection,
                http.TraceIdentifier,
                failure.UsedAuthorizationHeader,
                failure.ChallengeScheme);
        }

        var caller = ((ClientAuthentication.Authenticated)authentication).Client.ClientId;

        if (!parameters!.TrySingle("token", out var token))
        {
            return OAuthJsonResults.Error(
                OAuthSurface.Revocation,
                Rejection.Of(
                    ReasonCode.RepeatedParameter,
                    OAuthErrorCode.InvalidRequest,
                    "The 'token' parameter appeared more than once.",
                    "parameter=token"),
                http.TraceIdentifier);
        }

        if (string.IsNullOrEmpty(token))
        {
            return OAuthJsonResults.Error(
                OAuthSurface.Revocation,
                Rejection.Of(
                    ReasonCode.TokenParameterMissing,
                    OAuthErrorCode.InvalidRequest,
                    "The 'token' parameter is required."),
                http.TraceIdentifier);
        }

        // A hint and nothing more, exactly as at /introspect. RFC 7009 §2.1: a server that cannot
        // find a token under the hinted type "SHOULD extend its search across all supported token
        // types", so this picks the order of the two lookups and never which of them may run. A
        // client that mislabels its token still gets it revoked.
        _ = parameters.TrySingle("token_type_hint", out var hint);

        if (string.Equals(hint, "refresh_token", StringComparison.Ordinal))
        {
            _ = await RevokeRefreshTokenAsync(services, caller, token, cancellationToken)
                || await RevokeAccessTokenAsync(services, caller, token, cancellationToken);
        }
        else
        {
            _ = await RevokeAccessTokenAsync(services, caller, token, cancellationToken)
                || await RevokeRefreshTokenAsync(services, caller, token, cancellationToken);
        }

        // Whatever happened above. §2.2, and X-39: found and revoked, never existed, already dead,
        // and somebody else's are one answer, because the difference between them is exactly what a
        // caller holding a token they should not have would like to learn.
        return OAuthJsonResults.RevocationDone();
    }

    /// <summary>
    /// Revoke the grant behind an access token, or report that this is not one of ours.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns whether the token was recognised, not whether anything was revoked - a token that is
    /// this server's but another client's is recognised and left alone, which stops the search
    /// rather than letting it fall through to a refresh-token lookup that cannot match it either.
    /// </para>
    /// <para>
    /// <b>An expired access token is not recognised here</b>, because validation refuses it, and it
    /// therefore revokes nothing. That is the RFC's own reading - an expired token already has the
    /// property the caller asked for - but it is worth stating, because "revoke this and end the
    /// session" is what a caller may have meant, and the refresh token is the parameter that does
    /// that.
    /// </para>
    /// </remarks>
    private static async Task<bool> RevokeAccessTokenAsync(
        IServiceProvider services,
        ClientIdentifier caller,
        string token,
        CancellationToken cancellationToken)
    {
        var options = services.GetRequiredService<AuthorizationServerOptions>();
        var keys = services.GetRequiredService<SigningKeyRing>();

        // Read per call rather than captured: the key ring rotates under a live process, and a
        // validator holding yesterday's set refuses to revoke tokens minted this morning.
        var parameters = Rfc9068ValidationParameters.ForIntrospection(
            options.ValidatedIssuer, keys.PublicVerificationKeys());

        var result = await Handler.ValidateTokenAsync(token, parameters);

        if (!result.IsValid)
        {
            return false;
        }

        var grantId = result.ClaimsIdentity.FindFirst("gid")?.Value;

        if (grantId is not { Length: > 0 })
        {
            // A token from a build before `gid` existed. There is nothing to key the revocation on,
            // and inventing one from `sub` would revoke every grant that subject holds - including
            // the ones belonging to other clients. Recognised, so the search stops; nothing revoked.
            return true;
        }

        await RevokeGrantAsync(services, caller, grantId, cancellationToken);

        return true;
    }

    /// <summary>Revoke the family and grant behind a refresh token, or report it is not one of ours.</summary>
    /// <remarks>
    /// <para>
    /// The family goes first and the grant second, which is the order <c>GrantHandlers</c> uses on
    /// reuse detection. It matters on a partial failure: a revoked family with a live grant refuses
    /// the refresh and keeps existing access tokens working until they expire, while a revoked grant
    /// with a live family would let a rotation mint tokens against a grant that is gone.
    /// </para>
    /// <para>
    /// <b>A consumed token - one already rotated away - still revokes its family, and that is not
    /// the same answer <c>/introspect</c> gives about it.</b> Introspection reports it inactive,
    /// because the question there is "would this token work"; here the question is "make this stop",
    /// and the thing the caller is pointing at is a session whose current token is the successor.
    /// Treating a consumed row as unrecognised would answer 200 while leaving that session running,
    /// which is the one outcome this endpoint must never produce.
    /// </para>
    /// </remarks>
    private static async Task<bool> RevokeRefreshTokenAsync(
        IServiceProvider services,
        ClientIdentifier caller,
        string token,
        CancellationToken cancellationToken)
    {
        // The prefix is checked by the parser, so a string not shaped like one of our refresh tokens
        // costs no store round trip at all.
        if (!OpaqueSecret.TryParse(token, TokenPurpose.RefreshToken, out var presented))
        {
            return false;
        }

        var record = await services.GetRequiredService<IRefreshTokenStore>()
            .FindAsync(Sha256Hash.Of(presented), cancellationToken);

        if (record is null)
        {
            return false;
        }

        var grant = await services.GetRequiredService<IGrantStore>()
            .FindAsync(record.GrantId, cancellationToken);

        // Ownership is decided on the grant rather than on anything the presented token carries: a
        // refresh token is an opaque string and says nothing about who holds it.
        if (grant is null || !grant.ClientId.Equals(caller))
        {
            return true;
        }

        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();

        _ = await services.GetRequiredService<IRefreshTokenStore>()
            .RevokeFamilyAsync(record.FamilyId, now, cancellationToken);

        _ = await services.GetRequiredService<IGrantStore>()
            .RevokeAsync(record.GrantId, now, cancellationToken);

        return true;
    }

    /// <summary>Revoke a grant, if it is the caller's.</summary>
    /// <remarks>
    /// <para>
    /// <c>RevokeAsync</c> on a grant already revoked answers false and changes nothing, so an
    /// already-revoked token needs no branch of its own - which is what makes §2.2's "already
    /// revoked is a success" true here by construction rather than by a check somebody has to
    /// remember to write.
    /// </para>
    /// <para>
    /// <b>The refresh family is not revoked on this path, and cannot be.</b> An access token carries
    /// <c>gid</c> and no family id, and <c>IRefreshTokenStore</c> exposes no read from one to the
    /// other. It is covered rather than missed: the refresh grant checks the grant is active, so a
    /// revoked grant refuses the rotation the family would have served. A second way to reach
    /// <c>RevokeFamilyAsync</c> that did not also revoke the grant would break that - the same
    /// coupling <c>IntrospectionEndpoint</c> records from the other side.
    /// </para>
    /// </remarks>
    private static async Task RevokeGrantAsync(
        IServiceProvider services,
        ClientIdentifier caller,
        string grantId,
        CancellationToken cancellationToken)
    {
        var grants = services.GetRequiredService<IGrantStore>();
        var grant = await grants.FindAsync(grantId, cancellationToken);

        if (grant is null || !grant.ClientId.Equals(caller))
        {
            return;
        }

        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();

        _ = await grants.RevokeAsync(grantId, now, cancellationToken);
    }
}
