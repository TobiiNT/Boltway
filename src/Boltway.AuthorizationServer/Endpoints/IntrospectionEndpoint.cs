using System.Text.Json.Serialization;
using Boltway.AuthorizationServer.Abstractions.Grants;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.OAuth.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// RFC 7662 token introspection. E-15.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it is for here, concretely.</b> This server's access tokens are signed JWTs, so a
/// resource server verifies them offline and never asks us anything. That is fast and it has one
/// consequence: <b>ending a session does not cut access</b>, because the token keeps verifying
/// until it expires. <c>IGrantStore.IsRevokedAsync</c> - the denylist - existed for a resource
/// server to consult and, measured across this repository and a deployment consuming it, had no
/// production caller, because there was no channel to reach it through. This is that channel.
/// </para>
/// <para>
/// <b>An unusable token is <c>{"active": false}</c> with status 200, never an error.</b> RFC 7662
/// §2.2 requires it: a garbage string, an expired token, one signed by somebody else and one whose
/// grant was revoked are all the same answer, so an attacker holding a stolen token learns only
/// that it does not work - not why, and not whether it was ever real. The error responses on this
/// endpoint are all about the <i>caller</i>: a missing parameter, or client authentication.
/// </para>
/// <para>
/// <b>Confidential clients only.</b> §2.1 requires authorization on this endpoint "to prevent token
/// scanning attacks", and <c>MetadataBuilder</c> already refuses to advertise <c>none</c> as an
/// auth method here. <c>OAuthErrors</c> has carried the two rows for this surface - X-37 and X-38 -
/// since before the endpoint existed, including a note that a bearer-authenticated variant would
/// need a third; it still would, and there still is not one.
/// </para>
/// <para>
/// <b>Any authenticated client may introspect any token, and that is a decision rather than an
/// oversight.</b> RFC 7662 §5 warns against disclosing a token's contents to a party not entitled
/// to it, and the tighter rule - a client may introspect only tokens whose audience it owns - needs
/// a client-to-resource mapping this server does not have, since resources are registered
/// independently of clients. What bounds the disclosure instead is who can get here at all: a
/// configured confidential client with a secret, which in a deployment is the resource servers and
/// nothing else. Adding that mapping is the way to tighten this, not a scope check bolted on here.
/// </para>
/// </remarks>
public static class IntrospectionEndpoint
{
    /// <summary>Map <c>POST /introspect</c>.</summary>
    /// <remarks>
    /// <c>MapPost</c> alone, so routing answers 405 to every other method by itself. A GET carrying
    /// a token in the query string is the shape that puts credentials in access logs and browser
    /// history, and RFC 7662 §2.1 specifies POST.
    /// </remarks>
    public static IEndpointRouteBuilder MapIntrospection(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints
            .MapPost(AuthorizationServerPaths.Introspect, HandleAsync)
            .AllowAnonymous()
            .WithName("boltway-introspect");

        return endpoints;
    }

    /// <summary>
    /// The answer for anything this server cannot vouch for right now.
    /// </summary>
    /// <remarks>
    /// One instance, reached by every negative path, so no branch can accidentally answer with a
    /// body carrying a stray field. §2.2 is explicit that a false response says nothing else.
    /// </remarks>
    private static readonly IntrospectionResponseBody Inactive = new() { Active = false };

    /// <summary>
    /// One handler for the process, like <c>AccessTokenValidator</c> keeps.
    /// </summary>
    /// <remarks>
    /// It is thread-safe for validation and it caches the reflection it uses to read claims, so a
    /// new one per request throws that away on the endpoint most likely to be called on every
    /// single request a resource server serves.
    /// </remarks>
    private static readonly JsonWebTokenHandler Handler = new();

    /// <summary>
    /// Answer the introspection, or shed if the store cannot be reached. X-43.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Neither <c>active</c> is available when the lookup failed, and that is the whole reason
    /// this endpoint sheds.</b> <c>true</c> would report a token whose grant may have been revoked
    /// as usable - the denylist is the one thing this endpoint exists to consult, so failing open on
    /// it is failing at the job. <c>false</c> is worse in a quieter way: it is a definite answer
    /// built from no information, and a resource server reading it discards a live session. "The
    /// revocation state could not be determined" is neither of those, and 503 is how it is said.
    /// </para>
    /// <para>
    /// The caller here is a resource server on a schedule, not a person - the same case
    /// <c>/token</c> makes for a <c>Retry-After</c> mattering more than an explanation. RFC 7662
    /// §2.3 sends error responses through RFC 6749 §5.2, so the closed set applies here exactly as
    /// it does there and the refusal carries no <c>error</c> member.
    /// </para>
    /// </remarks>
    private static async Task<IResult> HandleAsync(HttpContext http, CancellationToken cancellationToken)
    {
        try
        {
            return await IntrospectAsync(http, cancellationToken);
        }
        catch (Exception unreachable) when (TransientStoreFailure.Describes(unreachable))
        {
            return StoreLoadShed.Answer(http, OAuthSurface.Introspection, unreachable);
        }
    }

    private static async Task<IResult> IntrospectAsync(HttpContext http, CancellationToken cancellationToken)
    {
        var services = http.RequestServices;

        if (!FormBody.TryRead(http, "introspection", out var parameters, out var formRejection))
        {
            return OAuthJsonResults.Error(OAuthSurface.Introspection, formRejection!, http.TraceIdentifier);
        }

        // Client authentication first, before the token parameter is even looked at. §2.1 exists to
        // stop scanning, and a server that reports "the token parameter is missing" to an
        // unauthenticated caller has told them the endpoint is live and takes that parameter.
        var authentication = await services.GetRequiredService<ClientAuthenticator>()
            .AuthenticateAsync(
                new ClientAuthenticationContext(parameters!, http.Request.Headers.Authorization),
                cancellationToken);

        if (authentication is ClientAuthentication.Failed failure)
        {
            return OAuthJsonResults.Error(
                OAuthSurface.Introspection,
                failure.Rejection,
                http.TraceIdentifier,
                failure.UsedAuthorizationHeader,
                failure.ChallengeScheme);
        }

        if (!parameters!.TrySingle("token", out var token))
        {
            return OAuthJsonResults.Error(
                OAuthSurface.Introspection,
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
                OAuthSurface.Introspection,
                Rejection.Of(
                    ReasonCode.TokenParameterMissing,
                    OAuthErrorCode.InvalidRequest,
                    "The 'token' parameter is required."),
                http.TraceIdentifier);
        }

        // A hint and nothing more. §2.1: "the server MAY ignore this parameter" and MUST still
        // answer correctly when it is wrong or absent, because a client that mislabels a token
        // would otherwise be told a live token is dead. So it picks the order of the two lookups
        // and never which of them is allowed to run.
        _ = parameters.TrySingle("token_type_hint", out var hint);

        var refreshFirst = string.Equals(hint, "refresh_token", StringComparison.Ordinal);

        var answer = refreshFirst
            ? await IntrospectRefreshTokenAsync(services, token, cancellationToken)
              ?? await IntrospectAccessTokenAsync(services, token, cancellationToken)
            : await IntrospectAccessTokenAsync(services, token, cancellationToken)
              ?? await IntrospectRefreshTokenAsync(services, token, cancellationToken);

        return OAuthJsonResults.Introspection(answer ?? Inactive);
    }

    /// <summary>
    /// Read a token as one of ours, or return null to say "not an access token of mine".
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null and <see cref="Inactive"/> are deliberately different returns. Null means "this is not
    /// something I recognise as an access token", which lets the caller try the refresh-token
    /// lookup; <see cref="Inactive"/> is the final answer. Collapsing them would make a revoked
    /// access token fall through to a refresh-token lookup that cannot match it - harmless today
    /// and the kind of thing that stops being harmless when a third token type is added.
    /// </para>
    /// <para>
    /// <b>The revocation check is the reason this endpoint exists</b>, and it happens after the
    /// signature: a valid signature says the token was minted, not that the grant behind it still
    /// stands. It is keyed on the <c>gid</c> claim, which <c>JwtTokenMinter</c> writes for exactly
    /// this and which <c>AccessTokenDescriptor</c> describes as "emitted so a resource server can
    /// consult a revocation denylist without introspection" - a resource server can now do it
    /// <i>with</i> introspection, which is the part that needed a channel.
    /// </para>
    /// <para>
    /// A token with no <c>gid</c> is reported active on its signature and expiry alone. This server
    /// has always written the claim, so that case is a token from a build that did not - treating
    /// its absence as revoked would refuse every live session on the deploy that introduced this.
    /// </para>
    /// </remarks>
    private static async Task<IntrospectionResponseBody?> IntrospectAccessTokenAsync(
        IServiceProvider services, string token, CancellationToken cancellationToken)
    {
        var options = services.GetRequiredService<AuthorizationServerOptions>();
        var keys = services.GetRequiredService<SigningKeyRing>();

        // Read per call rather than captured: the key ring rotates under a live process, and a
        // validator holding yesterday's set answers `active: false` for tokens it minted this
        // morning.
        var parameters = Rfc9068ValidationParameters.ForIntrospection(
            options.ValidatedIssuer, keys.PublicVerificationKeys());

        // **Expiry is judged against the system clock, not this server's injected TimeProvider.**
        // `TokenValidationParameters.TimeProvider` is internal in Microsoft.IdentityModel 8.22.0 -
        // present in the assembly, not callable - so there is no way to hand the library the clock
        // the revocation lookup below is timestamped against. In production they are the same
        // clock and nothing turns on it; the two only diverge under a fake one, which is why the
        // tests for this endpoint run the fixture at wall-clock time and say so.
        var result = await Handler.ValidateTokenAsync(token, parameters);

        if (!result.IsValid)
        {
            // Not ours, or no longer valid. Either way this is not an access token this server can
            // vouch for - and the caller cannot tell which, which is §2.2 working.
            return null;
        }

        var identity = result.ClaimsIdentity;
        var grantId = identity.FindFirst("gid")?.Value;

        if (grantId is { Length: > 0 }
            && await services.GetRequiredService<IGrantStore>().IsRevokedAsync(grantId, cancellationToken))
        {
            return Inactive;
        }

        return new IntrospectionResponseBody
        {
            Active = true,
            Scope = identity.FindFirst("scope")?.Value,
            ClientId = identity.FindFirst("client_id")?.Value,
            Subject = identity.FindFirst("sub")?.Value,
            TokenType = "Bearer",
            IssuedAt = Seconds(identity.FindFirst("iat")?.Value),
            ExpiresAt = Seconds(identity.FindFirst("exp")?.Value),

            // The claim as it was minted. An access token here carries exactly one audience, and
            // returning the first is reporting what is on the token rather than choosing among
            // several - a token with two would need this to be an array, which RFC 7662 §2.2 allows
            // and nothing in this server can produce.
            Audience = identity.FindFirst("aud")?.Value,
            Issuer = identity.FindFirst("iss")?.Value,
            JwtId = identity.FindFirst("jti")?.Value,
        };
    }

    /// <summary>
    /// Read a token as a refresh token of ours, or return null.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Live means: the row exists, it has not been rotated away, it has not expired, and the
    /// grant behind it still stands.</b> There is no separate check for a revoked token
    /// <i>family</i>, and that is worth stating rather than leaving to be noticed:
    /// <c>IRefreshTokenStore</c> exposes no read for it, and the one production call to
    /// <c>RevokeFamilyAsync</c> - reuse detection in <c>GrantHandlers</c> - revokes the grant on
    /// the very next line. So the grant check covers it today. A second caller of
    /// <c>RevokeFamilyAsync</c> that did not also revoke the grant would make this endpoint report
    /// a dead family as live, and would need a store read added here.
    /// </para>
    /// <para>
    /// <b>The scope and the subject come from the grant, not from the token.</b> A refresh token is
    /// an opaque string carrying nothing, so the grant is the only source - and it is the current
    /// one rather than a snapshot, which is the honest answer to "what would this token get you if
    /// you used it right now".
    /// </para>
    /// </remarks>
    private static async Task<IntrospectionResponseBody?> IntrospectRefreshTokenAsync(
        IServiceProvider services, string token, CancellationToken cancellationToken)
    {
        // The prefix is checked by the parser, so a string that is not shaped like one of our
        // refresh tokens costs no store round trip at all.
        if (!OpaqueSecret.TryParse(token, TokenPurpose.RefreshToken, out var presented))
        {
            return null;
        }

        var record = await services.GetRequiredService<IRefreshTokenStore>()
            .FindAsync(Sha256Hash.Of(presented), cancellationToken);

        if (record is null)
        {
            return null;
        }

        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();

        // Consumed rows are retained on purpose - reuse detection needs them - so "found" is not
        // "usable", and this is the difference.
        if (record.ConsumedAt is not null || record.ExpiresAt <= now)
        {
            return Inactive;
        }

        var grant = await services.GetRequiredService<IGrantStore>()
            .FindAsync(record.GrantId, cancellationToken);

        if (grant is not { IsActive: true })
        {
            return Inactive;
        }

        return new IntrospectionResponseBody
        {
            Active = true,
            Scope = grant.Scope.ToWireString(),
            ClientId = grant.ClientId.Value,
            Subject = grant.Subject.Value,

            // Not "Bearer". §2.2 defines this as the token's type per RFC 6749 §5.1, and a refresh
            // token is not a credential a resource server accepts - saying Bearer here would invite
            // exactly the confusion of presenting one to an API.
            TokenType = "refresh_token",
            IssuedAt = record.IssuedAt.ToUnixTimeSeconds(),
            ExpiresAt = record.ExpiresAt.ToUnixTimeSeconds(),

            // No audience: a refresh token is presented to this server and to nothing else, so it
            // has none. Omitted rather than filled with the grant's resources, which are what a
            // token minted *from* it may name.
            Issuer = services.GetRequiredService<AuthorizationServerOptions>().ValidatedIssuer.Value,
        };
    }

    /// <summary>A numeric date claim, or null if it is absent or unparseable.</summary>
    /// <remarks>
    /// Parsed rather than passed through as a string: RFC 7662 §2.2 types <c>exp</c> and <c>iat</c>
    /// as NumericDate, and a client comparing a JSON string to a number gets false every time
    /// without an error anywhere.
    /// </remarks>
    private static long? Seconds(string? claim) =>
        long.TryParse(claim, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out var value)
            ? value
            : null;
}

/// <summary>
/// An introspection response. RFC 7662 §2.2.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every member but <c>active</c> is omitted when null</b>, which is what makes the inactive
/// response the bare <c>{"active":false}</c> the RFC describes. A response padded with nulls would
/// still parse, and it would also tell a caller which fields this server knows about for a token it
/// has just declined to say anything about.
/// </para>
/// <para>
/// The set is RFC 7662's own and stops there. This server's tokens carry <c>gid</c> and
/// <c>auth_time</c> as well, and neither is here: a resource server calling introspection already
/// holds the token and can read them itself, so putting them in the response would widen what is
/// disclosed without answering a question anybody asked.
/// </para>
/// </remarks>
public sealed record IntrospectionResponseBody
{
    /// <summary>REQUIRED. Whether the token is usable right now.</summary>
    [JsonPropertyName("active")]
    public required bool Active { get; init; }

    /// <summary>OPTIONAL. Space-delimited, RFC 6749 §3.3.</summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    /// <summary>OPTIONAL. The client the token was issued to.</summary>
    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    /// <summary>OPTIONAL. The subject, as the token carries it.</summary>
    /// <remarks>
    /// <c>sub</c> and not <c>username</c>. RFC 7662 defines <c>username</c> as "a human-readable
    /// identifier for the resource owner", which this server would have to look up - disclosing
    /// more about the person than the token being introspected carries.
    /// </remarks>
    [JsonPropertyName("sub")]
    public string? Subject { get; init; }

    /// <summary>OPTIONAL. <c>Bearer</c> for an access token; <c>refresh_token</c> otherwise.</summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    /// <summary>OPTIONAL. NumericDate.</summary>
    [JsonPropertyName("exp")]
    public long? ExpiresAt { get; init; }

    /// <summary>OPTIONAL. NumericDate.</summary>
    [JsonPropertyName("iat")]
    public long? IssuedAt { get; init; }

    /// <summary>OPTIONAL. Who the token is for.</summary>
    [JsonPropertyName("aud")]
    public string? Audience { get; init; }

    /// <summary>OPTIONAL. Who issued it.</summary>
    [JsonPropertyName("iss")]
    public string? Issuer { get; init; }

    /// <summary>OPTIONAL. The token's identifier.</summary>
    [JsonPropertyName("jti")]
    public string? JwtId { get; init; }
}
