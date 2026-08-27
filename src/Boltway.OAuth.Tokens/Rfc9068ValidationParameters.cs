using Boltway.OAuth.Primitives.Ids;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens;

/// <summary>
/// The only place a <see cref="TokenValidationParameters"/> is constructed.
/// </summary>
/// <remarks>
/// <para>
/// N-09, and the reason it is a factory rather than a convention: two of the settings that matter
/// most are <b>unset by default</b> in <c>Microsoft.IdentityModel</c>, so a
/// <c>new TokenValidationParameters { ... }</c> written anywhere else is very likely to be missing
/// them without anyone noticing. An architecture test asserts this type contains the only
/// <c>newobj TokenValidationParameters</c> in the whole solution, which makes "every verifier is
/// configured correctly" a single site to review rather than a habit to maintain.
/// </para>
/// <para>
/// The two:
/// </para>
/// <list type="number">
/// <item><description>
/// <c>ValidTypes</c> - unset means the <c>typ</c> header is not checked, so an ID token is accepted
/// as an access token. Same signature, same issuer, same subject; only the type distinguishes them.
/// </description></item>
/// <item><description>
/// <c>ValidAlgorithms</c> - unset means the algorithm is taken from the token's own header, which
/// is the algorithm-confusion attack: an attacker re-signs a forged token using the published
/// public key as an HMAC secret.
/// </description></item>
/// </list>
/// </remarks>
public static class Rfc9068ValidationParameters
{
    /// <summary>
    /// Parameters for validating an access token at a resource server.
    /// </summary>
    /// <param name="issuer">The expected <c>iss</c>. Compared byte for byte.</param>
    /// <param name="audience">
    /// This resource's identifier. The token's <c>aud</c> must contain it exactly (N-01).
    /// </param>
    /// <param name="signingKeys">The issuer's public keys, from JWKS.</param>
    /// <param name="clockSkew">
    /// Tolerance for clock differences. Small on purpose: the library's default is five minutes,
    /// which silently extends every token's life by that much and is longer than some access tokens
    /// are meant to live.
    /// </param>
    public static TokenValidationParameters ForAccessToken(
        IssuerString issuer,
        ResourceIdentifier audience,
        IEnumerable<SecurityKey> signingKeys,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(audience);
        ArgumentNullException.ThrowIfNull(signingKeys);

        return new TokenValidationParameters
        {
            // RFC 9068 §4. Both spellings are legal on the wire (RFC 8725 §3.11 permits omitting
            // the "application/" prefix), so a verifier accepting only one rejects conformant
            // tokens from some issuers.
            ValidTypes = [TokenTypes.AccessToken, TokenTypes.AccessTokenWithPrefix],

            // Pinned, so the token cannot choose. Symmetric algorithms are absent by construction.
            ValidAlgorithms = SigningAlgorithms.All,

            ValidateIssuer = true,
            ValidIssuer = issuer.Value,

            // N-01. The audience is THIS resource's identifier, compared in full - never the
            // request's origin. A resource identifier legitimately carries a path
            // (https://mcp.example.com/mcp), and comparing only the origin is a shipped real-world
            // bug that broke ChatGPT custom connectors.
            ValidateAudience = true,
            ValidAudiences = [audience.Canonical],
            AudienceValidator = null,

            // The library's default here is TRUE, which makes the comparison above not quite the
            // byte-for-byte one the comment claims: `https://mcp.example.com/mcp/` is accepted
            // where `https://mcp.example.com/mcp` was registered. Measured through a running
            // resource server, not inferred from the property name.
            //
            // Two identifiers differing only by a trailing slash are two resources everywhere else
            // in this product - RFC 9728 §6 forbids normalizing them together, §3.3 makes the
            // metadata document's `resource` a byte-identity check, and Anthropic's own guidance is
            // that the value must match the MCP server URL "exactly as the user enters it in
            // Claude". Leaving the tolerance on means an audience restriction that is stricter in
            // the document than in the verifier, and the gap between them is where two separately
            // registered resources share one token.
            IgnoreTrailingSlashWhenValidatingAudience = false,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            TryAllIssuerSigningKeys = false,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,

            ClockSkew = clockSkew ?? TimeSpan.FromSeconds(30),
        };
    }

    /// <summary>
    /// Parameters for validating an ID token issued by an <b>upstream</b> identity provider.
    /// </summary>
    /// <param name="issuer">The upstream's issuer identifier, as configured.</param>
    /// <param name="audience">This server's client identifier at that upstream.</param>
    /// <param name="signingKeys">The upstream's public keys, from its JWKS.</param>
    /// <param name="validTypes">
    /// The <c>typ</c> header values to accept. Must not be empty - see the exception below.
    /// </param>
    /// <param name="clockSkew">Clock tolerance.</param>
    /// <exception cref="ArgumentException"><paramref name="validTypes"/> is empty.</exception>
    /// <remarks>
    /// <para>
    /// The third construction site, and it is here rather than in the federation assembly because
    /// <c>StructuralRuleTests.Token_validation_parameters_have_one_construction_site</c> requires
    /// every <see cref="TokenValidationParameters"/> in the solution to be built in this type. That
    /// rule is what makes "what this process will accept as a token" one file to read. A federation
    /// provider building its own would be the second place, and the two would drift on exactly the
    /// settings the library leaves unset.
    /// </para>
    /// <para>
    /// This server is an OAuth <i>client</i> here, so the direction of every check is reversed from
    /// the two above: the issuer is somebody else's, the keys are somebody else's, and the audience
    /// is an identifier they issued to us. What does not reverse is which settings matter -
    /// <c>ValidTypes</c> and <c>ValidAlgorithms</c> are unset by default in
    /// <c>Microsoft.IdentityModel</c> on this path too.
    /// </para>
    /// <para>
    /// <b>What this method does not check: <c>nonce</c>.</b> The value it would have to equal lives
    /// in the browser's pending-request cookie, which nothing in this assembly can see. The
    /// comparison is done once, in the authorization server's callback endpoint, against the
    /// <c>nonce</c> claim of the token this method has already established is genuine. Saying so
    /// here because a reader arriving at "the ID token is validated properly" needs to know which
    /// half of it happens where.
    /// </para>
    /// </remarks>
    public static TokenValidationParameters ForUpstreamIdToken(
        UpstreamIssuer issuer,
        UpstreamAudience audience,
        IEnumerable<SecurityKey> signingKeys,
        IReadOnlyList<string> validTypes,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(signingKeys);
        ArgumentNullException.ThrowIfNull(validTypes);

        if (validTypes.Count == 0)
        {
            throw new ArgumentException(
                "An upstream ID token must be validated against at least one `typ` header value. "
                + "There is deliberately no way to express 'do not check': leaving ValidTypes unset "
                + "is the library default that N-09 exists to correct, and it would accept any JWT "
                + "the upstream ever signs with these keys.",
                nameof(validTypes));
        }

        return new TokenValidationParameters
        {
            // Pinned, like every other verifier here. The trade is recorded rather than glossed:
            // OIDC Core does not require a `typ` header on an ID token, so an upstream that omits it
            // is refused by this validator. Google, Entra, Okta, Auth0 and Keycloak all set "JWT".
            // The set is configurable per provider; being able to switch the check off is not.
            ValidTypes = validTypes,

            // The same closed set this server signs with. `none` has no path here - RequireSignedTokens
            // below is the second half of that - and no symmetric algorithm is listed, so an upstream
            // key published in a JWKS cannot be turned into an HMAC secret.
            ValidAlgorithms = SigningAlgorithms.All,

            ValidateIssuer = true,
            ValidIssuer = issuer.Value,

            // The audience is this server's client identifier AT THE UPSTREAM. Note the parameter
            // type: it is neither a ResourceIdentifier nor a ClientIdentifier, because it is neither
            // - it is an identifier a third party issued to us, and it must not be interchangeable
            // at a call site with the two identifiers this server issues.
            ValidateAudience = true,
            ValidAudiences = [audience.Value],
            AudienceValidator = null,
            IgnoreTrailingSlashWhenValidatingAudience = false,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,

            // True here, and false on the two verifiers above, which is a real difference rather
            // than an inconsistency. Those two validate tokens this server minted, where the `kid`
            // is ours and a token naming an unknown one is a token we did not issue. This one
            // validates a token minted by somebody else, mid-rotation, where a `kid` we have not
            // seen means the cached key set is stale - and refusing every token during an upstream's
            // key rotation is an outage caused by the upstream doing the right thing. The keys are
            // still only the ones fetched from the upstream's own JWKS.
            TryAllIssuerSigningKeys = true,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,

            ClockSkew = clockSkew ?? TimeSpan.FromSeconds(30),
        };
    }

    /// <summary>
    /// Parameters for validating an ID token, as a relying party would.
    /// </summary>
    /// <param name="issuer">The expected <c>iss</c>.</param>
    /// <param name="audience">
    /// The <b>client identifier</b>. N-10: an ID token's audience is the client, never a resource.
    /// </param>
    /// <param name="signingKeys">The issuer's public keys.</param>
    /// <param name="clockSkew">Clock tolerance.</param>
    /// <remarks>
    /// Note the parameter type. <see cref="ForAccessToken"/> takes a
    /// <see cref="ResourceIdentifier"/> and this takes a <see cref="ClientIdentifier"/>, so the two
    /// audiences cannot be swapped at a call site - the compiler refuses. Putting a resource URL in
    /// an ID token's <c>aud</c> makes every conformant relying party reject it at OIDC Core
    /// §3.1.3.7 rule 3, and the rejection surfaces on the client with no error code the server
    /// controls.
    /// </remarks>
    public static TokenValidationParameters ForIdToken(
        IssuerString issuer,
        ClientIdentifier audience,
        IEnumerable<SecurityKey> signingKeys,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(signingKeys);

        return new TokenValidationParameters
        {
            ValidTypes = [TokenTypes.IdToken],
            ValidAlgorithms = SigningAlgorithms.All,

            ValidateIssuer = true,
            ValidIssuer = issuer.Value,

            ValidateAudience = true,
            ValidAudiences = [audience.Value],

            // Same correction as on the access-token path, for the same reason one layer over: a
            // CIMD client identifier is a URL compared with RFC 3986 §6.2.1 Simple String
            // Comparison everywhere else in this product, so two spellings differing by a trailing
            // slash are two clients. Turned off here as well rather than only where it was
            // measured, because an ID token accepted for the neighbouring spelling of a client id
            // is the same defect and the asymmetry would read as a deliberate distinction.
            IgnoreTrailingSlashWhenValidatingAudience = false,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            TryAllIssuerSigningKeys = false,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,

            ClockSkew = clockSkew ?? TimeSpan.FromSeconds(30),
        };
    }

    /// <summary>
    /// Parameters for reading back an access token <b>this server issued</b>, at <c>/introspect</c>.
    /// </summary>
    /// <param name="issuer">This server's own issuer identifier.</param>
    /// <param name="signingKeys">This server's own public keys.</param>
    /// <param name="clockSkew">Clock tolerance.</param>
    /// <remarks>
    /// <para>
    /// <b>The one factory here with <c>ValidateAudience</c> off, and the reason is that there is no
    /// audience to validate against.</b> Every other verifier in this type is a party checking
    /// "was this token minted for me". Introspection is the issuer answering "did I mint this, and
    /// does it still stand" about a token minted for somebody else - the caller is the resource
    /// server, and the audience is one of the facts being reported back rather than a gate. Passing
    /// an audience in would require the endpoint to know which resource each presented token was
    /// for before it has read it, which is the thing it is being asked.
    /// </para>
    /// <para>
    /// <b>Nothing else is relaxed, and that is what keeps the omission narrow.</b> Issuer, type,
    /// algorithm, signature and expiry are all checked exactly as on the resource-server path, so
    /// the only tokens this accepts are unexpired access tokens carrying this server's own
    /// signature. A forged token, an ID token presented as an access token, and a token from
    /// another issuer are all refused here as they are everywhere else - and a refusal becomes
    /// <c>active: false</c> rather than an error, per RFC 7662 §2.2.
    /// </para>
    /// <para>
    /// <b>What the caller must still do.</b> A valid signature means the token was minted; it does
    /// not mean the grant behind it still stands. Revocation is a store lookup the endpoint makes
    /// afterwards, and it is the entire point of offering introspection over a signed token that a
    /// resource server could otherwise verify offline by itself.
    /// </para>
    /// </remarks>
    public static TokenValidationParameters ForIntrospection(
        IssuerString issuer,
        IEnumerable<SecurityKey> signingKeys,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(signingKeys);

        return new TokenValidationParameters
        {
            ValidTypes = [TokenTypes.AccessToken, TokenTypes.AccessTokenWithPrefix],
            ValidAlgorithms = SigningAlgorithms.All,

            ValidateIssuer = true,
            ValidIssuer = issuer.Value,

            // See the remarks. Set explicitly rather than left to the library, so that a reader
            // finding it off here knows it was decided rather than forgotten - which is the whole
            // argument for this type existing.
            ValidateAudience = false,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            TryAllIssuerSigningKeys = false,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,

            ClockSkew = clockSkew ?? TimeSpan.FromSeconds(30),
        };
    }

    /// <summary>
    /// Parameters for validating a client assertion at the token endpoint. RFC 7523 §3.
    /// </summary>
    /// <param name="clientId">
    /// The client. It is <b>both</b> the expected <c>iss</c> and the expected <c>sub</c> - §3 makes
    /// them the same value for this profile, and the <c>sub</c> half is checked by the caller
    /// because a <c>TokenValidationParameters</c> has no place to express it.
    /// </param>
    /// <param name="audiences">
    /// Every value this server will accept in <c>aud</c>. See the caller for why there are two.
    /// </param>
    /// <param name="signingKeys">The client's own public keys, from its <c>jwks_uri</c>.</param>
    /// <param name="clockSkew">Clock tolerance.</param>
    /// <remarks>
    /// <para>
    /// <b>The issuer is the client, which reads oddly and is what §3 says.</b> Everywhere else in
    /// this file the issuer is this server; here the assertion is minted by the client, about
    /// itself, for us. So <see cref="TokenValidationParameters.ValidIssuer"/> is a client identifier
    /// and <see cref="TokenValidationParameters.ValidAudiences"/> holds this server's - the exact
    /// reverse of <see cref="ForIdToken"/>, one method up.
    /// </para>
    /// <para>
    /// <b>No <c>ValidTypes</c>, deliberately, and it is the one place in this file that omits it.</b>
    /// N-09 pins <c>typ</c> everywhere else because two of this server's own token kinds are
    /// otherwise interchangeable. Here there is nothing to confuse: a client assertion is verified
    /// against the <i>client's</i> keys, and this server mints nothing with those keys, so there is
    /// no second token kind a valid signature could belong to. RFC 7523 registers no <c>typ</c>
    /// requirement, and demanding one would refuse conformant clients - measured on ChatGPT's own
    /// metadata, which declares <c>token_endpoint_auth_signing_alg</c> and no type at all.
    /// </para>
    /// <para>
    /// <c>TryAllIssuerSigningKeys</c> is true for the reason <see cref="ForUpstreamIdToken"/> gives:
    /// these are somebody else's keys, mid-rotation a <c>kid</c> we have not seen means our cached
    /// set is stale, and refusing every assertion while a client rotates correctly is an outage we
    /// caused. The caller pairs it with a bounded refetch on exactly that miss.
    /// </para>
    /// </remarks>
    public static TokenValidationParameters ForClientAssertion(
        ClientIdentifier clientId,
        IReadOnlyList<string> audiences,
        IEnumerable<SecurityKey> signingKeys,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(audiences);
        ArgumentNullException.ThrowIfNull(signingKeys);

        if (audiences.Count == 0)
        {
            throw new ArgumentException(
                "A client assertion must be validated against at least one audience. There is "
                + "deliberately no way to express 'do not check': an assertion with an unchecked "
                + "audience is one this server would accept after it was minted for somebody else.",
                nameof(audiences));
        }

        return new TokenValidationParameters
        {
            // The same closed set this server signs with, and the reason is sharper here than
            // anywhere else in this file: these keys arrive in a JWKS from a host an attacker may
            // control. No symmetric algorithm is listed, so a published public key cannot be turned
            // into an HMAC secret, and `none` has no path at all - RequireSignedTokens below is the
            // other half.
            ValidAlgorithms = SigningAlgorithms.All,

            ValidateIssuer = true,
            ValidIssuer = clientId.Value,

            ValidateAudience = true,
            ValidAudiences = audiences,
            AudienceValidator = null,
            IgnoreTrailingSlashWhenValidatingAudience = false,

            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            TryAllIssuerSigningKeys = true,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,

            ClockSkew = clockSkew ?? TimeSpan.FromSeconds(30),
        };
    }
}
