using System.Security.Claims;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;
using Boltway.ResourceServer.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.ResourceServer.Bearer;

/// <summary>Why an access token was refused. Every case maps to <c>invalid_token</c> and a 401.</summary>
internal enum AccessTokenFailure
{
    /// <summary>Not a failure.</summary>
    None = 0,

    /// <summary><c>exp</c> is in the past, beyond the configured skew.</summary>
    Expired,

    /// <summary>
    /// <c>aud</c> does not contain this resource's identifier. N-01's second leg.
    /// </summary>
    WrongAudience,

    /// <summary>
    /// Anything else: bad signature, unknown <c>kid</c>, <c>alg</c> off the allow-list, <c>typ</c>
    /// that is not <c>at+jwt</c>, <c>iss</c> mismatch, unparseable JWT.
    /// </summary>
    Rejected,

    /// <summary>
    /// The token is genuine and unexpired, and the grant behind it has been revoked.
    /// </summary>
    /// <remarks>
    /// <b>Not produced by <see cref="AccessTokenValidator"/>, and it could not be.</b> Every other
    /// member here is a property of the token, decided offline from the signature and the claims.
    /// This one is a property of the authorization server's store at this instant, so it is decided
    /// by <c>IAccessTokenRevocationCheck</c> after validation has already succeeded — which is the
    /// entire reason a signed token needs anything asked about it at all.
    /// </remarks>
    Revoked,
}

/// <summary>A validated access token, or the reason there is not one.</summary>
/// <param name="Failure">Why it was refused. <see cref="AccessTokenFailure.None"/> on success.</param>
/// <param name="Principal">The token's claims, on success.</param>
/// <param name="Scopes">The <c>scope</c> claim, parsed. Empty when the token carries none.</param>
/// <param name="Diagnosis">
/// The validation exception's type and message, for the log and never for the response.
/// </param>
/// <remarks>
/// <para>
/// <see cref="Diagnosis"/> is the field this record grew for A-09, and its absence was the sharpest
/// finding of the review that motivated the work. Four <see cref="AccessTokenFailure"/> values
/// cannot express the difference between a signature that does not verify, a <c>kid</c> naming no
/// configured key, an <c>iss</c> mismatch and a <c>typ</c> that is not <c>at+jwt</c> — nor should
/// they, because the client must be told the same thing for all four. But
/// <c>Microsoft.IdentityModel</c> computes that difference and hands it over as a
/// <c>SecurityTokenException</c>, and it used to be discarded on the line that classified it.
/// </para>
/// <para>
/// The concrete cost: a customer who rotates a signing key and forgets to add the new one to
/// <c>ProtectedResourceOptions.SigningKeys</c> gets a wall of identical 401s. The library already
/// knows the answer — <c>SecurityTokenSignatureKeyNotFoundException: IDX10500: No security keys
/// were provided</c> — and there was nowhere it was written down.
/// </para>
/// </remarks>
internal readonly record struct AccessTokenResult(
    AccessTokenFailure Failure, ClaimsPrincipal? Principal, ScopeSet Scopes, string? Diagnosis = null);

/// <summary>
/// Validates an access token against the RFC 9068 profile.
/// </summary>
/// <remarks>
/// <para>
/// The validation parameters come from <c>Rfc9068ValidationParameters.ForAccessToken</c> and are
/// not built here. That is not delegation for its own sake: two of the settings that decide whether
/// this server is safe — <c>ValidTypes</c> and <c>ValidAlgorithms</c> — are <b>unset by default</b>
/// in <c>Microsoft.IdentityModel</c>, so a hand-written <c>TokenValidationParameters</c> is very
/// likely to be missing them and to look completely ordinary while doing so. An architecture test
/// asserts that factory is the only construction site in the solution.
/// </para>
/// <para>
/// What those two settings buy, concretely: without <c>ValidTypes</c> an <b>ID token</b> is a valid
/// access token here — same signature, same issuer, same subject, and only <c>typ</c> tells them
/// apart (N-09). Without <c>ValidAlgorithms</c> the token chooses its own algorithm, which is the
/// RS256→HS256 confusion attack, where the attacker signs a forged token using the published public
/// key as an HMAC secret.
/// </para>
/// </remarks>
internal sealed class AccessTokenValidator
{
    private readonly ProtectedResource _resource;
    private readonly ProtectedResourceOptions _options;
    private readonly JsonWebTokenHandler _handler = new();

    /// <summary>Built by the container. Public on an internal type, so activation can find it.</summary>
    public AccessTokenValidator(ProtectedResource resource, IOptions<ProtectedResourceOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _resource = resource;
        _options = options.Value;
    }

    /// <summary>Validate one token.</summary>
    internal async Task<AccessTokenResult> ValidateAsync(string token)
    {
        // Read per validation rather than captured, because the set changes under a live process:
        // a JWKS refresher replaces it on a timer, and an in-process key ring rotates on a schedule.
        var parameters = Rfc9068ValidationParameters.ForAccessToken(
            _resource.Issuer, _resource.Identifier, _options.CurrentSigningKeys(), _options.ClockSkew);

        var result = await _handler.ValidateTokenAsync(token, parameters);

        if (!result.IsValid)
        {
            return new AccessTokenResult(
                Classify(result.Exception), Principal: null, ScopeSet.Empty, Describe(result.Exception));
        }

        var identity = result.ClaimsIdentity;
        var principal = new ClaimsPrincipal(identity);

        // RFC 9068 §2.2.3: `scope` is a space-delimited STRING, not an array. Reading it as a
        // string is what the specification requires, and it is also what the minter on the other
        // side of this contract writes — an array here would parse to nothing at all, and the
        // symptom would be every scoped call returning 403 with a token that looks correct.
        _ = ScopeSet.TryParse(identity.FindFirst("scope")?.Value, out var scopes, out _);

        return new AccessTokenResult(AccessTokenFailure.None, principal, scopes);
    }

    /// <summary>
    /// Map a validation exception to a failure kind.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The kinds exist only to pick one of three <b>constant</b> <c>error_description</c> strings.
    /// They do not change the status code or the <c>error</c> value, both of which are
    /// <c>401</c> / <c>invalid_token</c> for every RFC 9068 §4 validation failure (X-33) — the
    /// audience case included, which is what makes it a <c>401</c> rather than a <c>403</c>.
    /// </para>
    /// <para>
    /// Anything unrecognised falls to <see cref="AccessTokenFailure.Rejected"/> rather than to a
    /// case that names a cause. A default that guessed would put a specific claim about someone
    /// else's token into a response header on the strength of not having matched anything.
    /// </para>
    /// </remarks>
    private static AccessTokenFailure Classify(Exception? exception) => exception switch
    {
        SecurityTokenExpiredException => AccessTokenFailure.Expired,
        SecurityTokenInvalidAudienceException => AccessTokenFailure.WrongAudience,
        _ => AccessTokenFailure.Rejected,
    };

    /// <summary>
    /// The exception's type and message, for the operator. A-09.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the value <see cref="Classify"/> throws away, and keeping it is the point: the four
    /// distinct <c>SecurityTokenException</c> subtypes that all become
    /// <see cref="AccessTokenFailure.Rejected"/> are one answer to the client and four different
    /// remedies for whoever is on call. The library's <c>IDXnnnnn</c> codes are stable and
    /// searchable, and <c>SecurityTokenInvalidIssuerException</c> names both issuers in its message,
    /// which is the whole of that diagnosis.
    /// </para>
    /// <para>
    /// <b>What is deliberately not here: the token.</b> Not the compact serialization, not the
    /// header, not a claim. The message is the library's own and is derived from the token's
    /// metadata rather than its bytes — <c>IDX10501</c> quotes the <c>kid</c> and the configured
    /// key ids, which are public — but the value is filtered and capped in <c>Rejection.Of</c>
    /// anyway, because "the message can never contain the credential" is a claim about a dependency
    /// rather than about this code.
    /// </para>
    /// <para>
    /// The exception is <b>not</b> attached to the log line as an <see cref="Exception"/> argument.
    /// A stack trace here describes our own middleware, is identical every time, and would multiply
    /// the size of the one log event that fires once per request under a broken key rotation.
    /// </para>
    /// </remarks>
    private static string? Describe(Exception? exception) =>
        exception is null ? null : $"validator={exception.GetType().Name}: {exception.Message}";
}
