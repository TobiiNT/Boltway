namespace Boltway.OAuth.Tokens;

/// <summary>
/// The <c>typ</c> header values this server issues and accepts.
/// </summary>
/// <remarks>
/// <para>
/// N-09. RFC 9068 §2.1 requires an access token to carry <c>typ: at+jwt</c>, and the reason is
/// cross-JWT confusion: without it, an <b>ID token</b> — which the client legitimately holds, and
/// which is signed by the same key, carries the same <c>iss</c> and a <c>sub</c> — is a
/// structurally valid access token. A resource server that checks the signature, the issuer, the
/// expiry and the subject, but not the type, accepts it.
/// </para>
/// <para>
/// <c>TokenValidationParameters.ValidTypes</c> is <b>unset by default</b>, which means the stock
/// ASP.NET Core JWT configuration does not make this check. That is the single most important
/// sentence in this file.
/// </para>
/// </remarks>
public static class TokenTypes
{
    /// <summary>RFC 9068 §2.1. The <c>typ</c> of every access token this server issues.</summary>
    public const string AccessToken = "at+jwt";

    /// <summary>
    /// The media-type spelling of the same thing.
    /// </summary>
    /// <remarks>
    /// RFC 8725 §3.11 permits the <c>application/</c> prefix to be omitted, so both spellings are
    /// legal on the wire and a verifier that accepts only one will reject conformant tokens from
    /// some issuers. We emit the short form and accept both.
    /// </remarks>
    public const string AccessTokenWithPrefix = "application/at+jwt";

    /// <summary>OIDC Core. The <c>typ</c> of every ID token.</summary>
    public const string IdToken = "JWT";
}

/// <summary>
/// Signing algorithms this server will use or accept.
/// </summary>
/// <remarks>
/// <para>
/// A closed set, and everything absent from it is absent deliberately.
/// </para>
/// <para>
/// <b>No <c>HS256</c> or any other symmetric algorithm.</b> Not because HMAC is weak, but because
/// mixing symmetric and asymmetric algorithms in one verifier is the classic algorithm-confusion
/// attack: the verifier is handed a public key, an attacker re-signs a forged token with that
/// public key as an HMAC secret, and a verifier that picks its algorithm from the token's own
/// header accepts it. The public key is published in JWKS, so the "secret" is not secret. Keeping
/// symmetric algorithms out of the allow-list means the confusion has no path.
/// </para>
/// <para>
/// <b>No <c>none</c>.</b> There is no code path that produces or accepts an unsigned token.
/// </para>
/// </remarks>
public enum SigningAlgorithm
{
    /// <summary>Not set.</summary>
    None = 0,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 with SHA-256. The interop floor.
    /// </summary>
    /// <remarks>
    /// Mandatory to implement per RFC 9068 §2.1, required in
    /// <c>id_token_signing_alg_values_supported</c> by OIDC Discovery, and what ChatGPT signs its
    /// client assertions with. Every client understands it.
    /// </remarks>
    RS256 = 1,

    /// <summary>ECDSA P-256 with SHA-256. Smaller tokens, offered but never the only option.</summary>
    ES256 = 2,
}

/// <summary>Helpers for <see cref="SigningAlgorithm"/>.</summary>
public static class SigningAlgorithms
{
    /// <summary>Smallest RSA modulus accepted. Below this the key is refused outright.</summary>
    public const int MinimumRsaKeySizeBits = 2048;

    /// <summary>The JWA name, as it appears in a JOSE header and in JWKS.</summary>
    public static string ToJwaName(this SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.RS256 => "RS256",
        SigningAlgorithm.ES256 => "ES256",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Not a signing algorithm."),
    };

    /// <summary>
    /// Parse a JWA name. Anything not in the closed set returns <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Ordinal and case-sensitive: JWA names are literals, and accepting <c>rs256</c> would mean
    /// two spellings of one algorithm, which is one more than a comparison should have to consider.
    /// </remarks>
    public static bool TryParse(string? name, out SigningAlgorithm algorithm)
    {
        algorithm = name switch
        {
            "RS256" => SigningAlgorithm.RS256,
            "ES256" => SigningAlgorithm.ES256,
            _ => SigningAlgorithm.None,
        };

        return algorithm != SigningAlgorithm.None;
    }

    /// <summary>Every algorithm this server accepts, as JWA names. The verifier allow-list.</summary>
    public static IReadOnlyList<string> All { get; } = ["RS256", "ES256"];

    /// <summary>
    /// Every algorithm this server <b>issues</b> with, as JWA names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A different question from <see cref="All"/>, and the two were the same list for a release.
    /// The discovery document's <c>id_token_signing_alg_values_supported</c> is an issuer
    /// capability, it was filled from the verifier allow-list, and so this server advertised ES256
    /// while <c>TokenIssuer.MintAsync</c> asks the ring for RS256 and nothing else. A relying party
    /// configuring <c>id_token_signed_response_alg=ES256</c> from that document rejects every token
    /// this server can produce.
    /// </para>
    /// <para>
    /// Accepting more than you issue is ordinary and safe — it is what makes a rotation across
    /// algorithms possible. Advertising more than you issue is a promise to somebody else's code.
    /// Grow this list when <c>TokenIssuer</c> can mint the algorithm, not when the ring can hold it.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> Issued { get; } = ["RS256"];
}
