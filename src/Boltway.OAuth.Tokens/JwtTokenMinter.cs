using System.Security.Cryptography;
using Boltway.OAuth.Primitives.Encoding;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens;

/// <summary>A key this server signs with.</summary>
/// <remarks>
/// Constructing one stamps <see cref="SecurityKey.KeyId"/> from <see cref="Kid"/>, and that is not
/// bookkeeping. The verifier is configured with <c>TryAllIssuerSigningKeys = false</c>, so it only
/// considers keys whose id matches the token's <c>kid</c> header - a key without an id matches
/// nothing and every signature check fails with "no security keys were provided", which reads like
/// a missing key rather than an unlabelled one. Trying every key instead would be worse: it turns
/// each verification into a scan over the whole JWKS and hides a genuine rotation problem.
/// </remarks>
public sealed class SigningKeyHandle
{
    /// <summary>Create a handle, labelling the key with its identifier.</summary>
    public SigningKeyHandle(string kid, SigningAlgorithm algorithm, SecurityKey key)
    {
        ArgumentException.ThrowIfNullOrEmpty(kid);
        ArgumentNullException.ThrowIfNull(key);

        if (algorithm is SigningAlgorithm.None)
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm), "A signing key needs a real algorithm.");
        }

        if (key is RsaSecurityKey { Rsa: not null } rsa && rsa.Rsa.KeySize < SigningAlgorithms.MinimumRsaKeySizeBits)
        {
            throw new ArgumentOutOfRangeException(
                nameof(key), rsa.Rsa.KeySize, $"RSA keys must be at least {SigningAlgorithms.MinimumRsaKeySizeBits} bits.");
        }

        key.KeyId = kid;

        Kid = kid;
        Algorithm = algorithm;
        Key = key;
    }

    /// <summary>The key identifier, published in JWKS and echoed in every JOSE header.</summary>
    public string Kid { get; }

    /// <summary>Which algorithm this key is for.</summary>
    public SigningAlgorithm Algorithm { get; }

    /// <summary>The key material, private for signing and public for verifying.</summary>
    public SecurityKey Key { get; }
}

/// <summary>
/// Mints access tokens and ID tokens.
/// </summary>
/// <remarks>
/// Both methods take a descriptor whose audience type differs, so the compiler is what keeps N-10
/// true: there is no way to hand an access token's resource audience to the ID token path.
/// </remarks>
public sealed class JwtTokenMinter
{
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    /// <summary>Mint an access token. RFC 9068.</summary>
    public MintedToken MintAccessToken(AccessTokenDescriptor descriptor, SigningKeyHandle key)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(key);

        // RFC 9068 §2.2's required claims, all present and none of them optional here.
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = descriptor.Issuer.Value,
            ["aud"] = descriptor.Audience.Canonical,
            ["sub"] = descriptor.Subject.Value,
            ["client_id"] = descriptor.ClientId.Value,
            ["iat"] = descriptor.IssuedAt.ToUnixTimeSeconds(),
            ["exp"] = descriptor.ExpiresAt.ToUnixTimeSeconds(),
            ["jti"] = descriptor.JwtId,

            // Our grant identifier, so a resource server can check a revocation denylist without
            // an introspection round trip on every call.
            ["gid"] = descriptor.GrantId,
        };

        // RFC 9068 §2.2.3: scope is a space-delimited STRING, not an array. Emitting an array is a
        // common and quiet defect - most resource servers read it with a string accessor and see
        // nothing at all, so the token appears to carry no scopes.
        if (!descriptor.Scope.IsEmpty)
        {
            claims["scope"] = descriptor.Scope.ToWireString();
        }

        if (descriptor.AuthTime is { } authTime)
        {
            claims["auth_time"] = authTime.ToUnixTimeSeconds();
        }

        AddExtra(claims, descriptor.Extra);

        return Mint(claims, TokenTypes.AccessToken, key, descriptor.ExpiresAt);
    }

    /// <summary>Mint an ID token. OIDC Core §2.</summary>
    public MintedToken MintIdToken(IdTokenDescriptor descriptor, SigningKeyHandle key)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(key);

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = descriptor.Issuer.Value,

            // The CLIENT, not a resource. See IdTokenDescriptor's remarks for why the two are
            // different types.
            ["aud"] = descriptor.Audience.Value,
            ["sub"] = descriptor.Subject.Value,
            ["iat"] = descriptor.IssuedAt.ToUnixTimeSeconds(),
            ["exp"] = descriptor.ExpiresAt.ToUnixTimeSeconds(),
        };

        // Echoed verbatim when the client sent one, and absent otherwise. Never generated: the
        // client checks this value against what it stored, so a server-invented nonce would pass a
        // replay check the client believes it is performing.
        if (!string.IsNullOrEmpty(descriptor.Nonce))
        {
            claims["nonce"] = descriptor.Nonce;
        }

        if (descriptor.AuthTime is { } authTime)
        {
            claims["auth_time"] = authTime.ToUnixTimeSeconds();
        }

        if (!string.IsNullOrEmpty(descriptor.AccessTokenHash))
        {
            claims["at_hash"] = descriptor.AccessTokenHash;
        }

        AddExtra(claims, descriptor.Extra);

        return Mint(claims, TokenTypes.IdToken, key, descriptor.ExpiresAt);
    }

    /// <summary>
    /// The <c>at_hash</c> for an access token. OIDC Core §3.1.3.6.
    /// </summary>
    /// <remarks>
    /// Left-most half of the SHA-256 of the ASCII access token, base64url encoded. It lets a client
    /// verify that the access token it received belongs with the ID token it received, which is
    /// what stops a substituted access token going unnoticed.
    /// </remarks>
    public static string ComputeAccessTokenHash(string accessToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);

        var digest = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken));

        return Base64Url.Encode(digest.AsSpan(0, digest.Length / 2));
    }

    private MintedToken Mint(
        Dictionary<string, object> claims, string tokenType, SigningKeyHandle key, DateTimeOffset expiresAt)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(key.Key, key.Algorithm.ToJwaName()),

            // The header that distinguishes an access token from an ID token. Without it the two
            // are interchangeable to any verifier that does not check `typ` - and `ValidTypes` is
            // unset by default, so most do not.
            TokenType = tokenType,

            // Times come from the claims dictionary, which holds the exact values the caller
            // decided. Letting the handler stamp its own would silently disagree with what was
            // persisted alongside the grant.
            Expires = null,
            IssuedAt = null,
            NotBefore = null,
        };

        return new MintedToken(_handler.CreateToken(descriptor), expiresAt, key.Kid);
    }

    /// <summary>
    /// Merge caller-supplied claims, refusing to overwrite a protocol claim.
    /// </summary>
    /// <remarks>
    /// A claims mapper is a customer extension point, and the one thing it must never be able to do
    /// is restate <c>aud</c> (which would defeat N-01) or <c>iss</c> (N-13). Throwing rather than
    /// ignoring, because a mapper that believes it set a claim and did not is a subtler failure
    /// than one that stops.
    /// </remarks>
    private static void AddExtra(Dictionary<string, object> claims, IReadOnlyDictionary<string, object?>? extra)
    {
        if (extra is null)
        {
            return;
        }

        foreach (var (name, value) in extra)
        {
            if (Reserved.Contains(name))
            {
                throw new InvalidOperationException(
                    $"'{name}' is a protocol claim and cannot be set by a claims mapper. Overwriting " +
                    "it would defeat the guarantee the surrounding code makes about the token.");
            }

            if (value is not null)
            {
                claims[name] = value;
            }
        }
    }

    private static readonly System.Collections.Frozen.FrozenSet<string> Reserved =
        System.Collections.Frozen.FrozenSet.ToFrozenSet(
            ["iss", "aud", "sub", "exp", "iat", "nbf", "jti", "typ", "alg", "kid",
             "scope", "client_id", "gid", "cnf", "nonce", "at_hash", "auth_time"],
            StringComparer.Ordinal);
}
