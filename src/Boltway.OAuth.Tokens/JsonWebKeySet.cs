using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Boltway.OAuth.Primitives.Encoding;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.OAuth.Tokens;

/// <summary>
/// Serializes the JWKS document published at <c>/.well-known/jwks.json</c>. RFC 7517.
/// </summary>
/// <remarks>
/// <para>
/// This type builds each JWK <b>field by field from the public parameters</b> rather than asking a
/// library to serialize a key object. That is the difference between a JWKS document and an
/// incident: a serializer handed a private key writes the private members too, and for RSA those
/// are <c>d</c>, <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c> and <c>qi</c> - publishing any of them at
/// a public, cacheable, CORS-enabled endpoint hands over the ability to mint tokens as this server.
/// </para>
/// <para>
/// Whitelisting the public members means a future key type cannot leak by default: it fails to
/// serialize until someone adds it deliberately. A blacklist would have the opposite property.
/// A test asserts the rendered document contains none of the private member names.
/// </para>
/// </remarks>
public static class JsonWebKeySet
{
    /// <summary>Render a JWKS document.</summary>
    public static string Render(IReadOnlyList<SigningKeyHandle> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        var jwks = new JsonArray();

        foreach (var key in keys)
        {
            jwks.Add(ToPublicJwk(key));
        }

        return new JsonObject { ["keys"] = jwks }.ToJsonString(
            new JsonSerializerOptions { WriteIndented = false });
    }

    /// <summary>
    /// One key, public parameters only.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// The key type is not one this method knows how to reduce to public parameters. Throwing is
    /// the safe direction: the alternative is emitting something unreviewed at a public endpoint.
    /// </exception>
    private static JsonObject ToPublicJwk(SigningKeyHandle key)
    {
        var jwk = key.Key switch
        {
            RsaSecurityKey { Rsa: not null } rsa => FromRsa(rsa.Rsa.ExportParameters(includePrivateParameters: false)),
            RsaSecurityKey rsa => FromRsa(rsa.Parameters),
            ECDsaSecurityKey { ECDsa: not null } ec => FromEcdsa(ec.ECDsa.ExportParameters(includePrivateParameters: false)),
            _ => throw new NotSupportedException(
                $"'{key.Key.GetType().Name}' cannot be reduced to public JWK parameters. Add an " +
                "explicit case rather than letting a serializer decide what to publish — at this " +
                "endpoint the difference is whether the private key leaves the process."),
        };

        // RFC 7517 §4. `kid` is what lets a verifier pick the right key without trying all of them;
        // `use` and `alg` narrow what the key may be applied to.
        jwk["kid"] = key.Kid;
        jwk["use"] = "sig";
        jwk["alg"] = key.Algorithm.ToJwaName();

        return jwk;
    }

    /// <summary>RSA public members only: <c>n</c> and <c>e</c>. RFC 7518 §6.3.1.</summary>
    private static JsonObject FromRsa(RSAParameters parameters)
    {
        if (parameters.Modulus is null || parameters.Exponent is null)
        {
            throw new InvalidOperationException("An RSA public key needs both a modulus and an exponent.");
        }

        return new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64Url.Encode(parameters.Modulus),
            ["e"] = Base64Url.Encode(parameters.Exponent),
        };
    }

    /// <summary>EC public members only: <c>crv</c>, <c>x</c> and <c>y</c>. RFC 7518 §6.2.1.</summary>
    private static JsonObject FromEcdsa(ECParameters parameters)
    {
        if (parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new InvalidOperationException("An EC public key needs both coordinates.");
        }

        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64Url.Encode(parameters.Q.X),
            ["y"] = Base64Url.Encode(parameters.Q.Y),
        };
    }

    /// <summary>
    /// The JWK private member names, for the test that asserts none of them is ever published.
    /// </summary>
    /// <remarks>
    /// Public so the resource server and the doctor can run the same check against a live endpoint:
    /// "does this issuer publish its private key" is worth asking of anyone's JWKS, not only ours.
    /// </remarks>
    public static IReadOnlyList<string> PrivateMemberNames { get; } = ["d", "p", "q", "dp", "dq", "qi", "k"];
}
