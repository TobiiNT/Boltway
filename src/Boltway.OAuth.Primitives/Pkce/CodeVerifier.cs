using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Boltway.OAuth.Primitives.Encoding;

namespace Boltway.OAuth.Primitives.Pkce;

/// <summary>
/// A PKCE <c>code_verifier</c>, RFC 7636 §4.1.
/// </summary>
/// <remarks>
/// The grammar is <c>43*128unreserved</c> where <c>unreserved = ALPHA / DIGIT / "-" / "." / "_" /
/// "~"</c>. Both bounds are enforced: below 43 characters the verifier carries less entropy than
/// the 256-bit minimum the RFC requires, and a length cap keeps an attacker from using the token
/// endpoint as a hashing oracle.
/// </remarks>
public readonly struct CodeVerifier
{
    /// <summary>RFC 7636 §4.1 minimum length.</summary>
    public const int MinLength = 43;

    /// <summary>RFC 7636 §4.1 maximum length.</summary>
    public const int MaxLength = 128;

    private CodeVerifier(string value) => Value = value;

    /// <summary>The verifier as sent, ASCII.</summary>
    /// <remarks>
    /// Carries the same attributes as <c>OpaqueSecret.Wire</c>, for the same reason and after the
    /// same omission: this reads as a request parameter - it arrives in a form post next to
    /// <c>grant_type</c> - and it is a credential. Whoever holds it can redeem the matching
    /// authorization code, which is why <c>GrantHandlers</c> logs its <i>length</i> and never its
    /// value. It had no serialization defence at all until a test went looking.
    /// </remarks>
    [JsonIgnore]
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string Value { get; }

    /// <summary>
    /// Never returns the verifier. Covers string interpolation and exception messages; the
    /// attributes on <see cref="Value"/> cover serialization.
    /// </summary>
    public override string ToString() => "<redacted>";

    /// <summary>Parse a verifier from a token request. Validates the grammar; changes nothing.</summary>
    public static bool TryParse(string? raw, out CodeVerifier verifier)
    {
        verifier = default;

        if (raw is null || raw.Length is < MinLength or > MaxLength)
        {
            return false;
        }

        foreach (var c in raw)
        {
            if (!IsUnreserved(c))
            {
                return false;
            }
        }

        verifier = new CodeVerifier(raw);
        return true;
    }

    /// <summary>Mint a verifier. Used by the conformance client, never on the server's own path.</summary>
    public static CodeVerifier Generate()
    {
        // 32 bytes -> 43 base64url characters, exactly the RFC minimum, and every character it
        // produces is already in the unreserved set.
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return new CodeVerifier(Base64Url.Encode(entropy));
    }

    /// <summary>
    /// The S256 transformation: base64url(SHA-256(ASCII(verifier))), RFC 7636 §4.6.
    /// </summary>
    /// <remarks>
    /// ASCII, not UTF-8. The grammar admits only unreserved characters so the two encodings agree
    /// on every legal input, but stating it keeps the code honest about what the RFC says.
    /// </remarks>
    public string ComputeS256Challenge()
    {
        Span<byte> ascii = stackalloc byte[Value.Length];
        System.Text.Encoding.ASCII.GetBytes(Value, ascii);

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(ascii, hash);

        return Base64Url.Encode(hash);
    }

    private static bool IsUnreserved(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '.' or '_' or '~';
}
