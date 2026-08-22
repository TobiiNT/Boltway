using System.Security.Cryptography;
using Boltway.OAuth.Primitives.Encoding;

namespace Boltway.OAuth.Primitives.Pkce;

/// <summary>
/// A PKCE <c>code_challenge</c> as it arrived on an authorization request, RFC 7636 §4.2.
/// </summary>
public readonly struct CodeChallenge
{
    /// <summary>An S256 challenge is SHA-256 in unpadded base64url: always exactly 43 characters.</summary>
    public const int S256Length = 43;

    private CodeChallenge(string value, CodeChallengeMethod method)
    {
        Value = value;
        Method = method;
    }

    /// <summary>The challenge exactly as sent. Stored against the authorization code.</summary>
    public string Value { get; }

    /// <summary>The transformation. Only <see cref="CodeChallengeMethod.S256"/> is ever valid.</summary>
    public CodeChallengeMethod Method { get; }

    /// <summary>
    /// Parse the <c>code_challenge_method</c> parameter.
    /// </summary>
    /// <remarks>
    /// <b>An absent method is not <c>plain</c> here.</b> RFC 7636 §4.3 says the parameter defaults
    /// to <c>plain</c> when omitted, and this server refuses that default rather than implementing
    /// it: omission returns <see cref="CodeChallengeMethod.None"/>, which the authorize pipeline
    /// rejects with <c>invalid_request</c>.
    /// <para>
    /// The distinction is the RFC 9700 §4.8 downgrade attack. If omission silently meant
    /// <c>plain</c>, an attacker who can strip one query parameter turns every S256 flow into a
    /// plain one, and <c>plain</c> puts the verifier in the authorization request. The parameter
    /// an attacker can remove must not be the parameter that selects the weaker mode.
    /// </para>
    /// </remarks>
    public static CodeChallengeMethod ParseMethod(string? raw) =>
        string.Equals(raw, "S256", StringComparison.Ordinal) ? CodeChallengeMethod.S256 : CodeChallengeMethod.None;

    /// <summary>Parse a challenge. Only S256-shaped values are accepted.</summary>
    public static bool TryParse(string? raw, CodeChallengeMethod method, out CodeChallenge challenge)
    {
        challenge = default;

        if (method != CodeChallengeMethod.S256 || raw is null || raw.Length != S256Length)
        {
            return false;
        }

        // Decode rather than merely charset-check.
        //
        // The length and alphabet alone do not constrain the value to something SHA-256 could have
        // produced: a 32-byte payload leaves the final sextet's low four bits zero, so only 16 of
        // the 64 alphabet characters are canonical in the last position. Checking the charset
        // accepts about three quarters of malformed challenges, and each one then surfaces at
        // /token as an opaque PKCE mismatch — which is exactly the diagnosis this check exists to
        // prevent. Decoding to 32 bytes rejects them here, where the error can say what is wrong.
        //
        // Mutation testing flags the `||` below as survivable, and it is right that no test kills
        // it — but the mutant is equivalent, not a gap, so do not go looking for the test that
        // closes it. `raw.Length` is already pinned at 43 above; `TryDecode` sets `decoded` to an
        // empty array on every failure path; and 43 unpadded characters decode to exactly 32 bytes
        // or not at all. So the two operands are always equal on reachable input, and `||` and
        // `&&` agree. The length comparison is a backstop against a later edit to either constant,
        // and it is kept for that reason alone.
        if (!Base64Url.TryDecode(raw, out var decoded) || decoded.Length != 32)
        {
            return false;
        }

        challenge = new CodeChallenge(raw, method);
        return true;
    }

    /// <summary>
    /// Rehydrate a challenge previously stored against an authorization code.
    /// </summary>
    internal static CodeChallenge Rehydrate(string value, CodeChallengeMethod method) => new(value, method);

    /// <summary>
    /// Does <paramref name="verifier"/> satisfy this challenge?
    /// </summary>
    /// <remarks>
    /// Constant-time comparison. The challenge is not secret — it travelled in a query string — but
    /// this method is also the shape every future secret comparison gets copied from, and a variable
    /// -time compare that is safe today is a template for one that is not.
    /// </remarks>
    public bool Matches(in CodeVerifier verifier)
    {
        // A default(CodeVerifier) has a null Value, and ComputeS256Challenge would throw on it. A
        // token handler that compared before parsing would then return 500 instead of the
        // invalid_grant the client needs to recover, so this fails closed rather than throwing.
        if (Method != CodeChallengeMethod.S256 || verifier.Value is null || Value is null)
        {
            return false;
        }

        var computed = verifier.ComputeS256Challenge();

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(computed),
            System.Text.Encoding.ASCII.GetBytes(Value));
    }
}
