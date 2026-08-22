namespace Boltway.OAuth.Primitives.Pkce;

/// <summary>
/// The PKCE transformation, RFC 7636 §4.2.
/// </summary>
/// <remarks>
/// <para>
/// There is deliberately no <c>Plain</c> member. RFC 7636 defines it, and OAuth 2.1 §7.5.1 plus
/// RFC 9700 §2.1.1 both refuse it: under <c>plain</c> the challenge <i>is</i> the verifier, so an
/// attacker who can read the authorization request — browser history, a referrer header, a proxy
/// log, the address bar over someone's shoulder — has everything needed to redeem the code.
/// </para>
/// <para>
/// Its absence is the enforcement. A parser that maps the string <c>"plain"</c> to nothing cannot
/// be talked into accepting it later by a configuration flag, and there is no enum member for a
/// downgrade path to target. The metadata document advertises <c>["S256"]</c> for the same reason.
/// </para>
/// </remarks>
public enum CodeChallengeMethod
{
    /// <summary>Not supplied, or not recognized. Never valid on a request.</summary>
    None = 0,

    /// <summary>base64url(SHA-256(ASCII(code_verifier))), RFC 7636 §4.2.</summary>
    S256 = 1,
}
