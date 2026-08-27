namespace Boltway.OAuth.Primitives.Secrets;

/// <summary>
/// What a minted secret is for. Part of the value, not metadata about it.
/// </summary>
/// <remarks>
/// Every purpose gets a distinct wire prefix, and parsing checks the prefix <b>before</b> hashing.
/// That is what makes a registration access token unable to be valid at <c>/token</c>: the refresh
/// store only ever receives a value that parsed as <see cref="RefreshToken"/>, and a
/// <c>bw_rat_</c> string never gets that far.
/// <para>
/// Registration access tokens are the case that motivates this. They are the sole authenticator for
/// full control of a client record - read, rewrite, delete - so a bug that let one be accepted
/// somewhere else is not a small bug. Minting them from the same pipeline as everything else, with
/// a distinct prefix, means the separation is checked on every parse rather than remembered.
/// </para>
/// </remarks>
public enum TokenPurpose
{
    /// <summary>
    /// Not a purpose. The value of a <see langword="default"/> secret, which is not a secret.
    /// </summary>
    /// <remarks>
    /// Zero is deliberately not a real purpose. With <c>AuthorizationCode = 0</c>, the
    /// <see langword="out"/> value from a <i>failed</i> <c>TryParse</c> described itself as an
    /// authorization code - so a caller who ignored the returned <see cref="bool"/> got a struct
    /// that logged as <c>"AuthorizationCode:&lt;redacted&gt;"</c>, reading exactly like a live code,
    /// and then threw on first use. Reserving zero makes the uninitialised value name itself.
    /// </remarks>
    None = 0,

    /// <summary>An authorization code. Single use, short lived.</summary>
    AuthorizationCode = 1,

    /// <summary>A refresh token. Rotated on every use.</summary>
    RefreshToken = 2,

    /// <summary>An RFC 7592 registration access token. Full control of one client record.</summary>
    RegistrationAccessToken = 3,

    /// <summary>A client secret, for confidential clients.</summary>
    ClientSecret = 4,
}
