using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Boltway.OAuth.Primitives.Encoding;

namespace Boltway.OAuth.Primitives.Secrets;

/// <summary>
/// A high-entropy secret this server minted: an authorization code, a refresh token, a registration
/// access token, or a client secret.
/// </summary>
/// <remarks>
/// <para>
/// Two properties, both required by N-16. The entropy comes from
/// <see cref="RandomNumberGenerator"/> and is 256 bits — <c>System.Random</c> is banned project-wide
/// and <c>Guid.NewGuid</c> makes no cryptographic promise about its 122. And the plaintext is never
/// persisted: only <see cref="Sha256Hash"/> of it reaches a database column, so disclosure of the
/// database is not account takeover.
/// </para>
/// <para>
/// The wire form is <c>{prefix}{43 base64url characters}</c>. The prefix is not decoration: it lets
/// a value be rejected for being the wrong <i>kind</i> of secret before any lookup happens, and it
/// makes a leaked token greppable in a log dump by what it is.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Usage",
    "CA2231:Overload operator equals on overriding value type Equals",
    Justification =
        "Deliberate. Equals and GetHashCode throw so that a secret cannot be compared as plaintext " +
        "or used as a dictionary key (N-16). Defining == and != would either reintroduce that " +
        "comparison or throw at run time; leaving them undefined makes `a == b` a COMPILE error, " +
        "which is the stronger guarantee and the whole point.")]
public readonly struct OpaqueSecret
{
    private const int EntropyBytes = 32;

    private OpaqueSecret(TokenPurpose purpose, string wire)
    {
        Purpose = purpose;
        Wire = wire;
    }

    /// <summary>What this secret is for.</summary>
    public TokenPurpose Purpose { get; }

    /// <summary>
    /// The full value as it goes over the wire. Handed to the client exactly once, at mint time,
    /// and never recoverable afterwards.
    /// </summary>
    /// <remarks>
    /// The attributes are the leak defence, and they matter more than the <see cref="ToString"/>
    /// override does. Overriding <c>ToString</c> stops string interpolation; it does nothing about
    /// <c>JsonSerializer.Serialize(secret)</c>, Serilog's <c>{@secret}</c> destructuring, or any
    /// structured-logging provider that reflects over properties — all of which would have emitted
    /// <c>{"Purpose":2,"Wire":"ck_rt_…"}</c> with the live token in it.
    /// </remarks>
    [JsonIgnore]
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string Wire { get; }

    /// <summary>Mint a new secret with 256 bits of entropy.</summary>
    public static OpaqueSecret Generate(TokenPurpose purpose)
    {
        Span<byte> entropy = stackalloc byte[EntropyBytes];
        RandomNumberGenerator.Fill(entropy);

        return new OpaqueSecret(purpose, PrefixFor(purpose) + Base64Url.Encode(entropy));
    }

    /// <summary>
    /// Build a secret from material a key derivation produced.
    /// </summary>
    /// <param name="purpose">Which kind of secret this is.</param>
    /// <param name="material">
    /// Exactly <see cref="EntropyBytes"/> bytes from a cryptographic KDF or MAC — never from a
    /// non-cryptographic generator, a counter, or a hash of something guessable.
    /// </param>
    /// <remarks>
    /// <para>
    /// Narrow by intent. The refresh path needs a token that two concurrent redemptions can both
    /// compute from the same record, which <see cref="Generate"/> cannot provide because its output
    /// is random. Everything else should keep using <see cref="Generate"/>: derived material is only
    /// as unguessable as the key and the label behind it, and this entry point cannot check either.
    /// </para>
    /// <para>
    /// <b>And narrow by accessibility, because "deliberately narrow" was not true while it was
    /// public.</b> A review measured it: <c>FromDerivedMaterial(TokenPurpose.RefreshToken,
    /// SHA256("user@example.com"))</c> minted a valid <c>ck_rt_…</c> that <see cref="TryParse"/>
    /// accepted, and <c>TokenPurpose.RegistrationAccessToken</c> — the sole authenticator for full
    /// control of a client record — behaved identically. The 32-byte check is the right guard for
    /// the stated purpose, wire indistinguishability, and no guard whatsoever for the one the name
    /// suggests. On a shipped package that is an unguessability claim with nothing behind it.
    /// </para>
    /// </remarks>
    internal static OpaqueSecret FromDerivedMaterial(TokenPurpose purpose, ReadOnlySpan<byte> material)
    {
        if (purpose == TokenPurpose.None)
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "A secret needs a real purpose.");
        }

        if (material.Length != EntropyBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(material),
                material.Length,
                $"Derived material must be exactly {EntropyBytes} bytes so the result is "
                + "indistinguishable on the wire from a generated secret — TryParse checks the length.");
        }

        return new OpaqueSecret(purpose, PrefixFor(purpose) + Base64Url.Encode(material));
    }

    /// <summary>
    /// Parse a presented secret, checking that it is the kind of secret the caller expects.
    /// </summary>
    /// <param name="wire">The value as presented by the client.</param>
    /// <param name="expected">The purpose this call site accepts. Nothing else will parse.</param>
    /// <param name="secret">The parsed secret.</param>
    /// <remarks>
    /// The prefix check runs before anything hashes or touches storage, so presenting a refresh
    /// token where an authorization code is expected is refused on shape rather than on a failed
    /// lookup. That difference matters: a failed lookup at <c>/token</c> is <c>invalid_grant</c>,
    /// which tells a client to discard a token that may be perfectly good.
    /// </remarks>
    public static bool TryParse(string? wire, TokenPurpose expected, out OpaqueSecret secret)
    {
        secret = default;

        if (wire is null || expected == TokenPurpose.None)
        {
            return false;
        }

        var prefix = PrefixFor(expected);

        if (!wire.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var body = wire[prefix.Length..];

        // 32 bytes of entropy is exactly 43 unpadded base64url characters. A value of any other
        // length did not come from Generate.
        if (body.Length != 43 || !Base64Url.TryDecode(body, out var decoded) || decoded.Length != EntropyBytes)
        {
            return false;
        }

        secret = new OpaqueSecret(expected, wire);
        return true;
    }

    /// <summary>The prefix identifying each kind of secret on the wire.</summary>
    /// <remarks>
    /// No prefix is a prefix of another — <c>ck_rt_</c> and <c>ck_rat_</c> diverge at index 4 —
    /// which is what makes the <c>StartsWith</c> check in <see cref="TryParse"/> unambiguous.
    /// </remarks>
    private static string PrefixFor(TokenPurpose purpose) => purpose switch
    {
        TokenPurpose.AuthorizationCode => "ck_ac_",
        TokenPurpose.RefreshToken => "ck_rt_",
        TokenPurpose.RegistrationAccessToken => "ck_rat_",
        TokenPurpose.ClientSecret => "ck_cs_",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown token purpose."),
    };

    /// <summary>Whether this is a real secret rather than a <see langword="default"/>.</summary>
    public bool IsPresent => Wire is not null && Purpose != TokenPurpose.None;

    /// <summary>
    /// Never returns the secret. Covers string interpolation and exception messages; the
    /// attributes on <see cref="Wire"/> cover serialization and structured logging.
    /// </summary>
    public override string ToString() => $"{Purpose}:<redacted>";

    /// <summary>Not supported. Compare hashes, never plaintext.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    /// <remarks>
    /// <see cref="ValueType.Equals(object)"/> would otherwise compare the plaintext with
    /// <c>string.Equals</c> — variable-time, and reachable through
    /// <c>HashSet&lt;OpaqueSecret&gt;</c> or <c>List.Contains</c> without anyone writing a
    /// comparison. N-16 says the comparison is <c>FixedTimeEquals</c> on a hash; leaving a second
    /// route open makes that a convention rather than a rule. No timing signal was measurable
    /// through the boxing, so this closes an API hole rather than a demonstrated oracle.
    /// </remarks>
    public override bool Equals(object? obj) =>
        throw new NotSupportedException(
            "Compare Sha256Hash values with FixedTimeEquals; never compare secret plaintext (N-16).");

    /// <summary>Not supported, so that a secret cannot be used as a dictionary key.</summary>
    /// <exception cref="NotSupportedException">Always.</exception>
    public override int GetHashCode() =>
        throw new NotSupportedException(
            "An OpaqueSecret must not be a hash key; key on Sha256Hash instead (N-16).");
}
