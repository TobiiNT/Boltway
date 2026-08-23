using System.Security.Cryptography;
using System.Text;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Token;

/// <summary>
/// Derives a refresh token's plaintext from its position in the family.
/// </summary>
/// <remarks>
/// <para>
/// This exists to make the grace window observable to the client it was built for. N-08's
/// acceptance criterion is "two concurrent redemptions ⇒ one successor, <b>both callers get it</b>",
/// and the store honours that — <c>ReplayedWithinGrace</c> hands back the successor record rather
/// than minting a second one. But only the successor's <i>hash</i> is stored, so a handler that
/// generated the plaintext itself had nothing to return to the loser and answered
/// <c>invalid_grant</c>.
/// </para>
/// <para>
/// That answer went to exactly the wrong population. Claude refreshes proactively and reactively,
/// so the two race in normal operation, and the reactive one is racing <i>because</i> it just got a
/// 401 and needs a token now. Clients branch on <c>invalid_grant</c> as "this refresh token is
/// dead". So the window prevented family revocation and, from the client's side, looked exactly
/// like death.
/// </para>
/// <para>
/// Deriving the plaintext deterministically from <c>(familyId, generation)</c> fixes it with no
/// extra storage and no plaintext at rest: both racers compute the same value from the same record.
/// The server key is what stops a <b>client</b> doing the same — a client that could derive its own
/// successor could walk the chain without ever rotating, which is the property rotation exists to
/// create.
/// </para>
/// </remarks>
public sealed class RefreshTokenDeriver
{
    private readonly byte[] _key;

    /// <summary>The shortest key accepted. HMAC-SHA256's block security level.</summary>
    public const int MinimumKeyBytes = 32;

    /// <summary>
    /// Create a deriver over a key.
    /// </summary>
    /// <param name="key">
    /// The secret. Must be stable across restarts <b>and across instances</b> — a per-process key
    /// makes the grace window work only when both racers land on the same node, which is the subtle
    /// half-failure this class exists to remove. It belongs in a key manager alongside the signing
    /// keys, and it is equivalent in value to the whole refresh-token corpus.
    /// </param>
    public RefreshTokenDeriver(ReadOnlySpan<byte> key)
    {
        if (key.Length < MinimumKeyBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(key),
                key.Length,
                $"A refresh-token derivation key must be at least {MinimumKeyBytes} bytes. Anything "
                + "shorter is a brute-force target that yields every refresh token this server will "
                + "ever issue.");
        }

        _key = key.ToArray();
    }

    /// <summary>
    /// The encoder for the derivation label. Strict, and that is the whole point.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Encoding.UTF8"/> — the static property — replaces every ill-formed sequence with
    /// U+FFFD instead of failing. An adversarial review measured what that means here:
    /// <c>Derive("\uD800", 1)</c>, <c>Derive("\uDC00", 1)</c> and <c>Derive("�", 1)</c> all
    /// produced the <b>same token</b>, because all three encode to the same bytes. A collision in
    /// this function is two distinct families sharing one live refresh token, which is a
    /// cross-account credential leak rather than a hashing curiosity.
    /// </para>
    /// <para>
    /// <c>Sha256Hash.OfString</c> already reached this conclusion and its comment names the same
    /// hazard. This is the keyed derivation, where the consequence is strictly worse, and it was
    /// using the permissive encoder.
    /// </para>
    /// <para>
    /// Throwing is correct rather than harsh. A lone surrogate in a family id means the id did not
    /// come from where this server thinks it comes from — <c>Guid.ToString("N")</c> — so it is a
    /// corrupted or hostile store row, and a token minted from it is worth less than an exception.
    /// </para>
    /// </remarks>
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The token for one position in a family.</summary>
    /// <param name="familyId">Which family.</param>
    /// <param name="generation">How many rotations deep.</param>
    /// <exception cref="EncoderFallbackException">
    /// <paramref name="familyId"/> is not well-formed UTF-16. See <see cref="StrictUtf8"/>.
    /// </exception>
    /// <remarks>
    /// <para>
    /// The two inputs are separated by a byte that cannot occur in either, so <c>("ab", 1)</c> and
    /// <c>("a", …)</c> cannot collide by concatenation.
    /// </para>
    /// <para>
    /// An earlier version of this remark credited that to the alphabets — "family ids are hex and
    /// generations are decimal, so a NUL is outside both". That reasoning is weaker than the
    /// property it defends, and a review that checked found the stronger one: the <i>generation</i>
    /// is NUL-free, so the last NUL always splits the two fields and the parse back is unambiguous
    /// no matter what the family id contains. Injectivity therefore does not depend on a caller
    /// honouring the hex convention — which matters, because <c>RefreshTokenRecord.FamilyId</c> is
    /// an unconstrained <see langword="string"/> hydrated from a customer's database column.
    /// </para>
    /// </remarks>
    public OpaqueSecret Derive(string familyId, int generation)
    {
        ArgumentException.ThrowIfNullOrEmpty(familyId);

        return OpaqueSecret.FromDerivedMaterial(TokenPurpose.RefreshToken, Material(familyId, generation));
    }

    /// <summary>
    /// The same successor, spelled the way it was before the <c>ck_</c> wire prefix was retired.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The material is identical — the prefix sits outside the MAC — so this is the same token
    /// under its old name rather than a second credential. It exists for one branch: the grace
    /// window checks a reconstructed successor against the hash the store holds and fails closed
    /// when they differ, and a row written before the rename holds the hash of the old spelling.
    /// </para>
    /// <para>
    /// Without it that refusal fires on an upgrade and blames the operator's
    /// <c>RefreshTokenDerivationKey</c>, which would be the one route into it where that sentence
    /// is false. Retire this with <c>OpaqueSecret</c>'s legacy prefix, or sooner: only a family
    /// whose successor was minted inside the grace window spanning the upgrade can reach it.
    /// </para>
    /// </remarks>
    public OpaqueSecret DeriveLegacy(string familyId, int generation)
    {
        ArgumentException.ThrowIfNullOrEmpty(familyId);

        return OpaqueSecret.FromLegacyDerivedMaterial(TokenPurpose.RefreshToken, Material(familyId, generation));
    }

    private byte[] Material(string familyId, int generation)
    {
        var label = StrictUtf8.GetBytes($"boltway/refresh\0{familyId}\0{generation}");

        return HMACSHA256.HashData(_key, label);
    }
}
