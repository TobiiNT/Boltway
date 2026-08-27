using System.Security.Cryptography;
using Boltway.OAuth.Primitives.Encoding;

namespace Boltway.OAuth.Primitives.Secrets;

/// <summary>
/// The SHA-256 of a secret. The only form of a secret that is ever persisted.
/// </summary>
/// <remarks>
/// <para>
/// SHA-256 rather than Argon2id, deliberately, and the distinction is worth stating because it
/// looks like a downgrade. Argon2id exists to make guessing a <i>low-entropy human-chosen password</i>
/// expensive. These values are 256 bits from a CSPRNG: there is no dictionary, no reuse across
/// sites, and no offline guessing attack that a slow hash would defend against. What a slow hash
/// would do is put ~100 ms of work on the <c>/token</c> path, which has a 10-second budget the
/// client treats as terminal. Passwords use Argon2id; minted secrets use SHA-256.
/// </para>
/// <para>
/// Comparison is <see cref="CryptographicOperations.FixedTimeEquals"/> and there is no other
/// comparison API on this type. A <c>==</c> on the stored bytes would be a timing oracle against a
/// value the server holds.
/// </para>
/// </remarks>
public readonly struct Sha256Hash : IEquatable<Sha256Hash>
{
    /// <summary>SHA-256 output length.</summary>
    public const int Length = 32;

    private readonly byte[] _value;

    private Sha256Hash(byte[] value) => _value = value;

    /// <summary>The raw digest. This is what goes in the database column.</summary>
    public ReadOnlySpan<byte> Value => _value;

    /// <summary>Hash a minted secret.</summary>
    public static Sha256Hash Of(in OpaqueSecret secret) => OfString(secret.Wire);

    /// <summary>
    /// Hash an arbitrary string. Used for lookup keys that are not secrets - a CIMD
    /// <c>client_id</c> URL used as a cache key, for instance.
    /// </summary>
    public static Sha256Hash OfString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        // Strict UTF-8, and the strictness is the point.
        //
        // The permissive encoder replaces every lone surrogate with U+FFFD, so "\uD800",
        // "\uDC00" and "\uFFFD" all hash identically - the exact "two different inputs hash the
        // same" that choosing UTF-8 over ASCII was supposed to avoid. This overload keys CIMD
        // cache entries by client_id, so a collision means two distinct clients sharing one cache
        // entry. Ill-formed UTF-16 cannot appear in a well-formed identifier, so throwing is
        // right: it is a bug at the caller, not an input to tolerate.
        return new Sha256Hash(SHA256.HashData(StrictUtf8.GetBytes(value)));
    }

    private static readonly System.Text.UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    /// <summary>Rehydrate a digest read back from storage.</summary>
    /// <remarks>
    /// Copies. Storing the caller's reference would make this "immutable" value type mutate after
    /// construction, and the realistic route is not malice: a data-access layer reading into a
    /// pooled or reused buffer (<c>ArrayPool</c>, <c>DbDataReader.GetBytes</c>, a shared row
    /// buffer) silently corrupts a stored digest, and the symptom is a spurious
    /// <c>invalid_grant</c> rather than an exception.
    /// </remarks>
    public static bool TryFromBytes(ReadOnlySpan<byte> bytes, out Sha256Hash hash)
    {
        hash = default;

        if (bytes.Length != Length)
        {
            return false;
        }

        hash = new Sha256Hash(bytes.ToArray());
        return true;
    }

    /// <summary>
    /// Constant-time equality, and reflexive even for <see langword="default"/>.
    /// </summary>
    /// <remarks>
    /// Two uninitialised hashes compare equal, because <see cref="object.Equals(object)"/> requires
    /// reflexivity and a type that breaks it corrupts every collection built on it - a
    /// <c>Dictionary&lt;Sha256Hash, …&gt;</c> could not find a key it had just stored, and a
    /// <c>HashSet</c> would accept the same value repeatedly. The safety property that matters
    /// belongs on <see cref="Matches"/>, which refuses an absent digest outright: an uninitialised
    /// field must not authenticate, but it must still behave like a value.
    /// </remarks>
    public bool Equals(Sha256Hash other) =>
        _value is null
            ? other._value is null
            : other._value is not null && CryptographicOperations.FixedTimeEquals(_value, other._value);

    /// <summary>
    /// Constant-time equality against a presented secret. Refuses an absent digest or secret.
    /// </summary>
    public bool Matches(in OpaqueSecret presented) =>
        _value is not null && presented.IsPresent && Equals(Of(presented));

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Sha256Hash other && Equals(other);

    /// <summary>
    /// A hash code derived from the digest.
    /// </summary>
    /// <remarks>
    /// Safe to expose: this is already a one-way function of the secret, and the 32 bits a hash code
    /// leaks about a 256-bit digest do not narrow a search for the preimage to anything useful. It
    /// exists so a digest can key a dictionary.
    /// </remarks>
    public override int GetHashCode() =>
        _value is null ? 0 : BitConverter.ToInt32(_value, 0);

    /// <summary>base64url of the digest, for logs and diagnostics.</summary>
    public override string ToString() => _value is null ? "<empty>" : Base64Url.Encode(_value);

    /// <summary>Constant-time equality.</summary>
    public static bool operator ==(Sha256Hash left, Sha256Hash right) => left.Equals(right);

    /// <summary>Constant-time inequality.</summary>
    public static bool operator !=(Sha256Hash left, Sha256Hash right) => !left.Equals(right);
}
