using System.Security.Cryptography;
using System.Text;
using Boltway.AuthorizationServer.Abstractions.Users;
using Konscious.Security.Cryptography;

namespace Boltway.Identity.Passwords;

/// <summary>The outcome of verifying a password, and whether the stored hash is out of date.</summary>
/// <param name="Succeeded">Whether the password matched.</param>
/// <param name="NeedsRehash">
/// Whether the stored hash was produced with parameters weaker than the current configuration.
/// </param>
/// <remarks>
/// The two are independent — <see cref="NeedsRehash"/> describes the stored value and is answerable
/// without the password — but they are returned together because the only moment an upgrade is
/// possible is the moment both are known: re-hashing needs the plaintext, and the plaintext may only
/// be trusted once <see cref="Succeeded"/> is <see langword="true"/>. A caller must check both.
/// </remarks>
public readonly record struct PasswordVerification(bool Succeeded, bool NeedsRehash);

/// <summary>
/// Reports whether a stored hash should be replaced, so a login can upgrade it in passing.
/// </summary>
/// <remarks>
/// Separate from <see cref="IPasswordHasher"/> because that interface ships in the abstractions
/// assembly and is the contract a customer's own implementation satisfies; requiring an upgrade
/// policy of every implementation would make the simplest case harder for no benefit. A caller that
/// wants transparent upgrades asks for this interface and gets it when the shipped hasher is
/// registered.
/// </remarks>
public interface IPasswordUpgradePolicy
{
    /// <summary>Verify, and report whether the stored hash is behind the current configuration.</summary>
    PasswordVerification VerifyForUpgrade(string password, string encodedHash);

    /// <summary>Whether a stored hash is behind the current configuration. Needs no password.</summary>
    bool NeedsRehash(string encodedHash);
}

/// <summary>
/// Argon2id password hashing, in the PHC string format.
/// </summary>
/// <remarks>
/// <para>
/// <b>Argon2id rather than PBKDF2, and rather than SHA-256.</b> The distinction from
/// <c>Sha256Hash</c> is not that one algorithm is better: it is that the two protect different
/// things. A refresh token is 256 bits from a CSPRNG, so there is no dictionary to run and a slow
/// hash would only add latency. A password is chosen by a person, so an attacker holding the
/// database runs an offline guessing attack, and the only defence is making each guess expensive.
/// Argon2id is expensive in <i>memory</i> as well as time, which is what puts a GPU or an ASIC —
/// where PBKDF2's per-guess cost collapses by orders of magnitude — back on roughly the same footing
/// as the defender's server. It is OWASP's first choice and the winner of the Password Hashing
/// Competition.
/// </para>
/// <para>
/// <b>The dependency.</b> Argon2id is not in the BCL, so this costs one package:
/// <c>Konscious.Security.Cryptography.Argon2</c>, MIT, a pure-managed implementation by Keef Aragon.
/// The pin and the licence note predate this file — <c>Directory.Packages.props</c> has carried both
/// since the package list was written — so taking it is executing a decision this repository already
/// recorded rather than making a new one. It brings one transitive package,
/// <c>Konscious.Security.Cryptography.Blake2</c>, from the same author, and nothing else. The
/// implementation is checked against RFC 9106 §5.3's Argon2id test vector in
/// <c>Argon2idPasswordHasherTests</c>, so "this is really Argon2id" is measured rather than assumed
/// from the package name.
/// </para>
/// <para>
/// <b>Timing.</b> Verification takes its cost from the stored string, so it is fixed with respect to
/// the password, and the final comparison is
/// <see cref="CryptographicOperations.FixedTimeEquals"/>. This is what makes the login endpoint's
/// hash-against-a-dummy defence real: the work an unknown username does is the same work a known one
/// does. It holds only while the dummy and the account share parameters — after a cost increase, an
/// account still on the old cost is measurably faster than the freshly computed dummy, until it is
/// rehashed.
/// </para>
/// </remarks>
public sealed class Argon2idPasswordHasher : IPasswordHasher, IPasswordUpgradePolicy
{
    private readonly Argon2idParameters _current;

    /// <summary>Construct with the shipped defaults.</summary>
    public Argon2idPasswordHasher()
        : this(Argon2idParameters.Default) { }

    /// <summary>Construct with explicit parameters.</summary>
    /// <param name="parameters">The cost new hashes are produced with. Validated here, not later.</param>
    /// <exception cref="ArgumentOutOfRangeException">A parameter is outside its bounds.</exception>
    public Argon2idPasswordHasher(Argon2idParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        _current = parameters.Validated();
    }

    /// <summary>The parameters new hashes are produced with.</summary>
    public Argon2idParameters Parameters => _current;

    /// <inheritdoc />
    /// <exception cref="ArgumentException">
    /// <paramref name="password"/> is empty. See the comment above <c>Derive</c> for why.
    /// </exception>
    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length == 0)
        {
            throw new ArgumentException(
                "An empty password cannot be stored. Reject it in registration policy.", nameof(password));
        }

        var salt = RandomNumberGenerator.GetBytes(_current.SaltBytes);
        var hash = Derive(password, _current, salt, _current.HashBytes);

        return PhcString.Format(_current, salt, hash);
    }

    /// <inheritdoc />
    /// <remarks>
    /// The parameters come from <paramref name="encodedHash"/>, never from <see cref="Parameters"/>.
    /// Using the current configuration here is the standard way an upgrade path is botched: the
    /// deploy that raises the cost silently invalidates every password already stored, and the
    /// symptom is every existing user unable to sign in with a correct password.
    /// </remarks>
    public bool Verify(string password, string encodedHash) =>
        VerifyForUpgrade(password, encodedHash).Succeeded;

    /// <inheritdoc />
    public PasswordVerification VerifyForUpgrade(string password, string encodedHash)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length == 0)
        {
            // Never a false negative, and never an exception. See the comment above Derive.
            return new PasswordVerification(Succeeded: false, NeedsRehash: NeedsRehash(encodedHash));
        }

        if (!PhcString.TryParse(encodedHash, out var decoded))
        {
            // Fail closed. A hash we cannot read is not a password we can confirm, and a stored
            // value in an unknown format is reported as needing replacement because it certainly is
            // not the current one.
            return new PasswordVerification(Succeeded: false, NeedsRehash: true);
        }

        var computed = Derive(password, decoded!.Parameters, decoded.Salt, decoded.Hash.Length);

        return new PasswordVerification(
            CryptographicOperations.FixedTimeEquals(computed, decoded.Hash),
            IsBehind(decoded.Parameters));
    }

    /// <inheritdoc />
    public bool NeedsRehash(string encodedHash) =>
        !PhcString.TryParse(encodedHash, out var decoded) || IsBehind(decoded!.Parameters);

    /// <summary>
    /// Whether a stored hash is weaker than what this hasher would produce now.
    /// </summary>
    /// <remarks>
    /// <para>
    /// "At least as strong on every axis" rather than "identical", so an operator who <i>lowers</i>
    /// the cost does not trigger a mass downgrade of hashes that are already stronger than the new
    /// setting. Re-hashing those would spend the upgrade mechanism on making stored passwords worse.
    /// </para>
    /// <para>
    /// <see cref="Argon2idParameters.Parallelism"/> is compared for equality rather than by
    /// magnitude, and that is deliberate: lanes change the shape of the computation rather than its
    /// difficulty, so a stored <c>p=4</c> is not "stronger than" a configured <c>p=1</c>, it is a
    /// different function. A change in either direction means the stored hash came from a
    /// configuration the operator has moved away from.
    /// </para>
    /// </remarks>
    private bool IsBehind(Argon2idParameters stored) =>
        stored.MemoryKiB < _current.MemoryKiB
        || stored.Iterations < _current.Iterations
        || stored.Parallelism != _current.Parallelism
        || stored.SaltBytes < _current.SaltBytes
        || stored.HashBytes < _current.HashBytes;

    // ── Why an empty password is refused rather than hashed ───────────────────────────────────
    //
    // Found by a test, not by reading. POST /login with an empty password field threw
    // ArgumentException out of the library — "Argon2 needs a password set" — which the endpoint
    // does not catch. That was a 500 any unauthenticated request could provoke at will, and one
    // whose shape differed from every ordinary failed login.
    //
    // The fix is a refusal at both ends rather than a workaround. Padding the input or substituting
    // a placeholder would make the tag differ from what the Argon2 reference implementation computes
    // for the same inputs, and PHC interoperability is most of the reason for the storage format.
    // RFC 9106 permits a zero-length password; this LIBRARY does not, and the honest response is to
    // keep empty passwords out of storage entirely.
    //
    // So Hash throws — storing one is a registration-policy failure the caller should never reach —
    // and Verify answers false without calling the library. That cannot be a false negative BECAUSE
    // Hash throws: no hash this type produced is the hash of an empty password. The one case it gets
    // wrong is such a hash migrated in from another implementation, which would stop verifying.
    //
    // It is not a username oracle. The short-circuit is keyed on the password the caller just sent,
    // not on whether the account exists, so both branches of the login endpoint take it together and
    // the two responses stay indistinguishable.

    /// <summary>Run Argon2id.</summary>
    private static byte[] Derive(string password, Argon2idParameters parameters, byte[] salt, int length)
    {
        using var argon2 = new Argon2id(StrictUtf8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = parameters.MemoryKiB,
            Iterations = parameters.Iterations,
            DegreeOfParallelism = parameters.Parallelism,
        };

        return argon2.GetBytes(length);
    }

    /// <summary>
    /// Strict UTF-8, matching <c>Sha256Hash.OfString</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The permissive encoder maps every lone surrogate to U+FFFD, so <c>"\uD800"</c> and
    /// <c>"�"</c> would hash identically — two distinct passwords with one digest. Throwing
    /// keeps the mapping injective.
    /// </para>
    /// <para>
    /// It cannot throw on the login path. ASP.NET Core decodes form bodies from bytes as UTF-8 with
    /// replacement, so a password arriving over HTTP has already had any ill-formed sequence turned
    /// into U+FFFD and contains no lone surrogate to trip on. Reaching this exception means a
    /// programmatic caller passed an ill-formed UTF-16 string, which is a bug at the caller rather
    /// than input to tolerate.
    /// </para>
    /// <para>
    /// No Unicode normalization is applied. <c>InvariantGlobalization</c> is set for every project in
    /// this tree, and under it <see cref="string.Normalize()"/> is not available for non-ASCII input.
    /// The consequence is worth stating rather than leaving to be discovered: a password containing
    /// a character that can be composed two ways will only verify against the composition it was
    /// registered with.
    /// </para>
    /// </remarks>
    private static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);
}
