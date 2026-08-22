using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Abstractions.Users;

/// <summary>What a one-time link is for.</summary>
/// <remarks>
/// <b>Two purposes in one table, and they must not be interchangeable.</b> A verification token that
/// could be redeemed at the reset endpoint would let anyone who can receive a "confirm your address"
/// mail set the password — and that mail is sent to an address the account holder typed, sometimes
/// before anyone has proven it is theirs. The purpose is stored and compared on redemption.
/// </remarks>
public enum UserTokenPurpose
{
    /// <summary>Choose a new password without knowing the old one.</summary>
    PasswordReset = 0,

    /// <summary>Prove an address belongs to whoever received the mail.</summary>
    EmailVerification = 1,
}

/// <summary>A one-time link, as the store holds it.</summary>
/// <param name="TokenHash">
/// SHA-256 of the value in the link. <b>The plaintext is never stored</b> — N-16, the same rule
/// authorization codes and refresh tokens follow. A stolen database backup is then a list of hashes
/// rather than a set of live links into every account.
/// </param>
/// <param name="Subject">Whose account.</param>
/// <param name="Purpose">Which flow it belongs to.</param>
/// <param name="ExpiresAt">When it stops working.</param>
/// <param name="Detail">
/// What the redemption is about, when the purpose needs it. For
/// <see cref="UserTokenPurpose.EmailVerification"/> this is the address being proven, so that a
/// person who changes their address before clicking does not have the old link verify the new one.
/// </param>
public sealed record UserTokenRecord(
    Sha256Hash TokenHash,
    SubjectId Subject,
    UserTokenPurpose Purpose,
    DateTimeOffset ExpiresAt,
    string? Detail = null);

/// <summary>
/// Stores the one-time links behind the email flows. <c>S-47</c>.
/// </summary>
/// <remarks>
/// <para>
/// Small, and every method on it is one of the four things <c>S-47</c> requires: single use, hashed
/// at rest, expiring, and destroyed in bulk when the password changes by any route.
/// </para>
/// <para>
/// <b>There is no "find" that does not consume.</b> A store exposing a read would let a caller
/// validate a token and then act on it in two statements, and two concurrent redemptions of one
/// reset link would both succeed — which is a second key, arriving through the mechanism that
/// exists to prevent one. <see cref="RedeemAsync"/> is the only read, and it is a delete that
/// returns what it deleted.
/// </para>
/// </remarks>
public interface IUserTokenStore
{
    /// <summary>Persist a freshly minted token. <b>Add-only.</b></summary>
    /// <param name="token">The record.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="InvalidOperationException">
    /// A token with this hash already exists. It cannot happen with 256 bits of CSPRNG output, and
    /// overwriting would move somebody else's expiry, so it throws rather than being tolerated.
    /// </exception>
    Task StoreAsync(UserTokenRecord token, CancellationToken cancellationToken);

    /// <summary>
    /// Consume a token, atomically, and say what it was.
    /// </summary>
    /// <param name="tokenHash">The hash of the value out of the link.</param>
    /// <param name="purpose">Which flow is asking. A token for another purpose is not found.</param>
    /// <param name="now">Current time. An expired token is not found either.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>The record, or <see langword="null"/> when there is nothing to redeem.</returns>
    /// <remarks>
    /// <para>
    /// <b>The delete and the read are one operation, and the answer must come from what the delete
    /// actually removed.</b> A read followed by a delete lets two presentations of one link both
    /// return a record — a person double-clicking their own mail is enough to produce it, and an
    /// attacker racing a stolen link is the case that matters.
    /// </para>
    /// <para>
    /// <b>Expired and wrong-purpose are the same answer as absent</b>, and deliberately: the caller
    /// tells the person their link has expired either way (§7.3), so distinguishing them here would
    /// buy nothing and give an implementation three states to get right instead of two.
    /// </para>
    /// </remarks>
    Task<UserTokenRecord?> RedeemAsync(
        Sha256Hash tokenHash,
        UserTokenPurpose purpose,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Destroy every outstanding token of one purpose for one subject.
    /// </summary>
    /// <param name="subject">Whose.</param>
    /// <param name="purpose">Which flow's.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>How many were destroyed.</returns>
    /// <remarks>
    /// <b><c>S-47</c>'s fourth clause, and the one an implementation is most likely to omit.</b>
    /// Every password change calls this for <see cref="UserTokenPurpose.PasswordReset"/> — the
    /// self-service change, the reset link itself, and an operator's reset — because a reset link
    /// that still works after the password has changed is a second key to the account, held by
    /// whoever asked for it. Requesting a reset also calls it, so a person who clicks "forgot
    /// password" three times has one live link rather than three.
    /// </remarks>
    Task<int> DeleteForSubjectAsync(
        SubjectId subject, UserTokenPurpose purpose, CancellationToken cancellationToken);

    /// <summary>Delete tokens past their expiry. Housekeeping, not a protocol operation.</summary>
    /// <param name="now">Current time.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>How many were deleted.</returns>
    /// <remarks>
    /// Unlike a redeemed authorization code, an expired token here has nothing left to answer:
    /// <see cref="RedeemAsync"/> treats expired and absent identically, so there is no retry window
    /// to preserve and the row can go as soon as it is stale.
    /// </remarks>
    Task<int> DeleteExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken);
}
