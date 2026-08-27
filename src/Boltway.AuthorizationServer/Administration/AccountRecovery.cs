using System.Security.Cryptography;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.Notifications;
using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.Extensions.Logging;

namespace Boltway.AuthorizationServer.Administration;

/// <summary>How long a one-time link lives.</summary>
/// <remarks>
/// §1.9. Two numbers, and the difference between them is what each link is <i>for</i>. A reset is
/// something a person is doing right now, with their inbox already open; a verification is something
/// they may get to after lunch.
/// </remarks>
public sealed class AccountRecoveryOptions
{
    /// <summary>How long a password-reset link works. Fifteen minutes.</summary>
    /// <remarks>
    /// The email is the slow part, and the token does not need to outlive the walk to the inbox. A
    /// long-lived reset link is a password with an expiry date sitting in a mailbox whose own
    /// security this server knows nothing about.
    /// </remarks>
    public TimeSpan ResetLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an email-verification link works. Twenty-four hours.</summary>
    /// <remarks>
    /// Longer because the stakes are lower and the delay is ordinary: a verification link that has
    /// expired by the time somebody reads their mail is a flow nobody completes.
    /// </remarks>
    public TimeSpan VerificationLifetime { get; set; } = TimeSpan.FromHours(24);
}

/// <summary>What a redemption did.</summary>
public enum RecoveryOutcome
{
    /// <summary>It worked.</summary>
    Ok,

    /// <summary>
    /// The link is expired, already used, or was never issued.
    /// </summary>
    /// <remarks>
    /// One answer for all three. §7.3: a person who is not told their link expired clicks it again
    /// rather than asking for a new one, and there is nothing to enumerate - a token is 256 bits of
    /// CSPRNG output, so saying "that link no longer works" is not the oracle <c>S-48</c> is about.
    /// </remarks>
    NoSuchToken,

    /// <summary>The link was valid and names an account that is not there any more.</summary>
    NoSuchAccount,

    /// <summary>The new password was blank.</summary>
    BlankPassword,
}

/// <summary>The result of redeeming a reset link.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Subject">Whose account, when the link named one.</param>
/// <param name="SessionsRevoked">How many grants were revoked. §1.10 - always, on this route.</param>
public sealed record PasswordResetResultFromLink(
    RecoveryOutcome Outcome, SubjectId Subject = default, int SessionsRevoked = 0);

/// <summary>The result of redeeming a verification link.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Subject">Whose account, when the link named one.</param>
/// <param name="Email">The address that was proven.</param>
public sealed record EmailVerificationResult(
    RecoveryOutcome Outcome, SubjectId Subject = default, string? Email = null);

/// <summary>
/// The two flows that reach a person by email. <c>E-39</c>–<c>E-44</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Separate from <see cref="UserAdministration"/> because the caller is different.</b> Every
/// method there is an operator or an account holder doing something to an account they can already
/// reach. Every method here starts with somebody who <i>cannot</i> reach it, which is why the
/// entry points are public, why they are rate limited, and why the whole design is about not
/// answering questions.
/// </para>
/// <para>
/// <b>The rule that shapes the request half is <c>S-48</c>:</b> asking for a reset answers
/// identically whether or not the account exists, and does the same work either way. Not merely the
/// same status code - the same store reads, so the timing does not distinguish them. Otherwise this
/// endpoint is a way to test whether an address is registered here, at whatever rate the throttle
/// allows.
/// </para>
/// <para>
/// <b>The rule that shapes the redemption half is <c>S-47</c>:</b> a link is single use, hashed at
/// rest, expiring, and every outstanding reset link for a subject dies when the password changes by
/// any route. That last clause is why <see cref="UserAdministration"/> calls
/// <see cref="IUserTokenStore.DeleteForSubjectAsync"/> too - a link that still works after the
/// password has changed is a second key held by whoever asked for it.
/// </para>
/// </remarks>
/// <param name="users">The directory.</param>
/// <param name="tokens">Where the one-time links live.</param>
/// <param name="hasher">How a password becomes a stored credential.</param>
/// <param name="server">The issuer, which is what a link has to be absolute against.</param>
/// <param name="options">How long each kind of link lives.</param>
/// <param name="clock">The clock.</param>
/// <param name="notifications">
/// Where messages go, or <see langword="null"/> in a deployment that has registered no sender. The
/// flows still work - a token is still minted and still redeemable - and nothing arrives, which is
/// visible immediately rather than at 3am. Refusing to mint would be worse: the operator who has
/// not finished configuring mail would get a reset endpoint that answers 500.
/// </param>
/// <param name="grants">The grants, for §1.10's revocation.</param>
/// <param name="audit">Where the redemptions are recorded.</param>
/// <param name="logger">Where a failed send is reported.</param>
public sealed class AccountRecovery(
    IUserStore users,
    IUserTokenStore tokens,
    IPasswordHasher hasher,
    AuthorizationServerOptions server,
    AccountRecoveryOptions? options = null,
    TimeProvider? clock = null,
    INotificationSender? notifications = null,
    IGrantStore? grants = null,
    IAdminAuditStore? audit = null,
    ILogger<AccountRecovery>? logger = null)
{
    /// <summary>How many bytes of entropy a link carries.</summary>
    /// <remarks>
    /// 32 - 256 bits, the same as every other secret this server mints. It is what makes "that link
    /// no longer works" a safe sentence: there is nothing to enumerate, so the message can be honest
    /// without becoming an oracle.
    /// </remarks>
    public const int TokenBytes = 32;

    private readonly AccountRecoveryOptions _options = options ?? new AccountRecoveryOptions();
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <summary>
    /// Send somebody a reset link, or do exactly as much work and send nothing. <c>E-39</c>,
    /// <c>S-48</c>.
    /// </summary>
    /// <param name="handleOrEmail">What the person typed.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// <para>
    /// <b>Returns nothing, and that is the signature doing the work.</b> A method that reported
    /// whether it found an account would put the oracle one call site away from the wire, and the
    /// first caller to log the result would put it in a file. There is no answer to give: the only
    /// observable difference between the two cases is a message arriving in a mailbox, which only
    /// its owner can see.
    /// </para>
    /// <para>
    /// <b>The lookup accepts a handle or an address.</b> A person who has forgotten their password
    /// has usually also forgotten which of the two they signed up with, and refusing one of them
    /// turns "I cannot get in" into "I cannot even ask".
    /// </para>
    /// </remarks>
    public async Task RequestPasswordResetAsync(string handleOrEmail, CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();
        var account = await FindAsync(handleOrEmail, cancellationToken).ConfigureAwait(false);

        // Minted before the branch, so the CSPRNG draw and the hash happen either way. They are
        // microseconds against a database round trip, and doing them only on the found path is
        // exactly the sort of asymmetry a timing oracle is built from.
        var (secret, hash) = NewToken();
        var expiresAt = now + _options.ResetLifetime;

        if (account is null)
        {
            // The unfound path still touches the store, so a request for an unknown address costs
            // what a known one costs. Deleting nothing for a subject that does not exist is the
            // cheapest honest way to do that - it is the same statement the found path runs.
            await tokens.DeleteForSubjectAsync(
                SubjectId.FromStorage("unknown"), UserTokenPurpose.PasswordReset, cancellationToken)
                .ConfigureAwait(false);

            await RecordAsync(
                "user.password.forgot", null, handleOrEmail, AdminAuditOutcome.Refused,
                "no such account", cancellationToken).ConfigureAwait(false);

            return;
        }

        // Every earlier link dies first, so somebody who clicks "forgot password" three times holds
        // one live link rather than three. S-47.
        await tokens.DeleteForSubjectAsync(
            account.Subject, UserTokenPurpose.PasswordReset, cancellationToken).ConfigureAwait(false);

        await tokens.StoreAsync(
            new UserTokenRecord(hash, account.Subject, UserTokenPurpose.PasswordReset, expiresAt),
            cancellationToken).ConfigureAwait(false);

        await RecordAsync(
            "user.password.forgot", account.Subject, account.Username, AdminAuditOutcome.Succeeded,
            null, cancellationToken).ConfigureAwait(false);

        // A disabled account gets a link and cannot sign in with the new password anyway. Refusing
        // here would make this endpoint answer differently for a disabled account than for an
        // absent one, which is S-48 broken for the accounts most likely to be probed.
        if (account.Email is { Length: > 0 } address)
        {
            await SendAsync(
                new ResetPassword(Link(AuthorizationServerPaths.Reset, secret), expiresAt)
                {
                    To = address,
                    Handle = account.Username,
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Set a password with a link rather than with the old password. <c>E-40</c>, <c>E-43</c>.
    /// </summary>
    /// <param name="token">The value out of the link.</param>
    /// <param name="newPassword">What to set.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// <b>Sessions are revoked, always, and this is the one route where that is not a
    /// question.</b> §1.10: somebody resetting through email is usually doing it because they lost
    /// control of something, and the sessions an attacker holds are the thing a new password does
    /// not touch. An operator's reset defaults the other way because it is usually a colleague who
    /// forgot theirs.
    /// </remarks>
    public async Task<PasswordResetResultFromLink> RedeemPasswordResetAsync(
        string token, string newPassword, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            // Before the redemption, so a mistyped form does not consume the link and leave somebody
            // asking for a second one to fix a typo.
            return new PasswordResetResultFromLink(RecoveryOutcome.BlankPassword);
        }

        var now = _clock.GetUtcNow();

        var redeemed = await tokens
            .RedeemAsync(HashOf(token), UserTokenPurpose.PasswordReset, now, cancellationToken)
            .ConfigureAwait(false);

        if (redeemed is null)
        {
            return new PasswordResetResultFromLink(RecoveryOutcome.NoSuchToken);
        }

        var account = await users.FindBySubjectAsync(redeemed.Subject, cancellationToken).ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(
                "user.password.reset.link", redeemed.Subject, redeemed.Subject.Value,
                AdminAuditOutcome.Refused, "no such account", cancellationToken).ConfigureAwait(false);

            return new PasswordResetResultFromLink(RecoveryOutcome.NoSuchAccount, redeemed.Subject);
        }

        var applied = await users
            .SetPasswordHashAsync(redeemed.Subject, hasher.Hash(newPassword), cancellationToken)
            .ConfigureAwait(false);

        // Every session this account had predates the new password, so none of them are its
        // sessions any more. Separate from the write above by design - see StampSessionsAsync -
        // and unconditional on this path, because a password change nobody asked for is exactly
        // the case where the old browser must stop working.
        await users.StampSessionsAsync(redeemed.Subject, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);

        if (!applied)
        {
            await RecordAsync(
                "user.password.reset.link", redeemed.Subject, account.Username,
                AdminAuditOutcome.Refused, "gone", cancellationToken).ConfigureAwait(false);

            return new PasswordResetResultFromLink(RecoveryOutcome.NoSuchAccount, redeemed.Subject);
        }

        var revoked = grants is null
            ? 0
            : await grants.RevokeAllForSubjectAsync(redeemed.Subject, now, cancellationToken)
                .ConfigureAwait(false);

        await RecordAsync(
            "user.password.reset.link", redeemed.Subject, account.Username, AdminAuditOutcome.Succeeded,
            $"revoked {revoked} grant(s)", cancellationToken).ConfigureAwait(false);

        // The one message nobody asked for, and the reason it exists: somebody reading it who did
        // not do this has just learned that a person with access to their mailbox has their account.
        if (account.Email is { Length: > 0 } address)
        {
            await SendAsync(
                new PasswordChanged(now, revoked) { To = address, Handle = account.Username },
                cancellationToken).ConfigureAwait(false);
        }

        return new PasswordResetResultFromLink(RecoveryOutcome.Ok, redeemed.Subject, revoked);
    }

    /// <summary>Send a verification link for an account's current address. <c>E-41</c>.</summary>
    /// <param name="subject">Whose.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>Whether there was an address to send to.</returns>
    /// <remarks>
    /// <b>Not an oracle, and does not need <c>S-48</c>'s treatment.</b> The caller already holds a
    /// token for this subject, so "does this account exist" is not a secret being kept from them.
    /// </remarks>
    public async Task<bool> RequestEmailVerificationAsync(
        SubjectId subject, CancellationToken cancellationToken)
    {
        var account = await users.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false);

        if (account?.Email is not { Length: > 0 } address)
        {
            return false;
        }

        var now = _clock.GetUtcNow();
        var (secret, hash) = NewToken();
        var expiresAt = now + _options.VerificationLifetime;

        await tokens.DeleteForSubjectAsync(
            subject, UserTokenPurpose.EmailVerification, cancellationToken).ConfigureAwait(false);

        // The address is stored on the token. Somebody who requests a link, then changes their
        // address, then clicks the old link must not end up with the new address marked verified -
        // the link proves control of the mailbox it was sent to and of nothing else.
        await tokens.StoreAsync(
            new UserTokenRecord(hash, subject, UserTokenPurpose.EmailVerification, expiresAt, address),
            cancellationToken).ConfigureAwait(false);

        await SendAsync(
            new VerifyEmail(Link(AuthorizationServerPaths.VerifyEmail, secret), expiresAt)
            {
                To = address,
                Handle = account.Username,
            },
            cancellationToken).ConfigureAwait(false);

        return true;
    }

    /// <summary>Mark an address proven. <c>E-41</c>, <c>E-44</c>.</summary>
    /// <param name="token">The value out of the link.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<EmailVerificationResult> VerifyEmailAsync(
        string token, CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();

        var redeemed = await tokens
            .RedeemAsync(HashOf(token), UserTokenPurpose.EmailVerification, now, cancellationToken)
            .ConfigureAwait(false);

        if (redeemed is null)
        {
            return new EmailVerificationResult(RecoveryOutcome.NoSuchToken);
        }

        var account = await users.FindBySubjectAsync(redeemed.Subject, cancellationToken).ConfigureAwait(false);

        if (account is null)
        {
            return new EmailVerificationResult(RecoveryOutcome.NoSuchAccount, redeemed.Subject);
        }

        // The address on the token, compared to the address on the account. They differ when
        // somebody changed it after asking, and then this link proves nothing about what is there
        // now - so it verifies nothing rather than verifying the new one.
        if (!string.Equals(redeemed.Detail, account.Email, StringComparison.OrdinalIgnoreCase))
        {
            await RecordAsync(
                "user.email.verify", redeemed.Subject, account.Username, AdminAuditOutcome.Refused,
                "address changed since the link was sent", cancellationToken).ConfigureAwait(false);

            return new EmailVerificationResult(RecoveryOutcome.NoSuchToken, redeemed.Subject);
        }

        var applied = await users
            .SetEmailAsync(redeemed.Subject, account.Email, verified: true, cancellationToken)
            .ConfigureAwait(false);

        await RecordAsync(
            "user.email.verify", redeemed.Subject, account.Username,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            null, cancellationToken).ConfigureAwait(false);

        return applied
            ? new EmailVerificationResult(RecoveryOutcome.Ok, redeemed.Subject, account.Email)
            : new EmailVerificationResult(RecoveryOutcome.NoSuchAccount, redeemed.Subject);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>By handle, then by address, in one realm.</summary>
    /// <remarks>
    /// <para>
    /// This walks the realm to match an address. <c>ListAsync</c> is keyset-paged, so it is a scan -
    /// acceptable on an endpoint rate limited to a handful of calls a minute and on no other. Named
    /// rather than left to be discovered by whoever first has ten thousand accounts.
    /// </para>
    /// <para>
    /// <b>It is a scan for a reason that has expired, and the replacement is not a refactor.</b> The
    /// reason used to be that <c>IUserStore</c> had no lookup by email and adding one would mean an
    /// index on a column <c>S-48</c> makes it a defect to answer questions about.
    /// <c>FindByVerifiedEmailAsync</c> and <c>ix_users_realm_normalized_email</c> now both exist,
    /// added for the sign-in form (<c>S-62</c>), so the first half is simply false and the second
    /// half was answered: the index is not an oracle, because what leaks is the response, and
    /// <c>S-48</c> is enforced by this endpoint returning the same body and doing the same work
    /// either way.
    /// </para>
    /// <para>
    /// What stops this being a one-line change is that the two lookups do not agree on the same
    /// accounts. <c>FindByVerifiedEmailAsync</c> requires <c>EmailVerified</c>; this scan matches
    /// <c>Email</c> whether or not it was ever proven. Switching would stop sending reset links to
    /// unverified addresses - defensible, arguably correct, and a lockout for every account whose
    /// address was set by an operator and never confirmed. That is a decision about who can recover
    /// an account, not a performance change, and it belongs to whoever makes it deliberately.
    /// </para>
    /// </remarks>
    private async Task<UserAccount?> FindAsync(string handleOrEmail, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(handleOrEmail))
        {
            return null;
        }

        var realm = server.Realm.OrDefault;

        if (await users.FindByUsernameAsync(realm, handleOrEmail, cancellationToken).ConfigureAwait(false) is { } byHandle)
        {
            return byHandle;
        }

        if (!handleOrEmail.Contains('@', StringComparison.Ordinal))
        {
            return null;
        }

        SubjectId? after = null;

        while (true)
        {
            var page = await users.ListAsync(realm, after, 200, cancellationToken).ConfigureAwait(false);

            if (page.Count == 0)
            {
                return null;
            }

            foreach (var account in page)
            {
                if (string.Equals(account.Email, handleOrEmail, StringComparison.OrdinalIgnoreCase))
                {
                    return account;
                }
            }

            after = page[^1].Subject;
        }
    }

    private static (string Secret, Sha256Hash Hash) NewToken()
    {
        var secret = Base64Url.Encode(RandomNumberGenerator.GetBytes(TokenBytes));

        return (secret, Sha256Hash.OfString(secret));
    }

    /// <summary>
    /// Hash a token off the wire, without letting a malformed one throw.
    /// </summary>
    /// <remarks>
    /// <c>Sha256Hash.OfString</c> throws on ill-formed UTF-16, which is a bug at every other call
    /// site and ordinary input here - this string comes out of a query parameter. A value that
    /// cannot be hashed matches no row, which is the same answer as a value that simply is not one.
    /// </remarks>
    private static Sha256Hash HashOf(string token)
    {
        try
        {
            return Sha256Hash.OfString(token ?? string.Empty);
        }
        catch (ArgumentException)
        {
            return Sha256Hash.OfString(string.Empty);
        }
    }

    /// <summary>An absolute URL on this issuer.</summary>
    /// <remarks>
    /// Built from <c>Issuer</c> rather than from the request, because the request that asks for a
    /// reset is not the one that follows the link - and a <c>Host</c> header is attacker-controlled,
    /// so composing the link from it is how a reset mail comes to point at somebody else's server.
    /// </remarks>
    private string Link(string path, string token) =>
        server.Issuer!.TrimEnd('/') + path + "?token=" + Uri.EscapeDataString(token);

    /// <summary>
    /// Send, and treat a failure as something to log rather than to fail the operation on.
    /// </summary>
    /// <remarks>
    /// The write this describes has already committed. Throwing here would turn "your password was
    /// reset and we could not tell you" into "your password was not reset", which is worse for the
    /// person and does not un-send anything.
    /// </remarks>
    private async Task SendAsync(NotificationMessage message, CancellationToken cancellationToken)
    {
        if (notifications is null)
        {
            return;
        }

        try
        {
            await notifications.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception failure) when (failure is not OperationCanceledException)
        {
            // The message type and nothing off the message. The address is personal data and the
            // link is a live credential; a log file has different access rules from a mailbox.
            logger?.LogError(
                failure,
                "Could not send a {Notification} notification. The operation it describes has "
                + "already been applied.",
                message.GetType().Name);
        }
    }

    private Task RecordAsync(
        string action,
        SubjectId? subject,
        string handle,
        AdminAuditOutcome outcome,
        string? detail,
        CancellationToken cancellationToken)
    {
        if (audit is null)
        {
            return Task.CompletedTask;
        }

        return audit.RecordAsync(
            new AdminAuditEntry(
                _clock.GetUtcNow(),
                // Not `cli` and not `client`: nobody authenticated. The actor is whoever had the
                // link or typed the address, and saying so is more useful than picking one of the
                // two names that do not fit.
                "public",
                ActorSubject: null,
                ActorClient: null,
                action,
                server.Realm.OrDefault,
                subject,
                handle,
                outcome,
                CorrelationId: null)
            {
                Detail = detail,
            },
            cancellationToken);
    }
}
