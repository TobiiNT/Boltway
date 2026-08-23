using Boltway.AuthorizationServer.Abstractions.Clients;
using System.Security.Cryptography;
using Boltway.AuthorizationServer.Abstractions.Administration;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Administration;

/// <summary>Who asked for an administrative change.</summary>
/// <param name="Kind">What sort of caller it was.</param>
/// <param name="Subject">
/// Which account acted, when one did. <see langword="null"/> for a command line.
/// </param>
/// <remarks>
/// <b>The CLI's subject is honestly null.</b> Inventing one for a shell — or reusing the target's —
/// would make an audit trail that reads as if the person being changed made the change. "Somebody
/// with shell access did this" is a smaller claim and a true one, and it is the one an incident
/// review can act on.
/// </remarks>
public readonly record struct Actor(ActorKind Kind, SubjectId? Subject = null)
{
    /// <summary>A command run against the deployment.</summary>
    public static Actor Cli { get; } = new(ActorKind.Cli);

    /// <summary>Which client the subject acted through, when one was involved.</summary>
    public string? Client { get; init; }

    /// <summary>
    /// The correlation id this request already carries, so a refused action and its log line join up.
    /// </summary>
    public string? CorrelationId { get; init; }
}

/// <summary>What sort of caller made an administrative change.</summary>
public enum ActorKind
{
    /// <summary>A command line, with shell access and no subject.</summary>
    Cli,

    /// <summary>An authenticated client acting for a subject.</summary>
    Client,
}

/// <summary>How an administrative operation ended.</summary>
public enum AdministrationStatus
{
    /// <summary>It happened.</summary>
    Ok,

    /// <summary>No account with that handle in that realm.</summary>
    NoSuchAccount,

    /// <summary>
    /// The account was found and then not there when the write ran.
    /// </summary>
    /// <remarks>
    /// Rare, and distinct from <see cref="NoSuchAccount"/> on purpose: one means a typo and the
    /// other means something else changed the directory mid-operation. Collapsing them would tell
    /// an operator to check their spelling when the answer is to look at who else was working.
    /// </remarks>
    Gone,

    /// <summary>
    /// The current password did not verify. <c>S-49</c>, and only
    /// <see cref="UserAdministration.ChangePasswordAsync"/> returns it.
    /// </summary>
    WrongPassword,

    /// <summary>
    /// The account has no local password to change.
    /// </summary>
    /// <remarks>
    /// A federated-only account, or one that has been anonymised. Distinct from
    /// <see cref="WrongPassword"/> because the caller is the account holder and this is not an
    /// oracle about somebody else: telling them "there is nothing to verify against" is the only
    /// answer they can act on, and "wrong password" would send them hunting for a password that
    /// does not exist.
    /// </remarks>
    NoPassword,
}

/// <summary>An account that was just created, and its password.</summary>
/// <param name="Subject">The <c>sub</c> minted for it.</param>
/// <param name="Handle">What they type at the login page.</param>
/// <param name="Email">Their address, if one was given.</param>
/// <param name="Role">
/// What its tokens will claim it is, if anything — what was actually assigned, so a creation the
/// deployment's defaults filled in reports them here rather than <see langword="null"/>.
/// Space-separated when there are several, the same shape the claim has.
/// </param>
/// <param name="Password">
/// Generated here, returned once, and never stored in this form. The caller shows it to a person and
/// forgets it.
/// </param>
public sealed record CreatedAccount(
    SubjectId Subject, string Handle, string? Email, string? Role, string Password);

/// <summary>The outcome of a password reset.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Whose password it was, when there was one.</param>
/// <param name="Password">The new password, once.</param>
public sealed record PasswordResetResult(
    AdministrationStatus Status, SubjectId Subject = default, string? Password = null);

/// <summary>The outcome of somebody changing their own password.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Whose password. Always the caller's — this operation reaches nobody else.</param>
/// <param name="Revoked">
/// How many grants were revoked on the way, when the caller asked. Zero when they did not, and zero
/// when there was nothing live: the two are the same number and the caller knows which they asked
/// for.
/// </param>
/// <remarks>
/// <b>No password field, unlike <see cref="PasswordResetResult"/>.</b> The caller chose it and
/// already has it; sending it back would put a live credential in a response body for no reader.
/// </remarks>
public sealed record PasswordChangeResult(
    AdministrationStatus Status, SubjectId Subject = default, int Revoked = 0);

/// <summary>The outcome of enabling or disabling an account.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Which account, when there was one.</param>
/// <param name="DisabledAt">When it was disabled, or <see langword="null"/> if it is now enabled.</param>
public sealed record EnablementResult(
    AdministrationStatus Status, SubjectId Subject = default, DateTimeOffset? DisabledAt = null);

/// <summary>The outcome of an email change.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Which account, when there was one.</param>
/// <param name="Email">The address now on the account.</param>
/// <param name="Verified">Whether it is recorded as proven.</param>
public sealed record EmailChangeResult(
    AdministrationStatus Status, SubjectId Subject = default, string? Email = null, bool Verified = false);

/// <summary>The outcome of a role change.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Whose role it was, when there was one.</param>
/// <param name="Role">What it is now, or <see langword="null"/> when cleared.</param>
public sealed record RoleChangeResult(
    AdministrationStatus Status, SubjectId Subject = default, string? Role = null);

/// <summary>The outcome of replacing which roles an account holds.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Whose account, when there was one.</param>
/// <param name="Roles">What it holds now.</param>
public sealed record RolesChangeResult(
    AdministrationStatus Status, SubjectId Subject = default, IReadOnlyList<string>? Roles = null);

/// <summary>The outcome of creating a service account.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="ClientId">What the client presents as, when one was created.</param>
/// <param name="Secret">
/// The plaintext secret, <b>the only time it exists</b>.
/// </param>
/// <remarks>
/// <para>
/// <b>This field is the reason the whole operation is one call.</b> The store holds a SHA-256 and
/// nothing else, so this string cannot be recovered from anywhere afterwards — not from the
/// database, not from a log, not by an administrator with every permission there is. A caller that
/// does not show it to somebody has destroyed it.
/// </para>
/// <para>
/// Losing it is not a disaster and must not be treated as one: creating the service account again
/// rotates the secret in place. That is the recovery, and it is why nothing here tries to be
/// clever about escrowing a copy.
/// </para>
/// </remarks>
public sealed record ServiceAccountResult(
    AdministrationStatus Status, string? ClientId = null, string? Secret = null);

/// <summary>The outcome of revoking somebody's sessions.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Whose sessions, when there was an account.</param>
/// <param name="Revoked">
/// How many grants <b>this call</b> revoked. Zero means there was nothing live, not that it failed —
/// running it twice is how an operator makes sure, and the second run should say zero rather than
/// repeat the first answer.
/// </param>
public sealed record SessionRevocationResult(
    AdministrationStatus Status, SubjectId Subject = default, int Revoked = 0);

/// <summary>The outcome of anonymising an account.</summary>
/// <param name="Status">Whether it happened.</param>
/// <param name="Subject">Which account. It still exists — that is the point of the operation.</param>
/// <param name="Handle">What the username is now.</param>
/// <param name="Revoked">How many grants were revoked on the way.</param>
public sealed record AnonymisationResult(
    AdministrationStatus Status, SubjectId Subject = default, string? Handle = null, int Revoked = 0);

/// <summary>
/// The one implementation of each administrative operation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every caller is a caller.</b> The CLI verbs used to reach <see cref="IUserStore"/> directly
/// from the host's <c>Program.cs</c>. The moment an HTTP admin surface exists, that would be two
/// implementations of one operation — and the half that drifts first is the audit write, on the
/// operator path, which is the path used at 2am during an incident.
/// </para>
/// <para>
/// <b>An operator never supplies a password; the account holder must.</b> This paragraph used to
/// read "the password is generated here and never accepted", and the reasoning under it was about a
/// value typed into a terminal, where it lands in shell history, in scrollback, and in whatever ran
/// the command. That reasoning holds exactly where it was aimed —
/// <see cref="ResetPasswordAsync"/> is one person acting on another's account and still takes no
/// password, so no CLI verb can grow a field that puts one in a shell.
/// </para>
/// <para>
/// <see cref="ChangePasswordAsync"/> is the other operation and it has to accept two, because
/// <c>S-49</c> requires the current one as proof and a password somebody must remember cannot be
/// generated for them. It is reachable only from <c>E-34</c>, with the account holder's own token,
/// over the transport the whole server already depends on. <b>What keeps the original rule intact is
/// that the two are separate methods</b>: an HTTP handler still cannot hand a chosen password to the
/// operator path, and the CLI has no verb that reaches this one.
/// </para>
/// <para>
/// <b>It resolves handles, not subjects.</b> Both callers start from what a person typed. Resolving
/// in one place is what keeps "which realm was that looked up in" a single answer.
/// </para>
/// </remarks>
/// <param name="users">The directory.</param>
/// <param name="hasher">How a password becomes a stored credential.</param>
/// <param name="subjects">
/// What mints a <c>sub</c> for a new account, when a deployment has one.
/// </param>
/// <param name="audit">
/// Where administrative actions are recorded. Optional so that a deployment without an audit store
/// keeps working — the entry is skipped rather than the operation refused, because refusing to reset
/// a password because a log is unavailable locks somebody out to protect a record of locking them
/// out.
/// </param>
/// <param name="clock">What the audit entry is timestamped from.</param>
/// <param name="grants">
/// The grants, for the two operations that end somebody's sessions. Optional for the same reason
/// <paramref name="subjects"/> is: only two methods need it, and one that needs it says which line
/// is missing rather than failing to construct the whole service.
/// </param>
/// <param name="roles">
/// Where role definitions live, for the operations that define or assign one. Optional like the
/// rest: a deployment that never defines a role never needs it, and the failure when one is needed
/// names what was not registered rather than throwing a null reference two frames down.
/// </param>
/// <param name="clients">
/// Where service accounts live. Optional for the same reason and with the same failure: a
/// deployment that offers none never needs it.
/// </param>
/// <param name="tokens">
/// The one-time links, so that changing a password destroys every outstanding reset link for the
/// account — <c>S-47</c>'s fourth clause, which applies to <b>every</b> route and therefore to the
/// two here as well as to the reset link itself. Optional, because a deployment that has not turned
/// the email flows on has no links to destroy; when one is registered, every password change
/// destroys them, including the operator's.
/// </param>
/// <param name="accountDefaults">
/// What a new account holds when its creator names no role. Optional because absence is the
/// meaning: unregistered, creation assigns nothing it was not told to — see
/// <see cref="AccountDefaults"/> for why there is no empty value of it.
/// </param>
public sealed class UserAdministration(
    IUserStore users,
    IPasswordHasher hasher,
    ISubjectIdFactory? subjects = null,
    IAdminAuditStore? audit = null,
    TimeProvider? clock = null,
    IGrantStore? grants = null,
    IUserTokenStore? tokens = null,
    IRoleStore? roles = null,
    IClientStore? clients = null,
    AccountDefaults? accountDefaults = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    /// <summary>
    /// What an anonymised account's username becomes.
    /// </summary>
    /// <remarks>
    /// Derived from the subject, which is unique, so the <c>(realm, normalized_username)</c> index
    /// cannot collide however many accounts are anonymised — and so anonymising the same account
    /// twice is idempotent rather than a unique-violation. The subject is already on the row and in
    /// every audit entry about it, so this reveals nothing the record does not already hold.
    /// </remarks>
    public const string TombstonePrefix = "anonymised-";

    /// <summary>
    /// How many bytes of entropy a generated password carries.
    /// </summary>
    /// <remarks>
    /// 24 bytes, rendered as 32 base64 characters. Long enough that the Argon2id cost is defence in
    /// depth rather than the whole defence, and short enough to be retyped from a vault by a person
    /// who has to.
    /// </remarks>
    public const int PasswordBytes = 24;

    /// <summary>Create an account and return its password once.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">What they will type at the login page.</param>
    /// <param name="email">Their address, or <see langword="null"/>.</param>
    /// <param name="role">
    /// What its tokens should claim, or <see langword="null"/> to take the deployment's
    /// <see cref="AccountDefaults"/> — which fill an absence only: a named role is exactly what the
    /// account gets, defaults not unioned in.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="InvalidOperationException">
    /// The handle is taken. Raised by the store, whose message already says so — accounts are
    /// add-only, and overwriting one would replace its credentials. Also raised by the role
    /// assignment when a default names a role the realm does not define, which is the misconfigured
    /// deployment the host's <c>migrate</c> verb exists to catch first.
    /// </exception>
    public async Task<CreatedAccount> CreateAsync(
        Actor actor,
        RealmId realm,
        string handle,
        string? email,
        string? role,
        CancellationToken cancellationToken)
    {
        // Optional on the constructor and demanded here, because only this method needs it. The
        // shipped factory lives in Boltway.Identity, which this assembly does not reference —
        // so a deployment that never creates an account should not have to register one, and the
        // one that does should be told which line is missing rather than reading a container
        // activation failure naming a type it has never heard of.
        if (subjects is null)
        {
            throw new InvalidOperationException(
                "Creating an account mints a subject, and no ISubjectIdFactory is registered. "
                + "Ships: new UlidSubjectIdFactory(TimeProvider.System) from Boltway.Identity. "
                + "Every other operation here works without one.");
        }

        var password = NewPassword();
        var subject = subjects.Mint();

        await users.StoreAsync(
            new UserAccount(subject, handle, email, EmailVerified: false, hasher.Hash(password))
            {
                Realm = realm.OrDefault,
            },
            cancellationToken).ConfigureAwait(false);

        // Created first, assigned second, because creation does not assign — see UserAccount.Roles.
        // Not one transaction, and the failure that leaves behind is an account with no roles rather
        // than a half-made one: it can sign in, it holds nothing, and `set-role` finishes the job.
        // The alternative, deleting the account when the assignment fails, turns a mistyped role
        // into a handle that is taken by a row nobody can see.
        //
        // A named role wins outright; the defaults only ever fill an absence — see AccountDefaults
        // for why they are not unioned in. An empty string counts as absence: it is what a form
        // whose role field was left blank submits, and treating it as a name would record `role=`
        // in the audit trail and assign nothing.
        var named = role is { Length: > 0 };
        IReadOnlyList<string> assigned = named ? [role!] : accountDefaults?.Roles ?? [];

        if (assigned.Count > 0)
        {
            await users.SetRolesAsync(subject, assigned, cancellationToken).ConfigureAwait(false);
        }

        // Space-joined for the same reason a token's claim is: several roles are one field
        // everywhere a person reads them.
        var claimed = assigned.Count > 0 ? string.Join(' ', assigned) : null;

        await RecordAsync(actor, "user.create", realm, subject, handle, AdminAuditOutcome.Succeeded,
            claimed is null
                ? null
                : "role=" + claimed + (named ? string.Empty : " (defaulted)"),
            cancellationToken).ConfigureAwait(false);

        return new CreatedAccount(subject, handle, email, claimed, password);
    }

    /// <summary>Generate a new password for an existing account.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose password.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Sessions and refresh tokens already issued keep working: access tokens are signed rather than
    /// looked up, so nothing can withdraw one before it expires, and refresh tokens are derived from
    /// a key this does not touch. Revoking them is a separate decision and will be a separate flag.
    /// </remarks>
    public async Task<PasswordResetResult> ResetPasswordAsync(
        Actor actor, RealmId realm, string handle, CancellationToken cancellationToken)
    {
        var account = await users
            .FindByUsernameAsync(realm.OrDefault, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.password.reset", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new PasswordResetResult(AdministrationStatus.NoSuchAccount);
        }

        var password = NewPassword();

        var applied = await users
            .SetPasswordHashAsync(account.Subject, hasher.Hash(password), cancellationToken)
            .ConfigureAwait(false);

        // Every session this account had predates the new password, so none of them are its
        // sessions any more. Separate from the write above by design — see StampSessionsAsync —
        // and unconditional on this path, because a password change nobody asked for is exactly
        // the case where the old browser must stop working.
        await users.StampSessionsAsync(account.Subject, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);

        if (applied)
        {
            await DestroyResetLinksAsync(account.Subject, cancellationToken).ConfigureAwait(false);
        }

        await RecordAsync(actor, "user.password.reset", realm, account.Subject, handle,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            null, cancellationToken).ConfigureAwait(false);

        return applied
            ? new PasswordResetResult(AdministrationStatus.Ok, account.Subject, password)
            : new PasswordResetResult(AdministrationStatus.Gone, account.Subject);
    }

    /// <summary>
    /// Change your own password, proving you know the current one. <c>E-34</c>, <c>S-49</c>.
    /// </summary>
    /// <param name="actor">Who is asking. The subject on it is the account being changed.</param>
    /// <param name="subject">Whose password. <b>Never taken from a request body</b> — see remarks.</param>
    /// <param name="currentPassword">What is on the account now.</param>
    /// <param name="newPassword">What to replace it with.</param>
    /// <param name="revokeSessions">Whether to end every other session on the way.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>By subject, not by handle, and that is the difference from every other method here.</b>
    /// The rest resolve what a person typed, because an operator starts from a name. This one starts
    /// from the token: the caller supplies no identifier at all, so there is no parameter an
    /// <c>/account</c> handler could fill from a request body and no code path that reaches another
    /// account. §1.6 — two surfaces rather than one with a guard.
    /// </para>
    /// <para>
    /// <b>The current password is required even though the bearer token already authenticated the
    /// caller.</b> <c>S-49</c>: a stolen token is a credential that expires, and a password is one
    /// that does not. Without this check, thirty minutes of access becomes permanent access, and the
    /// theft survives every rotation the token design pays for.
    /// </para>
    /// <para>
    /// <b>Revoking other sessions is asked for, not inferred.</b> §1.10 splits on why: an email reset
    /// revokes because the person has probably lost control of something, and an operator reset does
    /// not because signing a colleague out of every device is a surprise. A self-service change is
    /// either of those and the server cannot tell which, so the caller says. The default is off, the
    /// same way <c>set-password</c>'s is, and the response carries the count so a caller who asked
    /// can say what happened.
    /// </para>
    /// <para>
    /// <b>The session this call is made from is revoked along with the rest.</b> Sparing it would
    /// mean deciding which grant the caller is holding, from a token that names a grant this service
    /// is not given — and getting that wrong leaves the compromised session alive, which is the one
    /// case the flag exists for.
    /// </para>
    /// </remarks>
    public async Task<PasswordChangeResult> ChangePasswordAsync(
        Actor actor,
        SubjectId subject,
        string currentPassword,
        string newPassword,
        bool revokeSessions,
        CancellationToken cancellationToken)
    {
        // Before anything is written, not beside the revocation itself. A caller who asked to end
        // their sessions asked because they think one of them is not theirs; discovering the store
        // is missing after the password has already changed would leave the account half-done and
        // the caller holding a 500 that says nothing about which half landed.
        if (revokeSessions)
        {
            RequireGrants();
        }

        var account = await users.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false);

        // The realm comes off the account rather than from a parameter: the caller proved a subject,
        // and a subject is unique across realms, so asking which directory to look in would be
        // asking for something that could only ever disagree with the answer.
        var realm = account?.Realm ?? RealmId.Default;
        var handle = account?.Username ?? subject.Value;

        if (account is null)
        {
            await RecordAsync(actor, "user.password.change", realm, null, handle,
                AdminAuditOutcome.Refused, "no such account", cancellationToken).ConfigureAwait(false);

            return new PasswordChangeResult(AdministrationStatus.NoSuchAccount);
        }

        if (account.PasswordHash is not { } stored)
        {
            await RecordAsync(actor, "user.password.change", realm, subject, handle,
                AdminAuditOutcome.Refused, "no local password", cancellationToken).ConfigureAwait(false);

            return new PasswordChangeResult(AdministrationStatus.NoPassword, subject);
        }

        if (!hasher.Verify(currentPassword, stored))
        {
            // Audited as a refusal, and it is the entry in this file most worth having: a run of
            // these against one subject is somebody working through a stolen token, and it is
            // invisible in the sign-in logs because no sign-in happened.
            await RecordAsync(actor, "user.password.change", realm, subject, handle,
                AdminAuditOutcome.Refused, "current password did not verify", cancellationToken)
                .ConfigureAwait(false);

            return new PasswordChangeResult(AdministrationStatus.WrongPassword, subject);
        }

        var applied = await users
            .SetPasswordHashAsync(subject, hasher.Hash(newPassword), cancellationToken)
            .ConfigureAwait(false);

        // Every session this account had predates the new password, so none of them are its
        // sessions any more. Separate from the write above by design — see StampSessionsAsync —
        // and unconditional on this path, because a password change nobody asked for is exactly
        // the case where the old browser must stop working.
        await users.StampSessionsAsync(subject, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);

        if (!applied)
        {
            await RecordAsync(actor, "user.password.change", realm, subject, handle,
                AdminAuditOutcome.Refused, "gone", cancellationToken).ConfigureAwait(false);

            return new PasswordChangeResult(AdministrationStatus.Gone, subject);
        }

        // After the password, not before. Dying in between this way leaves an account whose new
        // password works and whose old sessions are still live — recoverable by asking again. The
        // other order signs somebody out and then fails to change the credential they were signing
        // out to protect.
        await DestroyResetLinksAsync(subject, cancellationToken).ConfigureAwait(false);

        var revoked = revokeSessions
            ? await grants!.RevokeAllForSubjectAsync(subject, _clock.GetUtcNow(), cancellationToken)
                .ConfigureAwait(false)
            : 0;

        await RecordAsync(actor, "user.password.change", realm, subject, handle,
            AdminAuditOutcome.Succeeded,
            revokeSessions ? $"revoked {revoked} grant(s)" : null,
            cancellationToken).ConfigureAwait(false);

        return new PasswordChangeResult(AdministrationStatus.Ok, subject, revoked);
    }

    /// <summary>Set or clear an account's role.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose role.</param>
    /// <param name="role">The new role, or <see langword="null"/> to clear it.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Tokens already issued keep the old role until they expire. The role is a claim, and a claim
    /// that has been signed is not something a directory change can reach.
    /// </remarks>
    public async Task<RoleChangeResult> SetRoleAsync(
        Actor actor, RealmId realm, string handle, string? role, CancellationToken cancellationToken)
    {
        var account = await users
            .FindByUsernameAsync(realm.OrDefault, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.role", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new RoleChangeResult(AdministrationStatus.NoSuchAccount);
        }

        // One role, because that is what this operation has always meant and what every caller of
        // it says. Holding several is expressible in the store; offering it here is a surface with
        // its own audit shape, its own admin page and its own CLI verb, and none of those are this
        // method.
        var applied = await users
            .SetRolesAsync(account.Subject, role is { Length: > 0 } ? [role] : [], cancellationToken)
            .ConfigureAwait(false);

        await RecordAsync(actor, "user.role", realm, account.Subject, handle,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            role is null ? "cleared" : "role=" + role, cancellationToken).ConfigureAwait(false);

        return applied
            ? new RoleChangeResult(AdministrationStatus.Ok, account.Subject, role)
            : new RoleChangeResult(AdministrationStatus.Gone, account.Subject);
    }

    /// <summary>Disable an account, or enable one that was disabled.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose account.</param>
    /// <param name="enabled">Whether it should be able to sign in.</param>
    /// <param name="now">
    /// When the disabling happened. Passed in rather than read from a clock here, so the recorded
    /// time is the one the caller's <see cref="TimeProvider"/> reports and a test can move it.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Disabling stops the next sign-in and nothing else. Tokens already issued are signed rather
    /// than looked up, so nothing can withdraw one before it expires — which is worth knowing before
    /// disabling somebody in response to an incident and believing it is over.
    /// </remarks>
    public async Task<EnablementResult> SetEnabledAsync(
        Actor actor,
        RealmId realm,
        string handle,
        bool enabled,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var account = await users
            .FindByUsernameAsync(realm.OrDefault, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.enablement", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new EnablementResult(AdministrationStatus.NoSuchAccount);
        }

        // Re-disabling an already-disabled account keeps the original time rather than moving it.
        // "Since when" is the question a disabled account is asked, and answering it with the moment
        // somebody ran the command a second time loses the only fact worth having.
        DateTimeOffset? disabledAt = enabled ? null : account.DisabledAt ?? now;

        var applied = await users
            .SetEnabledAsync(account.Subject, disabledAt, cancellationToken)
            .ConfigureAwait(false);

        await RecordAsync(actor, "user.enablement", realm, account.Subject, handle,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            enabled ? "enabled" : "disabled", cancellationToken).ConfigureAwait(false);

        return applied
            ? new EnablementResult(AdministrationStatus.Ok, account.Subject, disabledAt)
            : new EnablementResult(AdministrationStatus.Gone, account.Subject);
    }

    /// <summary>Set or clear an account's email address.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose account.</param>
    /// <param name="email">The address, or <see langword="null"/> to remove it.</param>
    /// <param name="verified">Whether it has been proven to belong to this person.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>Clearing an address always clears the flag</b>, whatever the caller passed. A verified
    /// null is not a state — it would put <c>email_verified: true</c> in a token with no <c>email</c>
    /// claim beside it, which is a proof about nothing.
    /// </para>
    /// <para>
    /// Marking an address verified is an operator asserting it, not this server checking it. The
    /// flow that checks — a link sent to the address — is not built; until it is, this is the only
    /// thing that can make <c>email_verified</c> anything other than the constant it has always
    /// been, and it is worth knowing which of the two a given token's claim came from.
    /// </para>
    /// </remarks>
    public async Task<EmailChangeResult> SetEmailAsync(
        Actor actor,
        RealmId realm,
        string handle,
        string? email,
        bool verified,
        CancellationToken cancellationToken)
    {
        var account = await users
            .FindByUsernameAsync(realm.OrDefault, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.email", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new EmailChangeResult(AdministrationStatus.NoSuchAccount);
        }

        var isVerified = email is not null && verified;

        var applied = await users
            .SetEmailAsync(account.Subject, email, isVerified, cancellationToken)
            .ConfigureAwait(false);

        // The address is not in the entry. It is on the account, and a log that accumulated every
        // address a person has ever had is a second copy of the directory that nothing deletes from.
        await RecordAsync(actor, "user.email", realm, account.Subject, handle,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            email is null ? "cleared" : isVerified ? "set, verified" : "set, unverified",
            cancellationToken).ConfigureAwait(false);

        return applied
            ? new EmailChangeResult(AdministrationStatus.Ok, account.Subject, email, isVerified)
            : new EmailChangeResult(AdministrationStatus.Gone, account.Subject);
    }

    /// <summary>Revoke every grant this account holds. <c>E-30</c>.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose sessions.</param>
    /// <param name="now">When the revocation happened.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>Refresh chains stop immediately; access tokens do not.</b> The refresh handler loads the
    /// grant and refuses when it is not active, so every chain descended from a revoked grant is
    /// dead on its next rotation. An access token already issued is signed rather than looked up,
    /// and <c>IGrantStore.IsRevokedAsync</c> — the denylist a resource server would consult — is
    /// called by nothing in this repository. So "signed out everywhere" is true after one access
    /// token lifetime and not before, and an operator responding to a compromise should know which
    /// of the two they just did.
    /// </para>
    /// <para>
    /// <b>The account is untouched.</b> This does not disable it and does not change the password;
    /// somebody who still knows the password signs straight back in. Revoking sessions, disabling
    /// and resetting a password are three operations because they answer three different questions,
    /// and an incident usually wants more than one of them.
    /// </para>
    /// </remarks>
    public async Task<SessionRevocationResult> RevokeSessionsAsync(
        Actor actor, RealmId realm, string handle, DateTimeOffset now, CancellationToken cancellationToken)
    {
        RequireGrants();

        var account = await users
            .FindByUsernameAsync(realm.OrDefault, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.sessions.revoke", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new SessionRevocationResult(AdministrationStatus.NoSuchAccount);
        }

        var revoked = await grants!
            .RevokeAllForSubjectAsync(account.Subject, now, cancellationToken)
            .ConfigureAwait(false);

        // Succeeded even at zero. There were no live grants, which is a true and useful answer —
        // recording it as a refusal would put "somebody tried and was stopped" in the log for an
        // operator who did exactly what they meant to.
        await RecordAsync(actor, "user.sessions.revoke", realm, account.Subject, handle,
            AdminAuditOutcome.Succeeded,
            "revoked=" + revoked.ToString(System.Globalization.CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);

        return new SessionRevocationResult(AdministrationStatus.Ok, account.Subject, revoked);
    }

    /// <summary>Anonymise an account. Irreversible. <c>E-31</c>.</summary>
    /// <param name="actor">Who is asking.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose account.</param>
    /// <param name="now">When it happened.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// Username becomes a tombstone, email and credential and role are gone, external links are
    /// deleted, the account is disabled, and every grant is revoked. <b>The subject row stays</b>,
    /// so audit entries and grant history keep their referent — an audit trail that empties when the
    /// audited party asks is not an audit trail.
    /// </para>
    /// <para>
    /// <b>Sessions first, then the account, and the order is the recovery story.</b> These are two
    /// writes and nothing here can make them one. Anonymising first and dying in between would leave
    /// a tombstoned account whose refresh tokens still mint — a session belonging to a person the
    /// directory says is gone. This way round, dying in between leaves an ordinary account whose
    /// owner has been signed out, which is a state an operator can see and rerun.
    /// </para>
    /// </remarks>
    public async Task<AnonymisationResult> AnonymiseAsync(
        Actor actor, RealmId realm, string handle, DateTimeOffset now, CancellationToken cancellationToken)
    {
        RequireGrants();

        var account = await users
            .FindByUsernameAsync(realm.OrDefault, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.anonymise", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new AnonymisationResult(AdministrationStatus.NoSuchAccount);
        }

        var revoked = await grants!
            .RevokeAllForSubjectAsync(account.Subject, now, cancellationToken)
            .ConfigureAwait(false);

        var tombstone = TombstonePrefix + account.Subject.Value;

        var applied = await users
            .AnonymiseAsync(account.Subject, tombstone, now, cancellationToken)
            .ConfigureAwait(false);

        // The handle as typed is in the entry, which is the one place it survives — the account no
        // longer carries it. That is deliberate and it is the boundary of what this operation
        // promises: the directory stops naming the person, and the record of who was administered
        // stays readable, because otherwise nobody can answer "was this done properly".
        await RecordAsync(actor, "user.anonymise", realm, account.Subject, handle,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            "revoked=" + revoked.ToString(System.Globalization.CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);

        return applied
            ? new AnonymisationResult(AdministrationStatus.Ok, account.Subject, tombstone, revoked)
            : new AnonymisationResult(AdministrationStatus.Gone, account.Subject, null, revoked);
    }

    /// <summary>
    /// Destroy every outstanding reset link for this account. <c>S-47</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Called after the password has actually changed, on every route that changes one. A link that
    /// still works afterwards is a second key to the account, held by whoever asked for it — which
    /// on the operator route may be a person who has since been let go, and on the self-service
    /// route may be the attacker whose access is the reason the password is being changed.
    /// </para>
    /// <para>
    /// Silent when no store is registered, because a deployment without the email flows has no
    /// links. It is not a failure to destroy nothing.
    /// </para>
    /// </remarks>
    private Task DestroyResetLinksAsync(SubjectId subject, CancellationToken cancellationToken) =>
        tokens is null
            ? Task.CompletedTask
            : tokens.DeleteForSubjectAsync(subject, UserTokenPurpose.PasswordReset, cancellationToken);

    /// <summary>The two session operations need a grant store; say which line is missing.</summary>
    private void RequireGrants()
    {
        if (grants is null)
        {
            throw new InvalidOperationException(
                "Ending somebody's sessions revokes their grants, and no IGrantStore is registered. "
                + "AddBoltwayAuthorizationServer registers one with either storage package. "
                + "Every operation here except this one and anonymise works without it.");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The roles a realm defines, ordered by id.</summary>
    /// <remarks>
    /// Not audited. Reading the directory's own vocabulary changes nothing and happens on every
    /// render of the page that offers it, so an entry per call would bury the writes that matter.
    /// </remarks>
    public Task<IReadOnlyList<RoleDefinition>> ListRolesAsync(
        RealmId realm, CancellationToken cancellationToken) =>
        Roles.ListAsync(realm, cancellationToken);

    /// <summary>One role, or null.</summary>
    public Task<RoleDefinition?> FindRoleAsync(
        RealmId realm, string id, CancellationToken cancellationToken) =>
        Roles.FindAsync(realm, id, cancellationToken);

    /// <summary>Define a role. Throws when the realm already defines that id.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The immutable id a token will carry.</param>
    /// <param name="name">What to call it, defaulting to the id.</param>
    /// <param name="permissions">What it stands for, in the resource server's vocabulary.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="InvalidOperationException">The realm already defines that id.</exception>
    public async Task<RoleDefinition> CreateRoleAsync(
        Actor actor,
        RealmId realm,
        string id,
        string? name,
        IEnumerable<string> permissions,
        CancellationToken cancellationToken)
    {
        // Built before the audit entry, so a malformed id or a permission carrying whitespace is
        // refused without a "role.create succeeded" line to explain away afterwards.
        var role = new RoleDefinition(id, string.IsNullOrWhiteSpace(name) ? id : name, permissions)
        {
            Realm = realm.OrDefault,
        };

        await Roles.StoreAsync(role, cancellationToken).ConfigureAwait(false);

        await RecordAsync(actor, "role.create", realm, null, id, AdminAuditOutcome.Succeeded,
            Detail(role), cancellationToken).ConfigureAwait(false);

        return role;
    }

    /// <summary>Define the roles a deployment declares, skipping every one already defined.</summary>
    /// <param name="actor">Who is doing this — the CLI, when this runs from the migrate step.</param>
    /// <param name="realm">The directory.</param>
    /// <param name="seeds">What should exist.</param>
    /// <param name="cancellationToken">Cancels the writes.</param>
    /// <returns>One outcome per seed, in the seeds' order.</returns>
    /// <remarks>
    /// <para>
    /// <b>Create-if-absent, never converge-to-config.</b> After bootstrap the definitions belong to
    /// the admin surface, so a seed that finds its role already defined leaves it exactly as it is
    /// — name and permissions both — even when they differ from the seed. Re-asserting the seed on
    /// every deploy would quietly revert any edit an operator made in between, which turns the
    /// roles page into a lie that holds until the next deploy.
    /// </para>
    /// <para>
    /// Every seed is validated before anything is written, so one malformed entry fails the whole
    /// pass rather than applying half of it — a deploy log then shows either what was done or one
    /// message naming what to fix, never both. Validation must not depend on absence, or a typo in
    /// a seed would sit unnoticed exactly as long as the role it names exists.
    /// </para>
    /// <para>
    /// Each created role is audited through <see cref="CreateRoleAsync"/>; a skip writes no entry,
    /// because it changes nothing and this runs on every deploy — an entry per deploy per role
    /// would bury the writes that matter.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">A seed breaks <see cref="RoleDefinition"/>'s rules.</exception>
    public async Task<IReadOnlyList<SeededRole>> SeedRolesAsync(
        Actor actor, RealmId realm, IReadOnlyList<RoleSeed> seeds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(seeds);

        foreach (var seed in seeds)
        {
            _ = new RoleDefinition(seed.Id, seed.Name ?? seed.Id, seed.Permissions ?? []);
        }

        var outcomes = new List<SeededRole>(seeds.Count);

        foreach (var seed in seeds)
        {
            // The find resolves the Roles property first, so the "no store registered" failure
            // surfaces here and cannot reach the catch below wearing the wrong meaning.
            if (await FindRoleAsync(realm, seed.Id, cancellationToken).ConfigureAwait(false) is not null)
            {
                outcomes.Add(new SeededRole(seed.Id, Created: false));
                continue;
            }

            try
            {
                await CreateRoleAsync(
                    actor, realm, seed.Id, seed.Name, seed.Permissions ?? [], cancellationToken)
                    .ConfigureAwait(false);

                outcomes.Add(new SeededRole(seed.Id, Created: true));
            }
            catch (InvalidOperationException)
            {
                // Defined between the read and the write — a concurrent migrate, or an operator on
                // the admin page at the wrong second. The role exists, which is all a seed asks for,
                // so this is the same outcome as finding it above, not a failure to report.
                outcomes.Add(new SeededRole(seed.Id, Created: false));
            }
        }

        return outcomes;
    }

    /// <summary>Reword a role. False when the realm does not define it.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id.</param>
    /// <param name="name">The new name.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public async Task<bool> SetRoleNameAsync(
        Actor actor, RealmId realm, string id, string name, CancellationToken cancellationToken)
    {
        var applied = await Roles.SetNameAsync(realm, id, name, cancellationToken).ConfigureAwait(false);

        await RecordAsync(actor, "role.name", realm, null, id,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            applied ? "name=" + name : null, cancellationToken).ConfigureAwait(false);

        return applied;
    }

    /// <summary>Replace what a role stands for. False when the realm does not define it.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id.</param>
    /// <param name="permissions">The new permissions, replacing all of them.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// The audit detail is the whole new set rather than a diff, because a diff is only readable
    /// next to the entry before it and this line has to stand alone in a log somebody greps.
    /// </remarks>
    public async Task<bool> SetRolePermissionsAsync(
        Actor actor,
        RealmId realm,
        string id,
        IEnumerable<string> permissions,
        CancellationToken cancellationToken)
    {
        var listed = permissions.ToList();

        var applied = await Roles
            .SetPermissionsAsync(realm, id, listed, cancellationToken)
            .ConfigureAwait(false);

        await RecordAsync(actor, "role.permissions", realm, null, id,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            applied ? "permissions=" + string.Join(' ', listed.Order(StringComparer.Ordinal)) : null,
            cancellationToken).ConfigureAwait(false);

        return applied;
    }

    /// <summary>Remove a role and every assignment of it. False when it was not there.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">The directory.</param>
    /// <param name="id">The role id.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Accounts holding only this role are left holding none. That is the least-privileged outcome
    /// rather than a refusal, and the audit entry is the only record that it happened to them —
    /// which is why this one is audited even when it changes nobody.
    /// </remarks>
    public async Task<bool> DeleteRoleAsync(
        Actor actor, RealmId realm, string id, CancellationToken cancellationToken)
    {
        var deleted = await Roles.DeleteAsync(realm, id, cancellationToken).ConfigureAwait(false);

        await RecordAsync(actor, "role.delete", realm, null, id,
            deleted ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            null, cancellationToken).ConfigureAwait(false);

        return deleted;
    }

    /// <summary>Replace which roles an account holds.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">The directory.</param>
    /// <param name="handle">Whose account.</param>
    /// <param name="assigned">The ids it should hold, replacing all of them.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// The multi-valued sibling of <see cref="SetRoleAsync"/>, which stays because one role is what
    /// almost every caller means and `set-role ada founder` should not have to become a list.
    /// </remarks>
    public async Task<RolesChangeResult> SetRolesAsync(
        Actor actor,
        RealmId realm,
        string handle,
        IReadOnlyList<string> assigned,
        CancellationToken cancellationToken)
    {
        var account = await users.FindByUsernameAsync(realm, handle, cancellationToken).ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "user.roles", realm, null, handle,
                AdminAuditOutcome.Refused, null, cancellationToken).ConfigureAwait(false);

            return new RolesChangeResult(AdministrationStatus.NoSuchAccount);
        }

        var applied = await users
            .SetRolesAsync(account.Subject, assigned, cancellationToken)
            .ConfigureAwait(false);

        await RecordAsync(actor, "user.roles", realm, account.Subject, handle,
            applied ? AdminAuditOutcome.Succeeded : AdminAuditOutcome.Refused,
            assigned.Count == 0 ? "cleared" : "roles=" + string.Join(' ', assigned),
            cancellationToken).ConfigureAwait(false);

        return applied
            ? new RolesChangeResult(AdministrationStatus.Ok, account.Subject, assigned)
            : new RolesChangeResult(AdministrationStatus.NoSuchAccount);
    }

    /// <summary>
    /// Give an account a service account: a client that acts as it, with its own secret.
    /// </summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose account the client will act as.</param>
    /// <param name="scopes">Exactly what its tokens will carry.</param>
    /// <param name="cancellationToken">Cancels the writes.</param>
    /// <remarks>
    /// <para>
    /// <b>Scopes are a parameter and cannot be derived.</b> A role holds <i>permissions</i> —
    /// <c>docs_read</c>, in the resource server's vocabulary — and a token carries <i>scopes</i>,
    /// <c>docs:read</c>, in OAuth's. Nothing maps one to the other, and inventing a mapping here would
    /// be this library guessing at a vocabulary that belongs to somebody else's resource server.
    /// So the caller names them, and whoever presses the button sees what they are granting.
    /// </para>
    /// <para>
    /// <b>Calling it again rotates the secret rather than refusing.</b> The plaintext exists once,
    /// so "I lost it" has to have an answer, and the honest one is a new secret rather than an
    /// escrowed copy. The client id, the owner and the scopes are unchanged; only the credential
    /// moves, and the audit line says <c>client.rotate</c> so the two are not one event in the log.
    /// </para>
    /// <para>
    /// <b>The owner's roles are the ceiling on what the token can do.</b> Nothing here checks it,
    /// because there is nothing to check against yet — roles move after a service account is made.
    /// <c>ClientCredentialsGrant</c> applies it at every token request instead, refusing to issue
    /// when the owner is not entitled to a scope the client holds.
    ///
    /// This paragraph used to say the ceiling was applied "when the token is used, by whatever
    /// reads its roles". Nothing did: <c>AdminAuthorization</c> deliberately reads only the scope,
    /// which is the correct division, and this grant took scope straight off the client record —
    /// so the ceiling was a sentence true of nowhere, and a service account owned by an account
    /// with no administrative role could rewrite the whole directory.
    ///
    /// What it means for a caller is unchanged: pointing this at a founder creates a credential
    /// with a founder's reach, and the surface offering it should say so.
    /// </para>
    /// </remarks>
    public async Task<ServiceAccountResult> CreateServiceAccountAsync(
        Actor actor,
        RealmId realm,
        string handle,
        IReadOnlyList<string> scopes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var account = await users.FindByUsernameAsync(realm, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            await RecordAsync(actor, "client.create", realm, null, handle,
                AdminAuditOutcome.Refused, "no such account", cancellationToken).ConfigureAwait(false);

            return new ServiceAccountResult(AdministrationStatus.NoSuchAccount);
        }

        // Refused rather than issued with nothing, because the grant refuses an empty scope set at
        // the token endpoint — so this would otherwise mint a credential that can never obtain a
        // token, and the operator would find out at the service's first run rather than here.
        if (!ScopeSet.TryParse(string.Join(' ', scopes), out var parsed, out var scopeError)
            || parsed.IsEmpty)
        {
            await RecordAsync(actor, "client.create", realm, account.Subject, handle,
                AdminAuditOutcome.Refused, scopeError ?? "no scopes", cancellationToken)
                .ConfigureAwait(false);

            throw new ArgumentException(
                paramName: nameof(scopes),
                message: "A service account is issued exactly the scopes named here and nothing "
                    + "widens them, so it needs at least one. " + (scopeError ?? string.Empty));
        }

        var existing = await Clients.FindByOwnerAsync(account.Subject, cancellationToken)
            .ConfigureAwait(false);

        // Derived from the handle rather than random, so the id a person reads in a config file
        // says whose account it acts as. Reused on rotation, because the id is what a deployed
        // service is configured with and changing it would make rotating a secret a redeploy.
        var clientId = ClientIdentifier.ForPreRegistered(existing?.ClientId.Value ?? $"svc-{handle}");

        var secret = OpaqueSecret.Generate(TokenPurpose.ClientSecret);

        await Clients.StoreAsync(
            new ClientRecord
            {
                ClientId = clientId,
                ClientType = ClientType.Confidential,
                TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic,

                // None, and that is what makes it a service account rather than a client somebody
                // authorizes: it never reaches /authorize, so a redirect URI would be a promise
                // nothing keeps.
                RedirectUris = [],
                GrantTypes = ["client_credentials"],
                ResponseTypes = ["code"],
                ClientName = existing?.ClientName ?? $"Service account for {handle}",
                AllowedScopes = parsed,
                Owner = account.Subject,
            },
            Sha256Hash.Of(secret),
            cancellationToken).ConfigureAwait(false);

        await RecordAsync(actor, existing is null ? "client.create" : "client.rotate", realm,
            account.Subject, handle, AdminAuditOutcome.Succeeded,
            $"client_id={clientId.Value} scopes={parsed.ToWireString()}", cancellationToken)
            .ConfigureAwait(false);

        return new ServiceAccountResult(AdministrationStatus.Ok, clientId.Value, secret.Wire);
    }

    /// <summary>Stop or restart an account's service account.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose service account.</param>
    /// <param name="enabled">Whether it may obtain tokens.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <b>Not revocation.</b> It stops new tokens being issued; one already out lives until it
    /// expires. A service account holds no refresh token, so that window is one access-token
    /// lifetime and nothing can extend it — but it is not zero, and a caller telling somebody "this
    /// is off now" is telling them something that becomes true shortly.
    /// </remarks>
    public async Task<ServiceAccountResult> SetServiceAccountEnabledAsync(
        Actor actor, RealmId realm, string handle, bool enabled, CancellationToken cancellationToken)
    {
        var (account, client) = await FindServiceAccountAsync(realm, handle, cancellationToken)
            .ConfigureAwait(false);

        var action = enabled ? "client.enable" : "client.disable";

        if (client is null)
        {
            await RecordAsync(actor, action, realm, account?.Subject, handle,
                AdminAuditOutcome.Refused, "no service account", cancellationToken)
                .ConfigureAwait(false);

            return new ServiceAccountResult(AdministrationStatus.NoSuchAccount);
        }

        await Clients.SetEnabledAsync(client.ClientId, enabled, cancellationToken).ConfigureAwait(false);

        await RecordAsync(actor, action, realm, account!.Subject, handle,
            AdminAuditOutcome.Succeeded, $"client_id={client.ClientId.Value}", cancellationToken)
            .ConfigureAwait(false);

        return new ServiceAccountResult(AdministrationStatus.Ok, client.ClientId.Value);
    }

    /// <summary>Remove an account's service account entirely.</summary>
    /// <param name="actor">Who is doing this.</param>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose service account.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// Deleting is not the same as disabling and both are offered: disabling keeps the id and the
    /// secret so the service can be turned back on without being reconfigured, and deleting means
    /// the credential is gone and a new one will have a new secret. Tokens already issued outlive
    /// either, for the same reason.
    /// </remarks>
    public async Task<ServiceAccountResult> DeleteServiceAccountAsync(
        Actor actor, RealmId realm, string handle, CancellationToken cancellationToken)
    {
        var (account, client) = await FindServiceAccountAsync(realm, handle, cancellationToken)
            .ConfigureAwait(false);

        if (client is null)
        {
            await RecordAsync(actor, "client.delete", realm, account?.Subject, handle,
                AdminAuditOutcome.Refused, "no service account", cancellationToken)
                .ConfigureAwait(false);

            return new ServiceAccountResult(AdministrationStatus.NoSuchAccount);
        }

        await Clients.DeleteAsync(client.ClientId, cancellationToken).ConfigureAwait(false);

        await RecordAsync(actor, "client.delete", realm, account!.Subject, handle,
            AdminAuditOutcome.Succeeded, $"client_id={client.ClientId.Value}", cancellationToken)
            .ConfigureAwait(false);

        return new ServiceAccountResult(AdministrationStatus.Ok, client.ClientId.Value);
    }

    /// <summary>The service account acting as this handle, and the account itself.</summary>
    /// <param name="realm">Which directory.</param>
    /// <param name="handle">Whose.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <remarks>
    /// Public because the surfaces that offer the checkbox need to render its current state, and
    /// asking "does this person have one" through a create call would be a strange way to find out.
    /// </remarks>
    public async Task<(UserAccount? Account, ClientRecord? Client)> FindServiceAccountAsync(
        RealmId realm, string handle, CancellationToken cancellationToken)
    {
        var account = await users.FindByUsernameAsync(realm, handle, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            return (null, null);
        }

        return (account, await Clients.FindByOwnerAsync(account.Subject, cancellationToken)
            .ConfigureAwait(false));
    }

    /// <summary>The client store, or a failure naming what was not registered.</summary>
    private IClientStore Clients =>
        clients ?? throw new InvalidOperationException(
            "No IClientStore is registered, so this deployment cannot hold service accounts. "
            + "AddBoltwayInMemoryStorage and AddBoltwayEntityFrameworkStorage both register "
            + "one; a custom storage package has to as well.");

    /// <summary>The role store, or a failure naming what was not registered.</summary>
    private IRoleStore Roles =>
        roles ?? throw new InvalidOperationException(
            "No IRoleStore is registered, so this deployment cannot define or assign roles. "
            + "AddBoltwayInMemoryStorage and AddBoltwayEntityFrameworkStorage both register "
            + "one; a custom storage package has to as well.");

    /// <summary>A role as one audit line.</summary>
    private static string Detail(RoleDefinition role) =>
        $"name={role.Name} permissions={string.Join(' ', role.Permissions.Order(StringComparer.Ordinal))}";

    /// <summary>
    /// Append one audit entry, if this deployment keeps them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>After the change, not inside it, and that window is real.</b> Every relational store here
    /// creates its own <c>DbContext</c> per call, so two of them cannot presently share a
    /// transaction; a process that dies between the write and this line leaves a change with no
    /// entry. <see cref="IAdminAuditStore.RecordAsync"/> says what closing it would cost and why it
    /// was not done in a hurry.
    /// </para>
    /// <para>
    /// <b>A refused action is recorded too.</b> A handle that matched nobody is somebody trying, and
    /// a log holding only successes cannot tell "nobody tried" from "everybody was stopped".
    /// </para>
    /// </remarks>
    private Task RecordAsync(
        Actor actor,
        string action,
        RealmId realm,
        SubjectId? target,
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
                actor.Kind is ActorKind.Cli ? "cli" : "client",
                actor.Subject,
                actor.Client,
                action,
                realm.OrDefault,
                target,
                handle,
                outcome,
                actor.CorrelationId)
            {
                Detail = detail,
            },
            cancellationToken);
    }

    /// <summary>
    /// A password nobody chose.
    /// </summary>
    /// <remarks>
    /// <see cref="RandomNumberGenerator"/> rather than <c>Random</c> or <c>Guid.NewGuid()</c>, which
    /// is <c>N-16</c>'s rule about every secret this server mints. Base64 rather than a word list,
    /// because a word list is a dependency and a locale decision on a value nobody reads aloud.
    /// </remarks>
    private static string NewPassword() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(PasswordBytes));
}
