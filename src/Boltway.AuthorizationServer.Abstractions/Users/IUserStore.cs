using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Abstractions.Users;

/// <summary>An end user.</summary>
/// <param name="Subject">
/// The <c>sub</c> this server emits. A ULID, so it needs no sanitising anywhere downstream.
/// </param>
/// <param name="Username">What they type at the login page.</param>
/// <param name="Email">Their email, for the <c>email</c> claim.</param>
/// <param name="EmailVerified">Whether it was verified. Emitted as <c>email_verified</c>.</param>
/// <param name="PasswordHash">
/// An encoded Argon2id hash, or <see langword="null"/> for an account that only ever signs in
/// through an upstream provider.
/// </param>
/// <param name="DisabledAt">When the account was disabled, if it was.</param>
/// <remarks>
/// <para>
/// <b>Roles are opaque here on purpose.</b> This library stores strings and emits them as claims;
/// it never compares one to a constant, and there is no enumeration of allowed values.
/// <c>founder</c>, <c>admin</c>, <c>tier-2</c> are all the same to it. Knowing what a role
/// <i>means</i> is the resource server's job, and a library that shipped a vocabulary would be
/// shipping one customer's org chart to every other customer. <see cref="RoleDefinition"/> made
/// roles a table without relaxing that: the table holds names and does not know what they are for.
/// </para>
/// <para>
/// <b>This was a single <c>Role</c>, and widening it was a change to both halves at once.</b> The
/// note that used to sit here said so: <c>ResourceServerAuthenticator.FromClaims</c> read the role
/// with <c>FindFirst</c>, which takes one value and silently ignores the rest, so a set stored here
/// would have produced tokens whose second and third roles were dropped by the only consumer this
/// repository ships — a rule existing on one surface and not the other. Both halves moved together.
/// Anything else reading the <c>role</c> claim as a single string has to move with them, and the
/// deployment's own configuration counts: a role mapping that matches on one value will silently
/// pick whichever arrives first.
/// </para>
/// </remarks>
public sealed record UserAccount(
    SubjectId Subject,
    string Username,
    string? Email,
    bool EmailVerified,
    string? PasswordHash,
    DateTimeOffset? DisabledAt = null)
{
    /// <summary>
    /// What this account is, in whatever vocabulary the resource server behind this token uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Empty for an account holding none, never null. An account with no roles is a legitimate
    /// thing for a directory to hold — it is what every account looks like the moment before
    /// somebody is given something — and a null here would put a null check on every consumer for
    /// a state that is not exceptional.
    /// </para>
    /// <para>
    /// An init-only property rather than a constructor parameter, so that the construction sites
    /// which never mentioned a role did not have to change when this stopped being one string.
    /// </para>
    /// <para>
    /// <b>Read on the way out, refused on the way in.</b> <see cref="IUserStore.StoreAsync"/> will
    /// not accept an account carrying roles — assignment is
    /// <see cref="IUserStore.SetRolesAsync"/>'s job and nothing else's. Two ways to assign would be
    /// two places the "does this role exist" rule has to be remembered in the same way, and the
    /// relational store gets that rule from a foreign key whether or not anybody remembered. One
    /// way in means the two implementations agree by construction rather than by vigilance.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>
    /// Sign-ins older than this are no longer this account's. <see langword="null"/> until something
    /// invalidates them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What a session cookie could not previously survive being wrong about.</b> The cookie is
    /// self-contained: nothing is stored about it, so nothing could be revoked. Changing a password
    /// left every browser already holding one signed in, and so did ending every application's
    /// access — the two controls a person reaches for when they believe somebody else is in their
    /// account. This is the one fact that lets a stateless cookie be refused.
    /// </para>
    /// <para>
    /// <b>A moment rather than a random stamp, and that is what makes it composable.</b> The rule is
    /// "nothing authenticated before this counts", so one write invalidates every session at once
    /// and needs no list of them. A random value regenerated per event would say only "something
    /// changed" and could not express the same rule about sessions issued since.
    /// </para>
    /// <para>
    /// <b>Compared against the <c>auth_time</c> claim, not the ticket's issue time.</b> The cookie
    /// handler rewrites <c>IssuedUtc</c> every time sliding expiration renews a ticket, so a session
    /// in daily use would climb past any stamp and never be caught. <c>auth_time</c> is written once
    /// at sign-in and carried through renewals as a claim.
    /// </para>
    /// <para>
    /// <b>Null on every account that existed before this column, and null means valid.</b> Sessions
    /// are not invalidated by an upgrade — a deployment that signed everybody out on deploy would be
    /// spending its users' trust to buy nothing, since the sessions it killed were not suspected of
    /// anything.
    /// </para>
    /// </remarks>
    public DateTimeOffset? SessionsValidFrom { get; init; }

    /// <summary>Whether this account may sign in.</summary>
    public bool IsActive => DisabledAt is null;

    /// <summary>
    /// Which directory this account's username is unique within.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An init-only property with a default rather than a constructor parameter, so that adding it
    /// broke nothing: a single-realm deployment — which is every deployment today — never mentions
    /// it, and the column is there when a second directory turns up.
    /// </para>
    /// <para>
    /// <b>The subject is not scoped by it.</b> Subjects are ULIDs, so they are unique across every
    /// realm by construction, and the stores keyed on them — grants, consents, refresh families —
    /// need no realm column. Only lookups by something a person chose do.
    /// </para>
    /// </remarks>
    public RealmId Realm { get; init; } = RealmId.Default;
}

/// <summary>
/// A link from an upstream provider's subject to a local account.
/// </summary>
/// <param name="UpstreamIssuer">The upstream issuer identifier.</param>
/// <param name="UpstreamSubject">The subject as that provider knows it.</param>
/// <param name="Subject">Our own subject, minted by us.</param>
/// <remarks>
/// <para>
/// This table exists from day one with one row per user, even though only one upstream provider
/// ships. It is what keeps the local <c>sub</c> <b>ours</b>: an upstream subject is never passed
/// through into a token.
/// </para>
/// <para>
/// The alternative — emitting the upstream <c>sub</c> directly — looks simpler until a second
/// provider appears, at which point two users at different providers can collide, and every token
/// already issued is under an identifier this server does not control. Adding the table later
/// means a migration across every deployed database; adding it now costs one join.
/// </para>
/// </remarks>
public sealed record ExternalLogin(string UpstreamIssuer, string UpstreamSubject, SubjectId Subject)
{
    /// <summary>
    /// Which directory this link belongs to.
    /// </summary>
    /// <remarks>
    /// An upstream subject is chosen by the upstream provider, so the same Google account presented
    /// to two realms is the same pair of strings and must not resolve to one local account. That is
    /// the same reason the username needs a realm, arriving from the other side.
    /// </remarks>
    public RealmId Realm { get; init; } = RealmId.Default;
}

/// <summary>Stores users.</summary>
/// <remarks>
/// One aggregate, deliberately small. A customer replacing this — pointing the server at an
/// existing directory — does not inherit refresh rotation or consent along with it, and can unit
/// test the result without a web host, because nothing here mentions <c>HttpContext</c>.
/// </remarks>
public interface IUserStore
{
    /// <summary>Find by subject.</summary>
    Task<UserAccount?> FindBySubjectAsync(SubjectId subject, CancellationToken cancellationToken);

    /// <summary>
    /// Find by the name typed at the login page.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implementations must compare case-insensitively on a normalized form and must not let two
    /// accounts differ only by case — otherwise <c>Alice</c> and <c>alice</c> are two users, and
    /// which one a login reaches depends on the store's collation.
    /// </para>
    /// <para>
    /// <b>The realm is part of the key, not a filter applied afterwards.</b> Two realms may hold the
    /// same username, and a lookup in one must never return the other's row — enforced by the unique
    /// index being <c>(realm, normalized_username)</c> rather than by every query remembering.
    /// </para>
    /// </remarks>
    Task<UserAccount?> FindByUsernameAsync(
        RealmId realm, string username, CancellationToken cancellationToken);

    /// <summary>
    /// Find by an address the account has proved it controls.
    /// </summary>
    /// <param name="realm">The realm to look in — part of the key, as it is for a username.</param>
    /// <param name="email">The address as typed.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// The one account in this realm whose address matches <b>and is verified</b>, or
    /// <see langword="null"/> — including when more than one matches.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Verified only, and that is the whole security of it.</b> An unverified address is a string
    /// somebody typed about themselves. Accepting one here would mean anybody who can create an
    /// account can name a colleague's address and sign in under it once that colleague's password
    /// leaks anywhere — the address would authenticate nothing while looking like it did.
    /// <c>AccountRecovery</c> deliberately matches unverified addresses too, because a reset link is
    /// <i>sent to</i> the address and so proves control rather than assuming it; that is the
    /// opposite direction and the reason the two lookups are not one method.
    /// </para>
    /// <para>
    /// <b>More than one match is <see langword="null"/>, not a choice.</b> Nothing makes an address
    /// unique — a username has a unique index and an address has never had one, and adding one would
    /// refuse to migrate any deployment that already holds a duplicate. So ambiguity is answered by
    /// refusing rather than by returning whichever row the store happened to order first, which is a
    /// sign-in whose outcome depends on a collation.
    /// </para>
    /// <para>
    /// <b>Implementations must index this.</b> It is reached from the sign-in form, so a scan is
    /// unbounded work an anonymous caller can ask for — the shipped stores index
    /// <c>(realm, email)</c>. Compare case-insensitively: addresses are handed out on business
    /// cards in whatever case somebody felt like.
    /// </para>
    /// </remarks>
    Task<UserAccount?> FindByVerifiedEmailAsync(
        RealmId realm, string email, CancellationToken cancellationToken);

    /// <summary>Find the local account linked to an upstream subject.</summary>
    Task<UserAccount?> FindByExternalLoginAsync(
        RealmId realm, string upstreamIssuer, string upstreamSubject, CancellationToken cancellationToken);

    /// <summary>Create an account.</summary>
    Task StoreAsync(UserAccount user, CancellationToken cancellationToken);

    /// <summary>Link an upstream identity to a local account.</summary>
    Task LinkExternalLoginAsync(ExternalLogin link, CancellationToken cancellationToken);

    /// <summary>
    /// Every upstream identity attached to one account.
    /// </summary>
    /// <param name="subject">The local account.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The links, in no guaranteed order, or empty.</returns>
    /// <remarks>
    /// <para>
    /// The reverse of <see cref="FindByExternalLoginAsync"/>, and it is a read a person makes about
    /// their own account rather than one a sign-in makes. Without it the self-service page could
    /// offer to connect a provider and could not say whether connecting had already happened —
    /// measured, on a running deployment: a user pressed "Link Google", the round trip
    /// succeeded, the page came back identical, and nothing anywhere could tell them it had
    /// worked.
    /// </para>
    /// <para>
    /// <b>This is not a resolution path and must not become one.</b> It answers "what does this
    /// account hold", keyed on a subject the caller has already authenticated as. The question it
    /// must never be turned into is the reverse — "which account holds this identity" — which is
    /// <see cref="FindByExternalLoginAsync"/>, keyed on <c>(issuer, subject)</c> and on nothing
    /// looser, for the federation-takeover reason written there.
    /// </para>
    /// </remarks>
    Task<IReadOnlyList<ExternalLogin>> ListExternalLoginsAsync(
        SubjectId subject, CancellationToken cancellationToken);

    /// <summary>
    /// Replace which roles an account holds. Returns whether an account with that subject was found.
    /// </summary>
    /// <param name="subject">The account to change.</param>
    /// <param name="roles">
    /// The role ids it should hold, replacing all of them. Empty leaves it holding none, which is
    /// what clearing a role used to mean.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>A targeted setter rather than an update method, because <see cref="StoreAsync"/> is
    /// add-only and that is load-bearing.</b> It refuses an existing subject with "overwriting one
    /// would replace its credentials". A general <c>UpdateAsync(UserAccount)</c> would be exactly
    /// the overwrite that refusal exists to prevent: a caller who read an account, changed the
    /// roles and wrote it back would silently reset the password hash of anyone whose password
    /// changed in between. This method cannot touch a credential because it is not given one.
    /// </para>
    /// <para>
    /// It exists because a role you can only set at creation is not an authorization model, it is
    /// a default. Someone gets promoted; the alternative was writing SQL against a live directory.
    /// </para>
    /// <para>
    /// <b>Replaces rather than adds</b>, and the set it is given is the set it ends with. An
    /// add-one method would need a remove-one to match it, and "grant, then revoke, then read what
    /// is left" is three round trips describing a state the caller already knew.
    /// </para>
    /// <para>
    /// <b>Every id must be one the realm defines</b>, and an implementation refuses the write
    /// otherwise rather than storing an assignment nothing can resolve. That is not the same as
    /// promising no such row can exist: a directory restored from a backup taken before a role was
    /// defined holds one, and <see cref="IRoleStore"/> says what happens then. What this refuses is
    /// creating one on purpose, which is always a typo.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// One of the ids is not defined in the account's realm. The message names it, because the
    /// caller's next move is to fix a typo.
    /// </exception>
    Task<bool> SetRolesAsync(
        SubjectId subject, IReadOnlyList<string> roles, CancellationToken cancellationToken);

    /// <summary>
    /// Refuse every sign-in this account made before <paramref name="at"/>.
    /// </summary>
    /// <param name="subject">Whose sessions.</param>
    /// <param name="at">The moment before which sign-ins stop counting. Normally now.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>Whether an account was found and stamped.</returns>
    /// <remarks>
    /// <para>
    /// <b>Separate from <see cref="SetPasswordHashAsync"/> rather than folded into it.</b> They
    /// coincide on the password routes and nowhere else: ending every application's access stamps
    /// without touching the password, and an administrator setting a hash during a migration should
    /// not sign anybody out. A method that did both would make the common pairing convenient and the
    /// two uncommon ones impossible.
    /// </para>
    /// <para>
    /// <b>Monotonic in practice, and not enforced.</b> Every caller passes the current time, so the
    /// value only moves forward. A store refusing to move it backwards would be enforcing a rule
    /// nothing needs and would turn a clock skew into a failed password change.
    /// </para>
    /// </remarks>
    Task<bool> StampSessionsAsync(
        SubjectId subject, DateTimeOffset at, CancellationToken cancellationToken);

    /// <summary>
    /// Replace an account's stored password hash. <see langword="false"/> when no such account
    /// exists — the same contract as <see cref="SetRolesAsync"/>, and for the same reason: the
    /// caller's next move is to report a typo in a handle, not to have created one.
    /// </summary>
    /// <param name="subject">The account to change.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <param name="passwordHash">
    /// An <b>already-hashed</b> credential, from <see cref="IPasswordHasher.Hash"/>. The name says
    /// hash rather than password so that nobody reads the signature and passes what the person
    /// typed: a store is the last place that should be deciding how a password is hashed, and a
    /// method called <c>SetPasswordAsync</c> is an invitation to hand it one.
    /// </param>
    /// <remarks>
    /// A targeted setter rather than a general update, which is the same decision
    /// <see cref="SetRolesAsync"/> records from the other side. Rewriting the whole account to
    /// change one field is how a password change silently reverts a role, or an email, to whatever
    /// the caller happened to have read a moment earlier.
    /// </remarks>
    Task<bool> SetPasswordHashAsync(
        SubjectId subject, string passwordHash, CancellationToken cancellationToken);

    /// <summary>
    /// Disable an account, or enable one that was disabled. <see langword="false"/> when no such
    /// account exists.
    /// </summary>
    /// <param name="subject">The account.</param>
    /// <param name="disabledAt">
    /// When it was disabled, or <see langword="null"/> to enable it. A time rather than a flag,
    /// because <see cref="UserAccount.DisabledAt"/> is one: "since when" is the question asked of
    /// every disabled account and a boolean cannot answer it.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>The rule this completes was enforced and unsettable.</b> Both sign-in paths — local and
    /// federated — refuse an account whose <see cref="UserAccount.DisabledAt"/> is set, and nothing
    /// in the library, the CLI or any store method could set it. The rule existed; the control did
    /// not, so the only way to disable somebody was to write SQL against a live directory.
    /// </para>
    /// <para>
    /// It does not revoke anything. Access tokens are signed rather than looked up, so an issued one
    /// keeps working until it expires; refresh families are a separate store and a separate
    /// decision. Disabling stops the next sign-in, which is what it says and all it says.
    /// </para>
    /// </remarks>
    Task<bool> SetEnabledAsync(
        SubjectId subject, DateTimeOffset? disabledAt, CancellationToken cancellationToken);

    /// <summary>
    /// Set or clear an account's email, and say whether it is verified.
    /// <see langword="false"/> when no such account exists.
    /// </summary>
    /// <param name="subject">The account.</param>
    /// <param name="email">The address, or <see langword="null"/> to remove it.</param>
    /// <param name="verified">
    /// Whether it has been proven to belong to this person. Both together, never separately.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>One method, because they are one fact.</b> Changing an address while leaving
    /// <c>email_verified</c> true carries a proof about the old address onto the new one, which is
    /// the account-recovery hole in miniature: whoever can change the address inherits the claim
    /// that it was checked. A separate <c>SetEmailVerified</c> would make that the default mistake
    /// rather than an impossible one.
    /// </para>
    /// <para>
    /// <b>And <c>email_verified</c> has never been true.</b> <c>UserAccountClaims</c> puts it in
    /// every token this server has ever issued and nothing anywhere set it, so a resource server
    /// trusting the claim was reading a constant. This is the method that can make it mean
    /// something; whether it does is up to whatever proves the address.
    /// </para>
    /// </remarks>
    Task<bool> SetEmailAsync(
        SubjectId subject, string? email, bool verified, CancellationToken cancellationToken);

    /// <summary>
    /// The accounts in a realm, oldest first, starting after <paramref name="after"/>.
    /// </summary>
    /// <param name="realm">Which directory.</param>
    /// <param name="after">
    /// The last subject of the previous page, or <see langword="null"/> for the first page.
    /// </param>
    /// <param name="limit">How many to return.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <remarks>
    /// <para>
    /// <b>Keyset, never <c>OFFSET</c>.</b> Subjects are ULIDs, so ordering by subject <i>is</i>
    /// ordering by creation, and "everything after this one" is an index seek whatever page it is.
    /// <c>OFFSET</c> makes page 500 read 500 pages, on the one table that grows for the life of the
    /// deployment and is paged through exactly when somebody is trying to find out what happened.
    /// </para>
    /// <para>
    /// It also does not skip or repeat when the set changes underneath it. An account created while
    /// somebody is paging shifts every subsequent <c>OFFSET</c> by one, so a row is silently missed —
    /// which on this table means an account nobody reviewing the directory ever sees.
    /// </para>
    /// <para>
    /// <b>There is no count, deliberately.</b> A total is a second query over the whole table for a
    /// number that is stale before it is rendered, and every caller that wants one is really asking
    /// "is there more", which is answered by asking for one row more than the page.
    /// </para>
    /// </remarks>
    Task<IReadOnlyList<UserAccount>> ListAsync(
        RealmId realm, SubjectId? after, int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Replace everything identifying about an account, keeping the row. Irreversible.
    /// </summary>
    /// <param name="subject">Whose account.</param>
    /// <param name="tombstoneUsername">
    /// What the username becomes. Supplied rather than generated here so that every store agrees on
    /// it — the caller derives it from the subject, which is unique, so the
    /// <c>(realm, normalized_username)</c> index cannot collide however many accounts are
    /// anonymised.
    /// </param>
    /// <param name="now">When it happened, recorded as the disabled time.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>Whether an account with that subject was found.</returns>
    /// <remarks>
    /// <para>
    /// <b>The subject row stays, and that is the whole point.</b> Deleting a user with outstanding
    /// grants leaves dangling references, and an audit trail that empties when the audited party
    /// asks is not an audit trail. What a person is owed is that the account stops naming them —
    /// which this does — not that the record of what was done stops existing.
    /// </para>
    /// <para>
    /// <b>One method because it must be one write.</b> Username, email, credential, role,
    /// enablement and every external link, together. A half-anonymised account is worse than either
    /// end state: an account whose username is a tombstone and whose email still identifies the
    /// person reads as anonymised to anybody looking at it.
    /// </para>
    /// <para>
    /// <b>The role goes with it.</b> An anonymised account carries no entitlement — not because a
    /// tombstone could sign in, it has no credential and no link, but because a role surviving on it
    /// is an entitlement waiting for anything that ever re-enables an account by subject.
    /// </para>
    /// <para>
    /// <b>Sessions are not this method's job.</b> Revoking grants is
    /// <see cref="Stores.IGrantStore.RevokeAllForSubjectAsync"/>, and the operation that anonymises
    /// calls both. Reaching across aggregates from inside a user store would put grant revocation in
    /// every implementation of this interface, including a customer's adapter onto a directory that
    /// has no grants at all.
    /// </para>
    /// </remarks>
    Task<bool> AnonymiseAsync(
        SubjectId subject, string tombstoneUsername, DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>
/// Mints the <c>sub</c> for a new account.
/// </summary>
/// <remarks>
/// <para>
/// A seam, and it lives here rather than in <c>Boltway.Identity</c> because the authorization
/// server needs it: provisioning a local account for a first-time federated sign-in has to mint a
/// subject, and the server does not reference that assembly. The shipped implementation —
/// <c>UlidSubjectIdFactory</c> — stays there with the ULID it produces.
/// </para>
/// <para>
/// A-18 is what this is for. <see cref="SubjectId.FromStorage"/> wraps whatever string it is handed,
/// because it is the rehydration path for rows already in a database; an identifier <i>shape</i> is
/// a promise about what is created, so a creation site is the only place it can be kept.
/// </para>
/// </remarks>
public interface ISubjectIdFactory
{
    /// <summary>Mint a subject identifier for a new account.</summary>
    SubjectId Mint();
}

/// <summary>Hashes and verifies passwords.</summary>
/// <remarks>
/// Argon2id, unlike the minted secrets, which use SHA-256. The difference is what the attacker has
/// to work with: a password is low-entropy and human-chosen, so an offline guessing attack is real
/// and a slow hash is the defence. A 256-bit CSPRNG value has no dictionary, so the same slowness
/// would only cost latency on a path with a ten-second budget.
/// </remarks>
public interface IPasswordHasher
{
    /// <summary>Hash a password for storage. Returns the encoded form, salt included.</summary>
    string Hash(string password);

    /// <summary>
    /// Verify a password against a stored hash, in constant time with respect to the password.
    /// </summary>
    /// <remarks>
    /// Implementations must do the work even when the account does not exist, or the response time
    /// distinguishes "no such user" from "wrong password" — which turns the login form into a
    /// username oracle.
    /// </remarks>
    bool Verify(string password, string encodedHash);
}
