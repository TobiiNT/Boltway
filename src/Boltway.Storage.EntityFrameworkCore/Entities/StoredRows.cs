using Boltway.AuthorizationServer.Abstractions.Grants;

namespace Boltway.Storage.EntityFrameworkCore.Entities;

/// <summary>
/// The rows, deliberately separate from the records in Abstractions.
/// </summary>
/// <remarks>
/// <para>
/// Mapping <see cref="AuthorizationCodeRecord"/> and friends directly would mean a value converter
/// for every one of <c>Sha256Hash</c>, <c>ScopeSet</c>, <c>ClientIdentifier</c>, <c>SubjectId</c> and
/// <c>IReadOnlyList&lt;string&gt;</c>, and two of those do not fit one column:
/// <c>ClientIdentifier</c> carries a <c>Kind</c> that cannot be recovered from its value, and a
/// resource list is not a scalar. Separate rows cost a mapping function per aggregate and buy
/// columns whose types are exactly what the query needs - <c>INTEGER</c> ticks that compare
/// numerically, <c>BLOB</c> digests that compare byte for byte and are subject to no collation.
/// </para>
/// <para>
/// <b>Every timestamp is UTC ticks in an integer column.</b> Storing a <c>DateTimeOffset</c> in
/// SQLite gives a TEXT column carrying an offset, and <c>WHERE expires_at &lt;= @now</c> against
/// TEXT is a string comparison that orders <c>+02:00</c> against <c>Z</c> by spelling rather than by
/// instant. Ticks round-trip exactly and order by instant on both providers. The cost is that the
/// original offset is not kept; nothing in the store contract reads it, and
/// <see cref="DateTimeOffset"/> equality compares instants, so a value written at +02:00 and read
/// back at +00:00 is equal to the one that was written.
/// </para>
/// <para>
/// <b>No column holds a plaintext secret.</b> Codes and refresh tokens are keyed on their SHA-256
/// digest, which is the only form <see cref="Boltway.OAuth.Primitives.Secrets.Sha256Hash"/>
/// can produce.
/// </para>
/// </remarks>
internal sealed class AuthorizationCodeRow
{
    /// <summary>SHA-256 of the code. Primary key.</summary>
    public required byte[] CodeHash { get; set; }

    /// <summary>The grant this code produces tokens for.</summary>
    public required string GrantId { get; set; }

    /// <summary>The client the code was issued to.</summary>
    public required string ClientId { get; set; }

    /// <summary>How that client got its identifier. Stored, never re-derived from the value.</summary>
    public required int ClientIdKind { get; set; }

    /// <summary>The redirect URI the authorization request carried.</summary>
    public required string RedirectUriUsed { get; set; }

    /// <summary>The PKCE challenge, or null.</summary>
    public string? CodeChallenge { get; set; }

    /// <summary>The PKCE method.</summary>
    public required int ChallengeMethod { get; set; }

    /// <summary>Whether the authorization request carried a challenge at all.</summary>
    public required bool PkceWasRequested { get; set; }

    /// <summary>Scopes, space-separated as they go on the wire.</summary>
    public required string Scope { get; set; }

    /// <summary>The RFC 8707 grant set, newline-separated.</summary>
    public required string Resources { get; set; }

    /// <summary>The OIDC nonce, or null.</summary>
    public string? Nonce { get; set; }

    /// <summary>When the user authenticated, in UTC ticks.</summary>
    public required long AuthTime { get; set; }

    /// <summary>When the code was issued, in UTC ticks.</summary>
    public required long IssuedAt { get; set; }

    /// <summary>When the code expires, in UTC ticks.</summary>
    public required long ExpiresAt { get; set; }

    /// <summary>When the code was redeemed, in UTC ticks, or null.</summary>
    public long? RedeemedAt { get; set; }
}

/// <summary>One issued refresh token.</summary>
internal sealed class RefreshTokenRow
{
    /// <summary>SHA-256 of the token. Primary key.</summary>
    public required byte[] TokenHash { get; set; }

    /// <summary>The grant this token refreshes.</summary>
    public required string GrantId { get; set; }

    /// <summary>Every token descended from one authorization code shares this.</summary>
    public required string FamilyId { get; set; }

    /// <summary>How many rotations deep this token is.</summary>
    public required int Generation { get; set; }

    /// <summary>The token this one replaced.</summary>
    public byte[]? PredecessorHash { get; set; }

    /// <summary>The token that replaced this one, set when it is consumed.</summary>
    public byte[]? SuccessorHash { get; set; }

    /// <summary>When it was issued, in UTC ticks.</summary>
    public required long IssuedAt { get; set; }

    /// <summary>When it expires, in UTC ticks.</summary>
    public required long ExpiresAt { get; set; }

    /// <summary>When it was rotated away, in UTC ticks, or null.</summary>
    public long? ConsumedAt { get; set; }
}

/// <summary>
/// A revoked refresh-token family. <b>A row exists only once the family has been revoked.</b>
/// </summary>
/// <remarks>
/// <para>
/// The contract never mentions this table, because <c>RefreshTokenRecord</c> has no revoked field
/// and <c>RevokeFamilyAsync</c> writes nothing to the token rows - it counts them. So a relational
/// store has to choose a shape, and the two candidates are not equivalent.
/// </para>
/// <para>
/// <b>Chosen:</b> revocation is a property of the family, held in one row. <b>Rejected:</b> a
/// <c>revoked_at</c> stamped on every token row by an <c>UPDATE … WHERE family_id = @f</c>. The two
/// differ in a case a caller can reach: a token stored into an already-revoked family through
/// <c>StoreAsync</c> is live under the per-row shape and dead under this one, because the per-row
/// UPDATE ran before that row existed. The in-memory store keeps a separate
/// <c>_revokedFamilies</c> dictionary and so has the shape chosen here; matching it is what keeps
/// two implementations answering the same thing on the same input. The contract did not distinguish
/// them until <c>A_token_stored_into_a_revoked_family_is_revoked_too</c> was added, which is where
/// that choice is now pinned rather than left to whichever shape an implementer reaches for.
/// </para>
/// <para>
/// It also decides what <c>RevokeFamilyAsync</c>'s return value counts. "Rows this call
/// transitioned" is, under this shape, the number of <i>unconsumed</i> tokens in the family at the
/// moment the family row was inserted - and zero for every later call, because the insert is what
/// makes the call the one that did it.
/// </para>
/// </remarks>
internal sealed class RefreshTokenFamilyRow
{
    /// <summary>The family. Primary key.</summary>
    public required string FamilyId { get; set; }

    /// <summary>When it was revoked, in UTC ticks.</summary>
    public required long RevokedAt { get; set; }
}

/// <summary>A user's standing authorization for one client.</summary>
internal sealed class GrantRow
{
    /// <summary>Identifies this grant in tokens and in the denylist. Primary key.</summary>
    public required string GrantId { get; set; }

    /// <summary>Who authorized.</summary>
    public required string Subject { get; set; }

    /// <summary>Who was authorized.</summary>
    public required string ClientId { get; set; }

    /// <summary>How that client got its identifier.</summary>
    public required int ClientIdKind { get; set; }

    /// <summary>What was authorized, space-separated.</summary>
    public required string Scope { get; set; }

    /// <summary>The RFC 8707 grant set, newline-separated.</summary>
    public required string Resources { get; set; }

    /// <summary>When consent was given, in UTC ticks.</summary>
    public required long CreatedAt { get; set; }

    /// <summary>When the user actually authenticated, in UTC ticks.</summary>
    public required long AuthTime { get; set; }

    /// <summary>When it was withdrawn, in UTC ticks, or null.</summary>
    public long? RevokedAt { get; set; }

    /// <summary>
    /// The browser the consent screen was clicked in, or null.
    /// </summary>
    /// <remarks>
    /// Nullable and never backfilled. Every grant created before this column existed has none, and
    /// nobody can say afterwards what device approved them - the same reason the connector's
    /// <c>actor</c> ledger column was left blank on its older rows.
    /// </remarks>
    public string? UserAgent { get; set; }
}

/// <summary>What a user has already agreed to for one client.</summary>
internal sealed class ConsentRow
{
    /// <summary>Who agreed. Half of the primary key.</summary>
    public required string Subject { get; set; }

    /// <summary>What they agreed to. The other half.</summary>
    public required string ClientId { get; set; }

    /// <summary>How that client got its identifier.</summary>
    public required int ClientIdKind { get; set; }

    /// <summary>The scopes granted, space-separated.</summary>
    public required string Scope { get; set; }

    /// <summary>The resources granted, newline-separated.</summary>
    public required string Resources { get; set; }

    /// <summary>When, in UTC ticks.</summary>
    public required long GrantedAt { get; set; }
}

/// <summary>A local account.</summary>
internal sealed class UserRow
{
    /// <summary>The <c>sub</c> this server emits. Primary key.</summary>
    public required string Subject { get; set; }

    /// <summary>
    /// Which directory this account's username is unique within.
    /// </summary>
    /// <remarks>
    /// Not part of the primary key, because the subject is a ULID and already unique everywhere. It
    /// is half of the <i>username</i> index, which is the only key here a person chose.
    /// </remarks>
    public required string Realm { get; set; }

    /// <summary>What they type at the login page, in the case they registered with.</summary>
    public required string Username { get; set; }

    /// <summary>
    /// The uppercase invariant form of <see cref="Username"/>, uniquely indexed.
    /// </summary>
    /// <remarks>
    /// A second column rather than a case-insensitive collation on the first. The interface asks for
    /// two different things - a lookup that ignores case, and a uniqueness rule that ignores case -
    /// and a collation delivers both only if the provider's collation happens to fold the same way
    /// the C# comparison does. Folding in C# and comparing the folded value ordinally makes the
    /// answer the same on every provider, which is the point of a shared contract suite.
    /// </remarks>
    public required string NormalizedUsername { get; set; }

    /// <summary>Their email, or null.</summary>
    public string? Email { get; set; }

    /// <summary>
    /// The uppercase invariant form of <see cref="Email"/>, indexed, or null when there is none.
    /// </summary>
    /// <remarks>
    /// A stored fold rather than a collation, for the reason <see cref="NormalizedUsername"/> gives.
    /// <b>Not unique</b>, and that is a deliberate difference from the username index: nothing has
    /// ever stopped two accounts carrying one address, so a unique index would refuse to migrate
    /// any deployment that already holds a duplicate. <c>FindByVerifiedEmailAsync</c> answers null
    /// when it finds two, which makes the ambiguity safe without making it impossible.
    /// </remarks>
    public string? NormalizedEmail { get; set; }

    /// <summary>Whether it was verified.</summary>
    public required bool EmailVerified { get; set; }

    /// <summary>An encoded Argon2id hash, or null for a federation-only account.</summary>
    public string? PasswordHash { get; set; }

    /// <summary>Sign-ins older than this are refused. Null until something invalidates them.</summary>
    /// <remarks>
    /// <para>
    /// Ticks, like <see cref="DisabledAt"/> above and every other moment in this file. A provider
    /// that rounds a <c>DateTimeOffset</c> to the millisecond would make a stamp and a sign-in in
    /// the same millisecond compare equal, and the comparison this feeds is a strict one.
    /// </para>
    /// <para>
    /// Nullable rather than defaulted to the epoch, because null and "the beginning of time" answer
    /// differently on upgrade: null leaves every existing session valid, which is the intent, while a
    /// default would have to be a moment and every moment signs somebody out.
    /// </para>
    /// </remarks>
    public long? SessionsValidFrom { get; set; }

    /// <summary>When the account was disabled, in UTC ticks, or null.</summary>
    public long? DisabledAt { get; set; }

    /// <summary>
    /// The roles this account holds, as rows in the join table.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This was a plain <c>role</c> column, and the comment on it said there was no roles table
    /// because "a lookup table would be a place to enforce a vocabulary, and enforcing one here
    /// means every customer inherits the first customer's org chart". The table exists now and that
    /// argument still holds - it is answered by the table holding no vocabulary rather than by
    /// there being no table. <c>roles</c> stores whatever ids and permission strings a deployment
    /// writes and this library compares none of them to a constant.
    /// </para>
    /// <para>
    /// A navigation rather than a second query, so that a read which returns an account returns what
    /// it holds. The single-column version could not be forgotten; a join that some read paths do
    /// and others do not is an account that has roles when it is looked up one way and not another.
    /// </para>
    /// </remarks>
    public ICollection<UserRoleRow> Roles { get; set; } = [];
}

/// <summary>A link from an upstream provider's subject to a local account.</summary>
internal sealed class ExternalLoginRow
{
    /// <summary>Which directory this link belongs to. Part of the primary key.</summary>
    /// <remarks>
    /// The same upstream account presented to two realms is the same pair of strings, and must not
    /// resolve to one local account.
    /// </remarks>
    public required string Realm { get; set; }

    /// <summary>The upstream issuer. Part of the primary key.</summary>
    public required string UpstreamIssuer { get; set; }

    /// <summary>The subject as that provider knows it. The last part.</summary>
    public required string UpstreamSubject { get; set; }

    /// <summary>Our own subject.</summary>
    public required string Subject { get; set; }
}

/// <summary>One administrative action, as stored.</summary>
/// <remarks>
/// A surrogate key, unlike every other row here. The natural key would be (time, actor, target) and
/// two actions in the same tick against the same account are a real sequence rather than a
/// collision - an append-only table is the one place a duplicate must be storable.
/// </remarks>
internal sealed class AdminAuditRow
{
    /// <summary>Insertion order, which is also the primary key.</summary>
    public long Id { get; set; }

    /// <summary>When, as ticks.</summary>
    public required long At { get; set; }

    /// <summary>What sort of caller: <c>cli</c> or <c>client</c>.</summary>
    public required string ActorKind { get; set; }

    /// <summary>Which account acted, or null for a command line.</summary>
    public string? ActorSubject { get; set; }

    /// <summary>Which client it acted through.</summary>
    public string? ActorClient { get; set; }

    /// <summary>What was done.</summary>
    public required string Action { get; set; }

    /// <summary>Which directory.</summary>
    public required string TargetRealm { get; set; }

    /// <summary>Whose account, when the handle resolved to one.</summary>
    public string? TargetSubject { get; set; }

    /// <summary>The handle as typed, whether or not it resolved.</summary>
    public string? TargetHandle { get; set; }

    /// <summary>Whether it landed.</summary>
    public required string Outcome { get; set; }

    /// <summary>What changed, in one short string.</summary>
    public string? Detail { get; set; }

    /// <summary>The id a refusal already carries.</summary>
    public string? CorrelationId { get; set; }
}

/// <summary>A one-time link, as a row. S-47.</summary>
internal sealed class UserTokenRow
{
    /// <summary>SHA-256 of the value in the link, and the primary key. The plaintext is never here.</summary>
    public required byte[] TokenHash { get; set; }

    /// <summary>Whose account.</summary>
    public required string Subject { get; set; }

    /// <summary>Which flow: 0 password reset, 1 email verification.</summary>
    public required int Purpose { get; set; }

    /// <summary>When it stops working, as ticks.</summary>
    public required long ExpiresAt { get; set; }

    /// <summary>What the redemption is about - the address, for a verification.</summary>
    public string? Detail { get; set; }
}

/// <summary>A role a deployment defined.</summary>
/// <remarks>
/// Realm-scoped, because the id is a key a person chose - the same reason a username is. Two
/// directories holding an <c>editor</c> that means different things is what having realms is for.
/// </remarks>
internal sealed class RoleRow
{
    /// <summary>Which directory defines it. Half of the primary key.</summary>
    public required string Realm { get; set; }

    /// <summary>What a token carries. The other half, matched ordinally.</summary>
    /// <remarks>
    /// No normalized twin, unlike a username. A role id is not typed at a login page by somebody
    /// who might shift-lock it - it is written once into configuration and compared to a claim, and
    /// every consumer compares ordinally. Folding here would make this store answer a question no
    /// consumer asks, and make <c>Founder</c> and <c>founder</c> one role on this side while they stay two on
    /// the other.
    /// </remarks>
    public required string Id { get; set; }

    /// <summary>What a person reads. The only editable half.</summary>
    public required string Name { get; set; }

    /// <summary>What the role stands for, space-separated, in the resource server's vocabulary.</summary>
    /// <remarks>
    /// One column rather than a third table. A permission has no attributes of its own here - this
    /// library does not know what one is - so a table would hold nothing but the string, and the
    /// join would exist to express a set that a space-separated column already expresses. The same
    /// shape <c>GrantRow.Scope</c> uses, for the same reason, and <c>RoleDefinition</c> refuses a
    /// permission carrying whitespace so the round trip cannot lose one.
    /// </remarks>
    public required string Permissions { get; set; }
}

/// <summary>An account holding a role.</summary>
internal sealed class UserRoleRow
{
    /// <summary>Whose account. Half of the primary key.</summary>
    public required string Subject { get; set; }

    /// <summary>Which realm the role is defined in - the account's own.</summary>
    /// <remarks>
    /// Carried here so the foreign key can be the whole of the role's key. Without it this row
    /// could name an <c>editor</c> without saying whose, and the database could not tell that the
    /// role exists.
    /// </remarks>
    public required string Realm { get; set; }

    /// <summary>Which role. The other half of the primary key.</summary>
    public required string RoleId { get; set; }

    /// <summary>The account, so a read can carry its roles in one query.</summary>
    public UserRow? User { get; set; }
}

/// <summary>
/// A client this deployment created, rather than one it was configured with or one that named
/// itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>A-08 is why this table is small and why nothing writes to it on the CIMD path.</b> A hundred
/// sequential CIMD connections must leave it unchanged; caching a resolved metadata document here
/// is the obvious move and it breaks the zero-registration property CIMD exists for. Rows arrive from
/// administration only.
/// </para>
/// <para>
/// The columns are the subset of <c>ClientRecord</c> that a stored client needs. Response types are
/// absent because only <c>code</c> is ever honoured, and grant types are absent because they are
/// derived from <see cref="Owner"/> exactly as they are for a configured client - a stored list
/// would be a second place for the two sets to overlap.
/// </para>
/// </remarks>
internal sealed class ClientRow
{
    /// <summary>What it presents as. Primary key.</summary>
    public required string ClientId { get; set; }

    /// <summary>How the identifier was obtained. Always pre-registered for a row here.</summary>
    /// <remarks>
    /// Stored rather than assumed, for the same reason the other three tables store it: it is what
    /// an audit entry and a consent page read, and a value derived from "we found it here" cannot
    /// disagree with the truth. A column that only ever holds one value today is also the column
    /// that stops being wrong the day dynamic registration writes here.
    /// </remarks>
    public required int ClientIdKind { get; set; }

    /// <summary>What a person reads. Self-asserted for a CIMD client; administrative here.</summary>
    public string? Name { get; set; }

    /// <summary>SHA-256 of the secret, or null for a public client. The plaintext is never held.</summary>
    public byte[]? SecretHash { get; set; }

    /// <summary>The account this client acts as, or null for one that acts for whoever signs in.</summary>
    public string? Owner { get; set; }

    /// <summary>Space separated. Exactly what a service account is issued.</summary>
    public string Scopes { get; set; } = string.Empty;

    /// <summary>Space separated, matched exactly, never by prefix. Empty for a service account.</summary>
    public string RedirectUris { get; set; } = string.Empty;

    /// <summary>When it stopped being allowed to authorize, in UTC ticks, or null.</summary>
    /// <remarks>
    /// A timestamp rather than a flag, the same as <c>UserRow.DisabledAt</c>, because "when" is the
    /// question asked immediately after "is it". <b>Not revocation</b>: it stops new tokens being
    /// issued and the ones already out live until they expire.
    ///
    /// Ticks rather than a DateTimeOffset, matching every other instant in this schema. PostgreSQL
    /// would otherwise get a <c>timestamptz</c>, which holds microseconds where a .NET tick is 100ns -
    /// measured lossy on this server, and <c>PostgreSqlSchemaTests</c> fails the whole schema if any
    /// column is a timestamp of any kind.
    /// </remarks>
    public long? DisabledAt { get; set; }

    /// <summary>When it was created, in UTC ticks.</summary>
    public required long CreatedAt { get; set; }
}

/// <summary>
/// One client assertion this server has already accepted. RFC 7523 §3.
/// </summary>
/// <remarks>
/// The client and the identifier together are the key, because a <c>jti</c> is unique per issuer
/// rather than globally and the issuer of a client assertion is the client. Keyed on <c>jti</c>
/// alone, one client setting its identifier to <c>"1"</c> would lock every other client out of that
/// value for as long as the row lived.
/// </remarks>
internal sealed class ClientAssertionRow
{
    /// <summary>The client the assertion authenticated - its <c>iss</c> and <c>sub</c>.</summary>
    public required string ClientId { get; set; }

    /// <summary>The assertion's <c>jti</c>, verbatim.</summary>
    public required string JwtId { get; set; }

    /// <summary>The assertion's <c>exp</c>, as ticks. Past it the validator refuses without asking here.</summary>
    public required long ExpiresAt { get; set; }
}
