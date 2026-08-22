using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Abstractions.Administration;

/// <summary>What an administrative action did, or failed to do.</summary>
public enum AdminAuditOutcome
{
    /// <summary>The change landed.</summary>
    Succeeded,

    /// <summary>It did not, and the entry says an attempt was made anyway.</summary>
    /// <remarks>
    /// Recorded rather than skipped. A refused attempt is the half of an audit trail that shows
    /// somebody trying, and a log that only contains successes cannot distinguish "nobody tried" from
    /// "everybody was stopped".
    /// </remarks>
    Refused,
}

/// <summary>
/// One administrative action, as it happened.
/// </summary>
/// <param name="At">When.</param>
/// <param name="ActorKind">
/// What sort of caller. <c>cli</c> for a command line, <c>client</c> for an authenticated one.
/// </param>
/// <param name="ActorSubject">
/// Which account acted, or <see langword="null"/> for a command line.
/// </param>
/// <param name="ActorClient">Which client it acted through, when one was involved.</param>
/// <param name="Action">What was done, as a stable identifier — <c>user.password.reset</c>.</param>
/// <param name="TargetRealm">Which directory it happened in.</param>
/// <param name="TargetSubject">
/// Whose account, when one was resolved. <see langword="null"/> when the handle matched nobody,
/// which is itself worth recording.
/// </param>
/// <param name="TargetHandle">The handle the caller typed, whether or not it resolved.</param>
/// <param name="Outcome">Whether it landed.</param>
/// <param name="CorrelationId">
/// The id a refusal already carries, so a refused administrative action and its log line join up.
/// </param>
/// <remarks>
/// <b>No before-and-after values.</b> The entry says a password was reset, not what it was; it says
/// a role changed, and the new role is the one thing a reader needs to reconstruct the state. An
/// audit table that accumulated old values would become a second copy of the directory, with the
/// property that nothing ever deletes from it.
/// </remarks>
public sealed record AdminAuditEntry(
    DateTimeOffset At,
    string ActorKind,
    SubjectId? ActorSubject,
    string? ActorClient,
    string Action,
    RealmId TargetRealm,
    SubjectId? TargetSubject,
    string? TargetHandle,
    AdminAuditOutcome Outcome,
    string? CorrelationId)
{
    /// <summary>
    /// What changed, in one short string, when that is worth having.
    /// </summary>
    /// <remarks>
    /// The new role, or <c>disabled</c>. Never a credential and never an old value — see the type's
    /// own remarks. Optional because most actions are fully described by <see cref="Action"/>.
    /// </remarks>
    public string? Detail { get; init; }
}

/// <summary>Which entries to read back.</summary>
/// <param name="Realm">Restrict to one directory, or <see langword="null"/> for all.</param>
/// <param name="TargetSubject">Restrict to one account.</param>
/// <param name="Since">Only entries at or after this moment.</param>
/// <param name="Limit">How many, most recent first.</param>
public sealed record AuditQuery(
    RealmId? Realm = null,
    SubjectId? TargetSubject = null,
    DateTimeOffset? Since = null,
    int Limit = 100);

/// <summary>
/// Records what administrators did.
/// </summary>
/// <remarks>
/// <para>
/// <b>Append-only, through every surface.</b> No update, no delete, not through an API and not
/// through the CLI. An audit log an administrator can edit is a log that proves nothing about
/// administrators, which is the only thing it was for.
/// </para>
/// <para>
/// <b>The entry belongs in the same transaction as the change it describes.</b> A change that lands
/// without its line is a half-state whose surviving half is the invisible one. That guarantee is
/// <b>not delivered by the current implementation</b> — see the remarks on
/// <see cref="RecordAsync"/>, which say exactly what is missing and why it was not faked.
/// </para>
/// </remarks>
public interface IAdminAuditStore
{
    /// <summary>
    /// Append one entry.
    /// </summary>
    /// <param name="entry">What happened.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// <para>
    /// <b>Not yet in the same transaction as the change, and that is a measured gap rather than an
    /// oversight.</b> Every relational store here creates its own <c>DbContext</c> from a factory
    /// per call, so two stores cannot presently share one transaction — closing it means giving the
    /// storage layer an ambient context, which changes the lifetime and thread-safety of every write
    /// in a directory holding live credentials. Doing that quickly, to add a log line, is the wrong
    /// trade.
    /// </para>
    /// <para>
    /// So today the audit entry is written immediately after the change succeeds, and the window is
    /// real: a process that dies between the two leaves a change with no line. It is written down
    /// here rather than left for somebody to assume closed, which is the whole of what this
    /// repository keeps learning.
    /// </para>
    /// </remarks>
    Task RecordAsync(AdminAuditEntry entry, CancellationToken cancellationToken);

    /// <summary>Read entries back, most recent first.</summary>
    /// <param name="query">Which ones.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<IReadOnlyList<AdminAuditEntry>> ReadAsync(AuditQuery query, CancellationToken cancellationToken);
}
