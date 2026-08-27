using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.Identity.Subjects;

/// <summary>ULID subjects, minted from a <see cref="UlidFactory"/>.</summary>
/// <remarks>
/// <para>
/// A-18 says the identifiers this server emits are ULIDs, and until this existed that was a sentence
/// in a doc comment: <see cref="SubjectId.FromStorage"/> wraps whatever string it is handed, and
/// nothing anywhere produced one. An identifier shape is a promise about what is <i>created</i>, so
/// a creation site is the only place it can be kept.
/// </para>
/// <para>
/// <b>The scope of the guarantee, exactly.</b> Every subject minted here is a well-formed ULID.
/// <see cref="SubjectId.FromStorage"/> is unchanged and still accepts any string, because it is the
/// rehydration path for rows already in a database - including rows written by an earlier
/// deployment, or by a customer's own directory. So the claim is "what this server mints is a ULID",
/// not "every <see cref="SubjectId"/> in the process is one". <see cref="Ulid.IsWellFormed"/> is
/// public so a caller that needs the stronger statement can check for itself.
/// </para>
/// <para>
/// The <see cref="ISubjectIdFactory"/> interface moved to
/// <c>Boltway.AuthorizationServer.Abstractions.Users</c> when federated sign-in landed, because
/// the authorization server has to mint a subject for a newly provisioned federated account and does
/// not reference this assembly. The implementation stays here, where the ULID lives.
/// </para>
/// </remarks>
public sealed class UlidSubjectIdFactory : ISubjectIdFactory
{
    private readonly UlidFactory _ulids;

    /// <summary>Construct over a clock.</summary>
    public UlidSubjectIdFactory(TimeProvider time) => _ulids = new UlidFactory(time);

    /// <inheritdoc />
    public SubjectId Mint() => SubjectId.FromStorage(_ulids.Mint());
}
