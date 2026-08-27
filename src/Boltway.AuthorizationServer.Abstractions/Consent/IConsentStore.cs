using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Abstractions.Consent;

/// <summary>What a user has already agreed to for one client.</summary>
/// <param name="Subject">Who agreed.</param>
/// <param name="ClientId">What they agreed to.</param>
/// <param name="Scope">The scopes granted.</param>
/// <param name="Resources">The resources granted - the RFC 8707 grant set.</param>
/// <param name="GrantedAt">When.</param>
public sealed record ConsentRecord(
    SubjectId Subject,
    ClientIdentifier ClientId,
    ScopeSet Scope,
    IReadOnlyList<string> Resources,
    DateTimeOffset GrantedAt);

/// <summary>What to do about consent for this request.</summary>
public enum ConsentDecision
{
    /// <summary>Ask the user.</summary>
    Required = 0,

    /// <summary>They already agreed to at least this much; proceed without asking.</summary>
    AlreadyGranted = 1,

    /// <summary>Policy refuses. <c>access_denied</c>.</summary>
    Denied = 2,
}

/// <summary>The question a consent policy answers.</summary>
/// <param name="Client">Who is asking.</param>
/// <param name="Subject">Who would be agreeing.</param>
/// <param name="RequestedScope">What is being asked for now.</param>
/// <param name="RequestedResources">Which resources.</param>
/// <param name="Existing">What they agreed to before, if anything.</param>
public sealed record ConsentContext(
    ClientRecord Client,
    SubjectId Subject,
    ScopeSet RequestedScope,
    IReadOnlyList<string> RequestedResources,
    ConsentRecord? Existing);

/// <summary>Decides whether to show the consent page.</summary>
/// <remarks>
/// A seam so a customer can add policy - an org that pre-approves internal clients, say. It is
/// <b>not</b> a place to make consent optional for a public client: see
/// <c>PublicClientReconsentGuard</c>, which the server registers around whatever is supplied and
/// which a customer cannot remove.
/// </remarks>
public interface IConsentPolicy
{
    /// <summary>Decide.</summary>
    ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken);
}

/// <summary>Stores consent.</summary>
public interface IConsentStore
{
    /// <summary>What this user has agreed to for this client.</summary>
    Task<ConsentRecord?> FindAsync(SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken);

    /// <summary>
    /// Record consent, <b>widening</b> rather than replacing.
    /// </summary>
    /// <remarks>
    /// C-24: a client that comes back asking for one more scope must end up with the union, not
    /// with only the new scope. Replacing would silently revoke authority the user granted earlier
    /// and never withdrew, and the symptom is a tool that worked yesterday returning 403 today.
    /// </remarks>
    Task<ConsentRecord> GrantAsync(
        SubjectId subject,
        ClientIdentifier clientId,
        ScopeSet scope,
        IReadOnlyList<string> resources,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    /// <summary>
    /// Everything this user has agreed to, for every client. <c>E-37</c>.
    /// </summary>
    /// <param name="subject">Whose consent.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>One record per client, newest grant first. Empty when there is none.</returns>
    /// <remarks>
    /// <b>This is the only way a person can find out what they have approved.</b> Consent is
    /// remembered so a returning client need not ask again, which is a good property and also means
    /// an approval given once is invisible from then on. A withdrawal endpoint without a list is a
    /// door with no handle: <see cref="RevokeAsync"/> needs a client id, and the whole reason to
    /// call it is that you no longer remember which ones there are.
    /// </remarks>
    Task<IReadOnlyList<ConsentRecord>> ListAsync(SubjectId subject, CancellationToken cancellationToken);

    /// <summary>Withdraw consent entirely.</summary>
    Task<bool> RevokeAsync(SubjectId subject, ClientIdentifier clientId, CancellationToken cancellationToken);
}

/// <summary>
/// Forces a public client to ask again, whatever the inner policy said.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8252 §8.6. A public client cannot be authenticated, so consent is the <b>only</b> evidence
/// the user agreed - and anything that can reach the authorization endpoint can claim to be that
/// client. Skipping the prompt on a repeat visit is the classic "we made it faster" regression: it
/// converts a stolen or guessed <c>client_id</c> into a silent authorization.
/// </para>
/// <para>
/// Registered by the server around whatever <see cref="IConsentPolicy"/> the customer supplies, not
/// by the extension method they call. A seam is a place to change policy; it is not a place to
/// reintroduce a defect.
/// </para>
/// </remarks>
public sealed class PublicClientReconsentGuard(IConsentPolicy inner) : IConsentPolicy
{
    private readonly IConsentPolicy _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    /// <inheritdoc />
    public async ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var decision = await _inner.DecideAsync(context, cancellationToken);

        // Denied still means denied - the guard only ever makes the answer stricter, never laxer.
        if (decision is not ConsentDecision.AlreadyGranted)
        {
            return decision;
        }

        if (context.Client.ClientType is ClientType.Public)
        {
            return ConsentDecision.Required;
        }

        // RFC 8252 §8.6 is the rule above. This one is C-24, and it is enforced here rather than
        // trusted to the policy because the policy is a customer's code and the obvious first draft
        // gets it wrong.
        //
        // `AlreadyGranted` is documented as "they already agreed to AT LEAST this much", so the
        // comparison belongs to whoever answers - and the natural implementation, `context.Existing
        // is not null ? AlreadyGranted : Required`, does not make it. A review executed exactly that
        // draft against a record covering `mcp:tools` on one resource, requested
        // `mcp:tools offline_access openid` on a DIFFERENT resource, and got a code with no consent
        // page and then an access token whose `aud` was a resource the user had never seen. Under
        // `prompt=none` it returned a code where X-13 requires `consent_required`.
        //
        // So the server checks the subset itself. A policy that answers `AlreadyGranted` for a
        // widened request now gets `Required` and the user is shown the widened scopes - which is
        // the answer they would have got from a correct policy, and the failure mode of a wrong one
        // is now an extra prompt rather than a silent escalation that leaves no trace in the record.
        //
        // Only when there IS a record to compare against. A policy answering `AlreadyGranted` with
        // `Existing` null is asserting consent this server did not record - an organisation that
        // pre-approves its own first-party clients, or one whose consent lives in an external
        // system - and refusing that would break a legitimate design while catching nothing: the
        // naive draft this guard exists to correct returns `Required` in exactly that case. The
        // measured escalation needs a record that covers less than the request, so that is the
        // condition checked.
        if (context.Existing is not { } existing)
        {
            return decision;
        }

        var widenedScope = context.RequestedScope.Except(existing.Scope);
        var newResources = context.RequestedResources.Except(existing.Resources, StringComparer.Ordinal);

        return widenedScope.Count > 0 || newResources.Any()
            ? ConsentDecision.Required
            : decision;
    }
}
