using Boltway.AuthorizationServer.Abstractions.Consent;

namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// Ask once: a consent the user already gave stands while it covers what is being asked for.
/// </summary>
/// <remarks>
/// <para>
/// <b>The policy <see cref="AlwaysAskConsentPolicy"/> tells a deployment to write down, written
/// down once.</b> Its comparison is the one that remark says is owed: every requested scope and
/// every requested resource must already be in the record, not merely a record existing. A client
/// back for one more scope, or for a resource the user has never seen, is asked, and the page
/// shows the widened request.
/// </para>
/// <para>
/// <b>Not the default, and not a way round the public-client rule.</b> It answers
/// <see cref="ConsentDecision.AlreadyGranted"/>; <c>PublicClientReconsentGuard</c>, which the
/// endpoint wraps around every policy, still turns that into <see cref="ConsentDecision.Required"/>
/// for a public client whose redirect does not prove its identity. So what this changes is the
/// confidential clients, and the public ones an operator registered with
/// <c>RedirectProvesIdentity</c>. Everything describing itself - every CIMD client - is asked as
/// before.
/// </para>
/// <para>
/// <b>What it costs.</b> A repeat authorization for a covered client completes without the user
/// seeing a page, so a session in this browser is enough for that client to obtain a fresh code.
/// That is the purpose, and it is also why the consent list (<c>/me/consents</c>,
/// <c>/account/consents</c>) is where a person ends it: withdrawing deletes the record, and the
/// next authorization asks again. Withdrawal does not touch tokens already issued.
/// </para>
/// <para>
/// Register it <b>before</b> <c>AddBoltwayAuthorizationServer</c>, which adds the default with
/// <c>TryAdd</c>; registered after, it silently does nothing.
/// </para>
/// </remarks>
public sealed class RememberedConsentPolicy : IConsentPolicy
{
    /// <inheritdoc />
    public ValueTask<ConsentDecision> DecideAsync(ConsentContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Existing is not { } existing)
        {
            return ValueTask.FromResult(ConsentDecision.Required);
        }

        // C-24's comparison, made here rather than left to the guard: the guard re-checks it after
        // an AlreadyGranted, but a policy that answers AlreadyGranted for a widened request would be
        // the naive draft AlwaysAskConsentPolicy's remarks describe, corrected only by luck.
        var covered = context.RequestedScope.Except(existing.Scope).Count == 0
            && !context.RequestedResources.Except(existing.Resources, StringComparer.Ordinal).Any();

        return ValueTask.FromResult(covered ? ConsentDecision.AlreadyGranted : ConsentDecision.Required);
    }
}
