using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>
/// Applies <see cref="IScopeEntitlementPolicy"/>, in the one place every caller reaches.
/// </summary>
/// <remarks>
/// One implementation, called from the authorization endpoint, from the consent POST that resumes
/// it, and from refresh-token issuance. <c>InteractionRequirements</c> is here for the same reason
/// and its comment records what happened when it was two copies: only one of them was complete, and
/// the incomplete one was a bypass.
/// </remarks>
public static class ScopeEntitlement
{
    /// <summary>
    /// Narrow a request to what this subject may hold.
    /// </summary>
    /// <param name="services">Where the policy and the directory come from.</param>
    /// <param name="subject">Who is signing in.</param>
    /// <param name="requested">What survived the server's and the client's own scope checks.</param>
    /// <param name="cancellationToken">Cancels the lookup.</param>
    /// <returns>
    /// The granted set, which may be narrower and may be empty. An empty result is the caller's to
    /// turn into <c>invalid_scope</c>: the client asked for nothing this account can have.
    /// </returns>
    /// <remarks>
    /// <b>An account the directory no longer has gets nothing.</b> It is reachable — a session
    /// outlives the account it names — and the alternative, passing the request through unfiltered,
    /// would make deleting an account the way to obtain every scope.
    /// </remarks>
    public static async ValueTask<ScopeSet> FilterAsync(
        IServiceProvider services,
        SubjectId subject,
        ScopeSet requested,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(services);

        var policy = services.GetService<IScopeEntitlementPolicy>();

        // No policy at all, or the shipped one that cannot narrow anything. Both mean the same
        // answer, and the type check is what keeps the default free: loading the account in order to
        // hand it to a method whose whole body is `return requested` is a directory read on every
        // authorization and every refresh, bought for nothing.
        if (policy is null or PermissiveScopeEntitlementPolicy)
        {
            return requested;
        }

        var account = await services.GetRequiredService<IUserStore>()
            .FindBySubjectAsync(subject, cancellationToken)
            .ConfigureAwait(false);

        if (account is null)
        {
            return ScopeSet.Empty;
        }

        return await policy.FilterAsync(account, requested, cancellationToken).ConfigureAwait(false);
    }
}
