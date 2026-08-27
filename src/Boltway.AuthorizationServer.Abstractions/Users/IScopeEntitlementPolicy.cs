using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Abstractions.Users;

/// <summary>
/// Narrows a scope request to what this account may ever be granted.
/// </summary>
/// <remarks>
/// <para>
/// <b>The hole this plugs.</b> Scopes are requested by a client and granted by consent, so without a
/// further check any account could obtain <c>users:write</c> by signing in to a client that asks for
/// it and clicking allow. A scope is a statement about what a client may do on somebody's behalf; it
/// has never been a statement about whether that somebody is allowed to do it.
/// </para>
/// <para>
/// <b>It filters, it does not refuse.</b> OAuth already means "granted may be narrower than
/// requested", so a demotion should shrink what a client gets rather than stop it connecting. If
/// filtering leaves the set empty, <i>that</i> is <c>invalid_scope</c> - the client asked for
/// nothing it can have.
/// </para>
/// <para>
/// <b>It runs at <c>/authorize</c> and again at token issuance.</b> Once is not enough: a consent
/// granted while somebody was entitled would otherwise keep minting the scope after they are not,
/// for as long as the refresh family lives.
/// </para>
/// <para>
/// <b>The role stays opaque to the library.</b> The shipped default compares nothing; a deployment
/// implementing this is where a role becomes a decision, which is exactly where
/// <see cref="UserAccount.Roles"/>'s own documentation says vocabulary belongs.
/// </para>
/// </remarks>
public interface IScopeEntitlementPolicy
{
    /// <summary>Narrow <paramref name="requested"/> to what this account may hold.</summary>
    /// <param name="user">Who is signing in.</param>
    /// <param name="requested">What the client asked for, already validated against the server and the client.</param>
    /// <param name="cancellationToken">Cancels the decision.</param>
    ValueTask<ScopeSet> FilterAsync(UserAccount user, ScopeSet requested, CancellationToken cancellationToken);
}

/// <summary>
/// Grants whatever was requested. The default, so this is not a breaking change.
/// </summary>
/// <remarks>
/// Every deployment behaves exactly as it did before the seam existed. A permissive default is the
/// right one here and would be the wrong one for an authorization check that had always existed:
/// this narrows a set that is already bounded by the server's supported scopes and the client's
/// allowed scopes, so the default is "no additional narrowing" rather than "no checking".
/// </remarks>
public sealed class PermissiveScopeEntitlementPolicy : IScopeEntitlementPolicy
{
    /// <inheritdoc />
    public ValueTask<ScopeSet> FilterAsync(
        UserAccount user, ScopeSet requested, CancellationToken cancellationToken) =>
        ValueTask.FromResult(requested);
}
