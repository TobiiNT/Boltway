using System.Security.Claims;

namespace Boltway.ResourceServer.Revocation;

/// <summary>
/// Asks whether the authorization behind an already-valid access token still stands.
/// </summary>
/// <remarks>
/// <para>
/// <b>The gap this closes.</b> An access token here is a signed JWT, so
/// <c>AccessTokenValidator</c> answers "is this genuine and unexpired" without asking anybody. That
/// is the property that makes a resource server fast and it is also the reason ending a session
/// does nothing until the token expires: the authorization server records the revocation and no
/// resource server ever reads it. Its own <c>IGrantStore.IsRevokedAsync</c> is documented as the
/// denylist "for a resource server to consult" and had no production caller, because until this
/// seam there was nothing to consult it <i>through</i>.
/// </para>
/// <para>
/// <b>A seam rather than a fixed implementation, because how to ask is a deployment's choice.</b>
/// RFC 7662 introspection is one answer and <see cref="IntrospectionRevocationCheck"/> ships it. A
/// deployment sharing a database with its authorization server would rather read the store; one
/// running at scale would rather consume a revocation feed. None of those change what the
/// middleware does with the answer.
/// </para>
/// <para>
/// <b>Not registered means not checked</b>, which is the behaviour every deployment had before this
/// existed. That is a real cost - revocation lag stays one token lifetime - and it is the right
/// default: a resource server that suddenly required an authorization server to be reachable on
/// every request would be a new outage mode arriving with a package upgrade.
/// </para>
/// </remarks>
public interface IAccessTokenRevocationCheck
{
    /// <summary>
    /// Whether this token's authorization has been revoked.
    /// </summary>
    /// <param name="token">The raw token, as presented. Already validated when this is called.</param>
    /// <param name="principal">Its claims, so an implementation need not re-parse to find <c>gid</c>.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// <see langword="true"/> only when the authorization is <b>known</b> to be revoked.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>The return is deliberately not a tri-state, and the asymmetry is the contract.</b>
    /// "I could not find out" must answer <see langword="false"/> - the same as "still valid" - so
    /// that an implementation which cannot reach its authorization server keeps the resource server
    /// serving. An implementation must not throw to signal that either: an exception out of here
    /// reaches the middleware as a 500 on a request that was perfectly well authenticated.
    /// </para>
    /// <para>
    /// <b>Failing open silently is the thing to avoid, not failing open.</b> The window where
    /// revocation does not take effect is bounded and understood; a window nobody knows they are in
    /// is how a session someone ended stays live for a week. An implementation that cannot answer
    /// is expected to say so in its own logs, loudly enough to alert on.
    /// </para>
    /// </remarks>
    ValueTask<bool> IsRevokedAsync(string token, ClaimsPrincipal principal, CancellationToken cancellationToken);
}
