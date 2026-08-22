using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Abstractions.Tokens;

/// <summary>
/// Extra claims to put in an access token, beyond the protocol's own.
///
/// <para>
/// Without one, an access token carries <c>iss</c>, <c>aud</c>, <c>sub</c>, <c>scope</c>,
/// <c>client_id</c>, <c>iat</c>, <c>exp</c> and <c>jti</c> — and nothing that says who the
/// subject is. That is correct as a default and wrong as the only option: a resource server
/// wanting to record <em>who did this</em> gets an opaque identifier, so it either writes the
/// identifier into its audit trail or keeps a second table mapping subjects to people. Both
/// are worse than the authorization server saying it once.
/// </para>
///
/// <para>
/// <strong>What this cannot do is more important than what it can.</strong> The minter
/// refuses to let any claim here overwrite a protocol claim — a mapper that could set
/// <c>sub</c>, <c>aud</c> or <c>scope</c> would be an escalation seam wearing a convenience
/// interface, and the refusal is an exception rather than a silent skip.
/// </para>
///
/// <para>
/// The subject is the only identity passed in. Not the client, and not the resource: a claim
/// that varied by who was asking would make one user's token say different things about them
/// depending on which connector they were signing in to, and an audit trail assembled from
/// those is not one.
/// </para>
/// </summary>
public interface IAccessTokenClaims
{
    /// <summary>
    /// Claims for this subject, or empty. Called once per access token, on the issuing path —
    /// so it is on the latency budget of every sign-in and every refresh.
    /// </summary>
    /// <param name="subject">Who the token is about.</param>
    /// <param name="scope">What was granted, for a mapper that releases claims by scope.</param>
    /// <param name="ct">Cancellation.</param>
    ValueTask<IReadOnlyDictionary<string, object?>> ForAsync(
        SubjectId subject, ScopeSet scope, CancellationToken ct = default);
}
