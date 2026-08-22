using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Abstractions.Users;

/// <summary>Who is signed in, and when they proved it.</summary>
/// <param name="Subject">The <c>sub</c> every token for this session will carry.</param>
/// <param name="AuthenticatedAt">
/// When the user actually authenticated — <b>not</b> when this request arrived.
/// </param>
/// <remarks>
/// The distinction in <paramref name="AuthenticatedAt"/> is what makes <c>max_age</c> mean
/// anything. OIDC Core §3.1.2.1 requires the OP to re-authenticate when the elapsed time since the
/// user last authenticated exceeds <c>max_age</c>; stamping "now" here would make every session
/// permanently fresh and the parameter permanently satisfied, which is a silent failure of a
/// security control the relying party believes it is exercising.
/// </remarks>
public readonly record struct AuthenticatedUser(SubjectId Subject, DateTimeOffset AuthenticatedAt);

/// <summary>
/// Where the authorization endpoint learns whether a user is signed in.
/// </summary>
/// <remarks>
/// <para>
/// A seam, because how a customer authenticates their users is theirs: a cookie this server set, a
/// cookie their existing application set, an upstream SSO. The shipped implementation reads the
/// ASP.NET Core authentication result, which covers all three when the host is configured for them.
/// </para>
/// <para>
/// Deliberately <b>read-only</b>. Signing a user in is the login endpoint's job, and a seam that
/// could also authenticate would let an <see cref="IUserSession"/> implementation establish a
/// session <i>during</i> an authorization request — which is how "the connector logged me in as
/// someone else" happens.
/// </para>
/// </remarks>
public interface IUserSession
{
    /// <summary>The signed-in user, or <see langword="null"/>.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <remarks>
    /// Takes no request parameter, and that is what keeps this assembly free of an ASP.NET Core
    /// dependency: an implementation is registered per request and reaches its own context however
    /// it likes. The alternative — passing the request in as <see cref="object"/> for the
    /// implementation to downcast — would move the dependency from the project file into every
    /// implementation, where the compiler stops checking it.
    /// </remarks>
    ValueTask<AuthenticatedUser?> GetAsync(CancellationToken cancellationToken);
}
