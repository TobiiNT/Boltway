using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Authorize;

/// <summary>
/// The state an authorize request accumulates as it moves through the pipeline.
/// </summary>
/// <remarks>
/// Every field starts unset and is filled by exactly one stage. The ordering guarantee does not
/// come from this type - it comes from <see cref="ValidatedRedirect"/> being unconstructible before
/// stage 3 - but keeping the accumulation explicit means a stage reading something a later stage
/// sets is a null, not a silently wrong value.
/// </remarks>
public sealed class AuthorizeContext
{
    /// <summary>The parameters, as read.</summary>
    public required OAuthParameters Parameters { get; init; }

    /// <summary>A correlation id, minted before anything can fail.</summary>
    public required string CorrelationId { get; init; }

    /// <summary>The configured issuer.</summary>
    public required IssuerString Issuer { get; init; }

    /// <summary>Now, captured once so every timestamp in one request agrees.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>The client's <c>state</c>, if it sent one.</summary>
    public string? State { get; set; }

    /// <summary>The resolved client. Set by stage 2.</summary>
    public Abstractions.Clients.ClientRecord? Client { get; set; }

    /// <summary>
    /// Proof the redirect URI validated. Set by stage 3, and only stage 3.
    /// </summary>
    /// <remarks>
    /// Carried for the stages after validation that need to render a response, <b>not</b> as the
    /// route by which the validation stages reach it - those take it as a parameter, so that a
    /// stage hoisted above stage 3 fails to compile rather than dereferencing a null here.
    /// </remarks>
    public ValidatedRedirect? Redirect { get; set; }

    /// <summary>The PKCE challenge. Set by stage 5.</summary>
    public CodeChallenge? Challenge { get; set; }

    /// <summary>The requested scopes. Set by stage 6.</summary>
    public ScopeSet Scope { get; set; } = ScopeSet.Empty;

    /// <summary>The resolved resources. Set by stage 7.</summary>
    public IReadOnlyList<ResourceIdentifier> Resources { get; set; } = [];

    /// <summary>The OIDC nonce, if the client sent one. Set by stage 8.</summary>
    public string? Nonce { get; set; }

    /// <summary>Whether the request asked for OIDC at all - the <c>openid</c> scope.</summary>
    public bool IsOidc { get; set; }

    /// <summary>
    /// The <c>prompt</c> values the client sent, if any. Set by stage 8.
    /// </summary>
    /// <remarks>
    /// Carried rather than validated-and-dropped. Stage 9 needs <c>login</c> to force
    /// re-authentication and stage 10 needs <c>consent</c> to force re-consent, and if the value
    /// did not survive stage 8 those stages would have to re-read and re-validate
    /// <see cref="Parameters"/> - which is exactly the "a stage reading something a later stage
    /// sets" that this type exists to prevent.
    /// </remarks>
    public IReadOnlyList<string> Prompt { get; set; } = [];

    /// <summary>
    /// The <c>max_age</c> the client sent, if any. Set by stage 8.
    /// </summary>
    /// <remarks>
    /// OIDC Core §3.1.2.1: when this is present the OP must re-authenticate if the elapsed time
    /// since <see cref="AuthTime"/> exceeds it, and the ID token MUST then carry an
    /// <c>auth_time</c> claim.
    /// </remarks>
    public TimeSpan? MaxAge { get; set; }

    /// <summary>
    /// The browser this request arrived in, capped, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read at the edge with <c>ApprovingDevice.Read</c> and carried, rather than reached for
    /// deeper in: this type is transport-neutral on purpose, and a stage that could see an
    /// <c>HttpRequest</c> is a stage that could start depending on one.
    /// </para>
    /// <para>
    /// It ends up on the grant, so it says which device approved. Nothing updates it afterwards -
    /// see <c>ApprovingDevice</c> for why that is the question worth answering and why no address
    /// is recorded beside it.
    /// </para>
    /// </remarks>
    public string? UserAgent { get; init; }

    /// <summary>The authenticated user. Set by stage 9.</summary>
    public SubjectId? Subject { get; set; }

    /// <summary>When that user authenticated.</summary>
    public DateTimeOffset? AuthTime { get; set; }
}
