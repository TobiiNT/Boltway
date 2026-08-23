using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Abstractions.Clients;

/// <summary>
/// Whether a client can keep a secret.
/// </summary>
/// <remarks>
/// RFC 6749 §2.1, and it decides more than authentication. A public client cannot be authenticated
/// at all, so consent is the <i>only</i> evidence the user agreed — which is why RFC 8252 §8.6 says
/// not to skip repeat consent for one, and why this server does not.
/// </remarks>
public enum ClientType
{
    /// <summary>Not set.</summary>
    Unknown = 0,

    /// <summary>
    /// Cannot hold a secret. Every browser app, every native app, and both vendors' MCP clients.
    /// </summary>
    Public = 1,

    /// <summary>Holds a secret or a private key. A server-side client.</summary>
    Confidential = 2,
}

/// <summary>How a client authenticates at the token endpoint. RFC 7591.</summary>
public enum ClientAuthMethod
{
    /// <summary>
    /// No client authentication. The normal case here — Claude and Claude Code both declare it.
    /// </summary>
    None = 0,

    /// <summary>HTTP Basic. RFC 6749 §2.3.1.</summary>
    ClientSecretBasic = 1,

    /// <summary>Secret in the request body.</summary>
    ClientSecretPost = 2,

    /// <summary>
    /// A JWT signed with the client's private key, verified against its <c>jwks_uri</c>.
    /// </summary>
    /// <remarks>
    /// ChatGPT's published metadata offers this alongside <c>none</c>, so supporting it is what
    /// lets that client authenticate the way it prefers. It is not a lockout risk either way — the
    /// live document declares both — but implementing only <c>none</c> would refuse a client that
    /// asked for the stronger option.
    /// </remarks>
    PrivateKeyJwt = 3,
}

/// <summary>
/// A client, resolved and ready to be authorized against.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="IClientResolver"/> whatever the source: a CIMD document fetched moments
/// ago, a row written by dynamic registration, or an administrator's configuration. Everything
/// downstream sees the same shape, so the authorize pipeline has no idea which kind it is holding
/// — and that is the point, because a CIMD client is <b>not persisted</b> and a pipeline that could
/// tell would be tempted to write one.
/// </para>
/// <para>
/// A-08: a hundred sequential CIMD connections must leave the client table unchanged. "Just cache
/// it in the clients table" is the obvious move and it breaks the zero-registration property CIMD
/// exists for.
/// </para>
/// </remarks>
public sealed record ClientRecord
{
    /// <summary>The identifier, and how it was obtained.</summary>
    public required ClientIdentifier ClientId { get; init; }

    /// <summary>Whether it can keep a secret.</summary>
    public required ClientType ClientType { get; init; }

    /// <summary>How it authenticates at <c>/token</c>.</summary>
    public required ClientAuthMethod TokenEndpointAuthMethod { get; init; }

    /// <summary>
    /// Its registered redirect URIs, normalized when they were written.
    /// </summary>
    public required IReadOnlyList<RegisteredRedirectUri> RedirectUris { get; init; }

    /// <summary>The grants it declared.</summary>
    /// <remarks>
    /// Never used to reject a client <i>document</i> — C-14: a client declaring a grant this server
    /// has not enabled is not an error, it is a client that also works elsewhere. The check belongs
    /// on the request, against this set.
    /// </remarks>
    public required IReadOnlyList<string> GrantTypes { get; init; }

    /// <summary>The response types it declared. Only <c>code</c> is ever honoured.</summary>
    public required IReadOnlyList<string> ResponseTypes { get; init; }

    /// <summary>
    /// Its self-asserted display name, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <b>Self-asserted, and it must be rendered as such.</b> Anyone can publish
    /// <c>{"client_name":"Claude"}</c> at their own URL, so the consent page shows the host of the
    /// <c>client_id</c> alongside this — the hostname IS the mitigation, and CIMD cannot provide
    /// one on its own. HTML-encoded and length-capped wherever it is displayed.
    /// </remarks>
    public string? ClientName { get; init; }

    /// <summary>Its logo URL, or <see langword="null"/>. Proxied, never hotlinked.</summary>
    /// <remarks>
    /// ChatGPT's live metadata points this at a third-party CDN, so the "proxy it" rule has a real
    /// case from day one: hotlinking would leak every consent-page view to that host, and the
    /// consent page's own <c>default-src 'self'</c> would block it anyway.
    /// </remarks>
    public string? LogoUri { get; init; }

    /// <summary>Where to fetch its public keys for <c>private_key_jwt</c>.</summary>
    public string? JwksUri { get; init; }

    /// <summary>Scopes it may request, or empty for "whatever the server permits".</summary>
    public ScopeSet AllowedScopes { get; init; } = ScopeSet.Empty;

    /// <summary>Whether this client is currently permitted to authorize.</summary>
    /// <remarks>
    /// <b>Not revocation.</b> It stops new tokens being issued; the ones already out live until they
    /// expire, the same as disabling an account. A deployment that needs a credential dead now
    /// revokes the grants as well.
    /// </remarks>
    public bool IsEnabled { get; init; } = true;

    /// <summary>
    /// The account this client acts as, or <see langword="null"/> for a client that acts for
    /// whoever signs in through it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is what makes a service account possible without inventing a second kind of
    /// identity.</b> A <c>client_credentials</c> token has no sign-in behind it, so without an owner
    /// its <c>sub</c> would be the client — and everything downstream that hangs off an account
    /// would have nothing to hang off. Roles and permissions are properties of a
    /// <c>UserAccount</c>; a resource server that attributes writes to a person needs a person.
    /// Naming the account here means the minted token is shaped exactly like one a human got, and
    /// no consumer has to learn a second shape.
    /// </para>
    /// <para>
    /// <b>The owner's roles are the ceiling, and that is a reason to give a service account its own
    /// account rather than hanging a secret on somebody's.</b> A client owned by an account that
    /// holds every role is a non-expiring credential with that reach. Owned by an account holding
    /// one narrow role, it can only do that role's work — which is the difference between a key to
    /// the building and a key to one door.
    /// </para>
    /// <para>
    /// <b>Null is the ordinary case and must stay the default.</b> Every client that exists today —
    /// the admin UI, anything resolved through CIMD — acts for whoever authorized it, and a client
    /// silently acting as somebody would be the worst possible thing to arrive by accident.
    /// </para>
    /// </remarks>
    public SubjectId? Owner { get; init; }
}

/// <summary>Why a client could not be resolved.</summary>
public enum ClientResolutionError
{
    /// <summary>No error.</summary>
    None = 0,

    /// <summary>No client with that identifier, by any route.</summary>
    NotFound,

    /// <summary>Found, but administratively disabled.</summary>
    Disabled,

    /// <summary>A CIMD document could not be fetched or did not validate.</summary>
    MetadataUnusable,

    /// <summary>
    /// Resolution was not attempted, because this identifier has used up a budget. X-31.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="MetadataUnusable"/> because it is not a statement about the
    /// document. The identifier may be perfectly good and the document may be valid; what happened
    /// is that this instance declined to go and look right now. Collapsing the two would answer a
    /// throttled request with <c>invalid_client</c>, which tells the client to change something that
    /// is not wrong, and would hide the one piece of information that makes the response actionable
    /// — when to try again.
    /// </remarks>
    RateLimited,
}

/// <summary>The outcome of resolving a client identifier.</summary>
/// <param name="Client">The client, when resolution succeeded.</param>
/// <param name="Error">Why not, otherwise.</param>
/// <param name="Detail">
/// Which check failed, in words. A-07 and A-12: <c>curl</c> alone has to be enough to debug, and
/// "invalid_client" with no detail is the Auth0 behaviour this whole project is a reaction to.
/// </param>
public sealed record ClientResolution(ClientRecord? Client, ClientResolutionError Error, string? Detail)
{
    /// <summary>
    /// How long until it is worth asking again. Set only for
    /// <see cref="ClientResolutionError.RateLimited"/>.
    /// </summary>
    /// <remarks>
    /// Carried here rather than parsed back out of <see cref="Detail"/>, because it becomes the
    /// <c>Retry-After</c> header and a header derived by reading English out of a sentence is a
    /// header that breaks when the sentence is reworded.
    /// </remarks>
    public TimeSpan? RetryAfter { get; init; }

    /// <summary>Resolution succeeded.</summary>
    public static ClientResolution Resolved(ClientRecord client) =>
        new(client, ClientResolutionError.None, null);

    /// <summary>Resolution failed, and here is which check.</summary>
    public static ClientResolution Failed(ClientResolutionError error, string detail) =>
        new(null, error, detail);

    /// <summary>Resolution was declined by a budget, and here is when to ask again. X-31.</summary>
    public static ClientResolution RateLimited(string detail, TimeSpan retryAfter) =>
        new(null, ClientResolutionError.RateLimited, detail) { RetryAfter = retryAfter };
}

/// <summary>
/// Turns a <c>client_id</c> into a client.
/// </summary>
/// <remarks>
/// Implementations are tried in order and the first that resolves wins. Shipping order is
/// pre-registered, then dynamic, then CIMD — cheapest and most-trusted first, with the one that
/// makes an outbound request last.
/// </remarks>
public interface IClientResolver
{
    /// <summary>Whether this resolver could plausibly handle this identifier.</summary>
    /// <remarks>
    /// A cheap shape test, so a CIMD resolver does not make an outbound request for an identifier
    /// that is obviously not a URL. It is not a claim that resolution will succeed.
    /// </remarks>
    bool CanResolve(ClientIdentifier clientId);

    /// <summary>Resolve, or explain why not.</summary>
    ValueTask<ClientResolution> ResolveAsync(ClientIdentifier clientId, CancellationToken cancellationToken);
}

/// <summary>Persists clients. Used by dynamic registration and by configuration.</summary>
/// <remarks>
/// Note what is absent: no method here is called on the CIMD path. That is A-08 expressed as an
/// API rather than as a promise.
/// </remarks>
public interface IClientStore
{
    /// <summary>Find a persisted client.</summary>
    Task<ClientRecord?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken);

    /// <summary>Persist a client, with its secret.</summary>
    /// <param name="client">The client.</param>
    /// <param name="secretHash">
    /// SHA-256 of its secret, or <see langword="null"/> for a public client. <b>The plaintext never
    /// reaches this interface</b> — the caller mints it, hashes it, shows it once and forgets it.
    /// </param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <remarks>
    /// One call rather than a client write followed by a secret write, because the two halves are
    /// not independently useful: a confidential client with no secret cannot authenticate, and a
    /// secret with no client is a row nothing reaches. Two calls is two chances to land half of it.
    /// </remarks>
    Task StoreAsync(ClientRecord client, Sha256Hash? secretHash, CancellationToken cancellationToken);

    /// <summary>
    /// The SHA-256 of a client's secret, or <see langword="null"/> if it has none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Separate from <see cref="FindAsync"/> rather than a field on <see cref="ClientRecord"/>,
    /// because that record is passed to the authorize pipeline, the consent page and the audit
    /// trail — every one of which would then be handling a credential digest it has no use for. The
    /// only caller is client authentication.
    /// </para>
    /// <para>
    /// A <i>disabled</i> client still answers with its hash. Authentication and authorization are
    /// different questions, and withholding it would make a disabled client look like a
    /// misconfigured one — the authenticator would report that it is registered as public and must
    /// not present credentials, which sends the reader somewhere else entirely. Resolution refuses
    /// a disabled client, with <c>Disabled</c>.
    /// </para>
    /// </remarks>
    /// <param name="clientId">Which client.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    Task<Sha256Hash?> FindSecretAsync(ClientIdentifier clientId, CancellationToken cancellationToken);

    /// <summary>Remove a client. RFC 7592 delete.</summary>
    Task<bool> DeleteAsync(ClientIdentifier clientId, CancellationToken cancellationToken);

    /// <summary>
    /// The service account acting as this person, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Singular because one account holds at most one, which is a product decision rather than
    /// something the schema enforces — the table would take several. It is what the administrative
    /// surface is: a checkbox on a person, not a list to curate.
    /// </para>
    /// <para>
    /// This is also the query asked when somebody leaves, and it has to be answerable <i>before</i>
    /// their account is disabled rather than discovered afterwards by a job that stopped running.
    /// </para>
    /// </remarks>
    Task<ClientRecord?> FindByOwnerAsync(SubjectId owner, CancellationToken cancellationToken);

    /// <summary>
    /// Stop or restart a client authorizing, without destroying it.
    /// </summary>
    /// <remarks>
    /// <b>Not revocation, and the difference has to reach whoever presses it.</b> This stops new
    /// tokens being issued; the ones already out live until they expire, exactly as disabling an
    /// account does. A deployment that needs a credential dead now revokes the grant as well —
    /// <c>ClientCredentialsGrant.DeriveGrantId</c> is how that id is computed for a service account.
    /// </remarks>
    /// <param name="clientId">Which client.</param>
    /// <param name="enabled">Whether it may authorize.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>Whether a client with that id was found.</returns>
    Task<bool> SetEnabledAsync(
        ClientIdentifier clientId, bool enabled, CancellationToken cancellationToken);
}
