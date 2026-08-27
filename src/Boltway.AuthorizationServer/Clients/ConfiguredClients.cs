using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>One client a deployment registered by hand.</summary>
/// <param name="ClientId">What it presents as. Not a URL, unlike a CIMD client.</param>
/// <param name="Name">What the consent page shows. Still self-asserted as far as N-14 is concerned.</param>
/// <param name="RedirectUris">Where a code may be sent. Matched exactly, never by prefix.</param>
/// <param name="SecretHash">
/// SHA-256 of the secret, or <see langword="null"/> for a public client. <b>The plaintext is never
/// held</b> - the same rule every other credential here follows.
/// </param>
public sealed record ConfiguredClient(
    ClientIdentifier ClientId,
    string? Name,
    IReadOnlyList<RegisteredRedirectUri> RedirectUris,
    Sha256Hash? SecretHash)
{
    /// <summary>Whether it can keep a secret.</summary>
    public ClientType ClientType => SecretHash is null ? ClientType.Public : ClientType.Confidential;

    /// <summary>
    /// The account this client acts as, or <see langword="null"/> for an ordinary client.
    /// </summary>
    /// <remarks>
    /// Setting it makes this a service account, which is a different kind of client rather than an
    /// ordinary one with an extra field - see <see cref="GrantTypes"/>.
    /// </remarks>
    public SubjectId? Owner { get; init; }

    /// <summary>
    /// What a service account may ask for. Ignored unless <see cref="Owner"/> is set.
    /// </summary>
    /// <remarks>
    /// Required for a service account and meaningless without one. <c>ClientCredentialsGrant</c>
    /// refuses an empty set rather than reading it as "everything the server permits", which is what
    /// empty means for a client a human authorizes - there is no human here to see what it turned
    /// into.
    /// </remarks>
    public ScopeSet Scopes { get; init; } = ScopeSet.Empty;

    /// <summary>
    /// The grants this client may use, decided by whether it names an owner.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The two sets do not overlap, and that is the design.</b> A client that names an owner acts
    /// as that account and does so without a browser; a client that does not acts for whoever signs
    /// in through it. A client offering both would be one that a human can authorize *and* that
    /// holds a standing credential for somebody else's account - two different answers to "who is
    /// this token for", selected by which endpoint the caller happened to use.
    /// </para>
    /// <para>
    /// So this is derived rather than configurable. A deployment that could write the list by hand
    /// could write that combination by hand, and nothing downstream would notice.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> GrantTypes =>
        Owner is null ? InteractiveGrants : ServiceAccountGrants;

    internal static readonly string[] InteractiveGrants = ["authorization_code", "refresh_token"];

    internal static readonly string[] ServiceAccountGrants = ["client_credentials"];
}

/// <summary>
/// Clients a deployment names in configuration, rather than ones that name themselves.
/// </summary>
/// <remarks>
/// <para>
/// <b>This existed as a seam and as a test double and nowhere a deployment could reach.</b>
/// <c>IClientResolver</c>, <c>IClientSecretStore</c> and <c>client_secret_basic</c> were all
/// shipped, <c>CimdClientResolver</c> was the only implementation in <c>src/</c>, and §7.1 says of the
/// admin BFF that "it uses the client store and <c>client_secret_basic</c> that already exist".
/// Measured while building that BFF: they did not. This is them.
/// </para>
/// <para>
/// <b>It does not replace CIMD, it sits beside it.</b> Both resolvers are registered and the
/// pipeline tries each in turn, so a deployment can serve Claude - which identifies itself by a
/// metadata URL - and its own admin UI, which cannot, since a confidential client's secret has no
/// business in a document served over the public internet.
/// </para>
/// <para>
/// <b><c>CanResolve</c> is the shape test that keeps the two apart.</b> A configured id is a plain
/// string, so this resolver claims anything it was given and declines everything else rather than
/// answering authoritatively for identifiers it has never heard of - which would stop the CIMD
/// resolver from ever being asked.
/// </para>
/// </remarks>
/// <param name="clients">Every configured client, by identifier.</param>
public sealed class ConfiguredClientResolver(IReadOnlyDictionary<string, ConfiguredClient> clients)
    : IClientResolver
{
    /// <summary>
    /// The response types a configured client may use.
    /// </summary>
    /// <remarks>
    /// Fixed rather than configurable, and only <c>code</c> is ever honoured. The grant list used to
    /// be fixed here beside it for the same reason; it moved to <see cref="ConfiguredClient"/> when
    /// a service account became a thing a deployment can configure, because it is no longer the same
    /// answer for every client - see <c>ConfiguredClient.GrantTypes</c>. It is still derived rather
    /// than typed, which is the half that mattered.
    /// </remarks>
    private static readonly string[] Responses = ["code"];

    /// <inheritdoc />
    public bool CanResolve(ClientIdentifier clientId) =>
        clientId.Value is { Length: > 0 } value && clients.ContainsKey(value);

    /// <inheritdoc />
    public ValueTask<ClientResolution> ResolveAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        if (clientId.Value is not { Length: > 0 } value || !clients.TryGetValue(value, out var configured))
        {
            // NotFound rather than an authoritative refusal, so the pipeline goes on to ask the CIMD
            // resolver. This one knows about the clients it was told about and nothing else.
            return ValueTask.FromResult(
                ClientResolution.Failed(ClientResolutionError.NotFound, "No configured client with that id."));
        }

        return ValueTask.FromResult(ClientResolution.Resolved(new ClientRecord
        {
            // ForPreRegistered, so the kind on the record says how this client was learned about.
            // It is what an audit entry and a consent page read, and deriving it from "we found it
            // here" is the only way it cannot disagree with the truth.
            ClientId = ClientIdentifier.ForPreRegistered(value),
            ClientType = configured.ClientType,
            TokenEndpointAuthMethod = configured.SecretHash is null
                ? ClientAuthMethod.None
                : ClientAuthMethod.ClientSecretBasic,
            RedirectUris = configured.RedirectUris,
            GrantTypes = configured.GrantTypes,
            ResponseTypes = Responses,
            ClientName = configured.Name,
            Owner = configured.Owner,
            AllowedScopes = configured.Scopes,
        }));
    }
}

/// <summary>
/// The secrets of configured clients.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hashes, never plaintext.</b> A deployment configures the hash; this compares. The
/// authenticator does the comparison in constant time, so what is stored here can leak without
/// handing anybody a working credential.
/// </para>
/// <para>
/// Returning <see langword="null"/> means "this client has no secret", which the authenticator
/// reads as "cannot authenticate with one" rather than as "any secret will do".
/// </para>
/// </remarks>
/// <param name="clients">Every configured client, by identifier.</param>
public sealed class ConfiguredClientSecretStore(IReadOnlyDictionary<string, ConfiguredClient> clients)
    : IClientSecretStore
{
    /// <inheritdoc />
    public Task<Sha256Hash?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken) =>
        Task.FromResult(
            clientId.Value is { Length: > 0 } value && clients.TryGetValue(value, out var configured)
                ? configured.SecretHash
                : null);
}

/// <summary>Registers clients a deployment names in configuration.</summary>
public static class ConfiguredClientServiceCollectionExtensions
{
    /// <summary>
    /// Register a fixed set of clients, and their secrets.
    /// </summary>
    /// <param name="services">The container.</param>
    /// <param name="clients">Every client this deployment registered by hand.</param>
    /// <remarks>
    /// <para>
    /// Call this <b>before</b> <c>AddBoltwayAuthorizationServer</c>. Resolvers are tried in
    /// registration order and the CIMD one is added by that call, so registering here first means a
    /// configured id is answered from configuration rather than after an outbound fetch that was
    /// never going to find anything.
    /// </para>
    /// <para>
    /// <c>IClientSecretStore</c> is registered with <c>Add</c> rather than <c>TryAdd</c>, on
    /// purpose: the shipped default is <c>NoClientSecretsStore</c>, which answers "no secret" for
    /// every client, and quietly keeping it would mean a confidential client that cannot ever
    /// authenticate. A deployment wanting its own store registers it after this call.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddConfiguredClients(
        this IServiceCollection services, IReadOnlyList<ConfiguredClient> clients)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(clients);

        var byId = clients.ToDictionary(c => c.ClientId.Value!, StringComparer.Ordinal);

        // A service account with no secret is the one misconfiguration here that hands somebody
        // else's account away, and it is silent: the resolver would produce a client whose
        // TokenEndpointAuthMethod is None, the authenticator would correctly authenticate it as a
        // public client presenting nothing, and `client_credentials` would then mint a token for
        // the owner to anybody who knows the client_id. Nothing downstream is wrong; each layer is
        // doing its job on a record that should not exist.
        //
        // A startup failure on the ADMIN_ROLES precedent, which this repository has already paid
        // for once: an empty value was legal, silent, and meant nobody could administer anything,
        // discovered at somebody's next sign-in rather than at the deploy that caused it.
        foreach (var client in clients)
        {
            if (client.Owner is null)
            {
                continue;
            }

            if (client.SecretHash is null)
            {
                throw new InvalidOperationException(
                    $"Client '{client.ClientId.Value}' names an owner but has no secret. A client that "
                    + "acts as an account authenticates or anybody who knows its id can be issued "
                    + "that account's token.");
            }

            if (client.Scopes.IsEmpty)
            {
                throw new InvalidOperationException(
                    $"Client '{client.ClientId.Value}' names an owner but no scopes. A service account "
                    + "is issued exactly the scopes configured here, and an empty set is refused at "
                    + "the token endpoint rather than read as 'everything' — so this client could "
                    + "never obtain a token.");
            }
        }

        services.AddSingleton<IClientResolver>(new ConfiguredClientResolver(byId));
        services.AddSingleton<IClientSecretStore>(new ConfiguredClientSecretStore(byId));

        return services;
    }
}
