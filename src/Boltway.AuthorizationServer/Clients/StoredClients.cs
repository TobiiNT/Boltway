using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>
/// Clients an administrator created, resolved from <see cref="IClientStore"/>.
/// </summary>
/// <remarks>
/// <para>
/// The third resolver, beside the configured one and the CIMD one. It exists because a service
/// account is created at runtime — the whole point of it being in a table rather than in an
/// environment variable is that making one does not mean editing a deploy.
/// </para>
/// <para>
/// <b><c>CanResolve</c> claims everything, and that is why order matters.</b> A stored id is a plain
/// string with no shape to test, exactly like a configured one, so this resolver cannot decline by
/// inspection — it declines by not finding a row. Registered after the configured resolver and
/// before CIMD: configuration wins over the table so a deployment can always override what is
/// stored, and both win over an outbound fetch that was never going to find a non-URL identifier.
/// </para>
/// <para>
/// <b>A disabled client is refused here, not at authentication.</b> <c>Disabled</c> rather than
/// <c>NotFound</c>, because the two send a reader to different places and the difference is the
/// whole value of having turned it off deliberately.
/// </para>
/// </remarks>
/// <param name="clients">The store.</param>
public sealed class StoredClientResolver(IClientStore clients) : IClientResolver
{
    private readonly IClientStore _clients = clients ?? throw new ArgumentNullException(nameof(clients));

    /// <inheritdoc />
    public bool CanResolve(ClientIdentifier clientId) => clientId.Value is { Length: > 0 };

    /// <inheritdoc />
    public async ValueTask<ClientResolution> ResolveAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        var client = await _clients.FindAsync(clientId, cancellationToken);

        if (client is null)
        {
            // NotFound rather than an authoritative refusal, so the pipeline goes on to ask the
            // CIMD resolver. This one knows about the rows it holds and nothing else.
            return ClientResolution.Failed(
                ClientResolutionError.NotFound, "No stored client with that id.");
        }

        if (!client.IsEnabled)
        {
            return ClientResolution.Failed(
                ClientResolutionError.Disabled,
                "This client has been disabled. Tokens already issued are unaffected until they "
                + "expire; revoke its grant to end those.");
        }

        return ClientResolution.Resolved(client);
    }
}

/// <summary>
/// The secrets of stored clients, read through the same store.
/// </summary>
/// <remarks>
/// An adapter rather than a second store, so there is one row and no way for two sources to
/// disagree about whether a client exists. It is here rather than in the storage package because
/// <see cref="IClientSecretStore"/> belongs to the authorization server, and storage must not
/// reference it — the dependency only goes one way.
/// </remarks>
/// <param name="clients">The store.</param>
public sealed class StoredClientSecretStore(IClientStore clients) : IClientSecretStore
{
    private readonly IClientStore _clients = clients ?? throw new ArgumentNullException(nameof(clients));

    /// <inheritdoc />
    public Task<Sha256Hash?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken) =>
        _clients.FindSecretAsync(clientId, cancellationToken);
}

/// <summary>
/// Secrets looked up across several stores, first answer wins.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ClientAuthenticator"/> takes one secret store, and each source of clients answers
/// only for its own: <c>ConfiguredClientSecretStore</c> knows the configured entries and nothing
/// else, <see cref="StoredClientSecretStore"/> knows the table and nothing else. Before this type,
/// registering the second replaced the first — so turning stored clients on took away the
/// configured confidential clients' ability to authenticate; on the deployment that found this,
/// two first-party clients that had authenticated fine the moment before. Resolvers already chain;
/// secrets now chain the same way.
/// </para>
/// <para>
/// The order is the resolvers' order — configured first — though in any sane deployment the id
/// spaces do not overlap. If one ever does, the earlier registration answering is the same rule
/// client resolution applies, so the two lookups cannot disagree about which client an id means.
/// </para>
/// </remarks>
/// <param name="stores">The stores, in the order to ask them.</param>
public sealed class ChainedClientSecretStore(IReadOnlyList<IClientSecretStore> stores) : IClientSecretStore
{
    private readonly IReadOnlyList<IClientSecretStore> _stores =
        stores ?? throw new ArgumentNullException(nameof(stores));

    /// <inheritdoc />
    public async Task<Sha256Hash?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        foreach (var store in _stores)
        {
            if (await store.FindAsync(clientId, cancellationToken).ConfigureAwait(false) is { } hash)
            {
                return hash;
            }
        }

        return null;
    }
}

/// <summary>Registers the resolver and secret store that read from <see cref="IClientStore"/>.</summary>
public static class StoredClientServiceCollectionExtensions
{
    /// <summary>
    /// Resolve clients from the store as well as from configuration.
    /// </summary>
    /// <param name="services">The container.</param>
    /// <remarks>
    /// <para>
    /// Call this <b>after</b> <c>AddConfiguredClients</c> and <b>before</b>
    /// <c>AddBoltwayAuthorizationServer</c>. Resolvers are tried in registration order, so
    /// that puts configuration first, the table second, and the outbound CIMD fetch last.
    /// </para>
    /// <para>
    /// <b>The secret store this registers chains onto whatever was registered before it.</b> This
    /// paragraph used to say the opposite — that this registration simply wins — and the sentence
    /// beside it admitted the consequence without drawing it: a store that answers only for the
    /// table, winning outright, is the configured confidential clients losing their secrets. On
    /// the deployment that found this, those clients are the admin UI and Grafana, so "turn on
    /// service accounts" would have read as "sign-in broke". The chain asks the earlier
    /// registration first and the table second, the same order the resolvers use.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddStoredClients(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IClientResolver>(
            sp => new StoredClientResolver(sp.GetRequiredService<IClientStore>()));

        // Captured now, because by resolution time this call's own registration is the one
        // GetRequiredService returns — the previous descriptor is only reachable from here.
        var prior = services.LastOrDefault(
            d => !d.IsKeyedService && d.ServiceType == typeof(IClientSecretStore));

        services.AddSingleton<IClientSecretStore>(sp =>
        {
            var stored = new StoredClientSecretStore(sp.GetRequiredService<IClientStore>());

            return prior is null
                ? stored
                : new ChainedClientSecretStore([Materialize(prior, sp), stored]);
        });

        return services;
    }

    /// <summary>The store a descriptor describes, however it was registered.</summary>
    private static IClientSecretStore Materialize(ServiceDescriptor prior, IServiceProvider services) =>
        prior.ImplementationInstance as IClientSecretStore
        ?? (prior.ImplementationFactory is { } factory
            ? (IClientSecretStore)factory(services)
            : (IClientSecretStore)ActivatorUtilities.CreateInstance(services, prior.ImplementationType!));
}
