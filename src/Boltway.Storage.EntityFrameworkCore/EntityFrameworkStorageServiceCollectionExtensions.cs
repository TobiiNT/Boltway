using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Storage.EntityFrameworkCore.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.Storage.EntityFrameworkCore;

/// <summary>Registers the stores this package implements.</summary>
public static class EntityFrameworkStorageServiceCollectionExtensions
{
    /// <summary>
    /// Register the grant, code, refresh-token, consent and user stores over
    /// <see cref="AuthDbContext"/>.
    /// </summary>
    /// <param name="services">The collection.</param>
    /// <returns>The collection, for chaining.</returns>
    /// <remarks>
    /// <para>
    /// <b>This does not configure a provider and does not register one.</b> A caller still owes two
    /// things: an <c>IDbContextFactory&lt;AuthDbContext&gt;</c> — a factory rather than a scoped
    /// context, because these stores are singletons and a <c>DbContext</c> is not thread-safe — and
    /// an <see cref="IRelationalStoreBehavior"/>. A provider package such as
    /// <c>Boltway.Storage.Sqlite</c> supplies both and calls this; wiring it by hand is
    /// supported and is the path a customer on an unlisted provider takes.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> throughout, so a host that already registered something else for one of these
    /// keeps it and gets the rest — which is the shape of a migration, one store at a time.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBoltwayEntityFrameworkStores(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Registered unconditionally rather than as an optional constructor parameter: the
        // built-in container activates these stores by constructor, and it does not fall back to a
        // default value for a service it cannot resolve. An instrument nobody listens to costs a
        // branch on a cached flag, so there is nothing to save by making it conditional.
        services.TryAddSingleton<StorageMetrics>();

        services.TryAddSingleton<IGrantStore, EfGrantStore>();
        services.TryAddSingleton<IAuthorizationCodeStore, EfAuthorizationCodeStore>();
        services.TryAddSingleton<IRefreshTokenStore, EfRefreshTokenStore>();
        services.TryAddSingleton<IConsentStore, EfConsentStore>();
        services.TryAddSingleton<IUserStore, EfUserStore>();
        services.TryAddSingleton<IRoleStore, EfRoleStore>();
        services.TryAddSingleton<AuthorizationServer.Abstractions.Administration.IAdminAuditStore, EfAdminAuditStore>();
        services.TryAddSingleton<IUserTokenStore, EfUserTokenStore>();

        // The one store whose in-memory sibling is not merely less durable but less correct: a
        // per-process replay set admits one use of an assertion per replica. This is the
        // implementation a deployment running private_key_jwt needs.
        services.TryAddSingleton<IClientAssertionReplayStore, EfClientAssertionReplayStore>();

        // The client table. Registering it does not by itself make a stored client resolvable —
        // AddStoredClients on the authorization server side is what puts a resolver in front of it,
        // and the order it is called in decides whether configuration or the table wins.
        services.TryAddSingleton<IClientStore, EfClientStore>();

        return services;
    }
}
