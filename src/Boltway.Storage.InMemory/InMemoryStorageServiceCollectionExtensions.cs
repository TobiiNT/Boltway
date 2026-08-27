using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Users;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.Storage.InMemory;

/// <summary>Registers every store this package implements.</summary>
public static class InMemoryStorageServiceCollectionExtensions
{
    /// <summary>
    /// Register the grant, code, refresh-token, consent and user stores, all in memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One call rather than five, because five is where a deployment forgets one. Forgetting one is
    /// a startup failure now - <c>MapBoltwayAuthorizationServer</c> names every missing seam
    /// before the host serves anything - but it was not when this was written: it was a
    /// <c>server_error</c> on the first client, after the user had already typed a password. Three
    /// separate reviewers built a host for this server and all three discovered the store list by
    /// triggering that failure, one service at a time.
    /// </para>
    /// <para>
    /// <b>Deliberately not registered by <c>AddBoltwayAuthorizationServer</c>.</b> Everything
    /// here loses its contents when the process restarts: every refresh token dies, every consent is
    /// asked again, and any authorization mid-flight fails. That is fine for a single instance, a
    /// test, or a first run, and wrong for anything else - so it has to be a line a deployment
    /// wrote, not a default it inherited. A server that silently ran on in-memory storage in
    /// production would be behaving exactly as configured and nobody would have chosen it.
    /// </para>
    /// <para>
    /// <c>TryAdd</c> throughout, so a host that already registered a durable store for one of these
    /// keeps it and gets the rest - which is the shape of a migration, one store at a time.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddBoltwayInMemoryStores(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IGrantStore, InMemoryGrantStore>();
        services.TryAddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
        services.TryAddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.TryAddSingleton<IConsentStore, InMemoryConsentStore>();
        services.TryAddSingleton<IUserTokenStore, InMemoryUserTokenStore>();

        // Registered here rather than only where private_key_jwt is configured, so a host that
        // enables that method finds the seam filled and a host that does not pays a dictionary it
        // never writes to. What it must not be taken for is a deployment-grade one: see
        // InMemoryClientAssertionReplayStore for why this store's per-process limit is a hole in the
        // property rather than a persistence inconvenience.
        services.TryAddSingleton<IClientAssertionReplayStore, InMemoryClientAssertionReplayStore>();

        // Local accounts too. This method said "the four stores" and left InMemoryUserStore out,
        // even though it lives in this package - so a host that called it still had IUserStore in
        // its missing-services list, with the obvious one-line fix already apparently applied. The
        // only reason it was noticed is that the startup check reports every seam at once.
        //
        // Empty, so /login refuses everyone until the host seeds an account. That is the right
        // default for a store with no persistence: an empty user table is obviously empty, whereas
        // a seeded demo account that survived into production would not be.
        // Concrete as well as behind the interface: InMemoryUserStore takes this one directly,
        // because refusing an assignment to a role nothing defines needs the definitions, and two
        // separately-resolved instances would be two different sets of them.
        services.TryAddSingleton<InMemoryRoleStore>();
        services.TryAddSingleton<IRoleStore>(sp => sp.GetRequiredService<InMemoryRoleStore>());
        services.TryAddSingleton<IUserStore, InMemoryUserStore>();
        services.TryAddSingleton<IClientStore, InMemoryClientStore>();

        return services;
    }
}
