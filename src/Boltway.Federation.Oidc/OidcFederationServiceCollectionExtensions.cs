using Boltway.AuthorizationServer.Abstractions.Federation;
using Boltway.OAuth.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.Federation.Oidc;

/// <summary>Wires an upstream OpenID Connect provider into a host.</summary>
public static class OidcFederationServiceCollectionExtensions
{
    /// <summary>
    /// Register one upstream identity provider.
    /// </summary>
    /// <param name="services">The host's services.</param>
    /// <param name="options">The provider's configuration.</param>
    /// <param name="configureTransport">
    /// The outbound client's budgets, applied only the first time a provider is registered. This is
    /// where an on-premises deployment sets
    /// <see cref="UpstreamEndpointClientOptions.AllowPrivateAddresses"/>.
    /// </param>
    /// <returns>The same collection.</returns>
    /// <exception cref="ArgumentException">The options do not validate.</exception>
    /// <remarks>
    /// <para>
    /// Validation runs <b>here</b>, synchronously, and throws — the same choice
    /// <c>AddBoltwayAuthorizationServer</c> makes and for the same reason: a deferred check
    /// turns a mistyped issuer into a failure at the moment a user clicks a button, minutes after
    /// the deploy looked successful, and it is attributed to the user.
    /// </para>
    /// <para>
    /// The transport is registered with <c>TryAdd</c> and is shared by every provider, so the
    /// outbound budget is per upstream host rather than per provider, and two providers at the same
    /// upstream cannot each spend a full budget at it.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddExternalIdentityProvider(
        this IServiceCollection services,
        OidcProviderOptions options,
        Action<UpstreamEndpointClientOptions>? configureTransport = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.TryValidate(out var errors))
        {
            throw new ArgumentException(
                $"The upstream identity provider '{options.Scheme}' is not configured usably:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, errors.Select(e => "  - " + e)),
                nameof(options));
        }

        services.TryAddSingleton(TimeProvider.System);

        var transport = new UpstreamEndpointClientOptions();
        configureTransport?.Invoke(transport);

        services.TryAddSingleton(transport);
        services.TryAddSingleton<IUpstreamEndpointClient>(sp => new UpstreamEndpointClient(
            sp.GetRequiredService<UpstreamEndpointClientOptions>(),
            resolver: null,
            sp.GetRequiredService<TimeProvider>()));

        // AddSingleton, not TryAdd: several providers are the point, and TryAdd would silently keep
        // only the first. Duplicate schemes are refused at map time by the authorization server,
        // which is where the route table is and therefore where the collision actually matters.
        services.AddSingleton<IExternalIdentityProvider>(sp => new OidcExternalProvider(
            options,
            sp.GetRequiredService<IUpstreamEndpointClient>(),
            sp.GetRequiredService<TimeProvider>()));

        return services;
    }
}
