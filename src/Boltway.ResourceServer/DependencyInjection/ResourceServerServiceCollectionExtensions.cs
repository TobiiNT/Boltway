using Boltway.ResourceServer.Bearer;
using Boltway.ResourceServer.Revocation;
using Microsoft.Extensions.Logging;
using Boltway.ResourceServer.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Boltway.ResourceServer.DependencyInjection;

/// <summary>Wiring the resource server into a host.</summary>
public static class ResourceServerServiceCollectionExtensions
{
    /// <summary>
    /// Register the protected resource: its identity, its metadata document, its token validator.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The configuration does not describe a usable resource. Thrown at registration rather than
    /// deferred to the first request, because every failure this validation catches presents as a
    /// <b>200</b>: a metadata document naming the wrong resource, or an <c>https</c> identifier that
    /// is really <c>http</c>, is served cheerfully and discarded by every client that reads it. A
    /// server that will not start is diagnosable; one that answers 200 with an unusable document is
    /// the failure mode the whole conformance exercise exists to avoid.
    /// </exception>
    public static IServiceCollection AddBoltwayProtectedResource(
        this IServiceCollection services, Action<ProtectedResourceOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.AddSingleton(provider =>
        {
            var options = provider.GetRequiredService<IOptions<ProtectedResourceOptions>>().Value;

            if (!ProtectedResource.TryCreate(options, out var resource, out var error))
            {
                throw new InvalidOperationException(
                    "The protected resource is not configured correctly: " + error);
            }

            return resource!;
        });

        services.AddSingleton<AccessTokenValidator>();

        return services;
    }

    /// <summary>
    /// Check every accepted token against the authorization server's revocation state, over RFC 7662.
    /// </summary>
    /// <param name="services">The container.</param>
    /// <param name="configure">Where to ask and with what.</param>
    /// <remarks>
    /// <para>
    /// <b>What this buys, and what it costs.</b> Without it, ending a session takes effect when the
    /// access token expires and not before, because a signed token is verified offline and this
    /// server never asks anybody. With it, the lag is
    /// <see cref="IntrospectionOptions.CacheLifetime"/> instead — thirty seconds by default against
    /// a thirty-minute token. The cost is a client credential of this resource server's own and a
    /// round trip on the first request of each cache window.
    /// </para>
    /// <para>
    /// <b>Registered as a singleton, deliberately.</b> The cache is the whole point and a scoped
    /// instance would build an empty one per request, turning every call into a round trip while
    /// looking like it was configured correctly.
    /// </para>
    /// <para>
    /// <b>Its own named client, not the application's</b> — see
    /// <see cref="IntrospectionRevocationCheck.HttpClientName"/>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddIntrospectionRevocationCheck(
        this IServiceCollection services, Action<IntrospectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddHttpClient(IntrospectionRevocationCheck.HttpClientName);

        // Registered here rather than left to the host, so the fail-open count exists wherever the
        // check does. A meter the host never names publishes nothing — but that is one line in a
        // host, whereas a metrics object nobody constructed is a silence with no fix at all.
        services.TryAddSingleton<Diagnostics.ResourceServerMetrics>();

        services.AddSingleton<IAccessTokenRevocationCheck>(sp =>
        {
            // Built here rather than bound from configuration, so a missing endpoint or an empty
            // secret is a startup failure with the property named — `required` members on the
            // options type do that much — rather than a fail-open warning on every request that
            // reads as the authorization server being down.
            var options = new IntrospectionOptions();
            configure(options);
            Validate(options);

            return new IntrospectionRevocationCheck(
                sp.GetRequiredService<IHttpClientFactory>(),
                options,
                sp.GetRequiredService<ILogger<IntrospectionRevocationCheck>>(),
                sp.GetService<TimeProvider>(),
                sp.GetRequiredService<Diagnostics.ResourceServerMetrics>());
        });

        return services;
    }

    /// <summary>
    /// Refuse a half-configured check at startup rather than on every request.
    /// </summary>
    /// <remarks>
    /// The failure this replaces: with no endpoint or a blank secret, every request would fail open
    /// and log a warning naming the authorization server, so a configuration mistake would present
    /// itself as somebody else's outage and revocation would quietly do nothing for as long as
    /// nobody read the logs.
    /// </remarks>
    private static void Validate(IntrospectionOptions options)
    {
        List<string> missing = [];

        if (options.Endpoint is null || !options.Endpoint.IsAbsoluteUri) missing.Add(nameof(options.Endpoint));
        if (options.ClientId.Length == 0) missing.Add(nameof(options.ClientId));
        if (options.ClientSecret.Length == 0) missing.Add(nameof(options.ClientSecret));

        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"AddIntrospectionRevocationCheck is missing {string.Join(", ", missing)}. Every request "
                + "would fail open and log a warning blaming the authorization server, which is a "
                + "configuration error wearing an outage's clothes.");
        }
    }
}

/// <summary>Placing the bearer gate in the pipeline.</summary>
public static class ResourceServerApplicationBuilderExtensions
{
    /// <summary>
    /// Add the bearer gate.
    /// </summary>
    /// <remarks>
    /// <b>Call this after <c>UseRouting()</c> and before <c>UseEndpoints()</c>.</b> Before routing,
    /// there is no endpoint yet, so the middleware cannot see that the metadata document is
    /// anonymous or which scopes an endpoint declares — it would challenge the discovery document
    /// and deadlock the flow. After the endpoints, the handler has already run and its result is
    /// already destined for a <c>200</c>, which produces no authentication prompt in Claude at all.
    /// </remarks>
    public static IApplicationBuilder UseBoltwayProtectedResource(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseMiddleware<BearerAuthenticationMiddleware>();
    }
}
