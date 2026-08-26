using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.ResourceServer.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Boltway.ResourceServer.DependencyInjection;

/// <summary>
/// Wiring a resource server's verification keys to the authorization server's JWKS.
/// </summary>
/// <remarks>
/// <para>
/// <b>This lived in <c>Boltway.Mcp</c> until 0.4.0, and nothing about it was ever MCP-shaped</b> -
/// its imports are this package's options, a key source and dependency injection, and not one type
/// from the MCP SDK. What that cost was measured on 2026-08-26, on the first consumer outside this
/// repository: an author wiring a resource server looked for "how do I point verification keys at
/// an issuer" in the resource-server package, did not find it, and wrote this class again by hand -
/// down to the same sentence about a 401 that re-authenticating cannot fix. A helper a consumer
/// reimplements is a helper filed where they do not look.
/// </para>
/// <para>
/// <c>Boltway.Mcp</c> keeps a forwarder marked obsolete, so a deployment already calling it there
/// keeps working and is told once where the call moved to.
/// </para>
/// <para>
/// This replaced a <c>JwksRefresher</c> that lived here and did the same job with its own fetch
/// loop, its own parse and its own key-diffing. Two implementations of one thing agree for about a
/// month; these two had already stopped. The refresher hardcoded <c>/.well-known/jwks.json</c>
/// rather than reading <c>jwks_uri</c> out of the discovery document, so it could not follow an
/// authorization server that published its key set anywhere else — including this repository's own,
/// whose path is configurable. It also had no backoff, so a dead issuer was re-fetched on every
/// tick forever.
/// </para>
/// <para>
/// What is kept is the decision that mattered: <b>a connector that starts with no keys does not
/// start.</b> Serving with an empty key set means refusing every request as a 401, which presents a
/// startup failure as the caller's problem in the one shape that makes them retry forever. A
/// container that will not start gets restarted and shows up in the logs as what it is.
/// </para>
/// <para>
/// That is not in tension with <see cref="JwksKeySource.CurrentKeys"/> never throwing, which is the
/// opposite-looking rule one layer down. They are about two different moments: fail loudly at
/// startup, before anything is served; absorb quietly at lookup, because throwing there returns 500
/// to a caller holding a perfectly good token. <see cref="JwksKeySource.RefreshAsync"/> exists for
/// exactly this — its own remarks call it the startup call, because unlike <c>CurrentKeys</c> it
/// reports a failure rather than absorbing it.
/// </para>
/// </remarks>
public static class JwksSigningKeysExtensions
{
    /// <summary>
    /// Fill and keep filling <c>ProtectedResourceOptions.SigningKeySource</c> from the
    /// authorization server's JWKS, reached through its discovery document. Call after
    /// <c>AddBoltwayProtectedResource</c>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="issuer">The authorization server's issuer URL.</param>
    /// <param name="configure">Cache lifetime, refresh floor and failure backoff.</param>
    /// <returns>The same collection.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="issuer"/> is not a usable issuer. Thrown here, at wiring time, rather than
    /// carried to the first request: a typo in a configuration value should fail the deploy, not
    /// one caller's token validation.
    /// </exception>
    public static IServiceCollection AddJwksSigningKeys(
        this IServiceCollection services,
        string issuer,
        Action<JwksKeySourceOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (!IssuerString.TryCreate(issuer, out var parsed, out var why))
        {
            throw new ArgumentException(
                $"'{issuer}' is not a usable issuer: {why}", nameof(issuer));
        }

        var options = new JwksKeySourceOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(TimeProvider.System);

        // TryAdd, and registering it here at all is the point. The refresher this replaced took an
        // IHttpClientFactory and registered its own named client, so wiring it was self-contained.
        // Moving to the guarded client without registering it left AddJwksSigningKeys depending on
        // a service only Boltway.Federation.Oidc registers — so a connector that used this and not
        // federation got an unresolvable dependency at startup. TryAdd rather than Add so a
        // deployment that already configured the transport keeps its own.
        services.TryAddSingleton(new UpstreamEndpointClientOptions());
        services.TryAddSingleton<IUpstreamEndpointClient>(sp => new UpstreamEndpointClient(
            sp.GetRequiredService<UpstreamEndpointClientOptions>(),
            resolver: null,
            sp.GetRequiredService<TimeProvider>()));

        services.TryAddSingleton(sp => new JwksKeySource(
            parsed,
            sp.GetRequiredService<IUpstreamEndpointClient>(),
            options,
            sp.GetRequiredService<TimeProvider>()));

        // Through IConfigureOptions rather than assigned in the primer's StartAsync, so the source
        // is installed the moment the options are first materialised. The refresher assigned it at
        // StartAsync and its comment worried about the window in which two sources of truth exist;
        // this closes that window rather than narrowing it.
        services.AddSingleton<IConfigureOptions<ProtectedResourceOptions>>(sp =>
            new ConfigureOptions<ProtectedResourceOptions>(o =>
                o.SigningKeySource = sp.GetRequiredService<JwksKeySource>().CurrentKeys));

        services.AddHostedService<JwksSigningKeyPrimer>();

        return services;
    }
}

/// <summary>
/// Fetches once before the host serves traffic, and refuses to start without keys.
/// </summary>
/// <remarks>
/// Nothing keeps fetching on a timer. <see cref="JwksKeySource.CurrentKeys"/> starts a background
/// refresh itself when its snapshot goes stale, so freshness is driven by traffic rather than by a
/// clock — a connector nobody is calling does not need current keys, and one that is being called
/// refreshes on the request that notices. That also removes the failure mode the timer had, where a
/// dead issuer was re-fetched every tick with no backoff.
/// </remarks>
internal sealed partial class JwksSigningKeyPrimer(
    JwksKeySource source,
    ILogger<JwksSigningKeyPrimer> logger) : IHostedService
{
    /// <summary>
    /// Source-generated rather than a direct <c>LogInformation</c> call, because CA1873 is an error
    /// here and boxing an <see langword="int"/> into the <c>params object?[]</c> trips it. The
    /// generated overload takes the argument by its own type and formats nothing when the level is
    /// disabled — which is what the rule is asking for rather than a guard around the call.
    /// </summary>
    private static partial class Log
    {
        [LoggerMessage(
            EventId = 200,
            EventName = "JwksSigningKeysReady",
            Level = LogLevel.Information,
            Message = "Signing keys ready: {Count} trusted from the authorization server's JWKS.")]
        internal static partial void KeysReady(ILogger logger, int count);
    }

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var refresh = await source.RefreshAsync(cancellationToken).ConfigureAwait(false);
        var count = refresh.KeyCount;

        if (count == 0)
        {
            throw new InvalidOperationException(
                "No signing keys could be fetched from the authorization server, so this connector "
                + "would answer every request with a 401 that re-authenticating cannot fix. "
                + $"Refresh reported {refresh.Outcome}"
                + (refresh.Detail is null ? "." : $": {refresh.Detail}"));
        }

        Log.KeysReady(logger, count);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
