using Boltway.OAuth.Net;
using Microsoft.Extensions.DependencyInjection;

using RsExtensions = Boltway.ResourceServer.DependencyInjection.JwksSigningKeysExtensions;

namespace Boltway.Mcp;

/// <summary>
/// Where <c>AddJwksSigningKeys</c> used to live.
/// </summary>
/// <remarks>
/// <para>
/// It moved to <c>Boltway.ResourceServer</c> in 0.4.0, because nothing about it was MCP-shaped: it
/// wires a key source into <c>ProtectedResourceOptions</c> and touches no MCP type. Filing it here
/// meant a resource-server author looking for it in the resource-server package did not find it -
/// measured on the first consumer outside this repository, who wrote the class again by hand.
/// </para>
/// <para>
/// <b>A forwarder rather than a removal.</b> Deleting it would break every connector already
/// calling it for a change that gains them nothing; this way the call keeps working and the
/// compiler says once where it went. At 0.x a break is allowed, which is exactly why one that buys
/// nothing should not be taken.
/// </para>
/// </remarks>
public static class JwksSigningKeysExtensions
{
    /// <summary>
    /// Fill and keep filling <c>ProtectedResourceOptions.SigningKeySource</c> from the
    /// authorization server's published key set.
    /// </summary>
    /// <param name="services">The container.</param>
    /// <param name="issuer">The authorization server's issuer.</param>
    /// <param name="configure">Optional key-source settings.</param>
    /// <returns><paramref name="services" />, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services" /> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="issuer" /> is not a usable issuer.</exception>
    [Obsolete(
        "Moved to Boltway.ResourceServer.DependencyInjection.JwksSigningKeysExtensions - it is "
            + "resource-server wiring and touches no MCP type. This forwarder calls it and will be "
            + "removed at 1.0.")]
    public static IServiceCollection AddJwksSigningKeys(
        this IServiceCollection services,
        string issuer,
        Action<JwksKeySourceOptions>? configure = null)
        => RsExtensions.AddJwksSigningKeys(services, issuer, configure);
}
