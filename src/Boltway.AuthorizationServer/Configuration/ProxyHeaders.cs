using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace Boltway.AuthorizationServer.Configuration;

/// <summary>
/// The forwarded-headers options for a deployment that is always behind exactly one proxy.
/// </summary>
/// <remarks>
/// <para>
/// This exists as a function in a library rather than an object literal in the host because the
/// object literal was wrong for a month and nothing could see it. The host wrote:
/// </para>
/// <code>
/// new ForwardedHeadersOptions
/// {
///     KnownIPNetworks = { },
///     KnownProxies = { },
/// }
/// </code>
/// <para>
/// <c>= { }</c> in an object initializer is a <b>collection</b> initializer: it means "call
/// <c>Add</c> zero times". It does not clear anything. Measured — the options came back holding
/// their defaults, <c>127.0.0.0/8</c> and <c>::1</c>, exactly as if the two lines were absent.
/// </para>
/// <para>
/// The cost of that was not cosmetic. A non-empty known list turns the proxy check on, Caddy
/// reaches these containers from a Docker bridge address rather than loopback, so every forwarded
/// header was <b>rejected</b>: <c>Request.IsHttps</c> stayed false behind working TLS, which
/// answers 500 on the sign-in form because antiforgery will not write a Secure cookie over what it
/// believes is http — and <c>RemoteIpAddress</c> stayed the proxy, so <c>LoginThrottle</c>'s
/// per-source limit put the whole deployment in one bucket. Fixing that limit was the entire
/// stated purpose of the change that introduced these two lines. It never worked, on Cloud Run
/// either, and the comment above it said the lists were cleared.
/// </para>
/// <para>
/// <b>Cleared means "believe the immediate peer", and that is sound only while the application is
/// unreachable except through the proxy.</b> True on Cloud Run, and true under the compose file
/// because it publishes no container port. Publish 8080 to the internet and <c>X-Forwarded-Proto</c>
/// becomes a header anyone can assert. If a deployment ever needs a reachable port, enumerate the
/// proxy instead of clearing the list.
/// </para>
/// </remarks>
public static class ProxyHeaders
{
    /// <summary>
    /// Options that trust <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c> from the immediate
    /// peer, and from nothing further out.
    /// </summary>
    /// <param name="hops">
    /// How many proxies stand in front. One is what both deployments have — Cloud Run's front end,
    /// or Caddy.
    /// <para>
    /// <b>This is the number to change if a CDN is ever put in front.</b> With Cloudflare's proxy
    /// on, the chain arriving at Caddy is already <c>client, cloudflare</c>, Caddy appends itself,
    /// and a limit of 1 takes the last hop — so every request is attributed to Caddy's neighbour
    /// rather than to the person, and the per-source login limit goes back to being per deployment.
    /// It fails the same silent way it failed before any of this existed.
    /// </para>
    /// </param>
    public static ForwardedHeadersOptions BehindOneProxy(int hops = 1)
    {
        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            ForwardLimit = hops,
        };

        // Clear(), never `= { }`. The whole reason this type exists is that the second one compiles,
        // reads as intent, and does nothing.
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Clear();

        return options;
    }
}
