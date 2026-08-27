using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Boltway.AuthorizationServer.Clients;

/// <summary>Wires the CIMD client resolver into a host.</summary>
public static class CimdServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="CimdClientResolver"/> as the last resolver in the chain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Order is behaviour, not style.</b> <c>GetServices&lt;IClientResolver&gt;()</c> returns
    /// registrations in the order they were added, and the pipeline takes the first resolver that
    /// answers. This one makes an outbound request, so it belongs last - which it is, provided the
    /// host registers its pre-registered and dynamic resolvers <i>before</i> calling
    /// <c>AddBoltwayAuthorizationServer</c>. A host that registers one afterwards puts it
    /// behind CIMD, and nothing here can detect that.
    /// </para>
    /// <para>
    /// <c>TryAddEnumerable</c> rather than <c>AddSingleton</c>, so calling this twice - directly and
    /// again through the CIMD profile - registers one resolver rather than two clients' worth of
    /// duplicate outbound fetches.
    /// </para>
    /// <para>
    /// The fetcher is registered with <c>TryAdd</c>, so a host that already supplied one keeps it.
    /// That is the seam a test uses to stay off the network, and the seam an operator uses to hand
    /// the fetcher a <see cref="SafeHttpFetcherOptions"/> with <c>AllowPrivateAddresses</c> set for
    /// local development.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddCimdClientResolver(
        this IServiceCollection services, Action<CimdClientResolverOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new CimdClientResolverOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(TimeProvider.System);

        // The host's clock, not TimeProvider.System, because the fetcher now counts a per-host
        // outbound budget on it (X-31). A fetcher holding its own clock would leave that window
        // undriveable from a test that moves the server's.
        services.TryAddSingleton<ISafeHttpFetcher>(sp => new SafeHttpFetcher(
            GuardPrivateAddresses(sp.GetService<SafeHttpFetcherOptions>(), sp.GetService<IHostEnvironment>()),
            resolver: null,
            time: sp.GetRequiredService<TimeProvider>()));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClientResolver, CimdClientResolver>(
            sp => new CimdClientResolver(
                sp.GetRequiredService<ISafeHttpFetcher>(),
                sp.GetRequiredService<TimeProvider>(),
                options,
                sp.GetService<Diagnostics.AuthorizationServerMetrics>())));

        return services;
    }

    /// <summary>
    /// Refuse to build a fetcher that can reach private addresses outside Development.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>SafeHttpFetcherOptions.AllowPrivateAddresses</c> has always said "Composition validation
    /// refuses to start a non-development host with this set, so the dangerous configuration cannot
    /// reach production by being forgotten in a config file." No such validation existed. A review
    /// measured the consequence on a real <c>Production</c> host: one anonymous
    /// <c>GET /authorize?client_id=https://127.0.0.1:&lt;port&gt;/c</c> - no session, no cookie -
    /// opened a TCP connection, and <c>https://169.254.169.254/latest/meta-data/</c> was fetched.
    /// The flag does not merely relax loopback; it short-circuits the whole RFC 6890 check.
    /// </para>
    /// <para>
    /// The same false sentence was repeated inside the test that proves the bypass works, so both
    /// places a reviewer would look to falsify it asserted it. That is the failure mode this project
    /// has now paid for four times, so the sentence is being made true rather than deleted.
    /// </para>
    /// <para>
    /// <b>What this does and does not cover.</b> It covers the DI path, which is how a deployment
    /// gets a fetcher. It cannot cover a caller who constructs <see cref="SafeHttpFetcher"/> itself
    /// - the test suite does exactly that, deliberately, and must keep being able to. So this is a
    /// guard on the configuration surface an operator actually touches, not a proof about the type.
    /// </para>
    /// <para>
    /// <see cref="IHostEnvironment"/> is resolved with <c>GetService</c>, not
    /// <c>GetRequiredService</c>: a container without one is a bare <c>ServiceCollection</c> in a
    /// test, not a production host. Absent an environment the answer is to refuse anyway, because
    /// "I could not tell" and "this is production" must not differ here.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The flag is set and the environment is not Development.
    /// </exception>
    private static SafeHttpFetcherOptions? GuardPrivateAddresses(
        SafeHttpFetcherOptions? options, IHostEnvironment? environment)
    {
        if (options is not { AllowPrivateAddresses: true } || environment is { } env && env.IsDevelopment())
        {
            return options;
        }

        throw new InvalidOperationException(
            "SafeHttpFetcherOptions.AllowPrivateAddresses is set"
            + (environment is null
                ? ", and no IHostEnvironment is registered so this cannot be confirmed to be a development host."
                : $", but the host environment is '{environment.EnvironmentName}', not Development.")
            + Environment.NewLine
            + "That flag disables the RFC 6890 special-use address check entirely — not just for "
            + "loopback — which turns /authorize into an unauthenticated port scanner and makes "
            + "http://169.254.169.254/ reachable by any anonymous request. CIMD section 8.6 permits "
            + "the exception for local development and says MUST NOT apply it in production."
            + Environment.NewLine
            + "Either clear the flag, or set the environment to Development if that is what this is.");
    }
}
