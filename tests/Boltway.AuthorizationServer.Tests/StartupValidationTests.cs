using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Federation;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Token;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A host that would fail on its first client fails while it is starting.
/// </summary>
/// <remarks>
/// <para>
/// Options validation was eager from the beginning; the service graph was not. Every seam the
/// request path reaches sits behind an <c>AddScoped(sp =&gt; …)</c> factory lambda, which
/// <c>ValidateOnBuild</c> cannot see through — measured with it switched on. So a host missing eight
/// services started cleanly, logged <c>Now listening on…</c>, and served both discovery documents
/// with HTTP 200 before failing on the first real request.
/// </para>
/// <para>
/// The failures were not equally visible, and that is what made this worth fixing rather than
/// documenting: a missing <c>IConsentStore</c> or <c>IUserSession</c> produced a
/// <c>server_error</c> redirect <i>after the user had typed their password</i>, and a missing
/// <c>IClientSecretStore</c> issued the authorization code first and then threw at <c>/token</c>, so
/// the failure landed on the client rather than on the deployment that caused it.
/// </para>
/// </remarks>
public sealed class StartupValidationTests
{
    /// <summary>Every missing service is named, not the first one found.</summary>
    /// <remarks>
    /// Three reviewers independently built a host for this server and all three discovered the
    /// required list the same way: one runtime failure at a time, restarting between each. Reporting
    /// them one per restart is the experience this project exists to be a reaction to.
    /// </remarks>
    [Fact]
    public async Task A_host_missing_every_seam_names_them_all_at_startup()
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(_ => { }));

        foreach (var name in new[]
        {
            nameof(IResourceRegistry), nameof(IGrantStore), nameof(IAuthorizationCodeStore),
            nameof(IRefreshTokenStore), nameof(IConsentStore), nameof(IUserSession),
            nameof(IUserStore), nameof(IPasswordHasher),
        })
        {
            Assert.Contains(name, error.Message, StringComparison.Ordinal);
        }

        // And it points at the one call that fixes most of them, because a list of eight interfaces
        // with no next step is only marginally better than a stack trace.
        Assert.Contains("AddBoltwayInMemoryStores", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two seams with a safe default are not reported, because they are registered.
    /// </summary>
    /// <remarks>
    /// <c>IConsentPolicy</c> and <c>IClientSecretStore</c> were required with no implementation
    /// anywhere, and both have an answer that is correct without knowing anything about the
    /// deployment: ask every time, and no client has a secret. Both fail closed. If either stopped
    /// being registered this test goes red rather than the failure moving to a request.
    /// </remarks>
    [Fact]
    public async Task The_seams_with_a_safe_default_are_not_demanded_of_the_host()
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(_ => { }));

        Assert.DoesNotContain(nameof(IConsentPolicy), error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(IClientSecretStore), error.Message, StringComparison.Ordinal);
    }

    /// <summary>Reported one at a time, so each message is attributable to its own omission.</summary>
    /// <remarks>
    /// The control for the first test. "Names them all" is also satisfied by a message that names
    /// every service unconditionally, which would be worse than useless — it would send a customer
    /// to register things they already had.
    /// </remarks>
    [Theory]
    [InlineData(nameof(IResourceRegistry))]
    [InlineData(nameof(IGrantStore))]
    [InlineData(nameof(IConsentStore))]
    [InlineData(nameof(IUserSession))]
    public async Task A_host_missing_exactly_one_seam_names_only_that_one(string missing)
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(services => RegisterEverythingExcept(services, missing)));

        Assert.Contains(missing, error.Message, StringComparison.Ordinal);

        foreach (var other in new[]
        {
            nameof(IResourceRegistry), nameof(IGrantStore), nameof(IConsentStore), nameof(IUserSession),
        }.Where(n => !string.Equals(n, missing, StringComparison.Ordinal)))
        {
            Assert.DoesNotContain(other, error.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>A fully wired host starts.</summary>
    /// <remarks>
    /// The control for all of the above. A validation that refuses everything would satisfy every
    /// other test in this file and break every deployment.
    /// </remarks>
    [Fact]
    public async Task A_fully_wired_host_starts()
    {
        using var host = await StartAsync(services => RegisterEverythingExcept(services, null));

        Assert.NotNull(host);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // "a way to authenticate", which is the condition federation made real
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A host with an account store, no password hasher and no upstream provider will not start.
    /// </summary>
    /// <remarks>
    /// The failure the old unconditional <c>IPasswordHasher</c> demand was really protecting against.
    /// Dropping that demand to let a federation-only deployment start had to not become "a host with
    /// no way to sign anyone in starts cleanly and fails at <c>/login</c>", which is a failure the
    /// user meets after a client has already redirected them there.
    /// </remarks>
    [Fact]
    public async Task A_host_with_no_password_hasher_and_no_provider_will_not_start()
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(services =>
            {
                RegisterEverythingExcept(services, null);
                services.RemoveAll<IPasswordHasher>();
            }));

        // Both ways out are named, not just the one this code's author had in mind.
        Assert.Contains("No user can sign in", error.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(IPasswordHasher), error.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(IExternalIdentityProvider), error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A federation-only host starts.
    /// </summary>
    /// <remarks>
    /// The control for the test above, and the whole reason the condition was changed. Without it,
    /// "the condition is real" is also satisfied by a condition that refuses everything.
    /// </remarks>
    [Fact]
    public async Task A_host_with_an_upstream_provider_and_no_password_hasher_starts()
    {
        using var host = await StartAsync(services =>
        {
            RegisterEverythingExcept(services, null);
            services.RemoveAll<IPasswordHasher>();
            services.AddSingleton<IExternalIdentityProvider>(new StubExternalProvider("google"));
        });

        Assert.NotNull(host);
    }

    [Fact]
    public async Task Two_providers_on_one_scheme_will_not_start()
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(services =>
            {
                RegisterEverythingExcept(services, null);
                services.AddSingleton<IExternalIdentityProvider>(new StubExternalProvider("google"));
                services.AddSingleton<IExternalIdentityProvider>(new StubExternalProvider("google"));
            }));

        Assert.Contains("registered under the scheme 'google'", error.Message, StringComparison.Ordinal);
    }

    /// <summary>A scheme that is not usable as a route segment will not start.</summary>
    /// <remarks>
    /// It becomes part of <c>/external/{scheme}/start</c>, so a scheme needing escaping produces a
    /// route nobody can reach and a sign-in button that does not work. A-18's rule about identifiers
    /// that end up in a path, applied where the path is built.
    /// </remarks>
    [Theory]
    [InlineData("Google")]
    [InlineData("goo gle")]
    [InlineData("../admin")]
    [InlineData("")]
    public async Task An_unusable_provider_scheme_will_not_start(string scheme)
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(services =>
            {
                RegisterEverythingExcept(services, null);
                services.AddSingleton<IExternalIdentityProvider>(new StubExternalProvider(scheme));
            }));

        Assert.Contains("not usable as a route segment", error.Message, StringComparison.Ordinal);
    }

    /// <summary>Provisioning without a subject factory will not start.</summary>
    /// <remarks>
    /// Demanded only when the policy that needs it is on. The seam is in
    /// <c>Boltway.AuthorizationServer.Abstractions</c> and the implementation is in
    /// <c>Boltway.Identity</c>, which the server does not reference — so this is the only place
    /// a host can be told it is missing.
    /// </remarks>
    [Fact]
    public async Task Provisioning_without_a_subject_factory_will_not_start()
    {
        var error = await Assert.ThrowsAsync<AuthorizationServerConfigurationException>(
            () => StartAsync(
                services =>
                {
                    RegisterEverythingExcept(services, null);
                    services.AddSingleton<IExternalIdentityProvider>(new StubExternalProvider("google"));
                },
                o => o.ExternalLogin.UnknownIdentity = UnknownExternalIdentityPolicy.Provision));

        Assert.Contains(nameof(ISubjectIdFactory), error.Message, StringComparison.Ordinal);
    }

    /// <summary>The control: with the factory registered, the same host starts.</summary>
    [Fact]
    public async Task Provisioning_with_a_subject_factory_starts()
    {
        using var host = await StartAsync(
            services =>
            {
                RegisterEverythingExcept(services, null);
                services.AddSingleton<IExternalIdentityProvider>(new StubExternalProvider("google"));
                services.AddSingleton<ISubjectIdFactory>(new UlidSubjectIdFactory(TimeProvider.System));
            },
            o => o.ExternalLogin.UnknownIdentity = UnknownExternalIdentityPolicy.Provision);

        Assert.NotNull(host);
    }

    /// <summary>A nonsense pending-request lifetime is a configuration failure, not a runtime one.</summary>
    [Fact]
    public void An_out_of_range_pending_request_lifetime_is_refused()
    {
        var options = new ExternalLoginOptions { PendingRequestLifetime = TimeSpan.FromHours(6) };

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, e => e.Contains("PendingRequestLifetime", StringComparison.Ordinal));
    }

    private static void RegisterEverythingExcept(IServiceCollection services, string? omit)
    {
        if (omit != nameof(IResourceRegistry))
        {
            services.AddSingleton<IResourceRegistry>(
                new TestResourceRegistry().Add(Build.Resource, "mcp:tools"));
        }

        // The shipped one-liner, then removed again when a test wants that store missing — which is
        // also a small check that the extension really does register what it says.
        services.AddBoltwayInMemoryStores();

        if (omit == nameof(IGrantStore))
        {
            services.RemoveAll<IGrantStore>();
        }

        if (omit == nameof(IConsentStore))
        {
            services.RemoveAll<IConsentStore>();
        }

        if (omit != nameof(IUserSession))
        {
            services.AddScoped<IUserSession>(_ => new TestUserSession(null));
        }

        // The shipped implementations, not doubles — this file is about what a real host must
        // register, so substituting fakes here would test the fixture rather than the wiring.
        services.AddSingleton<IUserStore>(new InMemoryUserStore());
                    services.AddSingleton<IRoleStore>(new InMemoryRoleStore());
        services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());
    }

    /// <summary>A provider that exists, so the startup condition can see one.</summary>
    /// <remarks>
    /// Never reached by a request in this file: these tests are about whether the host starts, and a
    /// provider that threw on use would still satisfy the condition — which is the point. Whether a
    /// provider works is <c>ExternalLoginFlowTests</c>' subject.
    /// </remarks>
    private sealed class StubExternalProvider(string scheme) : IExternalIdentityProvider
    {
        public string Scheme => scheme;

        public string DisplayName => "Stub";


        public string Issuer => "https://upstream.invalid";

        public ValueTask<ProviderAvailability> GetAvailabilityAsync(
            ExternalProviderContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(ProviderAvailability.Available);

        public ValueTask<string?> GetChallengeOriginAsync(CancellationToken cancellationToken) =>

            ValueTask.FromResult<string?>(null);


        public ValueTask<ExternalChallenge> BeginAsync(
            ExternalLoginContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(ExternalChallenge.To("https://upstream.example/authorize"));

        public ValueTask<ExternalLoginResult> CompleteAsync(
            ExternalCallbackContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult<ExternalLoginResult>(
                new ExternalLoginResult.Failed(ExternalFailureKind.ProviderUnavailable, "stub"));
    }

    private static async Task<IHost> StartAsync(
        Action<IServiceCollection> configure, Action<AuthorizationServerOptions>? options = null) =>
        await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(TestKeys.Ring());
                    services.AddSingleton<IClientResolver>(new TestClientResolver([Build.Client()]));

                    configure(services);

                    services.AddBoltwayAuthorizationServer(o =>
                    {
                        o.Issuer = Build.Issuer;
                        o.ScopesSupported.Add("openid");
                        o.ScopesSupported.Add("offline_access");
                        o.ScopesSupported.Add("mcp:tools");
                        o.RefreshTokenDerivationKey = Build.DerivationKey;

                        options?.Invoke(o);
                    });
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapBoltwayAuthorizationServer());
                }))
            .StartAsync();
}
