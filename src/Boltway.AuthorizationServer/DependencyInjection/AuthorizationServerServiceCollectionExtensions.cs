using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Clients;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Endpoints;
using Boltway.AuthorizationServer.Metadata;
using Boltway.AuthorizationServer.Token;
using Boltway.OAuth.Net;
using Boltway.OAuth.Tokens;
using Microsoft.AspNetCore.Routing;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Boltway.AuthorizationServer.DependencyInjection;

/// <summary>Thrown when a host is configured in a way that would serve a broken server.</summary>
/// <remarks>
/// A distinct type so a host can catch it and print the list, rather than surfacing an
/// <see cref="InvalidOperationException"/> that could have come from anywhere in startup.
/// </remarks>
public sealed class AuthorizationServerConfigurationException : Exception
{
    /// <summary>Every problem found, not just the first.</summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>Construct from the full list.</summary>
    public AuthorizationServerConfigurationException(IReadOnlyList<string> errors)
        : base(Format(errors)) => Errors = errors;

    /// <summary>Construct with a message.</summary>
    public AuthorizationServerConfigurationException(string message)
        : base(message) => Errors = [message];

    /// <summary>Construct with a message and an inner cause.</summary>
    public AuthorizationServerConfigurationException(string message, Exception innerException)
        : base(message, innerException) => Errors = [message];

    /// <summary>Construct with no detail. Present for the framework; prefer the other constructors.</summary>
    public AuthorizationServerConfigurationException()
        : this("The authorization server is misconfigured.") { }

    private static string Format(IReadOnlyList<string> errors) =>
        "The authorization server is misconfigured and will not start:"
        + Environment.NewLine
        + string.Join(Environment.NewLine, errors.Select(e => "  - " + e));
}

/// <summary>Wires the authorization server into a host.</summary>
public static class AuthorizationServerServiceCollectionExtensions
{
    /// <summary>
    /// Register the authorization server, failing the host if it is misconfigured.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Validation runs <b>here</b>, synchronously, and throws - not in an
    /// <c>IValidateOptions&lt;T&gt;</c> that fires on first resolution. The difference matters
    /// operationally: a deferred validation turns a misconfigured issuer into a 500 on the first
    /// client request, which is minutes after the deploy looked successful and is attributed to the
    /// client.
    /// </para>
    /// <para>
    /// The metadata document is built here too, for the same reason. It is the one artefact that
    /// proves the configuration produces something serveable, and building it at startup means a
    /// deployment that would have published a broken document never starts.
    /// </para>
    /// </remarks>
    /// <exception cref="AuthorizationServerConfigurationException">The configuration is invalid.</exception>
    public static IServiceCollection AddBoltwayAuthorizationServer(
        this IServiceCollection services, Action<AuthorizationServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AuthorizationServerOptions();
        configure(options);

        if (!options.TryValidate(out var errors))
        {
            throw new AuthorizationServerConfigurationException(errors);
        }


        var document = MetadataDocument.Create(options);

        // Frozen after the bytes exist. From here the served document is fixed, so a host that adds
        // a scope would create a divergence nothing detects: the options singleton would report a
        // scope the published metadata does not advertise, and the authorize pipeline - built from
        // the same options - would accept one no client can discover. Mutating now throws at the
        // mutation instead of going quiet.
        options.Freeze();

        services.AddSingleton(options);
        services.AddSingleton(document);

        // The advertised capability has to be a real one (N-06). The metadata document says
        // client_id_metadata_document_supported in this profile, so the resolver that honours it is
        // registered by the same switch. Last in the chain, because the host's own resolvers were
        // registered before this call - see AddCimdClientResolver.
        if (options.RegistrationProfile is ClientRegistrationProfile.ClientIdMetadataDocument)
        {
            services.AddCimdClientResolver();
        }

        // Scoped, because every one of these reaches a store, and a store is where a request-scoped
        // unit of work lives. Registering them as singletons would work today with the in-memory
        // stores and capture a DbContext the moment a real one is wired.
        services.AddScoped(sp => new AuthorizePipeline(
            [.. sp.GetServices<IClientResolver>()],
            sp.GetRequiredService<Abstractions.Resources.IResourceRegistry>(),
            options.ValidatedScopes));

        // Registered unconditionally, and read through GetService by the static callback: a host
        // that never names SessionRevalidation.ValidateAsync in its AddCookie simply never resolves
        // this. Scoped, because it reaches the directory.
        services.AddScoped(sp => new SessionRevalidation(
            sp.GetRequiredService<Abstractions.Users.IUserStore>(),
            options,
            sp.GetRequiredService<TimeProvider>(),
            sp.GetService<ILogger<SessionRevalidation>>()));

        // GetService rather than GetRequiredService for the notice, and the same opt-in shape the
        // claims mapper below uses: a deployment that registered no INotificationSender gets an
        // issuer that never looks for one. The notice itself takes the sender optionally too, so a
        // host that registers this and nothing to send with still starts and still authorizes.
        services.AddScoped(sp => new NewDeviceNotice(
            options,
            sp.GetRequiredService<Abstractions.Stores.IGrantStore>(),
            sp.GetService<Abstractions.Users.IUserStore>(),
            sp.GetService<Notifications.INotificationSender>(),
            sp.GetService<ILogger<NewDeviceNotice>>()));

        services.AddScoped(sp => new AuthorizationCodeIssuer(
            sp.GetRequiredService<Abstractions.Stores.IGrantStore>(),
            sp.GetRequiredService<Abstractions.Stores.IAuthorizationCodeStore>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<NewDeviceNotice>()));

        // private_key_jwt only. A deployment that never lists it pays for none of this: no key
        // cache, no assertion verifier, and no dependency on the replay store - which is why the
        // resolution below is GetService rather than GetRequiredService.
        if (options.TokenEndpointAuthMethods.Contains(ClientAuthMethod.PrivateKeyJwt))
        {
            services.TryAddSingleton(new ClientKeySourceOptions());
            services.TryAddSingleton(new ClientAssertionOptions());

            services.TryAddSingleton(sp => new ClientKeySource(
                sp.GetRequiredService<ISafeHttpFetcher>(),
                sp.GetRequiredService<TimeProvider>(),
                sp.GetRequiredService<ClientKeySourceOptions>()));

            services.TryAddScoped(sp => new ClientAssertionAuthenticator(
                sp.GetRequiredService<ClientKeySource>(),
                sp.GetRequiredService<Abstractions.Stores.IClientAssertionReplayStore>(),
                options,
                sp.GetRequiredService<TimeProvider>(),
                sp.GetRequiredService<ClientAssertionOptions>()));
        }

        services.AddScoped(sp => new ClientAuthenticator(
            [.. sp.GetServices<IClientResolver>()],
            sp.GetRequiredService<IClientSecretStore>(),
            [.. options.TokenEndpointAuthMethods],
            sp.GetService<ClientAssertionAuthenticator>()));

        // GetService for the claims mapper, and that is the whole opt-in: no mapper registered
        // means an access token carrying nothing about the subject but its identifier, which is
        // the right default for a resource server that only needs to know a request is authorised.
        // AddSubjectClaimsFromAccounts() is the one line that changes it.
        services.AddScoped(sp => new TokenIssuer(
            sp.GetRequiredService<JwtTokenMinter>(),
            sp.GetRequiredService<SigningKeyRing>(),
            sp.GetRequiredService<Abstractions.Stores.IRefreshTokenStore>(),
            options,
            sp.GetRequiredService<TimeProvider>(),
            sp.GetService<Abstractions.Tokens.IAccessTokenClaims>()));

        services.AddScoped(sp => new AuthorizationCodeGrant(
            sp.GetRequiredService<Abstractions.Stores.IAuthorizationCodeStore>(),
            sp.GetRequiredService<Abstractions.Stores.IGrantStore>(),
            sp.GetRequiredService<Abstractions.Stores.IRefreshTokenStore>(),
            sp.GetRequiredService<Abstractions.Resources.IResourceRegistry>(),
            sp.GetRequiredService<TokenIssuer>(),
            sp.GetRequiredService<TimeProvider>()));

        services.AddSingleton(new RefreshTokenDeriver(options.RefreshTokenDerivationKey));

        // The consent and login pages. TryAdd so a customer registering their own renderer before
        // this call keeps it - the view models stay ours either way, which is what makes N-14's
        // fields something a template can only fail to display rather than compute wrongly.
        // Both built from the options rather than by the container's constructor selection, so the
        // theme a deployment configured is the theme it gets. Resolving either type directly would
        // pick its parameterless constructor and silently produce unthemed pages - the setting
        // accepted, validated, and then ignored.
        //
        // Two registrations because they are two tiers. Replacing IInteractionLayout changes the
        // shell around markup the server still renders; replacing IInteractionRenderer replaces
        // that markup. A deployment should take the first and leave the second alone, which is why
        // the renderer resolves the layout rather than constructing one.
        //
        // The layout takes the localizer for the same reason the renderer does: the two sentences in
        // its brand panel are text on the page, so they come from the file the rest of the page's
        // text comes from. GetService, so a deployment with no translations gets the empty defaults
        // - which the panel omits - rather than a container failure.
        services.TryAddSingleton<IInteractionLayout>(sp =>
            new DefaultInteractionLayout(
                options.Interaction,
                sp.GetService<Microsoft.Extensions.Localization.IStringLocalizer>()));
        services.TryAddSingleton<IInteractionRenderer>(sp =>
            new DefaultInteractionRenderer(
                sp.GetRequiredService<IInteractionLayout>(),

                // GetService, so a deployment that configured no translations gets the built-in
                // English rather than a container failure. Registering the localizer is what
                // AddBoltwayInteractionLocalization does; not calling it is a valid shape.
                sp.GetService<Microsoft.Extensions.Localization.IStringLocalizer>(),

                // Threaded explicitly, for the reason the comment above gives about constructor
                // selection: this one is a plain bool, so a constructor picked by the container
                // would default it to false and the setting would be accepted, validated and
                // silently ignored - the exact failure that comment already exists to prevent.
                options.Interaction.ProvidersFirst));
        // Scoped, because it writes through stores that are. Registered here rather than left to
        // each host so that the CLI verbs and any admin endpoint resolve the same object graph -
        // two registrations would be two implementations again, arrived at from the container.
        //
        // It resolves IPasswordHasher and ISubjectIdFactory on construction, so a federation-only
        // deployment that never runs a password verb never builds it. That is the same shape the
        // verbs had before, moved from a GetRequiredService call to a constructor.
        services.TryAddScoped<Administration.UserAdministration>();

        // Registered rather than left absent, so the seam is composed in every deployment and a
        // customer replaces one registration instead of discovering they must add one. The shipped
        // implementation narrows nothing and ScopeEntitlement short-circuits on its type, so the
        // default costs a type check rather than a directory read.
        services.TryAddSingleton<Abstractions.Users.IScopeEntitlementPolicy,
            Abstractions.Users.PermissiveScopeEntitlementPolicy>();

        services.TryAddSingleton<IUserSignIn>(_ => new CookieUserSignIn());

        // X-31 for POST /login. TryAdd for both, so a host that registered its own limits before
        // this call keeps them - the seam SafeHttpFetcherOptions already uses. Registered here
        // rather than left to the host because the shipped default has to be the safe one: an
        // unbounded /login is what was measured, and "you should have added a limiter" is not a
        // defence a deployment can be expected to discover.
        services.TryAddSingleton(new LoginThrottleOptions());
        services.TryAddSingleton(sp => new LoginThrottle(
            sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<LoginThrottleOptions>()));

        // §3.1, and the same argument one notch louder: E-39 sends mail to an address the caller
        // chooses, so an unbounded one spends somebody else's inbox and the deployment's sending
        // reputation. Registered whether or not the flows are turned on, because the cost is one
        // object and the alternative is a conditional registration that is wrong the first time
        // somebody maps the endpoints by hand.
        services.TryAddSingleton(new RecoveryThrottleOptions());
        services.TryAddSingleton(sp => new RecoveryThrottle(
            sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<RecoveryThrottleOptions>()));

        // The words in the mail, and the lifetimes of the links. TryAdd for both: a deployment
        // writing its own subjects registers an INotificationRenderer before this call and keeps it.
        services.TryAddSingleton(new Administration.AccountRecoveryOptions());
        services.TryAddSingleton<Notifications.INotificationRenderer, Notifications.DefaultNotificationRenderer>();

        // Scoped, like UserAdministration and for the same reason: it reaches stores.
        services.TryAddScoped<Administration.AccountRecovery>();

        // Explicitly, because UseAntiforgery() auto-validates only handlers that BIND form data,
        // and the interaction handlers read Request.Form directly. Without the service registered
        // the endpoints throw rather than silently skipping the check.
        services.AddAntiforgery(o =>
        {
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.HttpOnly = true;

            // Strict is right here and wrong for the session cookie. This one is only ever needed on
            // a same-site form POST from our own page; the session cookie has to survive a top-level
            // cross-site navigation from claude.ai, so it must be Lax.
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.Name = "__Host-boltway-antiforgery";
        });

        services.AddScoped(sp => new RefreshTokenGrant(
            sp.GetRequiredService<Abstractions.Stores.IRefreshTokenStore>(),
            sp.GetRequiredService<Abstractions.Stores.IGrantStore>(),
            sp.GetRequiredService<Abstractions.Resources.IResourceRegistry>(),
            sp.GetRequiredService<TokenIssuer>(),
            sp.GetRequiredService<RefreshTokenDeriver>(),
            options,
            sp.GetRequiredService<TimeProvider>(),
            sp.GetService<Diagnostics.AuthorizationServerMetrics>(),
            sp));

        // Registered whether or not `client_credentials` is advertised, the same as the other two.
        // Options validation is what decides which grants a deployment offers; the dispatch switch
        // resolves a handler only for a grant that passed that check, so an unregistered one would
        // turn a configuration mistake into a DI exception at request time instead of the named
        // startup failure GrantTypesSupported already produces.
        services.AddScoped(sp => new ClientCredentialsGrant(
            sp.GetRequiredService<Abstractions.Users.IUserStore>(),
            sp.GetRequiredService<Abstractions.Stores.IGrantStore>(),
            sp.GetRequiredService<Abstractions.Resources.IResourceRegistry>(),
            sp.GetRequiredService<TokenIssuer>(),
            sp.GetRequiredService<TimeProvider>(),
            // Reaches the entitlement policy. Without it this grant is the one path to a token
            // that no role ceiling applies to.
            sp));

        // Registered unconditionally, and that costs nothing until something listens: an instrument
        // with no listener is a branch on a cached flag. What it does buy is that a host which
        // forgot AddMeter still has the instruments - so turning metrics on is a line in the
        // exporter's configuration rather than a rebuild.
        //
        // TryAdd, so a host that wants to own the lifetime keeps its own.
        services.TryAddSingleton<Diagnostics.AuthorizationServerMetrics>();

        // Registered here, mapped nowhere. A host that never calls MapStoreReadiness pays for one
        // uninitialised singleton; a host that does gets the endpoint without a second registration
        // call to forget. The route is opt-in because it is public and a library has no business
        // adding public routes to somebody else's server - see StoreReadiness.
        //
        // An explicit factory rather than the open generic: the constructor's last two parameters
        // are optional, and leaving the container to work out which constructor it can satisfy is
        // how a default silently becomes whatever the container happened to have. The windows are
        // chosen here, once, in the open.
        services.TryAddSingleton(sp => new Diagnostics.StoreReadiness(
            sp.GetRequiredService<Abstractions.Users.IUserStore>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<Diagnostics.StoreReadiness>>()));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<JwtTokenMinter>();

        // Federated sign-in. Registered unconditionally and harmless with no provider configured:
        // the state store is only reached from /external/{scheme}/*, and those routes refuse every
        // scheme when nothing is registered. TryAdd so a host that configured its own options before
        // this call keeps them.
        services.AddSingleton(options.ExternalLogin);
        services.TryAddSingleton(sp => new ExternalLoginStateStore(
            sp.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ExternalLoginOptions>()));

        // Two seams that were required, had no implementation anywhere, and whose safe answer does
        // not depend on anything about the deployment. Both fail closed, which is what makes them
        // defaults rather than conveniences: AlwaysAskConsentPolicy can only cause an extra prompt,
        // and NoClientSecretsStore can only cause a client presenting a secret to be refused.
        //
        // Storage is deliberately NOT defaulted the same way - see AddBoltwayInMemoryStores.
        // "Nobody chose in-memory and it went to production" is a worse outcome than a startup
        // error naming the store that is missing.
        services.TryAddSingleton<Abstractions.Consent.IConsentPolicy, AlwaysAskConsentPolicy>();
        services.TryAddSingleton<IClientSecretStore, NoClientSecretsStore>();

        return services;
    }

    /// <summary>
    /// Put the signed-in account's handle - and its email, when the grant covers it - into every
    /// access token.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Opt-in, because releasing a claim is not free: every resource server holding the token can
    /// read it, and one that only needs to know a request is authorised should not be handed a name
    /// and an address. Without this call an access token carries <c>iss</c>, <c>aud</c>,
    /// <c>sub</c>, <c>scope</c>, <c>client_id</c>, <c>iat</c>, <c>exp</c>, <c>jti</c> and
    /// <c>gid</c>, and nothing that says who the subject is.
    /// </para>
    /// <para>
    /// The reason to call it is an audit trail. A resource server recording <i>who did this</i> from
    /// a bare <c>sub</c> writes a ULID into its history, or keeps a second table mapping subjects to
    /// people - and the first is unreadable, while the second is a copy of this server's account
    /// list in a system that has no way to know when it went stale. Measured on the connector this
    /// was written for: every commit it made was attributed to
    /// <c>01KZAWCB5XY91G8N9XG84WR1EN</c>.
    /// </para>
    /// <para>
    /// Scoped, because it reaches <c>IUserStore</c> and every other consumer of a store here is.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddSubjectClaimsFromAccounts(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<Abstractions.Tokens.IAccessTokenClaims>(sp =>
            new UserAccountClaims(
                sp.GetRequiredService<Abstractions.Users.IUserStore>(),
                sp.GetRequiredService<Abstractions.Users.IRoleStore>()));

        return services;
    }

    /// <summary>
    /// The services a request will reach unconditionally, and the order a person would want them
    /// reported in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>IPasswordHasher</c> used to be on this list beside <c>IUserStore</c>, under a note saying
    /// that local passwords were the only way a user could authenticate and that the list would have
    /// to grow a condition when an upstream identity provider shipped. It has. The condition is in
    /// <see cref="CollectAuthenticationProblems"/>: <b>either</b> a password hasher <b>or</b> at least
    /// one <c>IExternalIdentityProvider</c>, and neither is still a startup failure.
    /// </para>
    /// <para>
    /// <c>IUserStore</c> stays unconditional, because both paths reach it. A federated sign-in
    /// resolves <c>(upstream issuer, upstream subject)</c> through
    /// <c>FindByExternalLoginAsync</c> - there is no deployment that authenticates a user and never
    /// touches the account store.
    /// </para>
    /// </remarks>
    private static readonly (Type Service, string Why)[] RequiredAtMapTime =
    [
        // First, because it is the one a host hits first and the one with the least discoverable
        // construction. It used to fail on its own two lines above this check - outside the
        // collected list - so a host learned about it, fixed it, and only then learned about the
        // other eight. Reporting nine at once is the whole point of collecting them.
        (typeof(SigningKeyRing),
            "the keys tokens are signed with. Construct: new SigningKeyRing([new ManagedSigningKey(new SigningKeyHandle(kid, SigningAlgorithm.RS256, key), SigningKeyState.Active, publishedAt, expiresAt)])."),

        (typeof(Abstractions.Resources.IResourceRegistry),
            "which resources this server issues tokens for. Ships: ConfiguredResourceRegistry.Create(...)."),
        (typeof(Abstractions.Stores.IGrantStore), "the grants behind issued tokens."),
        (typeof(Abstractions.Stores.IAuthorizationCodeStore), "authorization codes between /authorize and /token."),
        (typeof(Abstractions.Stores.IRefreshTokenStore), "refresh tokens and their rotation."),
        (typeof(Abstractions.Consent.IConsentStore), "what each user has already agreed to."),
        (typeof(Abstractions.Consent.IConsentPolicy), "whether to ask. A safe default is registered unless you replace it."),
        (typeof(IClientSecretStore), "confidential client secrets. A no-secrets default is registered unless you replace it."),
        (typeof(Abstractions.Users.IUserSession), "who is signed in. Ships: CookieUserSession, with AddAuthentication().AddCookie()."),
        (typeof(Abstractions.Users.IUserStore),
            "accounts, for POST /login and for resolving a federated identity to a local account."),
    ];

    /// <summary>Map every endpoint the server serves.</summary>
    /// <remarks>
    /// <para>
    /// The signing key ring is resolved here rather than taken as a parameter. It used to be a
    /// parameter, on the reasoning that a missing ring should stop the mapping call rather than
    /// surface at the first token request - but the token endpoint resolves it from the container,
    /// so one thing had two sources and a host could satisfy the parameter while leaving the
    /// container empty. That is what happened, and it presented as "no service for type
    /// SigningKeyRing" from inside a request.
    /// </para>
    /// <para>
    /// <see cref="ServiceProviderServiceExtensions.GetRequiredService{T}"/> at mapping time keeps
    /// the original guarantee: a host with no ring fails while it is starting, not while it is
    /// serving.
    /// </para>
    /// </remarks>
    public static IEndpointRouteBuilder MapBoltwayAuthorizationServer(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // The seam check runs first, before anything is resolved with GetRequiredService. The key
        // ring used to be fetched on the line above it, which meant a host missing everything was
        // told about the key ring alone, fixed that, restarted, and only then learned about the
        // other eight - one restart per service, which is the experience collecting them was
        // supposed to end. It is in the collected list now.
        RequireEveryServiceARequestWillReach(endpoints.ServiceProvider);
        RequireAdvertisedLocalesAreServed(endpoints.ServiceProvider);
        RequireASenderForTheEmailFlows(endpoints.ServiceProvider);
        RequireAReplayStoreForClientAssertions(endpoints.ServiceProvider);

        var document = endpoints.ServiceProvider.GetRequiredService<MetadataDocument>();
        var keyRing = endpoints.ServiceProvider.GetRequiredService<SigningKeyRing>();

        // Forces the fetcher to be built now rather than on the first /authorize, which is what
        // makes AddCimdClientResolver's AllowPrivateAddresses guard a startup failure. It was
        // written as a check inside the factory lambda - the exact lazy-resolution shape this whole
        // method exists to close - so a Production host with the flag set still bound, logged
        // "Now listening on", served both discovery documents, and only refused at the first
        // authorization request. Measured by the reviewer who built the sample.
        //
        // GetService, not GetRequiredService: a deployment using only pre-registered clients has no
        // CIMD resolver and therefore no fetcher, and that is a valid configuration rather than a
        // missing seam.
        _ = endpoints.ServiceProvider.GetService<ISafeHttpFetcher>();

        endpoints.MapOAuthDiscovery(document, keyRing);
        endpoints.MapAuthorize();
        endpoints.MapInteraction();
        endpoints.MapExternalLogin();
        endpoints.MapToken();

        // Routed and advertised move together, so `Every_advertised_endpoint_answers` keeps N-06
        // whichever way the flag is set. That test is why this endpoint could not simply be
        // advertised while it did not exist.
        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().UserInfoEnabled)
        {
            endpoints.MapUserInfo();
        }

        // Same pairing as UserInfo above, and it is the whole reason `/introspect` could be
        // advertised for so long without existing: one flag both routes and advertises, so
        // `Every_advertised_endpoint_answers` fails rather than a client discovering the 404.
        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().IntrospectionEnabled)
        {
            endpoints.MapIntrospection();
        }

        // The last of the four flags that advertised a path nothing routed. It is the same pairing
        // again, and the reason it is spelled out three times rather than folded into a loop is that
        // each flag decides its own default - see AuthorizationServerOptions.UserInfoEnabled for
        // what the four measured 404s cost.
        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().RevocationEnabled)
        {
            endpoints.MapRevocation();
        }

        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().AdministrationEnabled)
        {
            endpoints.MapAdministration();
        }

        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().SelfServiceEnabled)
        {
            endpoints.MapAccount();
        }

        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().SelfServicePagesEnabled)
        {
            endpoints.MapSelfServicePages();
        }

        if (endpoints.ServiceProvider.GetRequiredService<AuthorizationServerOptions>().PasswordRecoveryEnabled)
        {
            endpoints.MapPasswordRecovery();
        }

        return endpoints;
    }

    /// <summary>
    /// The email flows need somewhere for the email to go.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>PasswordRecoveryEnabled</c> with no <c>INotificationSender</c> registered is a reset
    /// endpoint that answers 202, mints a token, and delivers nothing. Every observable signal says
    /// it worked; the only thing that does not happen is the one the caller is waiting for, and they
    /// find out by checking an inbox that stays empty. That is the failure shape this server refuses
    /// to start into.
    /// </para>
    /// <para>
    /// The check is here rather than in <c>TryValidate</c> because it is about the container rather
    /// than about the options - <c>AddBoltwayAuthorizationServer</c> runs before the host has
    /// finished registering services, so asking then would refuse a deployment that registers its
    /// sender afterwards.
    /// </para>
    /// <para>
    /// <c>IUserTokenStore</c> is checked with it, because a flow that cannot persist a link cannot
    /// redeem one either - and both storage packages register it, so a deployment hits this only by
    /// wiring stores by hand.
    /// </para>
    /// </remarks>
    /// <summary>
    /// <c>private_key_jwt</c> needs somewhere to remember the assertions it has accepted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same shape as the email-flow check below, and the same reason: a flag turned on without
    /// the seam behind it produces a server that starts, serves discovery advertising the method,
    /// and then fails on the first client that uses it - after that client has been told, by the
    /// document, that it would work.
    /// </para>
    /// <para>
    /// <b>Not fixed by falling back to an in-memory set.</b> That is available and both storage
    /// packages register one, so the only host reaching this message is one wiring stores by hand.
    /// Substituting a per-process replay guard silently would be the worse failure: it admits one
    /// use of an assertion per replica, and nothing about that is visible from outside.
    /// </para>
    /// </remarks>
    private static void RequireAReplayStoreForClientAssertions(IServiceProvider services)
    {
        var options = services.GetRequiredService<AuthorizationServerOptions>();

        if (!options.TokenEndpointAuthMethods.Contains(ClientAuthMethod.PrivateKeyJwt))
        {
            return;
        }

        List<string> missing = [];

        if (services.GetService<Abstractions.Stores.IClientAssertionReplayStore>() is null)
        {
            missing.Add(
                "TokenEndpointAuthMethods contains private_key_jwt and no IClientAssertionReplayStore "
                + "is registered. RFC 7523 assertions would be verified and never remembered, so any "
                + "captured assertion could be presented again until it expired. Both storage packages "
                + "register one — AddBoltwayInMemoryStores() for development, "
                + "AddBoltwayPostgreSqlStores(...) for a deployment — or drop private_key_jwt from "
                + "the list.");
        }

        if (services.GetService<ISafeHttpFetcher>() is null)
        {
            missing.Add(
                "TokenEndpointAuthMethods contains private_key_jwt and no ISafeHttpFetcher is "
                + "registered. A client's signing keys are fetched from the jwks_uri in its own "
                + "metadata, which is a URL this server does not control, so it goes through the "
                + "guarded fetcher and nothing else. The CIMD profile registers one; a host that "
                + "replaced it must register its own.");
        }

        if (missing.Count > 0)
        {
            throw new AuthorizationServerConfigurationException(missing);
        }
    }

    private static void RequireASenderForTheEmailFlows(IServiceProvider services)
    {
        if (!services.GetRequiredService<AuthorizationServerOptions>().PasswordRecoveryEnabled)
        {
            return;
        }

        List<string> missing = [];

        if (services.GetService<Notifications.INotificationSender>() is null)
        {
            missing.Add(
                "PasswordRecoveryEnabled is set and no INotificationSender is registered. The "
                + "reset endpoint would answer 202, mint a link, and deliver nothing. Register one "
                + "— Boltway.Notifications.Smtp ships an implementation — or turn the flows "
                + "off.");
        }

        if (services.GetService<Abstractions.Users.IUserTokenStore>() is null)
        {
            missing.Add(
                "PasswordRecoveryEnabled is set and no IUserTokenStore is registered. Reset and "
                + "verification links live in it, so nothing could be issued or redeemed. Both "
                + "storage packages register one.");
        }

        if (missing.Count > 0)
        {
            throw new AuthorizationServerConfigurationException(missing);
        }
    }

    /// <summary>
    /// What the discovery document claims about language must be what the middleware does.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ui_locales_supported</c> was a free list copied into both documents, with a comment citing
    /// <c>N-06</c> and permitting exactly what it forbade - a deployment could advertise <c>vi</c>
    /// and serve English to everyone who asked. This is the generated-from-what-exists half, done as
    /// a comparison rather than an assignment because the two are configured in separate calls and
    /// a comparison does not care which ran first.
    /// </para>
    /// <para>
    /// It refuses in both directions. An advertised locale the middleware will not serve is a client
    /// asking for a language it cannot get; a served locale nobody advertises is a capability no
    /// client will ever ask for, which is a quieter waste and still a document that does not describe
    /// the server.
    /// </para>
    /// </remarks>
    private static void RequireAdvertisedLocalesAreServed(IServiceProvider resolved)
    {
        var advertised = resolved.GetRequiredService<AuthorizationServerOptions>().UiLocalesSupported;

        var localization = resolved
            .GetService<Microsoft.Extensions.Options.IOptions<Microsoft.AspNetCore.Builder.RequestLocalizationOptions>>();

        // No localization configured is the ordinary shape: the pages are in one language, and a
        // deployment naming it - or naming nothing - is telling the truth either way. Only the
        // multi-locale claim needs a mechanism behind it.
        if (localization is null)
        {
            if (advertised.Count > 1)
            {
                throw new InvalidOperationException(
                    "UiLocalesSupported lists " + advertised.Count + " locales ("
                    + string.Join(", ", advertised)
                    + ") and no localization is configured, so every page is served in one language "
                    + "whatever a client asks for. Call AddBoltwayInteractionLocalization, or "
                    + "list the one language these pages are written in.");
            }

            return;
        }

        var served = (localization.Value.SupportedUICultures ?? [])
            .Select(c => c.Name)
            .Where(name => name.Length > 0)
            .ToList();

        var unserved = advertised.Where(a => !served.Contains(a, StringComparer.OrdinalIgnoreCase)).ToList();
        var unadvertised = served.Where(s => !advertised.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();

        if (unserved.Count > 0 || unadvertised.Count > 0)
        {
            throw new InvalidOperationException(
                "ui_locales_supported and the request-localization middleware disagree. "
                + (unserved.Count > 0
                    ? "Advertised and not served: " + string.Join(", ", unserved) + ". "
                    : string.Empty)
                + (unadvertised.Count > 0
                    ? "Served and not advertised: " + string.Join(", ", unadvertised) + ". "
                    : string.Empty)
                + "The document has to describe the server: a client that respects the list will ask "
                + "for a language it cannot be given, and neither side sees an error.");
        }
    }

    /// <summary>
    /// A deployment must be able to authenticate somebody.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The condition the old comment on <see cref="RequiredAtMapTime"/> asked for. Demanding
    /// <c>IPasswordHasher</c> unconditionally would refuse a federation-only deployment, which is a
    /// legitimate shape - an organisation that has an identity provider and does not want a second
    /// password database. Dropping the demand entirely would let a host start with no way for a user
    /// to sign in at all, which fails at <c>/login</c> after a client has already been redirected
    /// there: exactly the "starts cleanly, breaks on the first client" failure this whole method
    /// family exists to move to startup.
    /// </para>
    /// <para>
    /// So: at least one of the two, and the message names both ways out rather than the one the
    /// author of this code happened to have in mind.
    /// </para>
    /// <para>
    /// Provider schemes are checked in the same pass, because a scheme that is not usable as a path
    /// segment produces a route nobody can reach and a URL on the login page that does not work -
    /// and it is a configuration mistake, which belongs at startup with the others.
    /// </para>
    /// <para>
    /// It reports into the <i>same</i> list as the seam check below and the two throw once, together.
    /// Splitting them was the first draft and it was wrong for the reason that method's own comment
    /// gives: a host missing everything would have been told about eight interfaces, fixed them,
    /// restarted, and only then learned it also had no way to sign anyone in.
    /// </para>
    /// </remarks>
    private static void CollectAuthenticationProblems(IServiceProvider resolved, List<string> problems)
    {
        var hasher = resolved.GetService<Abstractions.Users.IPasswordHasher>();
        var providers = resolved.GetServices<Abstractions.Federation.IExternalIdentityProvider>().ToList();

        if (hasher is null && providers.Count == 0)
        {
            problems.Add(
                "No user can sign in to this deployment. Register one of:" + Environment.NewLine
                + "      - IPasswordHasher, for local accounts. Ships: new Argon2idPasswordHasher() "
                + "from Boltway.Identity." + Environment.NewLine
                + "      - an IExternalIdentityProvider, for federated sign-in. Ships: "
                + "AddExternalIdentityProvider(GoogleFederation.Options(clientId, clientSecret)) "
                + "from Boltway.Federation.Oidc.");
        }

        // Duplicate schemes route the same path twice and make which provider answers depend on
        // registration order - which is the kind of thing that differs between a developer's machine
        // and production.
        foreach (var duplicate in providers
            .GroupBy(p => p.Scheme, StringComparer.Ordinal)
            .Where(g => g.Count() > 1))
        {
            problems.Add(
                $"Two identity providers are registered under the scheme '{duplicate.Key}'. "
                + "The scheme is the route segment, so only one of them would ever be reachable.");
        }

        // Provisioning mints a subject, and the ULID factory that mints one lives in
        // Boltway.Identity, which this assembly does not reference. Demanded only when the
        // policy that needs it is switched on: a deployment that refuses unknown identities never
        // reaches the factory, and requiring it anyway would be a seam nothing calls.
        if (resolved.GetRequiredService<ExternalLoginOptions>().UnknownIdentity
                is UnknownExternalIdentityPolicy.Provision
            && resolved.GetService<Abstractions.Users.ISubjectIdFactory>() is null)
        {
            problems.Add(
                "ExternalLoginOptions.UnknownIdentity is Provision, which mints a local account on a "
                + "first federated sign-in, and no ISubjectIdFactory is registered. Ships: "
                + "new UlidSubjectIdFactory(TimeProvider.System) from Boltway.Identity.");
        }

        foreach (var provider in providers)
        {
            if (!IsUsableScheme(provider.Scheme))
            {
                problems.Add(
                    $"The identity provider '{provider.GetType().Name}' has scheme "
                    + $"'{provider.Scheme}', which is not usable as a route segment. It must be 1-32 "
                    + "characters of [a-z0-9-], because it becomes part of /external/{scheme}/start.");
            }
        }
    }

    /// <summary>
    /// Whether a provider scheme is safe as a bare path segment.
    /// </summary>
    /// <remarks>
    /// Duplicated from <c>OidcProviderOptions</c> rather than shared, because this assembly does not
    /// reference the federation packages and must not: the whole point of the
    /// <c>IExternalIdentityProvider</c> seam is that a customer's own provider is not required to
    /// come from ours. The rule is four characters of predicate and both copies are pinned by a test
    /// that drives a bad scheme through this method.
    /// </remarks>
    private static bool IsUsableScheme(string? scheme) =>
        !string.IsNullOrEmpty(scheme)
        && scheme.Length <= 32
        && scheme.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');

    /// <summary>
    /// Fail at startup for a seam a request would have failed on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Options validation is eager; the service graph was not. Every seam below is behind an
    /// <c>AddScoped(sp =&gt; …)</c> factory lambda, so it is first resolved inside a request - and
    /// <c>ValidateOnBuild</c> cannot see through a factory lambda either, which was measured with it
    /// switched on. So a host with nine of these missing started cleanly, printed
    /// <c>Now listening on…</c>, served both discovery documents with HTTP 200, and then failed on
    /// the first real client.
    /// </para>
    /// <para>
    /// The failures were not equally visible, which is the part that mattered. A missing
    /// <c>IResourceRegistry</c> is a 500 on <c>/authorize</c>. A missing <c>IConsentStore</c> or
    /// <c>IUserSession</c> is a <c>server_error</c> redirect <b>after the user has typed their
    /// password</b>. A missing <c>IClientSecretStore</c> issues the code first and throws at
    /// <c>/token</c>, so the failure lands on the client. Three reviewers independently built a host
    /// for this server and all three found the list the same way: one runtime failure at a time.
    /// </para>
    /// <para>
    /// This runs at <c>Map</c> time rather than at <c>Add</c> time because that is the first moment
    /// the container exists and the host has finished registering - checking earlier would refuse a
    /// host that registers its stores after calling <c>AddBoltwayAuthorizationServer</c>, which
    /// is a perfectly ordinary way to write a <c>Program.cs</c>.
    /// </para>
    /// <para>
    /// Every missing service is reported, not the first. A customer fixing one typo per restart is
    /// the experience this project exists to be a reaction to.
    /// </para>
    /// </remarks>
    /// <exception cref="AuthorizationServerConfigurationException">
    /// One or more required services are not registered.
    /// </exception>
    private static void RequireEveryServiceARequestWillReach(IServiceProvider services)
    {
        // A scope, because most of these are registered scoped and resolving a scoped service from
        // the root provider throws a different, more confusing exception than the one being written.
        using var scope = services.CreateScope();

        List<string> missing = [];

        foreach (var (service, why) in RequiredAtMapTime)
        {
            try
            {
                if (scope.ServiceProvider.GetService(service) is null)
                {
                    missing.Add($"{service.Name} — {why}");
                }
            }
            catch (InvalidOperationException resolution)
            {
                // Registered, but not constructible: one of its own constructor arguments is
                // missing. The shipped case is CookieUserSession, which takes IHttpContextAccessor -
                // and without it the host fails with the framework's generic "unable to resolve
                // service while attempting to activate" several layers from the cause. Naming the
                // seam being built and quoting the inner reason turns that into a sentence, and it
                // does so for any seam rather than for the one that happened to bite first.
                missing.Add($"{service.Name} — registered, but could not be constructed: {resolution.Message}");
            }
        }

        CollectAuthenticationProblems(scope.ServiceProvider, missing);

        if (missing.Count == 0)
        {
            return;
        }

        throw new AuthorizationServerConfigurationException(
            "The authorization server is missing services that every request path reaches, so it "
            + "would start cleanly and fail on the first client:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, missing.Select(m => "  - " + m))
            + Environment.NewLine + Environment.NewLine
            + "For a single instance or a first run, AddBoltwayInMemoryStores() from "
            + "Boltway.Storage.InMemory registers all five in-memory stores. Note that it keeps everything "
            + "in memory: refresh tokens and consent do not survive a restart.");
    }
}
