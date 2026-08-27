using Boltway.AuthorizationServer.Abstractions.Federation;
using Boltway.Federation.Google;
using Boltway.Federation.Oidc;
using Boltway.OAuth.Net;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The relying party on its own, without the authorization server around it.
/// </summary>
/// <remarks>
/// <c>ExternalLoginFlowTests</c> drives everything through HTTP, which is the right shape for the
/// endpoints and the wrong shape for questions about the provider's own configuration - a
/// <c>typ</c> allow-list or a key-set refetch is a property of this class, and reaching it through
/// three redirects makes the assertion about the plumbing instead.
/// </remarks>
public sealed class OidcExternalProviderTests
{
    private sealed record Harness(FakeUpstreamProvider Upstream, OidcExternalProvider Provider, IUpstreamEndpointClient Http)
        : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Provider.Dispose();
            (Http as IDisposable)?.Dispose();
            await Upstream.DisposeAsync();
        }
    }

    private static async Task<Harness> StartAsync(Action<OidcProviderOptions>? configure = null)
    {
        var upstream = await FakeUpstreamProvider.StartAsync();
        var options = upstream.Options();

        configure?.Invoke(options);

        var http = new UpstreamEndpointClient(
            FakeUpstreamProvider.TransportOptions(), FakeUpstreamProvider.Resolver, TimeProvider.System);

        return new Harness(upstream, new OidcExternalProvider(options, http, TimeProvider.System), http);
    }

    private const string Callback = "https://auth.example.com/external/google/callback";

    private static ExternalCallbackContext Callback_(string verifier = "any-verifier") =>
        new("upstream-code", Callback, verifier, new Dictionary<string, string>(StringComparer.Ordinal));

    /// <summary>The control for everything below: a well-formed exchange authenticates.</summary>
    [Fact]
    public async Task A_well_formed_exchange_produces_a_principal()
    {
        await using var harness = await StartAsync();

        harness.Upstream.Behaviour.Nonce = "the-nonce";
        harness.Upstream.Behaviour.Email = "person@example.com";

        var result = await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None);

        var principal = Assert.IsType<ExternalLoginResult.Authenticated>(result).Principal;

        Assert.Equal(harness.Upstream.Issuer, principal.Issuer);
        Assert.Equal("upstream-subject-1", principal.Subject);

        // Returned uncompared. The comparison is the server's, against the pending-request cookie.
        Assert.Equal("the-nonce", principal.Nonce);
        Assert.Equal("person@example.com", principal.Claims["email"]);
    }

    /// <summary>
    /// The <c>typ</c> header is checked against the configured set.
    /// </summary>
    /// <remarks>
    /// <c>ValidTypes</c> is unset by default in <c>Microsoft.IdentityModel</c>, which is the defect
    /// N-09 exists for. Pointing the configured set at a value the upstream does not send is the only
    /// way to show the check is live - the fake signs <c>typ: JWT</c>, like every real provider - so
    /// a token refused here is refused on the header alone, and the test above is the control that
    /// the same token is otherwise accepted.
    /// </remarks>
    [Fact]
    public async Task An_id_token_whose_typ_is_not_in_the_configured_set_is_rejected()
    {
        await using var harness = await StartAsync(o =>
        {
            o.IdTokenTypeHeaders.Clear();
            o.IdTokenTypeHeaders.Add("at+jwt");
        });

        var result = await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None);

        Assert.Equal(
            ExternalFailureKind.IdentityTokenRejected,
            Assert.IsType<ExternalLoginResult.Failed>(result).Kind);
    }

    /// <summary>An empty <c>typ</c> allow-list cannot be expressed.</summary>
    [Fact]
    public async Task An_empty_typ_allow_list_is_refused_at_construction()
    {
        await using var upstream = await FakeUpstreamProvider.StartAsync();

        var options = upstream.Options();
        options.IdTokenTypeHeaders.Clear();

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, e => e.Contains("IdTokenTypeHeaders", StringComparison.Ordinal));
    }

    /// <summary>
    /// An RFC 9207 <c>iss</c> that disagrees is refused before the code is spent.
    /// </summary>
    /// <remarks>
    /// A mix-up attack in progress. Refusing before the exchange matters: spending the code at the
    /// wrong token endpoint is what hands it over.
    /// </remarks>
    [Fact]
    public async Task An_authorization_response_iss_that_disagrees_is_refused_without_an_exchange()
    {
        await using var harness = await StartAsync();

        var result = await harness.Provider.CompleteAsync(
            new ExternalCallbackContext(
                "upstream-code",
                Callback,
                "any-verifier",
                new Dictionary<string, string>(StringComparer.Ordinal) { ["iss"] = "https://elsewhere.example" }),
            CancellationToken.None);

        Assert.Equal(
            ExternalFailureKind.IdentityTokenRejected,
            Assert.IsType<ExternalLoginResult.Failed>(result).Kind);

        Assert.Empty(harness.Upstream.TokenRequests);
    }

    /// <summary>A matching <c>iss</c> is fine, and an absent one is fine.</summary>
    /// <remarks>
    /// The control for the test above. Many conformant providers do not send <c>iss</c> at all, so
    /// refusing its absence would break them - and a check that refused every response would satisfy
    /// the test above just as well.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task An_authorization_response_iss_that_matches_or_is_absent_is_accepted(bool present)
    {
        await using var harness = await StartAsync();

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        if (present)
        {
            parameters["iss"] = harness.Upstream.Issuer;
        }

        var result = await harness.Provider.CompleteAsync(
            new ExternalCallbackContext("upstream-code", Callback, "any-verifier", parameters),
            CancellationToken.None);

        Assert.IsType<ExternalLoginResult.Authenticated>(result);
    }

    /// <summary>
    /// A key set is fetched once and reused, and refetched when a token names a <c>kid</c> it lacks.
    /// </summary>
    /// <remarks>
    /// Both halves in one test because each is the other's control. Caching without refetching means
    /// every sign-in fails through an upstream's key rotation; refetching on any failure means a
    /// forged signature costs an outbound request.
    /// </remarks>
    [Fact]
    public async Task The_key_set_is_cached_and_refetched_only_for_an_unknown_kid()
    {
        await using var harness = await StartAsync(o => o.JwksMinimumRefreshInterval = TimeSpan.FromTicks(1));

        Assert.IsType<ExternalLoginResult.Authenticated>(
            await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None));
        Assert.Equal(1, harness.Upstream.JwksFetches);

        // A second good exchange reuses the cache.
        Assert.IsType<ExternalLoginResult.Authenticated>(
            await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None));
        Assert.Equal(1, harness.Upstream.JwksFetches);

        // A bad signature under a `kid` we do hold is not a rotation and buys no fetch.
        harness.Upstream.Behaviour.SignWithWrongKey = true;

        Assert.IsType<ExternalLoginResult.Failed>(
            await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None));
        Assert.Equal(1, harness.Upstream.JwksFetches);

        // A `kid` we do not hold does, and it still fails - the refetch is a way to learn about
        // rotation, not a way to accept a stranger.
        harness.Upstream.Behaviour.SignWithWrongKey = false;
        harness.Upstream.Behaviour.SignWithUnknownKid = true;

        Assert.IsType<ExternalLoginResult.Failed>(
            await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None));
        Assert.Equal(2, harness.Upstream.JwksFetches);
    }

    /// <summary>The refetch floor holds an unknown <c>kid</c> to one fetch per interval.</summary>
    /// <remarks>
    /// The control for the row above: with the shipped floor rather than a near-zero one, a burst of
    /// tokens naming random <c>kid</c>s - which anyone who can reach the callback can send - buys no
    /// fetches at all inside the interval.
    /// </remarks>
    [Fact]
    public async Task An_unknown_kid_cannot_drive_one_jwks_fetch_per_request()
    {
        await using var harness = await StartAsync();

        Assert.IsType<ExternalLoginResult.Authenticated>(
            await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None));

        harness.Upstream.Behaviour.SignWithUnknownKid = true;

        for (var i = 0; i < 5; i++)
        {
            Assert.IsType<ExternalLoginResult.Failed>(
                await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None));
        }

        // Still one: the default JwksMinimumRefreshInterval is five minutes and this test takes
        // milliseconds, so not one of the five was allowed to refetch.
        Assert.Equal(1, harness.Upstream.JwksFetches);
    }

    /// <summary>The discovery document is fetched once and cached.</summary>
    [Fact]
    public async Task Discovery_is_fetched_once()
    {
        await using var harness = await StartAsync();

        await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None);
        await harness.Provider.CompleteAsync(Callback_(), CancellationToken.None);

        Assert.Equal(1, harness.Upstream.DiscoveryFetches);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // configuration
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Google is configuration, and this is the whole of it.
    /// </summary>
    /// <remarks>
    /// The claim the project split is for. If this test ever needs a Google-specific branch to pass,
    /// "Google is not special" has stopped being true.
    /// </remarks>
    [Fact]
    public void The_google_provider_is_the_generic_one_with_three_values_filled_in()
    {
        var options = GoogleFederation.Options("123-abc.apps.googleusercontent.com", "a-secret");

        Assert.True(options.TryValidate(out var errors), string.Join("; ", errors));
        Assert.Equal("google", options.Scheme);
        Assert.Equal("https://accounts.google.com", options.ValidatedIssuer.Value);
        Assert.Equal("123-abc.apps.googleusercontent.com", options.ValidatedClientId.Value);

        // Nothing is hard-coded but the issuer: the three endpoints come from discovery, which is
        // what makes the same class work for a provider whose endpoints are on other hosts.
        Assert.Null(options.ValidatedAuthorizationEndpoint);
        Assert.Null(options.ValidatedTokenEndpoint);
        Assert.Null(options.ValidatedJwksUri);
        Assert.Equal(
            "https://accounts.google.com/.well-known/openid-configuration",
            options.ValidatedDiscoveryUri!.Value.Value);

        // `openid` and nothing else. An email is not an identity here, so asking for one by default
        // would be asking for data no decision may depend on.
        Assert.Equal(["openid"], options.Scopes);
    }

    [Theory]
    [InlineData("state")]
    [InlineData("nonce")]
    [InlineData("code_challenge")]
    [InlineData("redirect_uri")]
    public void A_reserved_authorization_parameter_cannot_be_overridden(string name)
    {
        var options = GoogleFederation.Options("client", "secret");
        options.AuthorizationParameters[name] = "chosen-by-configuration";

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, e => e.Contains($"may not contain '{name}'", StringComparison.Ordinal));
    }

    [Fact]
    public void An_issuer_that_is_not_an_https_url_is_refused()
    {
        var options = GoogleFederation.Options("client", "secret", o => o.Issuer = "http://accounts.google.com");

        Assert.False(options.TryValidate(out var errors));
        Assert.Contains(errors, e => e.Contains("Issuer", StringComparison.Ordinal));
    }

    /// <summary>
    /// A provider whose options do not validate cannot be constructed.
    /// </summary>
    /// <remarks>
    /// The constructor re-validates rather than trusting the registration extension, because it is
    /// public and reachable without it. Skipping validation is not merely untidy: it leaves
    /// <c>ValidatedIssuer</c> empty, and every ID token's <c>iss</c> would then be compared against
    /// the empty string.
    /// </remarks>
    [Fact]
    public async Task A_provider_with_unusable_options_cannot_be_constructed()
    {
        await using var upstream = await FakeUpstreamProvider.StartAsync();

        var options = upstream.Options();
        options.Issuer = "not-a-url";

        using var http = new UpstreamEndpointClient(
            FakeUpstreamProvider.TransportOptions(), FakeUpstreamProvider.Resolver, TimeProvider.System);

        Assert.Throws<ArgumentException>(
            () => new OidcExternalProvider(options, http, TimeProvider.System));
    }
}
