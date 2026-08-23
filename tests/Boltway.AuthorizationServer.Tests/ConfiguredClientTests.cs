using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Secrets;
using Microsoft.Extensions.DependencyInjection;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Clients a deployment names in configuration, rather than ones that name themselves.
/// </summary>
/// <remarks>
/// <para>
/// These existed as a seam, as a test double, and nowhere a deployment could reach.
/// <c>IClientResolver</c>, <c>IClientSecretStore</c> and <c>client_secret_basic</c> all shipped;
/// <c>CimdClientResolver</c> was the only implementation in <c>src/</c>. §7.1 says of the admin BFF
/// that "it uses the client store and <c>client_secret_basic</c> that already exist", and measured
/// while building that BFF, they did not.
/// </para>
/// <para>
/// The property most of this file is about is <b>coexistence</b>. A deployment serves Claude, which
/// identifies itself by a metadata URL, and its own admin UI, which cannot — a confidential client's
/// secret has no business in a document served over the public internet. Both resolvers are
/// registered, so the one that must not answer for the other's identifiers is the thing to pin.
/// </para>
/// </remarks>
public sealed class ConfiguredClientTests
{
    private static RegisteredRedirectUri Redirect(string raw)
    {
        Assert.True(RegisteredRedirectUri.TryRegister(raw, out var registered, out var error), error.ToString());

        return registered!.Value;
    }

    private static ConfiguredClient Admin(string? secret = "correct horse battery") => new(
        ClientIdentifier.ForPreRegistered("northwind-admin"),
        "Northwind admin",
        [Redirect("https://admin.northwind.example/signin-oidc")],
        secret is null ? null : Sha256Hash.OfString(secret));

    private static ConfiguredClientResolver ResolverFor(params ConfiguredClient[] clients) =>
        new(clients.ToDictionary(c => c.ClientId.Value!, StringComparer.Ordinal));

    private static readonly SubjectId Owner = SubjectId.FromStorage("usr_service");

    /// <summary>A service account: an owner, scopes, a secret, and no redirect URI.</summary>
    private static ConfiguredClient Nightly(
        SubjectId? owner = null, string scopes = "docs:read", string? secret = "correct horse battery")
    {
        _ = ScopeSet.TryParse(scopes, out var parsed, out _);

        return new ConfiguredClient(
            ClientIdentifier.ForPreRegistered("northwind-nightly"),
            "Nightly report",
            [],
            secret is null ? null : Sha256Hash.OfString(secret))
        {
            Owner = owner ?? Owner,
            Scopes = parsed,
        };
    }

    /// <summary>A client naming an owner does client_credentials, and only that.</summary>
    /// <remarks>
    /// The two sets not overlapping is the design rather than a default — a client offering both
    /// would be one a human can authorize *and* one holding a standing credential for somebody
    /// else's account, with which answer applying decided by the endpoint the caller used.
    /// </remarks>
    [Fact]
    public async Task A_client_naming_an_owner_gets_the_service_account_grant_and_not_the_code_flow()
    {
        var resolution = await ResolverFor(Nightly()).ResolveAsync(
            ClientIdentifier.ForPreRegistered("northwind-nightly"), CancellationToken.None);

        var client = resolution.Client;
        Assert.NotNull(client);

        Assert.Equal(["client_credentials"], client.GrantTypes);
        Assert.Equal(Owner, client.Owner);
        Assert.Equal("docs:read", client.AllowedScopes.ToWireString());
    }

    /// <summary>A client naming no owner is unchanged by any of this.</summary>
    [Fact]
    public async Task A_client_naming_no_owner_still_gets_the_code_flow_and_no_owner()
    {
        var resolution = await ResolverFor(Admin()).ResolveAsync(
            ClientIdentifier.ForPreRegistered("northwind-admin"), CancellationToken.None);

        var client = resolution.Client;
        Assert.NotNull(client);

        Assert.Equal(["authorization_code", "refresh_token"], client.GrantTypes);
        Assert.Null(client.Owner);
    }

    /// <summary>A service account with no secret is refused at startup, not at first use.</summary>
    /// <remarks>
    /// The failure it prevents is silent all the way down: the resolver produces a client whose
    /// auth method is None, the authenticator correctly authenticates a public client presenting
    /// nothing, and the grant then mints the owner's token for anybody who knows the client id.
    /// Every layer behaves correctly on a record that should not exist.
    /// </remarks>
    [Fact]
    public void A_service_account_without_a_secret_is_refused()
    {
        var services = new ServiceCollection();

        var error = Assert.Throws<InvalidOperationException>(
            () => services.AddConfiguredClients([Nightly(secret: null)]));

        Assert.Contains("no secret", error.Message, StringComparison.Ordinal);
    }

    /// <summary>A service account with no scopes could never obtain a token, so it is refused.</summary>
    [Fact]
    public void A_service_account_without_scopes_is_refused()
    {
        var services = new ServiceCollection();

        var error = Assert.Throws<InvalidOperationException>(
            () => services.AddConfiguredClients([Nightly(scopes: string.Empty)]));

        Assert.Contains("no scopes", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_configured_client_resolves_with_its_registered_redirect_and_secret_method()
    {
        var resolver = ResolverFor(Admin());

        var resolution = await resolver.ResolveAsync(
            ClientIdentifier.ForPreRegistered("northwind-admin"), CancellationToken.None);

        Assert.NotNull(resolution.Client);
        var client = resolution.Client;

        Assert.Equal(ClientType.Confidential, client.ClientType);
        Assert.Equal(ClientAuthMethod.ClientSecretBasic, client.TokenEndpointAuthMethod);
        Assert.Equal(
            ["https://admin.northwind.example/signin-oidc"],
            client.RedirectUris.Select(r => r.Value));

        // The kind says how this client was learned about, and it is derived from where it was
        // found rather than set beside it — an audit entry and the consent page both read it.
        Assert.Equal(ClientIdKind.PreRegistered, client.ClientId.Kind);
    }

    /// <summary>
    /// An id it has never heard of is <c>NotFound</c>, not an authoritative refusal.
    /// </summary>
    /// <remarks>
    /// <b>The assertion that keeps the two resolvers able to share a deployment.</b> The pipeline
    /// stops at the first authoritative answer, so a configured resolver that refused everything it
    /// did not recognise would make Claude's metadata URL unresolvable — and the symptom would be a
    /// vendor client that cannot connect, on a server that serves it perfectly well when the admin
    /// UI is not configured.
    /// </remarks>
    [Fact]
    public async Task An_unknown_id_is_not_found_rather_than_refused()
    {
        var resolver = ResolverFor(Admin());
        var claude = ClientIdentifier.ForCimd("https://claude.ai/oauth/mcp-oauth-client-metadata");

        Assert.False(resolver.CanResolve(claude));

        var resolution = await resolver.ResolveAsync(claude, CancellationToken.None);

        Assert.Null(resolution.Client);
        Assert.Equal(ClientResolutionError.NotFound, resolution.Error);
    }

    [Fact]
    public async Task A_client_with_no_secret_is_public_and_authenticates_with_none()
    {
        var resolver = ResolverFor(Admin(secret: null));

        var client = (await resolver.ResolveAsync(
            ClientIdentifier.ForPreRegistered("northwind-admin"), CancellationToken.None)).Client;

        Assert.Equal(ClientType.Public, client!.ClientType);
        Assert.Equal(ClientAuthMethod.None, client.TokenEndpointAuthMethod);
    }

    /// <summary>The secret store answers the hash, and nothing for a client it does not know.</summary>
    /// <remarks>
    /// Null means "this client has no secret", which the authenticator reads as "cannot authenticate
    /// with one" rather than as "any secret will do" — so answering null for an unknown id is the
    /// safe direction as well as the honest one.
    /// </remarks>
    [Fact]
    public async Task The_secret_store_answers_the_hash_and_nothing_for_a_stranger()
    {
        var configured = Admin();
        var store = new ConfiguredClientSecretStore(
            new Dictionary<string, ConfiguredClient>(StringComparer.Ordinal)
            {
                [configured.ClientId.Value!] = configured,
            });

        Assert.Equal(
            Sha256Hash.OfString("correct horse battery"),
            await store.FindAsync(ClientIdentifier.ForPreRegistered("northwind-admin"), CancellationToken.None));

        Assert.Null(await store.FindAsync(
            ClientIdentifier.ForPreRegistered("nobody"), CancellationToken.None));
    }

    /// <summary>
    /// The plaintext is not in the record, at any depth.
    /// </summary>
    /// <remarks>
    /// A deployment configures the hash and this holds the hash. The point of that is exactly this
    /// assertion: what is in memory, in a heap dump, or in whatever serialises a configuration
    /// object cannot be replayed as a credential.
    /// </remarks>
    [Fact]
    public void A_configured_client_never_holds_the_plaintext_secret()
    {
        var configured = Admin("a very specific secret nobody else would type");

        Assert.DoesNotContain(
            "a very specific secret nobody else would type",
            configured.ToString(),
            StringComparison.Ordinal);
    }
}
