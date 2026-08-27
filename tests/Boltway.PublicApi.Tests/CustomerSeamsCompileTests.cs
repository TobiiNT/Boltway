using System.Net;

using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Resources;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.PublicApi.Tests;

/// <summary>
/// A resource registry written the way a customer would have to write one.
/// </summary>
/// <remarks>
/// The existence of this type is most of the point - it is in an assembly with no
/// <c>InternalsVisibleTo</c> grant, so it compiles only while every member it touches is genuinely
/// public. The assertions below are secondary; the build is the test.
/// </remarks>
internal sealed class CustomerResourceRegistry : IResourceRegistry
{
    private readonly ResourceIdentifier _resource;
    private readonly ResourceRegistration _registration;

    public CustomerResourceRegistry(string canonical)
    {
        if (!ResourceIdentifier.TryRegister(canonical, out var resource, out var error))
        {
            throw new ArgumentException(error, nameof(canonical));
        }

        _resource = resource!;

        if (!ScopeSet.TryParse("read write", out var scopes, out var invalid))
        {
            throw new InvalidOperationException($"'{invalid}' is not a scope name.");
        }

        _registration = new ResourceRegistration(_resource, "A customer's MCP server", scopes);
    }

    public ValueTask<ResourceIdentifier?> ResolveAsync(
        RequestedResource requested, ClientRecord client, CancellationToken cancellationToken) =>
        ValueTask.FromResult(
            string.Equals(requested.Value, _resource.Canonical, StringComparison.Ordinal) ? _resource : null);

    public ValueTask<ResourceIdentifier?> DefaultForAsync(ClientRecord client, CancellationToken cancellationToken) =>
        ValueTask.FromResult<ResourceIdentifier?>(null);

    public ValueTask<IReadOnlyList<ResourceRegistration>> AllAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult<IReadOnlyList<ResourceRegistration>>([_registration]);
}

/// <summary>
/// A client resolver written the way a customer would have to write one.
/// </summary>
internal sealed class CustomerClientResolver : IClientResolver
{
    public bool CanResolve(ClientIdentifier clientId) => true;

    public ValueTask<ClientResolution> ResolveAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        if (!RegisteredRedirectUri.TryRegister("https://app.example.com/callback", out var redirect, out var error))
        {
            return ValueTask.FromResult(
                ClientResolution.Failed(ClientResolutionError.MetadataUnusable, error.ToString()));
        }

        return ValueTask.FromResult(ClientResolution.Resolved(new ClientRecord
        {
            ClientId = clientId,
            ClientType = ClientType.Public,
            TokenEndpointAuthMethod = ClientAuthMethod.None,
            RedirectUris = [redirect.Value],
            GrantTypes = ["authorization_code", "refresh_token"],
            ResponseTypes = ["code"],
        }));
    }
}

public class CustomerSeamsCompileTests
{
    private const string Canonical = "https://mcp.customer.example/mcp";

    /// <summary>
    /// The regression test for the bug that made this product unusable.
    /// </summary>
    /// <remarks>
    /// <c>IResourceRegistry</c> is public and required, and for a period no assembly outside this
    /// repository could implement it, because the only way to obtain the <c>ResourceIdentifier</c>
    /// it must return was <c>internal</c>. Every test in the solution passed throughout, because
    /// every test assembly that implemented the interface was on the grant list. This one is not,
    /// and never may be.
    /// </remarks>
    [Fact]
    public async Task A_customer_can_implement_a_resource_registry_from_the_public_api()
    {
        var registry = new CustomerResourceRegistry(Canonical);
        var client = await NewClientAsync();

        Assert.True(RequestedResource.TryParse(Canonical, out var requested));

        var resolved = await registry.ResolveAsync(requested, client, CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal(Canonical, resolved.Canonical);
    }

    [Fact]
    public async Task A_customer_can_implement_a_client_resolver_from_the_public_api()
    {
        var client = await NewClientAsync();

        Assert.Equal(ClientType.Public, client.ClientType);
        Assert.Single(client.RedirectUris);
    }

    /// <summary>
    /// The shipped registry is reachable and usable without writing an interface at all.
    /// </summary>
    /// <remarks>
    /// Opening the mint point made a custom registry possible. This is the other half - that the
    /// ordinary deployment shape, a fixed list of MCP servers known at startup, needs configuration
    /// rather than an implementation.
    /// </remarks>
    [Fact]
    public async Task The_shipped_registry_resolves_a_configured_resource()
    {
        var registry = Registry((Canonical, "Customer MCP"));
        var client = await NewClientAsync();

        Assert.True(RequestedResource.TryParse(Canonical, out var requested));

        var resolved = await registry.ResolveAsync(requested, client, CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal(Canonical, resolved.Canonical);
    }

    /// <summary>
    /// A-22, at the registry rather than at the token: <c>aud</c> is the full identifier.
    /// </summary>
    /// <remarks>
    /// A registry keyed by origin would answer this with the registration for <c>/mcp</c>, and every
    /// token minted for one MCP server would then be valid at every other one behind the same host.
    /// That exact bug shipped and broke ChatGPT custom connectors.
    /// </remarks>
    [Fact]
    public async Task The_shipped_registry_does_not_match_a_sibling_path_on_the_same_origin()
    {
        var registry = Registry((Canonical, "Customer MCP"));
        var client = await NewClientAsync();

        Assert.True(RequestedResource.TryParse("https://mcp.customer.example/other", out var sibling));

        Assert.Null(await registry.ResolveAsync(sibling, client, CancellationToken.None));
    }

    /// <summary>
    /// A-02: with two resources registered, a request naming none gets no default.
    /// </summary>
    /// <remarks>
    /// Picking one would make every token's audience depend on enumeration order, and RFC 8707
    /// registers no metadata field through which a client could ever notice.
    /// </remarks>
    [Fact]
    public async Task The_shipped_registry_refuses_to_guess_between_two_resources()
    {
        var registry = Registry(
            requireResourceParameter: false,
            ("https://a.customer.example/mcp", "A"),
            ("https://b.customer.example/mcp", "B"));

        var client = await NewClientAsync();

        Assert.Null(await registry.DefaultForAsync(client, CancellationToken.None));
    }

    /// <summary>
    /// The single-resource case does get a default, so the two-resource null above is a decision.
    /// </summary>
    /// <remarks>
    /// The control for the test above it. Without this, a registry whose <c>DefaultForAsync</c>
    /// simply returned <see langword="null"/> unconditionally would satisfy the A-02 test - and
    /// would be a different, silently worse behaviour.
    /// </remarks>
    [Fact]
    public async Task The_shipped_registry_defaults_when_there_is_only_one_resource()
    {
        var registry = Registry(requireResourceParameter: false, (Canonical, "Customer MCP"));
        var client = await NewClientAsync();

        var resolved = await registry.DefaultForAsync(client, CancellationToken.None);

        Assert.NotNull(resolved);
        Assert.Equal(Canonical, resolved.Canonical);
    }

    [Fact]
    public void The_shipped_registry_names_every_bad_identifier_not_just_the_first()
    {
        var error = Assert.Throws<ArgumentException>(() => Registry(
            ("http://insecure.example/mcp", "Insecure"),
            ("https://fragment.example/mcp#x", "Fragment")));

        Assert.Contains("insecure.example", error.Message, StringComparison.Ordinal);
        Assert.Contains("fragment.example", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_shipped_registry_refuses_the_same_identifier_twice()
    {
        Assert.Throws<ArgumentException>(() => new ConfiguredResourceRegistry(
            [Registration(Canonical, "First"), Registration(Canonical, "Second")]));
    }

    /// <summary>
    /// A nominated OIDC resource is returned where <c>DefaultForAsync</c> still refuses to guess.
    /// </summary>
    /// <remarks>
    /// The two methods disagreeing on the same registry is the point, not an inconsistency. A
    /// request naming no resource might have meant either of these two; a request carrying only
    /// <c>openid</c> cannot have meant either, because there is no operation in it to perform at
    /// one. The count is information about the first question and not about the second.
    /// </remarks>
    [Fact]
    public async Task The_shipped_registry_answers_a_nominated_oidc_resource_where_it_would_not_guess()
    {
        var registry = Registry(
            oidcResource: "https://b.customer.example/mcp",
            requireResourceParameter: false,
            resources:
            [
                ("https://a.customer.example/mcp", "A"),
                ("https://b.customer.example/mcp", "B"),
            ]);

        var client = await NewClientAsync();

        Assert.Null(await registry.DefaultForAsync(client, CancellationToken.None));

        var oidc = await registry.DefaultForOidcAsync(client, CancellationToken.None);
        Assert.NotNull(oidc);
        Assert.Equal("https://b.customer.example/mcp", oidc.Canonical);
    }

    /// <summary>
    /// Nominating nothing is the default, and it answers null.
    /// </summary>
    /// <remarks>
    /// The control for the test above, and the compatibility claim in one: every registry built
    /// before this parameter existed passes through this path, so "a deployment that nominates
    /// nothing behaves as it did" is asserted rather than assumed.
    /// </remarks>
    [Fact]
    public async Task The_shipped_registry_nominates_no_oidc_resource_by_default()
    {
        var registry = Registry(requireResourceParameter: false, (Canonical, "Customer MCP"));
        var client = await NewClientAsync();

        Assert.Null(await registry.DefaultForOidcAsync(client, CancellationToken.None));
    }

    /// <summary>
    /// Nominating a resource that is not registered is a boot failure, not a null.
    /// </summary>
    /// <remarks>
    /// Dropping it silently would turn one typo back into the <c>invalid_target</c> the nomination
    /// exists to remove - the same symptom, now with a configuration that looks correct. The
    /// message lists what <i>is</i> registered because the cause is nearly always a trailing slash
    /// or a wrong scheme, and the two strings side by side is the whole diagnosis.
    /// </remarks>
    [Fact]
    public void The_shipped_registry_refuses_to_nominate_an_unregistered_resource()
    {
        var error = Assert.Throws<ArgumentException>(() => Registry(
            oidcResource: "https://b.customer.example/mcp",
            requireResourceParameter: false,
            resources: [("https://a.customer.example/mcp", "A")]));

        Assert.Contains("https://b.customer.example/mcp", error.Message, StringComparison.Ordinal);
        Assert.Contains("https://a.customer.example/mcp", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A resource that fails to validate is reported before a nomination pointing at it.
    /// </summary>
    /// <remarks>
    /// Ordering, and it is deliberate. Both are wrong here, and an operator told "you nominated an
    /// unregistered resource" would go and fix the nomination - when the real fault is that the
    /// resource it names is <c>http</c> and never registered at all. The list comes first because
    /// fixing it makes the second error disappear on its own.
    /// </remarks>
    [Fact]
    public void A_misconfigured_resource_is_reported_before_a_nomination_that_names_it()
    {
        var error = Assert.Throws<ArgumentException>(() => Registry(
            oidcResource: "http://insecure.example/mcp",
            requireResourceParameter: false,
            resources: [("http://insecure.example/mcp", "Insecure")]));

        Assert.Contains("misconfigured", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("nominate", error.Message, StringComparison.Ordinal);
    }

    private static ConfiguredResourceRegistry Registry(
        string? oidcResource,
        bool requireResourceParameter,
        params (string Canonical, string Name)[] resources)
    {
        if (!ScopeSet.TryParse("read", out var scopes, out var invalid))
        {
            throw new InvalidOperationException($"'{invalid}' is not a scope name.");
        }

        return ConfiguredResourceRegistry.Create(
            resources.ToDictionary(r => r.Canonical, r => (r.Name, scopes), StringComparer.Ordinal),
            requireResourceParameter,
            oidcResource);
    }

    private static ConfiguredResourceRegistry Registry(params (string Canonical, string Name)[] resources) =>
        Registry(true, resources);

    private static ConfiguredResourceRegistry Registry(
        bool requireResourceParameter, params (string Canonical, string Name)[] resources)
    {
        if (!ScopeSet.TryParse("read", out var scopes, out var invalid))
        {
            throw new InvalidOperationException($"'{invalid}' is not a scope name.");
        }

        return ConfiguredResourceRegistry.Create(
            resources.ToDictionary(r => r.Canonical, r => (r.Name, scopes), StringComparer.Ordinal),
            requireResourceParameter);
    }

    private static ResourceRegistration Registration(string canonical, string name)
    {
        if (!ResourceIdentifier.TryRegister(canonical, out var resource, out var error))
        {
            throw new InvalidOperationException(error);
        }

        if (!ScopeSet.TryParse("read", out var scopes, out var invalid))
        {
            throw new InvalidOperationException($"'{invalid}' is not a scope name.");
        }

        return new ResourceRegistration(resource!, name, scopes);
    }

    /// <summary>
    /// A deployment can tell the one address answer with a single reading from the ones without.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Here rather than beside the behaviour tests because those live in an assembly this package
    /// grants <c>InternalsVisibleTo</c>, so they compile whether or not the members are public and
    /// prove nothing about what a stranger can reach. This assembly has no grant, so the calls below
    /// are the pin.
    /// </para>
    /// <para>
    /// Both are things a deployment genuinely needs. An operator alerting on <c>FetchOutcome</c>
    /// wants to page somebody for a link-local answer and not for the rest, because everything else
    /// in the blocklist is equally what a filtered resolver, an unconfigured host and an attack look
    /// like - so it has to be able to name the difference without re-deriving it from an address.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_deployment_can_tell_a_link_local_answer_from_an_ambiguous_one()
    {
        Assert.True(SpecialUseAddresses.IsLinkLocal(IPAddress.Parse("169.254.169.254")));

        // The control, and the reason the split is not just "is it blocked": this is refused too.
        Assert.False(SpecialUseAddresses.IsLinkLocal(IPAddress.Parse("0.0.0.0")));
        Assert.True(SpecialUseAddresses.IsBlocked(IPAddress.Parse("0.0.0.0")));

        // And the reason it can be read off an outcome without an address in hand.
        var blocked = new FetchOutcome.Blocked(BlockReason.LinkLocalAddress, "detail");
        Assert.Equal(BlockReason.LinkLocalAddress, blocked.Reason);
    }

    private static async Task<ClientRecord> NewClientAsync()
    {
        var resolution = await new CustomerClientResolver()
            .ResolveAsync(ClientIdentifier.ForPreRegistered("customer-app"), CancellationToken.None);

        Assert.NotNull(resolution.Client);
        return resolution.Client;
    }
}
