using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Redirects;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>A resolver holding a fixed set of clients.</summary>
internal sealed class TestClientResolver(params ClientRecord[] clients) : IClientResolver
{
    private readonly Dictionary<string, ClientRecord> _clients =
        clients.ToDictionary(c => c.ClientId.Value, StringComparer.Ordinal);

    /// <summary>Set to fail resolution with an authoritative error, to exercise the fall-through rule.</summary>
    public ClientResolution? ForcedFailure { get; set; }

    /// <summary>Which identifiers this resolver claimed. Lets a test assert a resolver was skipped.</summary>
    public List<string> Attempted { get; } = [];

    /// <summary>Disable a client, so a test can change the world mid-flow.</summary>
    public void Disable(string clientId) => _clients[clientId] = _clients[clientId] with { IsEnabled = false };

    public bool CanResolve(ClientIdentifier clientId) => true;

    public ValueTask<ClientResolution> ResolveAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        Attempted.Add(clientId.Value);

        if (ForcedFailure is { } failure)
        {
            return ValueTask.FromResult(failure);
        }

        return ValueTask.FromResult(
            _clients.TryGetValue(clientId.Value, out var client)
                ? ClientResolution.Resolved(client)
                : ClientResolution.Failed(ClientResolutionError.NotFound, "No such client."));
    }
}

/// <summary>A registry over a fixed set of resource URLs.</summary>
internal sealed class TestResourceRegistry : IResourceRegistry
{
    private readonly List<ResourceRegistration> _registrations = [];
    private ResourceIdentifier? _oidcDefault;

    /// <summary>Resources this client may not have, to exercise the indistinguishability rule.</summary>
    public HashSet<string> Forbidden { get; } = new(StringComparer.Ordinal);

    public TestResourceRegistry Add(string canonical, params string[] scopes)
    {
        var resource = ResourceIdentifier.TryRegister(canonical, out var identifier, out var error)
            ? identifier!
            : throw new InvalidOperationException(error);

        _ = ScopeSet.TryParse(string.Join(' ', scopes), out var scopeSet, out _);
        _registrations.Add(new ResourceRegistration(resource, canonical, scopeSet));
        return this;
    }

    public ValueTask<ResourceIdentifier?> ResolveAsync(
        RequestedResource requested, ClientRecord client, CancellationToken cancellationToken)
    {
        if (Forbidden.Contains(requested.Value))
        {
            return ValueTask.FromResult<ResourceIdentifier?>(null);
        }

        var found = _registrations.FirstOrDefault(
            r => string.Equals(r.Resource.Canonical, requested.Value, StringComparison.Ordinal));

        return ValueTask.FromResult(found?.Resource);
    }

    public ValueTask<ResourceIdentifier?> DefaultForAsync(ClientRecord client, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_registrations.Count == 1 ? _registrations[0].Resource : null);

    /// <summary>Nominate the resource a sign-in with no <c>resource</c> is audienced at.</summary>
    /// <remarks>
    /// Opt-in, and it must be called after the matching <see cref="Add"/>. A registry that has not
    /// been told falls through to the interface's default member and answers null — the same
    /// position every deployment written before this method existed is in, which is what makes
    /// "nothing changes unless you nominate one" a thing tests can observe rather than assert about
    /// their own double.
    /// </remarks>
    public TestResourceRegistry WithOidcDefault(string canonical)
    {
        _oidcDefault = _registrations
            .FirstOrDefault(r => string.Equals(r.Resource.Canonical, canonical, StringComparison.Ordinal))
            ?.Resource
            ?? throw new InvalidOperationException($"'{canonical}' is not registered, so it cannot be nominated.");

        return this;
    }

    public ValueTask<ResourceIdentifier?> DefaultForOidcAsync(
        ClientRecord client, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_oidcDefault);

    public ValueTask<IReadOnlyList<ResourceRegistration>> AllAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult<IReadOnlyList<ResourceRegistration>>(_registrations);
}

/// <summary>Builders for the objects every authorize test needs.</summary>
internal static class Build
{
    public const string Issuer = "https://auth.example.com";
    public const string Resource = "https://mcp.example.com/mcp";

    /// <summary>
    /// A second registered resource that no test's grant covers.
    /// </summary>
    /// <remarks>
    /// Needed to tell "widening beyond the grant" apart from "resource this server never heard of".
    /// A widening test that names an unregistered resource passes without the narrowing check,
    /// because the registry refuses it anyway — measured, the mutation removing that check survived.
    /// </remarks>
    public const string OtherResource = "https://other-mcp.example.com/mcp";

    /// <summary>A fixed derivation key, so a test's refresh tokens are reproducible.</summary>
    public static byte[] DerivationKey { get; } = [.. Enumerable.Range(0, 32).Select(i => (byte)i)];

    public static IssuerString ValidatedIssuer =>
        IssuerString.TryCreate(Issuer, out var issuer, out _) ? issuer : throw new InvalidOperationException();

    public static ScopeSet Scopes(string wire) =>
        ScopeSet.TryParse(wire, out var scopes, out _) ? scopes : throw new InvalidOperationException(wire);

    public static RegisteredRedirectUri Registered(string value) =>
        RegisteredRedirectUri.TryRegister(value, out var uri, out var error)
            ? uri!.Value
            : throw new InvalidOperationException($"'{value}' did not register: {error}.");

    public static ClientRecord Client(
        string clientId = "https://claude.ai/.well-known/oauth-client",
        ClientType type = ClientType.Public,
        params string[] redirectUris)
    {
        var uris = redirectUris.Length > 0 ? redirectUris : ["https://claude.ai/api/mcp/auth_callback"];

        return new ClientRecord
        {
            ClientId = ClientIdentifier.ForCimd(clientId),
            ClientType = type,
            TokenEndpointAuthMethod = ClientAuthMethod.None,
            RedirectUris = [.. uris.Select(Registered)],
            GrantTypes = ["authorization_code", "refresh_token"],
            ResponseTypes = ["code"],
        };
    }

    public static AuthorizeContext Context(IDictionary<string, string[]> parameters) =>
        new()
        {
            Parameters = new OAuthParameters(
                parameters.ToDictionary(p => p.Key, p => (IReadOnlyList<string>)p.Value, StringComparer.Ordinal)),
            CorrelationId = "test-correlation",
            Issuer = ValidatedIssuer,
            Now = new DateTimeOffset(2026, 8, 4, 12, 0, 0, TimeSpan.Zero),
        };

    /// <summary>A request every stage accepts, so a test can change exactly one thing.</summary>
    public static Dictionary<string, string[]> ValidRequest(string clientId = "https://claude.ai/.well-known/oauth-client") =>
        new(StringComparer.Ordinal)
        {
            ["client_id"] = [clientId],
            ["redirect_uri"] = ["https://claude.ai/api/mcp/auth_callback"],
            ["response_type"] = ["code"],
            ["code_challenge"] = ["E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"],
            ["code_challenge_method"] = ["S256"],
            ["scope"] = ["mcp:tools"],
            ["resource"] = [Resource],
            ["state"] = ["opaque-state"],
        };

    public static AuthorizePipeline Pipeline(
        IClientResolver? resolver = null,
        IResourceRegistry? resources = null,
        string supportedScopes = "openid offline_access mcp:tools story:read") =>
        new(
            [resolver ?? new TestClientResolver(Client())],
            resources ?? new TestResourceRegistry().Add(Resource, "mcp:tools"),
            Scopes(supportedScopes));

    public static AuthorizationServerOptions Options(Action<AuthorizationServerOptions>? tweak = null)
    {
        var options = new AuthorizationServerOptions { Issuer = Issuer };
        options.ScopesSupported.Add("openid");
        options.ScopesSupported.Add("offline_access");
        options.ScopesSupported.Add("mcp:tools");
        options.RefreshTokenDerivationKey = Build.DerivationKey;
        tweak?.Invoke(options);
        return options;
    }
}
