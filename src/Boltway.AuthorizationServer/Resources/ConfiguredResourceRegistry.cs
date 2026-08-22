using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Resources;

/// <summary>
/// A resource registry built from a fixed list, declared at startup.
/// </summary>
/// <remarks>
/// <para>
/// The shipped answer to N-01 for the deployment shape this product is actually sold into: one
/// authorization server in front of a handful of MCP servers whose addresses are known when the
/// process starts. A customer in that shape writes configuration, not an interface implementation.
/// </para>
/// <para>
/// It exists because of what an operability review measured. <c>IResourceRegistry</c> was public and
/// required, had no shipped implementation, and — because the only way to mint a
/// <see cref="ResourceIdentifier"/> was <c>internal</c> to a grant list the server assembly was not
/// on — could not be implemented by anybody outside this repository. The reviewer had to rename
/// their host assembly to <c>Boltway.AuthorizationServer.Tests</c> to make it compile. Opening
/// the mint point was half the fix; this is the other half, because "you must implement this
/// interface before the server will answer a single request" is a bad first five minutes even when
/// it is possible.
/// </para>
/// <para>
/// <b>Deliberately immutable after construction.</b> Registration validates once, at startup, where
/// a bad resource identifier is a boot failure with a message. A registry that could be added to at
/// runtime would move that failure to the first request that happened to name the new resource.
/// </para>
/// </remarks>
public sealed class ConfiguredResourceRegistry : IResourceRegistry
{
    private readonly IReadOnlyList<ResourceRegistration> _registrations;
    private readonly Dictionary<string, ResourceRegistration> _byCanonical;
    private readonly ResourceIdentifier? _oidcDefault;

    /// <summary>Build a registry from already-validated registrations.</summary>
    public ConfiguredResourceRegistry(IEnumerable<ResourceRegistration> registrations)
        : this(registrations, null)
    {
    }

    /// <summary>
    /// As above, naming the resource an OIDC-only request defaults into.
    /// </summary>
    /// <param name="registrations">The registrations.</param>
    /// <param name="oidcResource">
    /// The canonical identifier of one of <paramref name="registrations"/>, or <see langword="null"/>
    /// for a server that nominates none — which is the behaviour this type had before.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="oidcResource"/> names a resource that is not registered.
    /// </exception>
    public ConfiguredResourceRegistry(
        IEnumerable<ResourceRegistration> registrations, string? oidcResource)
    {
        ArgumentNullException.ThrowIfNull(registrations);

        _registrations = [.. registrations];

        // Ordinal, and on the full canonical string. A-22: a resource identifier carries a path, and
        // an origin-keyed lookup would make https://host/a and https://host/b the same resource —
        // which is the shipped bug that broke ChatGPT custom connectors, arriving through the back
        // door of a dictionary comparer.
        _byCanonical = new Dictionary<string, ResourceRegistration>(StringComparer.Ordinal);

        foreach (var registration in _registrations)
        {
            if (!_byCanonical.TryAdd(registration.Resource.Canonical, registration))
            {
                throw new ArgumentException(
                    $"'{registration.Resource.Canonical}' is registered twice. Two registrations for one "
                    + "identifier means the scopes that apply to it depend on list order.",
                    nameof(registrations));
            }
        }
        if (oidcResource is { Length: > 0 })
        {
            // Named rather than inferred, and it has to be one of the registered ones. A value that is
            // not registered would be a default nothing can resolve: every OIDC sign-in would be
            // audienced at an identifier this registry does not know, producing a token no resource
            // server can verify. Thrown rather than dropped to null, because dropping it turns a typo
            // in one environment variable back into the `invalid_target` this parameter exists to
            // remove — the same symptom, now with a correct-looking configuration.
            if (!_byCanonical.TryGetValue(oidcResource, out var oidc))
            {
                throw new ArgumentException(
                    $"The OIDC default resource `{oidcResource}` is not one of the registered resources. "
                    + "It has to be registered like any other, because a token audienced at an "
                    + "identifier this registry does not know is one nothing can verify. Registered: "
                    + (_byCanonical.Count == 0 ? "(none)" : string.Join(", ", _byCanonical.Keys)),
                    nameof(oidcResource));
            }

            _oidcDefault = oidc.Resource;
        }
    }

    /// <summary>
    /// Build a registry from configuration, validating every identifier.
    /// </summary>
    /// <param name="resources">
    /// Canonical identifier to (display name, scopes). The identifier must be an absolute
    /// <c>https</c> URL with no fragment; a path is expected rather than merely tolerated.
    /// </param>
    /// <param name="requireResourceParameter">
    /// Whether a request must name a resource explicitly. See
    /// <see cref="IResourceRegistry.DefaultForAsync"/> for why the answer is usually yes.
    /// </param>
    /// <param name="oidcResource">
    /// The canonical identifier one of <paramref name="resources"/> is registered under, nominated as
    /// the audience for a request that asks only for OIDC's own scopes. Must be a key of
    /// <paramref name="resources"/>. Null — the default — leaves the server nominating none, which is
    /// what every deployment did before this parameter existed, so omitting it changes nothing.
    /// </param>
    /// <exception cref="ArgumentException">
    /// An identifier did not validate. The message names every failure rather than the first,
    /// because a customer fixing one typo per restart is the experience this project exists to
    /// avoid.
    /// </exception>
    public static ConfiguredResourceRegistry Create(
        IReadOnlyDictionary<string, (string Name, ScopeSet Scopes)> resources,
        bool requireResourceParameter = true,
        string? oidcResource = null)
    {
        ArgumentNullException.ThrowIfNull(resources);

        // `oidcResource` is checked by the constructor rather than here, deliberately: a bad
        // identifier in `resources` should be reported before a nomination that points at it, so an
        // operator fixes the resource list first and does not read two unrelated errors as one.
        List<ResourceRegistration> registrations = [];
        List<string> errors = [];

        foreach (var (canonical, (name, scopes)) in resources)
        {
            if (!ResourceIdentifier.TryRegister(canonical, out var resource, out var error))
            {
                errors.Add(error!);
                continue;
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                errors.Add($"'{canonical}' has no display name. The consent page shows it to a user.");
                continue;
            }

            registrations.Add(new ResourceRegistration(resource!, name, scopes, requireResourceParameter));
        }

        if (errors.Count > 0)
        {
            throw new ArgumentException(
                "One or more protected resources are misconfigured:"
                + Environment.NewLine
                + string.Join(Environment.NewLine, errors.Select(e => "  - " + e)),
                nameof(resources));
        }

        return new ConfiguredResourceRegistry(registrations, oidcResource);
    }

    /// <inheritdoc />
    public ValueTask<ResourceIdentifier?> DefaultForOidcAsync(
        ClientRecord client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        // No A-02 count check here, and its absence is the point of this method existing separately.
        // `DefaultForAsync` refuses to choose between two registrations because a request that named
        // no resource might have meant either. A request carrying only OIDC's own scopes cannot have
        // meant either — it is not reaching a protected resource at all — so the number of them is
        // not information about this decision.
        //
        // The caller is responsible for having established that. See the interface.
        return ValueTask.FromResult(_oidcDefault);
    }

    /// <inheritdoc />
    public ValueTask<ResourceIdentifier?> ResolveAsync(
        RequestedResource requested, ClientRecord client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        // Unknown and not-permitted are the same answer, because distinguishing them enumerates the
        // customer's internal service topology for anyone who can reach /authorize. This registry
        // has no per-client permission model, so today only the first case can arise — the shape is
        // here so adding one later cannot introduce the oracle.
        return ValueTask.FromResult(
            _byCanonical.TryGetValue(requested.Value, out var registration) ? registration.Resource : null);
    }

    /// <inheritdoc />
    public ValueTask<ResourceIdentifier?> DefaultForAsync(ClientRecord client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);

        // A-02: exactly one registration means there is no ambiguity to resolve, so a request that
        // names no resource gets it. Two or more and the answer is null — picking one would make the
        // audience of every token depend on the order a dictionary happened to enumerate, which is a
        // silent cross-resource token leak that no client can detect (RFC 8707 has no metadata field
        // that would let it ask). Null here becomes an `invalid_target` the operator can read.
        //
        // A registration that requires an explicit `resource` opts out of even the single-resource
        // case.
        if (_registrations.Count == 1 && !_registrations[0].RequireResourceParameter)
        {
            return ValueTask.FromResult<ResourceIdentifier?>(_registrations[0].Resource);
        }

        return ValueTask.FromResult<ResourceIdentifier?>(null);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<ResourceRegistration>> AllAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(_registrations);
}
