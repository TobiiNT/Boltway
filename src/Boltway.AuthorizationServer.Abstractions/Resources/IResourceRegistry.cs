using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;

namespace Boltway.AuthorizationServer.Abstractions.Resources;

/// <summary>A protected resource this server issues tokens for.</summary>
/// <param name="Resource">
/// The canonical identifier, exactly as registered. Any HTTPS URL, path included — A-22, because an
/// MCP server lives at <c>https://mcp.example.com/mcp</c> and a scheme that demanded a proprietary
/// namespace would be one more ceremony between a customer and a working connector.
/// </param>
/// <param name="Name">A human name, for the consent page.</param>
/// <param name="Scopes">The scopes this resource defines.</param>
/// <param name="RequireResourceParameter">
/// Whether a request must name this resource explicitly rather than relying on a default.
/// </param>
public sealed record ResourceRegistration(
    ResourceIdentifier Resource,
    string Name,
    ScopeSet Scopes,
    bool RequireResourceParameter = true);

/// <summary>
/// The only source of a <see cref="ResourceIdentifier"/>.
/// </summary>
/// <remarks>
/// <para>
/// N-01's chokepoint. Inside the authorization server the only way to obtain a
/// <see cref="ResourceIdentifier"/> is <see cref="ResolveAsync"/>, and an access token cannot be
/// minted without one — so "accept the <c>resource</c> parameter and ignore it" and "stamp a house
/// default" have no code path there.
/// </para>
/// <para>
/// <b>What enforces that is a build gate, not the type system, and the difference matters.</b>
/// <see cref="ResourceIdentifier.TryRegister"/> is <see langword="public"/>, because this interface
/// is public and required and an implementation has to be able to return one — it was
/// <see langword="internal"/> for a period, during which no assembly outside the Boltway
/// repository could implement <c>IResourceRegistry</c> at all. Who may call it is instead held by an
/// IL rule over call sites, <c>Only_a_resource_registry_mints_a_resource_identifier</c>, which scans
/// this solution only. That is the right scope: the failure N-01 exists to stop is <i>this library</i>
/// silently stamping a house audience on a customer's behalf, where no client could detect it. A
/// customer's own registry choosing which resources exist is the role, not a threat.
/// </para>
/// <para>
/// This paragraph has twice claimed a stronger guarantee than the code had. It is written plainly
/// now because the claim is the thing an integrator relies on.
/// </para>
/// <para>
/// That matters because RFC 8707 registers no discovery metadata field, so a client has <b>no way
/// to detect</b> a server that ignores <c>resource</c>. A server that does issues tokens valid
/// everywhere the user has access, and a user who connects one hostile MCP server hands its
/// operator a token that works at all the others — with the client having done everything right.
/// </para>
/// </remarks>
public interface IResourceRegistry
{
    /// <summary>
    /// Resolve a requested resource, or <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <b>Unknown and not-permitted-for-this-client both return <see langword="null"/>, and the
    /// caller reports them identically.</b> Distinguishing them tells an attacker which resource
    /// identifiers exist, which is an enumeration oracle over the customer's internal service
    /// topology.
    /// </remarks>
    ValueTask<ResourceIdentifier?> ResolveAsync(
        RequestedResource requested, ClientRecord client, CancellationToken cancellationToken);

    /// <summary>
    /// The resource to use when a request names none.
    /// </summary>
    /// <remarks>
    /// A-02: consulted <b>only</b> when <c>resource</c> is absent, never as a fallback when one was
    /// sent and did not resolve. Returning <see langword="null"/> when more than one resource is
    /// registered is correct — silently picking one would make the audience depend on registration
    /// order.
    /// </remarks>
    ValueTask<ResourceIdentifier?> DefaultForAsync(ClientRecord client, CancellationToken cancellationToken);

    /// <summary>Everything registered, for the metadata document and the doctor.</summary>
    ValueTask<IReadOnlyList<ResourceRegistration>> AllAsync(CancellationToken cancellationToken);

    /// <summary>
    /// The resource a request that is <b>only</b> signing somebody in should be audienced at,
    /// or <see langword="null"/> if this server nominates none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Separate from <see cref="DefaultForAsync"/> because the question is different.</b> That
    /// one asks "is there one unambiguous resource here", and A-02 answers no as soon as there are
    /// two — picking one would make the audience of every token depend on dictionary order. This
    /// one asks something narrower: a request carrying nothing but OIDC's own scopes is not asking
    /// to reach a protected resource at all, it is asking who the user is, and the answer to *that*
    /// is not ambiguous however many resources are registered.
    /// </para>
    /// <para>
    /// <b>The caller must have established that the scope set is purely OIDC before calling this.</b>
    /// An implementation cannot check it — it is handed a client, not a scope set — so the guarantee
    /// lives at the call site. Calling it for a request that asks for anything else would hand that
    /// request an audience it did not name, which is the confused-deputy problem RFC 8707 exists to
    /// prevent.
    /// </para>
    /// <para>
    /// A default member returning <see langword="null"/>: a registry that has no opinion behaves
    /// exactly as it did before this existed, and no implementation outside this repository has to
    /// change to keep compiling.
    /// </para>
    /// </remarks>
    /// <param name="client">The client asking.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The resource, or <see langword="null"/>.</returns>
    ValueTask<ResourceIdentifier?> DefaultForOidcAsync(
        ClientRecord client, CancellationToken cancellationToken) =>
        ValueTask.FromResult<ResourceIdentifier?>(null);
}
