using Microsoft.AspNetCore.Builder;

namespace Boltway.ResourceServer.Authorization;

/// <summary>
/// Endpoint metadata: the scopes an access token must carry to reach this endpoint.
/// </summary>
/// <remarks>
/// Metadata rather than a filter, so that the same declaration is visible to the middleware that
/// writes the <c>401</c> as well as to the one that writes the <c>403</c>. That matters because the
/// no-credentials challenge (X-32) should name the scopes the endpoint actually needs: the MCP
/// scope-selection strategy reads the challenge's <c>scope</c> first and falls back to the metadata
/// document's whole <c>scopes_supported</c> only when the challenge has none, so an endpoint that
/// declares its scopes gets a minimal grant and one that does not gets everything.
/// </remarks>
public sealed class RequiredScopeMetadata
{
    /// <summary>Declare the scopes an endpoint requires.</summary>
    /// <param name="scopes">The scope names. Compared ordinally against the token's <c>scope</c> claim.</param>
    public RequiredScopeMetadata(params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        Scopes = [.. scopes];
    }

    /// <summary>The required scopes.</summary>
    public IReadOnlyList<string> Scopes { get; }
}

/// <summary>
/// Endpoint metadata: this endpoint needs a valid access token, whatever the default posture is.
/// </summary>
/// <remarks>
/// Redundant when <c>ProtectedResourceOptions.RequireBearerByDefault</c> is left on, which it is by
/// default. It exists for the host that turns the default off — a resource server mostly serving
/// public content with a few protected endpoints — so that "protected" is something an endpoint can
/// say for itself rather than a property of a configuration flag elsewhere.
/// </remarks>
public sealed class RequireBearerMetadata
{
    /// <summary>The single instance; the type carries no state.</summary>
    public static RequireBearerMetadata Instance { get; } = new();

    private RequireBearerMetadata()
    {
    }
}

/// <summary>Declaring what an endpoint requires.</summary>
public static class ResourceServerEndpointConventions
{
    /// <summary>
    /// Require a valid access token carrying every one of <paramref name="scopes"/>.
    /// </summary>
    /// <remarks>
    /// A token short of any of them is answered <c>403</c> with
    /// <c>error="insufficient_scope"</c> and the <b>whole</b> list in <c>scope</c> — not the missing
    /// subset. Claude asks for the union of the challenge's scopes and its discovery-time scope, and
    /// does not reliably carry forward what an earlier step-up granted, so a challenge naming only
    /// the delta re-authorizes the user into a narrower grant than they had.
    /// </remarks>
    public static TBuilder RequireScope<TBuilder>(this TBuilder builder, params string[] scopes)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(scopes);

        builder.Add(endpoint => endpoint.Metadata.Add(new RequiredScopeMetadata(scopes)));
        return builder;
    }

    /// <summary>Require a valid access token, without requiring any particular scope.</summary>
    public static TBuilder RequireBearer<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Add(endpoint => endpoint.Metadata.Add(RequireBearerMetadata.Instance));
        return builder;
    }
}
