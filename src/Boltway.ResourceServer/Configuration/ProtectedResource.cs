using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Boltway.OAuth.Primitives.Ids;
using Boltway.ResourceServer.Metadata;

namespace Boltway.ResourceServer.Configuration;

/// <summary>
/// <see cref="ProtectedResourceOptions"/> after validation: the identity, the document, the URLs.
/// </summary>
/// <remarks>
/// <para>
/// Built once at startup and held as a singleton, so the metadata bytes and their ETag are decided
/// before the first request rather than per request. Two consequences worth having: the ETag is a
/// hash of exactly the bytes that get sent, so a conditional request cannot be answered <c>304</c>
/// against a body that has since changed; and the challenge's <c>resource_metadata</c> URL is the
/// same string on every response, so a client's discovery cache key does not move.
/// </para>
/// <para>
/// <b>On the <see cref="ResourceIdentifier"/> below.</b> N-01's chokepoint is that an access token
/// cannot be <i>minted</i> for an audience nobody validated, which holds because
/// <c>AccessTokenDescriptor.Audience</c> requires a <see cref="ResourceIdentifier"/> and, inside the
/// authorization server, only an <c>IResourceRegistry</c> produces one. A resource server naming
/// <i>itself</i> from configuration is a different act: an RS-only deployment holds no signing key
/// and has no mint path to reach.
/// </para>
/// <para>
/// Three sentences that used to stand here were false and are worth recording rather than deleting.
/// They said <c>ResourceIdentifier</c>'s factory is <c>internal</c> to Primitives, that this
/// assembly holds an <c>InternalsVisibleTo</c> grant, and that no <b>public</b> factory exists
/// anywhere. <c>ResourceIdentifier.TryRegister</c> is <see langword="public"/>; this assembly holds
/// no grant and does not need one; and the "no public factory" claim has not been true since it was
/// opened so that customers could implement <c>IResourceRegistry</c> at all. What actually keeps
/// this type from becoming a second mint path is that it is <see langword="internal"/>, that no
/// public member of this assembly returns a <see cref="ResourceIdentifier"/> - asserted over the
/// whole public surface by a test in this project's test assembly - and that
/// <c>Only_a_resource_registry_mints_a_resource_identifier</c> names this type in an allowlist, so
/// a second one appearing is a diff a reviewer sees.
/// </para>
/// </remarks>
internal sealed class ProtectedResource
{
    private ProtectedResource(
        ResourceIdentifier identifier,
        IssuerString issuer,
        string metadataUrl,
        string metadataPath,
        ImmutableArray<byte> json,
        string etag,
        IReadOnlyList<string> scopesSupported)
    {
        Identifier = identifier;
        Issuer = issuer;
        MetadataUrl = metadataUrl;
        MetadataPath = metadataPath;
        Json = json;
        ETag = etag;
        ScopesSupported = scopesSupported;
    }

    /// <summary>This resource's identifier. The expected <c>aud</c>, compared in full.</summary>
    internal ResourceIdentifier Identifier { get; }

    /// <summary>The expected <c>iss</c>, and the one entry in <c>authorization_servers</c>.</summary>
    internal IssuerString Issuer { get; }

    /// <summary>
    /// The absolute, path-inserted metadata URL. This is what goes in every challenge.
    /// </summary>
    /// <remarks>
    /// The path-inserted form rather than the root form, because RFC 9728 §3.1 makes it the
    /// normative location for an identifier that has a path - and because a client that follows the
    /// pointer never has to guess. RFC 9728 §5.1 puts no same-origin requirement on this value.
    /// </remarks>
    internal string MetadataUrl { get; }

    /// <summary>The path component of <see cref="MetadataUrl"/>, for route matching.</summary>
    internal string MetadataPath { get; }

    /// <summary>The serialized metadata document.</summary>
    /// <remarks>
    /// An <see cref="ImmutableArray{T}"/> rather than a <c>byte[]</c> or a
    /// <see cref="ReadOnlyMemory{T}"/>: this object is a singleton and the ETag was computed from
    /// these bytes once, so a caller able to write through the buffer would change every subsequent
    /// response while the advertised tag went on describing the old ones.
    /// </remarks>
    internal ImmutableArray<byte> Json { get; }

    /// <summary>A strong ETag over <see cref="Json"/>, quoted and ready for the header.</summary>
    internal string ETag { get; }

    /// <summary>The scopes advertised in the document, for the <c>401</c> challenge.</summary>
    internal IReadOnlyList<string> ScopesSupported { get; }

    /// <summary>
    /// Validate configuration, or explain what is wrong with it.
    /// </summary>
    /// <remarks>
    /// Returns rather than throws so a configuration doctor can report every problem at once. The
    /// caller in <c>AddBoltwayProtectedResource</c> throws, because a resource server that
    /// starts with a broken identity serves a metadata document every client is required to
    /// discard - and does it with a 200, which is the hardest kind of failure to see.
    /// </remarks>
    internal static bool TryCreate(ProtectedResourceOptions options, out ProtectedResource? resource, out string? error)
    {
        ArgumentNullException.ThrowIfNull(options);

        resource = null;

        if (!ResourceIdentifier.TryRegister(options.Resource, out var identifier, out error))
        {
            return false;
        }

        // RFC 9728 §1.2 says a resource identifier SHOULD NOT have a query, and this server turns
        // that into MUST NOT. The reason is routing rather than purity: the metadata document is
        // served by matching the request's PATH, and a query is not part of it - so two identifiers
        // differing only in their query would resolve to one route, and whichever one lost would be
        // answered with a document naming the other. A client applies §3.3, finds a `resource` that
        // is not what it inserted, and discards a document that arrived with a 200.
        if (identifier!.Canonical.Contains('?', StringComparison.Ordinal))
        {
            error =
                $"'{identifier.Canonical}' has a query component. RFC 9728 §1.2 says a resource "
                + "identifier SHOULD NOT, and this server cannot serve one: the metadata document is "
                + "routed by path, so a query cannot distinguish two resources and one of them would "
                + "be served the other's document.";
            return false;
        }

        if (!IssuerString.TryCreate(options.AuthorizationServer, out var issuer, out error))
        {
            return false;
        }

        var scopes = options.ScopesSupported.Count > 0 ? options.ScopesSupported.ToArray() : null;

        var document = new ProtectedResourceMetadata
        {
            Resource = identifier.Canonical,
            AuthorizationServers = [issuer.Value],
            ScopesSupported = scopes,
            BearerMethodsSupported = ["header"],
            ResourceName = options.ResourceName,
            ResourceDocumentation = options.ResourceDocumentation,
            ResourcePolicyUri = options.ResourcePolicyUri,
            ResourceTosUri = options.ResourceTosUri,
        };

        var json = JsonSerializer.SerializeToUtf8Bytes(
            document, ProtectedResourceMetadataJsonContext.Default.ProtectedResourceMetadata);

        resource = new ProtectedResource(
            identifier,
            issuer,
            WellKnownResourceUri.Insert(identifier.Canonical),
            WellKnownResourceUri.PathOf(identifier.Canonical),
            [.. json],
            '"' + Convert.ToHexStringLower(SHA256.HashData(json)) + '"',
            scopes ?? []);

        return true;
    }
}
