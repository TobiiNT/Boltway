namespace Boltway.ResourceServer.Metadata;

/// <summary>
/// RFC 9728 §3/§3.1: where a protected resource's metadata lives.
/// </summary>
/// <remarks>
/// <para>
/// <b>Insertion, not appending.</b> The well-known segment goes <i>between</i> the host and the
/// path, so <c>https://mcp.example.com/mcp</c> publishes at
/// <c>https://mcp.example.com/.well-known/oauth-protected-resource/mcp</c> - not at
/// <c>https://mcp.example.com/mcp/.well-known/oauth-protected-resource</c>. The distillation in
/// <c>spec/research/protected-resource-metadata-and-mcp.md</c> calls this "the single most-failed
/// requirement", and it is the same rule RFC 8414 §3.1 states for authorization servers, which the
/// discovery endpoints on the AS side already implement.
/// </para>
/// <para>
/// Done by splicing the raw configured string, never by reading components off a
/// <see cref="Uri"/>. <c>Uri.AbsolutePath</c> percent-decodes and <c>Uri.Authority</c> lowercases
/// the host and elides the default port; either one produces a URL whose path no longer matches
/// the identifier the client will compare against under §3.3, and the client is then required to
/// discard the document. Both members are on this project's banned list for that reason.
/// </para>
/// </remarks>
internal static class WellKnownResourceUri
{
    /// <summary>The IANA-registered well-known suffix. RFC 9728 §8.3.</summary>
    internal const string Suffix = "/.well-known/oauth-protected-resource";

    private const string HttpsPrefix = "https://";

    /// <summary>
    /// Insert <see cref="Suffix"/> into a resource identifier.
    /// </summary>
    /// <param name="resource">
    /// An absolute <c>https</c> identifier with no fragment and no query - the shape
    /// <c>ProtectedResource.TryCreate</c> has already established.
    /// </param>
    /// <remarks>
    /// The one transformation applied is §3.1's: <c>https://host/</c> loses its terminating slash,
    /// because that slash "follows the host component" and the suffix takes its place. Every other
    /// byte of the path survives, trailing slash included - <c>https://host/mcp/</c> is a
    /// <i>different</i> resource identifier from <c>https://host/mcp</c>, and flattening the two
    /// here would publish the document at a URL whose §3.3 identity check then fails.
    /// </remarks>
    internal static string Insert(string resource)
    {
        var pathStart = resource.IndexOf('/', HttpsPrefix.Length);

        if (pathStart < 0)
        {
            return resource + Suffix;
        }

        var origin = resource[..pathStart];
        var rest = resource[pathStart..];

        // "https://host/" - the slash immediately after the host and nothing else.
        if (string.Equals(rest, "/", StringComparison.Ordinal))
        {
            return origin + Suffix;
        }

        return origin + Suffix + rest;
    }

    /// <summary>
    /// The path portion of <see cref="Insert"/> - what the routing table has to match.
    /// </summary>
    internal static string PathOf(string resource)
    {
        var inserted = Insert(resource);
        var pathStart = inserted.IndexOf('/', HttpsPrefix.Length);

        // Insert always produces at least the suffix after the origin, so a path is always present.
        return inserted[pathStart..];
    }
}
