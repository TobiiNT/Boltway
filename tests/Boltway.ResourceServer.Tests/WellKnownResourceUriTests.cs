using Boltway.ResourceServer.Metadata;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// RFC 9728 §3/§3.1: the insertion rule, against the specification's own table.
/// </summary>
/// <remarks>
/// The rows come from the distillation in <c>spec/research/protected-resource-metadata-and-mcp.md</c>,
/// which took them from the RFC. The "wrong" column of that table is the appended form, and it is
/// the one every implementation reaches for first - so the negative rows below are not decoration,
/// they are the failure this file exists to keep out.
/// </remarks>
public sealed class WellKnownResourceUriTests
{
    [Theory]
    // No path: the suffix is the whole path.
    [InlineData("https://resource.example.com", "https://resource.example.com/.well-known/oauth-protected-resource")]
    // §3.1: "any terminating slash following the host component MUST be removed before inserting".
    [InlineData("https://resource.example.com/", "https://resource.example.com/.well-known/oauth-protected-resource")]
    // One path segment. Insertion, not appending.
    [InlineData("https://resource.example.com/resource1", "https://resource.example.com/.well-known/oauth-protected-resource/resource1")]
    [InlineData("https://mcp.example.com/mcp", "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")]
    // Several segments, all preserved in order.
    [InlineData("https://mcp.example.com/tenants/acme/mcp", "https://mcp.example.com/.well-known/oauth-protected-resource/tenants/acme/mcp")]
    // A port is part of the authority and survives untouched.
    [InlineData("https://mcp.example.com:8443/mcp", "https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp")]
    public void The_well_known_segment_is_inserted_after_the_host(string resource, string expected) =>
        Assert.Equal(expected, WellKnownResourceUri.Insert(resource));

    [Fact]
    public void The_appended_form_is_never_produced()
    {
        // The single most-failed requirement in RFC 9728, stated as its own assertion so a
        // regression names itself rather than showing up as one row of a table.
        var inserted = WellKnownResourceUri.Insert("https://mcp.example.com/mcp");

        Assert.DoesNotContain("/mcp/.well-known", inserted, StringComparison.Ordinal);
        Assert.EndsWith("/mcp", inserted, StringComparison.Ordinal);
    }

    [Fact]
    public void A_trailing_slash_on_the_path_is_preserved()
    {
        // C-28: the `resource` value "must match your MCP server URL exactly as the user enters it
        // in Claude". https://h/mcp/ and https://h/mcp are two different resource identifiers, and
        // collapsing them here would publish the document at a URL whose §3.3 identity check then
        // fails for whichever one lost.
        Assert.Equal(
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/",
            WellKnownResourceUri.Insert("https://mcp.example.com/mcp/"));
    }

    [Fact]
    public void Case_in_the_path_is_preserved()
    {
        // RFC 9728 §6: comparisons are code-point-to-code-point and "Unicode Normalization MUST NOT
        // be applied at any point". Uri.AbsolutePath would percent-decode and Uri.Authority would
        // lower-case the host; both are banned in this project, and this row is what notices if
        // one comes back.
        Assert.Equal(
            "https://MCP.Example.com/.well-known/oauth-protected-resource/MCP",
            WellKnownResourceUri.Insert("https://MCP.Example.com/MCP"));
    }

    [Theory]
    [InlineData("https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp")]
    [InlineData("https://mcp.example.com", "/.well-known/oauth-protected-resource")]
    [InlineData("https://mcp.example.com/", "/.well-known/oauth-protected-resource")]
    [InlineData("https://mcp.example.com/tenants/acme/mcp", "/.well-known/oauth-protected-resource/tenants/acme/mcp")]
    public void The_path_is_what_the_router_has_to_match(string resource, string expected) =>
        Assert.Equal(expected, WellKnownResourceUri.PathOf(resource));
}
