using Boltway.OAuth.Primitives.Http;

namespace Boltway.OAuth.Primitives.Tests.Http;

/// <summary>X-32 to X-35, RFC 6750 §3, RFC 9728 §5.1.</summary>
public sealed class WwwAuthenticateTests
{
    private const string MetadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

    [Fact]
    public void The_challenge_starts_with_the_scheme()
    {
        Assert.StartsWith("Bearer ", WwwAuthenticate.Bearer(error: "invalid_token"), StringComparison.Ordinal);
    }

    [Fact]
    public void Resource_metadata_is_carried_and_quoted()
    {
        // The whole point of the header. A URL contains ':' and '/', neither of which is tchar, so
        // an unquoted value here is not merely untidy — it is unparseable.
        var header = WwwAuthenticate.Bearer(error: "invalid_token", resourceMetadataUrl: MetadataUrl);

        Assert.Contains($"resource_metadata=\"{MetadataUrl}\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void Parameters_are_comma_separated()
    {
        var header = WwwAuthenticate.Bearer(
            error: "invalid_token",
            errorDescription: "The access token expired",
            resourceMetadataUrl: MetadataUrl);

        Assert.Equal(
            "Bearer error=\"invalid_token\", error_description=\"The access token expired\", " +
            $"resource_metadata=\"{MetadataUrl}\"",
            header);
    }

    [Fact]
    public void Scopes_are_space_delimited_inside_one_quoted_value()
    {
        var header = WwwAuthenticate.Bearer(
            error: "insufficient_scope",
            resourceMetadataUrl: MetadataUrl,
            scopes: ["story:read", "story:write"]);

        Assert.Contains("scope=\"story:read story:write\"", header, StringComparison.Ordinal);
    }

    // ------------------------------------------------------- the truncation failure (the point)

    [Fact]
    public void A_quote_in_the_description_cannot_terminate_the_header_early()
    {
        // This is the bug the sanitiser exists for. An unescaped quote closes the quoted-string,
        // and everything after it — including resource_metadata — is lost or mis-parsed. Losing
        // resource_metadata does not degrade diagnostics; it removes the client's only pointer to
        // the authorization server, so the user cannot authenticate at all.
        var header = WwwAuthenticate.Bearer(
            error: "invalid_token",
            errorDescription: "token for \"acme\" is not valid",
            resourceMetadataUrl: MetadataUrl);

        Assert.DoesNotContain('\\', header);
        Assert.Equal(6, header.Count(c => c == '"'));   // exactly three quoted values, two quotes each
        Assert.Contains($"resource_metadata=\"{MetadataUrl}\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public void A_backslash_cannot_escape_its_way_out_either()
    {
        var header = WwwAuthenticate.Bearer(
            error: "invalid_token",
            errorDescription: @"path C:\temp\x",
            resourceMetadataUrl: MetadataUrl);

        Assert.DoesNotContain('\\', header);
        Assert.Contains($"resource_metadata=\"{MetadataUrl}\"", header, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("line one\nline two")]
    [InlineData("line one\r\nSet-Cookie: evil=1")]
    [InlineData("tab\there")]
    public void Control_characters_cannot_split_the_header(string description)
    {
        // Response splitting through an error message. A CR or LF that survived into a header value
        // would let a caller inject an entire additional header.
        var header = WwwAuthenticate.Bearer(error: "invalid_token", errorDescription: description);

        Assert.DoesNotContain('\n', header);
        Assert.DoesNotContain('\r', header);
        Assert.DoesNotContain('\t', header);
    }

    [Fact]
    public void A_long_description_is_capped_to_exactly_the_documented_length()
    {
        var header = WwwAuthenticate.Bearer(errorDescription: new string('x', 5000));

        // Assert the emitted value, not a loose upper bound: `header.Length < 240 + 64` would have
        // passed at any cap up to 303.
        Assert.Equal($"Bearer error_description=\"{new string('x', WwwAuthenticate.MaxDescriptionLength)}\"", header);
    }

    [Theory]
    // A scope is validated before the join, never sanitised after it. Sanitising afterwards turns a
    // space inside one scope into a separator, so two scopes become three — and this header is the
    // only thing telling the client what to re-authorise for.
    [InlineData(new[] { "read", "", "write" }, "read write")]
    [InlineData(new[] { "a\"b", "c" }, "c")]
    [InlineData(new[] { "story:read story:write" }, "")]
    [InlineData(new[] { "read", "wr ite" }, "read")]
    public void Scope_values_that_are_not_scope_tokens_are_dropped_not_mangled(string[] scopes, string expected)
    {
        var header = WwwAuthenticate.Bearer(error: "insufficient_scope", scopes: scopes);

        if (expected.Length == 0)
        {
            Assert.DoesNotContain("scope=", header, StringComparison.Ordinal);
        }
        else
        {
            Assert.Contains($"scope=\"{expected}\"", header, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void An_oversized_challenge_keeps_the_parameters_the_client_cannot_act_without()
    {
        // Capping only error_description left realm, resource_metadata and the scope list
        // unbounded, so a header could exceed a reverse proxy's buffer — nginx defaults to 4 KB —
        // and become a 502, leaving the client with no discovery pointer at all.
        var manyScopes = Enumerable.Range(0, 2000).Select(i => $"scope:{i}").ToArray();

        var header = WwwAuthenticate.Bearer(
            error: "insufficient_scope", resourceMetadataUrl: MetadataUrl, scopes: manyScopes);

        Assert.True(header.Length <= WwwAuthenticate.MaxHeaderLength, $"header was {header.Length} bytes");
        Assert.Contains("resource_metadata=", header, StringComparison.Ordinal);
        Assert.Contains("error=", header, StringComparison.Ordinal);
    }

    [Fact]
    public void A_description_of_only_forbidden_characters_is_omitted_entirely()
    {
        // Rather than emitting error_description="" — an empty value is not more informative than
        // no value, and it costs bytes in a header some proxies cap.
        var header = WwwAuthenticate.Bearer(
            error: "invalid_token",
            errorDescription: "\"\"\\\n",
            resourceMetadataUrl: MetadataUrl);

        Assert.DoesNotContain("error_description", header, StringComparison.Ordinal);
        Assert.Contains("resource_metadata", header, StringComparison.Ordinal);
    }

    [Fact]
    public void Absent_parameters_are_omitted_not_emitted_empty()
    {
        Assert.Equal("Bearer error=\"invalid_token\"", WwwAuthenticate.Bearer(error: "invalid_token"));
    }

    [Fact]
    public void Every_emitted_value_is_quoted()
    {
        var header = WwwAuthenticate.Bearer(
            realm: "boltway",
            error: "insufficient_scope",
            errorDescription: "needs more",
            resourceMetadataUrl: MetadataUrl,
            scopes: ["a", "b"]);

        // Five parameters, each contributing exactly two quotes.
        Assert.Equal(10, header.Count(c => c == '"'));
    }
}
