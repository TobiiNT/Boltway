using System.Reflection;
using Boltway.OAuth.Primitives.Ids;
using Boltway.ResourceServer.Configuration;
using Boltway.ResourceServer.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.ResourceServer.Tests;

/// <summary>What this server refuses to start with, and why each refusal is worth a startup failure.</summary>
public sealed class ProtectedResourceConfigurationTests
{
    [Theory]
    [InlineData(null, "required")]
    [InlineData("", "required")]
    // Not a URL at all.
    [InlineData("not-a-url", "absolute")]
    // http. Every OAuth URL but a loopback redirect must be https (S-33), and a resource identifier
    // is not a redirect.
    [InlineData("http://mcp.example.com/mcp", "https")]
    // RFC 8707 §2 and RFC 9728 §1.2: no fragment.
    [InlineData("https://mcp.example.com/mcp#frag", "fragment")]
    // Not canonical. Claude sends the resource in RFC 8707 canonical form no matter what the user
    // typed, and every comparison against it is ordinal - a registration that differs from its own
    // canonical form can never match a compliant client, and nothing reports the mismatch until
    // somebody's sign-in fails. These four are the ways a URL drifts from that form.
    [InlineData("HTTPS://mcp.example.com/mcp", "canonical")]
    [InlineData("https://MCP.example.com/mcp", "canonical")]
    [InlineData("https://mcp.example.com:443/mcp", "canonical")]
    [InlineData("https://mcp.example.com/mcp/", "canonical")]
    public void A_resource_identifier_that_is_not_one_stops_the_server(string? resource, string expectedInError)
    {
        var options = new ProtectedResourceOptions { Resource = resource, AuthorizationServer = Build.Issuer };

        Assert.False(ProtectedResource.TryCreate(options, out _, out var error));
        Assert.Contains(expectedInError, error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_resource_identifier_with_a_query_is_refused()
    {
        // RFC 9728 §1.2 says SHOULD NOT; this server says MUST NOT, and the reason is routing
        // rather than purity. The document is served by matching the request PATH, and a query is
        // not part of it - so two identifiers differing only in their query resolve to one route
        // and one of them is served the other's document. The client applies §3.3, finds a
        // `resource` it did not insert, and discards a document that arrived with a 200.
        var options = new ProtectedResourceOptions
        {
            Resource = "https://mcp.example.com/mcp?tenant=acme",
            AuthorizationServer = Build.Issuer,
        };

        Assert.False(ProtectedResource.TryCreate(options, out _, out var error));
        Assert.Contains("query", error!, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("http://auth.example.com")]
    // RFC 8414 §2: no query, no fragment.
    [InlineData("https://auth.example.com?x=1")]
    // A trailing slash makes it a different issuer under Simple String Comparison, and clients are
    // forbidden from normalizing it away.
    [InlineData("https://auth.example.com/")]
    public void An_authorization_server_that_is_not_a_valid_issuer_stops_the_server(string? issuer)
    {
        var options = new ProtectedResourceOptions { Resource = Build.Resource, AuthorizationServer = issuer };

        Assert.False(ProtectedResource.TryCreate(options, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Valid_configuration_is_the_control()
    {
        // Every row above asserts a refusal, and a TryCreate that always returned false would pass
        // all of them.
        var options = new ProtectedResourceOptions
        {
            Resource = Build.Resource,
            AuthorizationServer = Build.Issuer,
        };

        Assert.True(ProtectedResource.TryCreate(options, out var resource, out var error), error);
        Assert.Equal(Build.Resource, resource!.Identifier.Canonical);
        Assert.Equal(Build.MetadataUrl, resource.MetadataUrl);
    }

    [Theory]
    // A non-default port is part of the resource's identity, not a deviation from canonical form.
    [InlineData("https://mcp.example.com:8443/mcp")]
    // A root resource: the canonical form of a bare origin has no trailing slash to trim.
    [InlineData("https://mcp.example.com")]
    // Path case is preserved - canonicalization lowercases the scheme and host only.
    [InlineData("https://mcp.example.com/MCP")]
    public void A_canonical_resource_identifier_is_accepted(string resource)
    {
        var options = new ProtectedResourceOptions { Resource = resource, AuthorizationServer = Build.Issuer };

        Assert.True(ProtectedResource.TryCreate(options, out var created, out var error), error);
        Assert.Equal(resource, created!.Identifier.Canonical);
    }

    [Fact]
    public void Registration_throws_rather_than_deferring_a_broken_identity_to_the_first_request()
    {
        // Every failure this validation catches presents as a 200: a metadata document naming the
        // wrong resource is served cheerfully and discarded by every client that reads it. A server
        // that will not start is diagnosable; one that answers 200 with an unusable document is the
        // failure this whole exercise is about.
        var services = new ServiceCollection();
        services.AddBoltwayProtectedResource(o =>
        {
            o.Resource = "http://mcp.example.com/mcp";
            o.AuthorizationServer = Build.Issuer;
        });

        using var provider = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(provider.GetRequiredService<ProtectedResource>);
    }

    [Fact]
    public void No_public_member_of_this_assembly_hands_out_a_resource_identifier()
    {
        // The guard on the InternalsVisibleTo grant this assembly holds over Primitives.
        //
        // ResourceIdentifier's factory is internal so that N-01 has no public bypass: an access
        // token cannot be minted for an audience nobody validated, because the descriptor requires
        // one of these and only IResourceRegistry can produce one. The grant lets this assembly
        // name ITSELF from configuration, which is a different act - but InternalsVisibleTo is
        // granted per assembly, not per member, so one careless `public` here would re-open the
        // public factory that the design deliberately removed.
        var offenders = new List<string>();

        foreach (var type in typeof(ProtectedResourceOptions).Assembly.GetExportedTypes())
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (Leaks(method.ReturnType) || method.GetParameters().Any(p => Leaks(p.ParameterType)))
                {
                    offenders.Add($"{type.FullName}.{method.Name}");
                }
            }

            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (Leaks(property.PropertyType))
                {
                    offenders.Add($"{type.FullName}.{property.Name}");
                }
            }

            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (Leaks(field.FieldType))
                {
                    offenders.Add($"{type.FullName}.{field.Name}");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "A ResourceIdentifier is reachable from this assembly's public surface, which makes "
            + "N-01's \"no public factory\" false:" + Environment.NewLine + string.Join(Environment.NewLine, offenders));

        // Non-vacuity: the scan must actually be looking at a populated public surface.
        Assert.NotEmpty(typeof(ProtectedResourceOptions).Assembly.GetExportedTypes());
    }

    private static bool Leaks(Type type)
    {
        if (type == typeof(ResourceIdentifier))
        {
            return true;
        }

        // A collection or a Task of one leaks it just as thoroughly as a bare return.
        return type.IsGenericType && type.GetGenericArguments().Any(Leaks);
    }
}
