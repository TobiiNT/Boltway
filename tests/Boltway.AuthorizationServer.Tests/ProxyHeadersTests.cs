using Boltway.AuthorizationServer.Configuration;
// ForwardedHeadersOptions is in Builder; only the ForwardedHeaders enum is in HttpOverrides.
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The known-proxy lists are empty, and that assertion is the whole point of the type.
/// </summary>
/// <remarks>
/// <para>
/// The host used to build these options inline with <c>KnownIPNetworks = { }</c>, which is a
/// collection initializer - "call <c>Add</c> zero times" - and clears nothing. The defaults
/// survived, the proxy check stayed on, Caddy's bridge address failed it, and every forwarded
/// header was dropped. Behind working TLS the sign-in form answered 500, and the per-source login
/// limit counted the proxy instead of people.
/// </para>
/// <para>
/// Nothing could catch it. The host is not referenced by any test project, so the only thing that
/// ever compiled that file was the Docker build, and compiling a no-op tells you nothing. Moving
/// the four lines into a library is what makes the difference between the two spellings something
/// a test can see.
/// </para>
/// </remarks>
public sealed class ProxyHeadersTests
{
    [Fact]
    public void The_known_lists_are_empty_so_the_immediate_peer_is_believed()
    {
        var options = ProxyHeaders.BehindOneProxy();

        // Empty is what turns the known-address check off. Non-empty means the middleware compares
        // the caller against the list and drops the headers when it does not match - which is what
        // happened for a month, because the defaults are 127.0.0.0/8 and ::1 and a container behind
        // Caddy is neither.
        Assert.Empty(options.KnownIPNetworks);
        Assert.Empty(options.KnownProxies);
    }

    /// <summary>The control: the defaults this is expected to remove are really there.</summary>
    /// <remarks>
    /// Without this, the assertion above would keep passing if a future framework version shipped
    /// empty defaults - and would then say nothing about whether <c>Clear()</c> was still being
    /// called. A test that cannot fail for the original reason is not testing the original thing.
    /// </remarks>
    [Fact]
    public void And_the_defaults_it_removes_are_not_empty_to_begin_with()
    {
        var untouched = new ForwardedHeadersOptions();

        Assert.NotEmpty(untouched.KnownIPNetworks);
        Assert.NotEmpty(untouched.KnownProxies);
    }

    [Fact]
    public void Both_forwarded_headers_are_processed_and_only_one_hop_is_trusted()
    {
        var options = ProxyHeaders.BehindOneProxy();

        Assert.Equal(
            ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
            options.ForwardedHeaders);

        // One, because one proxy is what both deployments have. A CDN in front makes this 2 - see
        // the parameter's own note, and expect the failure to be silent if it is not changed.
        Assert.Equal(1, options.ForwardLimit);
    }
}
