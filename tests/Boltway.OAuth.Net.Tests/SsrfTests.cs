using System.Net;
using Boltway.OAuth.Net;

namespace Boltway.OAuth.Net.Tests;

/// <summary>
/// N-05. The URLs this server fetches are attacker-supplied by design — a CIMD
/// <c>client_id</c> <i>is</i> a URL sent by whoever starts an authorization flow.
/// </summary>
public sealed class SsrfTests
{
    /// <summary>
    /// A resolver that answers whatever the test says, and counts how often it was asked.
    /// </summary>
    private sealed class StubResolver(params IPAddress[] addresses) : IAddressResolver
    {
        public int Calls { get; private set; }

        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<IReadOnlyList<IPAddress>>(addresses);
        }
    }

    private static async Task<FetchOutcome> FetchAsync(string url, params IPAddress[] resolvesTo)
    {
        Assert.True(AbsoluteHttpsUrl.TryCreate(url, out var parsed), $"'{url}' should be a valid https URL");

        using var fetcher = new SafeHttpFetcher(resolver: new StubResolver(resolvesTo));

        return await fetcher.FetchAsync(
            new SafeFetchRequest(parsed, FetchPurpose.ClientIdMetadataDocument), CancellationToken.None);
    }

    // ------------------------------------------------------------------ the address blocklist

    [Theory]
    // The one that matters most: the cloud instance-metadata endpoint, which hands credentials to
    // anything that can reach it.
    [InlineData("169.254.169.254")]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.1.1")]
    [InlineData("100.64.0.1")]      // RFC 6598 carrier-grade NAT
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]       // multicast
    [InlineData("255.255.255.255")]
    [InlineData("192.0.0.1")]       // IETF protocol assignments
    [InlineData("198.18.0.1")]      // benchmarking
    public async Task An_ipv4_special_use_address_is_refused(string address)
    {
        var outcome = await FetchAsync("https://evil.example/c.json", IPAddress.Parse(address));

        var blocked = Assert.IsType<FetchOutcome.Blocked>(outcome);
        Assert.Equal(BlockReason.SpecialUseAddress, blocked.Reason);
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("fe80::1")]         // link-local
    [InlineData("fc00::1")]         // unique local
    [InlineData("fd00::1")]
    [InlineData("ff02::1")]         // multicast
    [InlineData("::")]
    [InlineData("64:ff9b::1")]      // NAT64 — translates to an IPv4 destination
    [InlineData("2001:db8::1")]     // documentation
    public async Task An_ipv6_special_use_address_is_refused(string address)
    {
        var outcome = await FetchAsync("https://evil.example/c.json", IPAddress.Parse(address));

        Assert.IsType<FetchOutcome.Blocked>(outcome);
    }

    [Theory]
    // The single most commonly missed entry: the metadata endpoint written as IPv6. A checker that
    // only knows IPv6 ranges finds this in none of them and says yes.
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:10.0.0.1")]
    [InlineData("::ffff:192.168.0.1")]
    public async Task An_ipv4_mapped_ipv6_address_is_unwrapped_before_the_check(string address)
    {
        var outcome = await FetchAsync("https://evil.example/c.json", IPAddress.Parse(address));

        var blocked = Assert.IsType<FetchOutcome.Blocked>(outcome);
        Assert.Equal(BlockReason.SpecialUseAddress, blocked.Reason);
    }

    [Fact]
    public async Task One_bad_address_among_several_refuses_the_whole_host()
    {
        // A host answering with one public and one private address must not be fetchable: which of
        // them gets used is not ours to decide, so the presence of a private one is disqualifying.
        var outcome = await FetchAsync(
            "https://evil.example/c.json",
            IPAddress.Parse("93.184.216.34"),
            IPAddress.Parse("169.254.169.254"));

        Assert.IsType<FetchOutcome.Blocked>(outcome);
    }

    [Fact]
    public async Task A_host_that_does_not_resolve_is_refused_as_dns_rather_than_as_address()
    {
        var outcome = await FetchAsync("https://nothing.example/c.json");

        var blocked = Assert.IsType<FetchOutcome.Blocked>(outcome);
        Assert.Equal(BlockReason.DnsFailed, blocked.Reason);
    }

    [Fact]
    public async Task The_blocked_message_names_the_host_and_the_address()
    {
        // A-12: curl alone must be enough to debug. "Blocked" with no detail sends an operator
        // hunting through DNS by hand.
        var outcome = await FetchAsync("https://evil.example/c.json", IPAddress.Parse("169.254.169.254"));

        var blocked = Assert.IsType<FetchOutcome.Blocked>(outcome);
        Assert.Contains("evil.example", blocked.Detail, StringComparison.Ordinal);
        Assert.Contains("169.254.169.254", blocked.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Resolution_happens_exactly_once_per_fetch()
    {
        // The TOCTOU property. Resolving here and letting HttpClient resolve again would let a
        // hostile DNS server answer public the first time and private the second; the validated
        // address is carried to the connect callback instead, so there is no second lookup.
        Assert.True(AbsoluteHttpsUrl.TryCreate("https://evil.example/c.json", out var url));

        var resolver = new StubResolver(IPAddress.Parse("169.254.169.254"));
        using var fetcher = new SafeHttpFetcher(resolver: resolver);

        await fetcher.FetchAsync(
            new SafeFetchRequest(url, FetchPurpose.ClientIdMetadataDocument), CancellationToken.None);

        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public async Task Private_addresses_are_reachable_only_when_deliberately_allowed()
    {
        // The development relaxation the CIMD draft permits. Composition validation refuses to
        // start a production host with this set, so it cannot arrive by being forgotten.
        Assert.True(AbsoluteHttpsUrl.TryCreate("https://localhost.example/c.json", out var url));

        using var fetcher = new SafeHttpFetcher(
            new SafeHttpFetcherOptions { AllowPrivateAddresses = true, TotalTimeout = TimeSpan.FromMilliseconds(250) },
            new StubResolver(IPAddress.Loopback));

        var outcome = await fetcher.FetchAsync(
            new SafeFetchRequest(url, FetchPurpose.ClientIdMetadataDocument), CancellationToken.None);

        // It gets past the address check and fails at the transport instead, because nothing is
        // listening — which is the proof that the check is what was bypassed.
        Assert.IsNotType<FetchOutcome.Blocked>(outcome);
    }

    // ------------------------------------------------------------------ the URL type

    [Theory]
    [InlineData("http://evil.example/c.json")]     // not https
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://evil.example/")]
    [InlineData("ftp://evil.example/")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:application/json,{}")]
    [InlineData("https://user:pw@evil.example/")]  // credentials the server would send onward
    [InlineData("https://evil.example/c.json#f")]  // a fragment is never sent, so it is a second identity
    [InlineData("https://evil.example/c\r\n.json")]
    [InlineData("  https://evil.example/c.json")]
    [InlineData("/relative")]
    [InlineData("")]
    public void A_url_the_fetcher_must_never_see_cannot_be_constructed(string raw)
    {
        // The fetcher takes AbsoluteHttpsUrl and nothing else, so these are refused by the type
        // system rather than by a check the fetcher has to remember.
        Assert.False(AbsoluteHttpsUrl.TryCreate(raw, out _));
    }

    [Theory]
    [InlineData("https://claude.ai/oauth/mcp-oauth-client-metadata", "claude.ai", 443)]
    [InlineData("https://chatgpt.com/oauth/client.json", "chatgpt.com", 443)]
    [InlineData("https://as.example.com:8443/jwks", "as.example.com", 8443)]
    public void A_real_client_metadata_url_parses(string raw, string host, int port)
    {
        Assert.True(AbsoluteHttpsUrl.TryCreate(raw, out var url));
        Assert.Equal(host, url.Host);
        Assert.Equal(port, url.Port);
        Assert.Equal(raw, url.Value);
    }
}
