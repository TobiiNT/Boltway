using Boltway.OAuth.Primitives.Redirects;

namespace Boltway.OAuth.Primitives.Tests.Redirects;

/// <summary>
/// N-03 (exact ordinal matching) and N-04 (the RFC 8252 §7.3 loopback port exception).
/// </summary>
/// <remarks>
/// Every row here is either a rule from a specification or a bypass someone has actually tried.
/// The negative rows matter more than the positive ones: a matcher that accepts everything passes
/// all the positives.
/// </remarks>
public sealed class RedirectUriMatcherTests
{
    /// <summary>For positive rows: both sides must parse, and the match is returned.</summary>
    private static RedirectMatch Match(string registered, string requested)
    {
        Assert.True(RegisteredRedirectUri.TryRegister(registered, out var reg, out var regError),
            $"registration of '{registered}' failed: {regError}");
        Assert.True(RequestedRedirectUri.TryParse(requested, out var req, out var reqError),
            $"parse of '{requested}' failed: {reqError}");

        return RedirectUriMatcher.Match(req!.Value, [reg!.Value]);
    }

    /// <summary>
    /// For negative rows: did this request reach the client's redirect URI, by any route?
    /// </summary>
    /// <remarks>
    /// A request refused at parse counts as "no", and is a strictly stronger refusal than one that
    /// parses and then fails to match. The negative rows care about the outcome, not which of the
    /// two layers produced it - pinning the layer would make the test fail every time a check moved
    /// earlier, which is the direction we want checks to move.
    /// </remarks>
    private static bool Reaches(string registered, string requested)
    {
        Assert.True(RegisteredRedirectUri.TryRegister(registered, out var reg, out var regError),
            $"registration of '{registered}' failed: {regError}");

        return RequestedRedirectUri.TryParse(requested, out var req, out _)
            && RedirectUriMatcher.Match(req!.Value, [reg!.Value]).Matched;
    }

    // ---------------------------------------------------------------- exact matching (N-03)

    [Theory]
    // The two vendor redirect URIs, measured live 2026-08-03.
    [InlineData("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback")]
    [InlineData("https://chatgpt.com/connector_platform_oauth_redirect", "https://chatgpt.com/connector_platform_oauth_redirect")]
    [InlineData("https://chatgpt.com/connector/oauth/mcp", "https://chatgpt.com/connector/oauth/mcp")]
    // A query string is part of the comparison, not a decoration.
    [InlineData("https://app.example.com/cb?tenant=a", "https://app.example.com/cb?tenant=a")]
    // A non-default port matches itself.
    [InlineData("https://app.example.com:8443/cb", "https://app.example.com:8443/cb")]
    // RFC 8252 §7.1 private-use scheme: the dot is what makes it legal.
    [InlineData("com.example.app:/oauth2redirect", "com.example.app:/oauth2redirect")]
    public void Exact_string_equality_matches(string registered, string requested)
    {
        var match = Match(registered, requested);

        Assert.True(match.Matched);
        Assert.Equal(RedirectMatchKind.Exact, match.Kind);
    }

    [Theory]
    // Case. The registration is lowercased on write; the request is NOT normalized, so this must
    // fail. Simple String Comparison, RFC 3986 §6.2.1.
    [InlineData("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/API/MCP/auth_callback")]
    // Default port written explicitly. System.Uri.AbsoluteUri would elide the :443 and make these
    // equal - which is exactly the normalization that widens an allowlist, and exactly why
    // Uri.AbsoluteUri is on the banned list.
    [InlineData("https://claude.ai/cb", "https://claude.ai:443/cb")]
    // Trailing slash is a different path.
    [InlineData("https://claude.ai/cb", "https://claude.ai/cb/")]
    // Dot segments. Uri would resolve these away; strings do not.
    [InlineData("https://claude.ai/cb", "https://claude.ai/a/../cb")]
    // Percent-encoded traversal. AbsolutePath would decode %2e%2e to .. and then resolve it.
    [InlineData("https://claude.ai/cb", "https://claude.ai/a/%2e%2e/cb")]
    // A different host that merely starts the same - the classic prefix-match bug.
    [InlineData("https://claude.ai/cb", "https://claude.ai.evil.example/cb")]
    // Subdomain is not the registered host.
    [InlineData("https://claude.ai/cb", "https://evil.claude.ai/cb")]
    // Extra query the registration does not have.
    [InlineData("https://app.example.com/cb", "https://app.example.com/cb?next=https://evil.example")]
    // Scheme downgrade on a public host.
    [InlineData("https://app.example.com/cb", "http://app.example.com/cb")]
    public void Anything_short_of_byte_equality_does_not_match(string registered, string requested)
    {
        Assert.False(Reaches(registered, requested));
    }

    // ------------------------------------------------- the loopback port exception (N-04, A-19)

    [Theory]
    // Claude Code registers portless and listens on whatever it managed to bind. Measured live:
    // its CIMD declares http://localhost/callback and http://127.0.0.1/callback.
    [InlineData("http://127.0.0.1/callback", "http://127.0.0.1:51004/callback")]
    [InlineData("http://localhost/callback", "http://localhost:3118/callback")]
    [InlineData("http://[::1]/callback", "http://[::1]:51004/callback")]
    // Registered WITH a port, requested with a different one: still fine. RFC 8252 §7.3 says the
    // port is not part of the comparison at all, in either direction.
    [InlineData("http://127.0.0.1:8080/callback", "http://127.0.0.1:9090/callback")]
    // IPv6 loopback written both ways must agree once brackets are stripped.
    [InlineData("http://[::1]:1/callback", "http://[::1]:2/callback")]
    public void Loopback_ignores_the_port_on_both_sides(string registered, string requested)
    {
        var match = Match(registered, requested);

        Assert.True(match.Matched);
        Assert.Equal(RedirectMatchKind.LoopbackPortIgnored, match.Kind);
    }

    [Fact]
    public void Loopback_redirect_returns_the_requested_port_not_the_registered_one()
    {
        // The whole reason the exception exists. Redirecting to the registered string would send
        // the browser to port 80, where the client is not listening.
        var match = Match("http://127.0.0.1/callback", "http://127.0.0.1:51004/callback");

        Assert.Equal("http://127.0.0.1:51004/callback", match.RequestedValue);
    }

    [Theory]
    // The path is still compared exactly. Without this, any process on the machine that can bind a
    // port could harvest authorization codes.
    [InlineData("http://127.0.0.1/callback", "http://127.0.0.1:51004/steal")]
    // So is the query.
    [InlineData("http://127.0.0.1/callback?a=1", "http://127.0.0.1:51004/callback?a=2")]
    // Alternate spellings of the loopback address.
    //
    // These four rows caught a real defect. IPAddress.IsLoopback accepts the whole 127.0.0.0/8
    // block and parses 127.1, 0x7f.1 and 2130706433 into it, so the matcher deliberately never
    // calls it - but measurement on .NET 10 showed System.Uri performing the SAME normalization one
    // layer earlier, so Uri.Host answered "127.0.0.1" for every one of these and the careful
    // literal comparison downstream was comparing an already-widened value. The host is now cut out
    // of the raw request bytes instead. Without that fix these three rows pass a match.
    [InlineData("http://127.0.0.1/callback", "http://127.1:51004/callback")]
    [InlineData("http://127.0.0.1/callback", "http://2130706433:51004/callback")]
    [InlineData("http://127.0.0.1/callback", "http://0x7f.1:51004/callback")]
    // The IPv4-mapped IPv6 form is not normalized by Uri, but it is still not one of the three
    // literals, so it is refused for the ordinary reason.
    [InlineData("http://127.0.0.1/callback", "http://[::ffff:127.0.0.1]:51004/callback")]
    // 0.0.0.0 is not loopback; it is every interface.
    [InlineData("http://127.0.0.1/callback", "http://0.0.0.0:51004/callback")]
    // The three loopback hosts are distinct from each other. localhost may resolve to ::1 on one
    // machine and 127.0.0.1 on another, so treating them as interchangeable would make the
    // allowlist depend on the host's resolver.
    [InlineData("http://127.0.0.1/callback", "http://localhost:51004/callback")]
    [InlineData("http://localhost/callback", "http://127.0.0.1:51004/callback")]
    public void Loopback_exception_does_not_widen_beyond_the_port(string registered, string requested)
    {
        Assert.False(Reaches(registered, requested));
    }

    [Fact]
    public void A_public_host_never_gets_the_port_exception()
    {
        // The single most important negative in this file. If the exception were gated on the
        // REQUEST looking like loopback, or applied to any scheme, then
        // https://claude.ai:1337/api/mcp/auth_callback would match a registration for
        // https://claude.ai/api/mcp/auth_callback and the attacker picks the port.
        var match = Match("https://claude.ai/api/mcp/auth_callback", "https://claude.ai:1337/api/mcp/auth_callback");

        Assert.False(match.Matched);
    }

    [Fact]
    public void A_loopback_request_cannot_promote_itself_against_an_https_registration()
    {
        var match = Match("https://claude.ai/cb", "http://127.0.0.1:51004/cb");

        Assert.False(match.Matched);
    }

    [Theory]
    // Registration says https, request says http on a loopback host. Same host string, same path:
    // everything the port-exception branch compares agrees, and only the gate refuses it.
    [InlineData("https://localhost/cb", "http://localhost:3000/cb")]
    [InlineData("https://127.0.0.1/cb", "http://127.0.0.1:3000/cb")]
    // ...and the reverse. A loopback registration is not satisfied by an https request, even one
    // pointing at the same loopback host.
    [InlineData("http://localhost/cb", "https://localhost/cb")]
    public void The_port_exception_needs_both_sides_to_be_loopback_not_either(string registered, string requested)
    {
        // The gate reads `registration.Kind != Loopback || requested.Kind != Loopback`, and
        // mutation testing turned that `||` into `&&` without a single test noticing. Under `&&`
        // the branch runs whenever EITHER side is loopback, and the body compares only host and
        // path - so a registration for https://localhost/cb would be satisfied by
        // http://localhost:3000/cb: a scheme downgrade to cleartext plus a port the client never
        // registered, handed an authorization code.
        //
        // Every existing negative for this gate differs in host as well as in kind
        // (claude.ai vs 127.0.0.1), so host equality refused them and the gate was never the
        // reason. These rows hold the host fixed, which is what leaves the gate as the only
        // remaining check.
        Assert.False(Reaches(registered, requested));
    }

    // ------------------------------------------------------------------- registration validation

    [Theory]
    [InlineData("https://claude.ai/cb#frag", RedirectUriError.HasFragment)]
    [InlineData("https://user:pw@claude.ai/cb", RedirectUriError.HasUserInfo)]
    [InlineData("http://app.example.com/cb", RedirectUriError.SchemeNotAllowed)]
    [InlineData("javascript:alert(1)", RedirectUriError.SchemeNotAllowed)]
    [InlineData("file:///etc/passwd", RedirectUriError.SchemeNotAllowed)]
    [InlineData("callback", RedirectUriError.NotAbsolute)]
    // On Unix, Uri.TryCreate parses a leading-slash path as an absolute file:// URI, so this
    // reaches the raw splitter - which finds no ':' and reports it as what it is.
    [InlineData("/relative/cb", RedirectUriError.NotAbsolute)]
    [InlineData("", RedirectUriError.Malformed)]
    [InlineData("http://127.0.0.1:0/callback", RedirectUriError.PortOutOfRange)]
    public void Registration_refuses_and_says_which_rule(string raw, RedirectUriError expected)
    {
        Assert.False(RegisteredRedirectUri.TryRegister(raw, out _, out var error));
        Assert.Equal(expected, error);
    }

    [Theory]
    // Scheme and host are case-insensitive per RFC 3986 §6.2.2.1, so they are lowercased on write.
    [InlineData("HTTPS://Claude.AI/api/CB", "https://claude.ai/api/CB")]
    [InlineData("HTTP://LocalHost/Callback", "http://localhost/Callback")]
    // ...and nothing after the authority is touched. The path keeps its case and its encoding.
    [InlineData("https://claude.ai/A%2fB?X=Y", "https://claude.ai/A%2fB?X=Y")]
    // An explicitly written default port survives normalization: it is part of the registered
    // string, and reconstructing through Uri would have silently dropped it.
    [InlineData("https://claude.ai:443/cb", "https://claude.ai:443/cb")]
    public void Registration_normalizes_scheme_and_authority_only(string raw, string expected)
    {
        Assert.True(RegisteredRedirectUri.TryRegister(raw, out var registered, out _));
        Assert.Equal(expected, registered!.Value.Value);
    }

    [Fact]
    public void A_registration_lowercased_on_write_matches_the_canonical_request()
    {
        // The consequence of normalizing on write: an operator who typed the host in mixed case
        // still gets a working client, because the stored form is canonical.
        var match = Match("HTTPS://Claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback");

        Assert.True(match.Matched);
    }

    [Fact]
    public void No_registrations_means_no_match()
    {
        Assert.True(RequestedRedirectUri.TryParse("https://claude.ai/cb", out var req, out _));

        Assert.False(RedirectUriMatcher.Match(req!.Value, []).Matched);
    }

    [Fact]
    public void The_first_matching_registration_wins_and_the_rest_are_not_consulted()
    {
        Assert.True(RegisteredRedirectUri.TryRegister("https://a.example/cb", out var first, out _));
        Assert.True(RegisteredRedirectUri.TryRegister("https://b.example/cb", out var second, out _));
        Assert.True(RequestedRedirectUri.TryParse("https://b.example/cb", out var req, out _));

        var match = RedirectUriMatcher.Match(req!.Value, [first!.Value, second!.Value]);

        Assert.True(match.Matched);
        Assert.Equal("https://b.example/cb", match.Registration.Value);
    }
}
