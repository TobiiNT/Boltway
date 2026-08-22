using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Boltway.ResourceServer.Tests;

/// <summary>X-32 through X-35, over a running server.</summary>
public sealed class BearerChallengeTests
{
    [Fact]
    public async Task No_credentials_gets_a_401_with_a_challenge()
    {
        // X-32, and the reason the whole handshake exists: "Claude does not honor a
        // WWW-Authenticate header on a 200 response", and a 200 carrying isError: true produces no
        // authentication prompt at all — the text goes to the model as a tool result and the
        // conversation moves on. The status code is the signal.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", Challenge(response).Scheme);
    }

    [Fact]
    public async Task The_challenge_points_at_the_metadata_document()
    {
        // RFC 9728 §5.1. Without this pointer a client falls back to probing, which costs
        // round-trips on every connection and only works if the platform serves /.well-known/*.
        // With it, discovery is one hop.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.Equal(Build.MetadataUrl, Parameter(response, "resource_metadata"));
    }

    [Fact]
    public async Task The_challenge_carries_error_even_though_rfc_6750_says_to_omit_it()
    {
        // X-32's exception. RFC 6750 §3.1 says a challenge answering a request with no credentials
        // should carry no error code; OpenAI needs both `error` and `error_description` present to
        // trigger its authentication UI, and Claude is content either way. A challenge one vendor
        // ignores is worse than a slightly over-specified one.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.Equal("invalid_token", Parameter(response, "error"));
        Assert.False(string.IsNullOrEmpty(Parameter(response, "error_description")));
    }

    [Fact]
    public async Task The_challenge_names_the_scopes_the_endpoint_needs()
    {
        // The MCP scope-selection strategy reads the challenge's `scope` first and falls back to
        // the document's whole scopes_supported only when it is absent. /mcp/write declares two, so
        // both are named and the grant stays minimal.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp/write", UriKind.Relative));

        var scopes = Parameter(response, "scope")!.Split(' ');

        Assert.Contains(Build.ToolScope, scopes);
        Assert.Contains(Build.WriteScope, scopes);
    }

    [Fact]
    public async Task An_endpoint_that_declares_no_scope_falls_back_to_the_advertised_set()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/protected", UriKind.Relative));

        var scopes = Parameter(response, "scope")!.Split(' ');

        Assert.Contains(Build.ToolScope, scopes);
        Assert.Contains(Build.WriteScope, scopes);
    }

    [Fact]
    public async Task Every_parameter_in_the_challenge_is_a_quoted_string()
    {
        // RFC 7235 auth-param values are token or quoted-string, and a URL contains ':' and '/',
        // neither of which is a tchar. An unquoted resource_metadata is a protocol violation that
        // several parsers answer by dropping the parameter — which removes the discovery pointer
        // while leaving a 401 that looks correct.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        var parameter = Challenge(response).Parameter!;

        foreach (var part in parameter.Split(", ", StringSplitOptions.RemoveEmptyEntries))
        {
            var value = part[(part.IndexOf('=', StringComparison.Ordinal) + 1)..];

            Assert.StartsWith("\"", value, StringComparison.Ordinal);
            Assert.EndsWith("\"", value, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task The_challenge_is_never_cached()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.True(response.Headers.CacheControl!.NoStore);
    }

    [Fact]
    public async Task The_body_repeats_the_header_and_says_nothing_else()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal("invalid_token", body.RootElement.GetProperty("error").GetString());
        Assert.Equal(
            Parameter(response, "error_description"),
            body.RootElement.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task A_valid_token_reaches_the_endpoint()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(fixture, "/mcp", Mint.AccessToken());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A_lower_case_bearer_scheme_is_accepted()
    {
        // RFC 9110 §11.1: the auth scheme is case-insensitive. A client sending "bearer" is
        // conformant, and refusing it would be a 401 nothing on the client side could fix.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.TryAddWithoutValidation("Authorization", "bearer " + Mint.AccessToken());

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task An_expired_token_gets_a_401_not_a_403()
    {
        // X-33. A 401 is what makes Claude refresh; the vendor documentation says it refreshes
        // "reactively on a 401 response". Any other status leaves a live connection dead.
        await using var fixture = await ResourceServerFixture.StartAsync();

        var expired = Mint.AccessToken(
            lifetime: TimeSpan.FromMinutes(-10), issuedAt: DateTimeOffset.UtcNow.AddMinutes(-20));

        using var response = await Get(fixture, "/mcp", expired);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_token", Parameter(response, "error"));
    }

    [Fact]
    public async Task A_token_signed_by_a_stranger_gets_a_401()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(fixture, "/mcp", Mint.AccessToken(key: TestKeys.Stranger));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_token", Parameter(response, "error"));
    }

    [Fact]
    public async Task A_token_from_another_issuer_gets_a_401()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        var foreign = Mint.AccessToken(
            audience: Build.Resolve(Build.Resource, issuer: "https://evil.example.com"),
            issuer: "https://evil.example.com");

        using var response = await Get(fixture, "/mcp", foreign);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_token", Parameter(response, "error"));
    }

    [Fact]
    public async Task An_unparseable_token_gets_a_401_and_the_request_never_reaches_the_header()
    {
        // The credential is syntactically a b64token, so this is a validation failure rather than a
        // malformed header — and the description that comes back is a constant. error_description
        // is the one parameter carrying free text, and a stray quote in it terminates the quoted
        // string early and eats the resource_metadata that follows.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(fixture, "/mcp", "aaa.bbb.ccc");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(Build.MetadataUrl, Parameter(response, "resource_metadata"));
    }

    [Fact]
    public async Task A_valid_token_short_of_a_scope_gets_a_403_with_insufficient_scope()
    {
        // X-34. A 403 without error="insufficient_scope" is terminal for Claude — no re-auth
        // prompt, permanently — so this is the only 403 the middleware can produce.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(fixture, "/mcp/write", Mint.AccessToken(scope: Build.ToolScope));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("insufficient_scope", Parameter(response, "error"));
    }

    [Fact]
    public async Task The_403_lists_every_scope_the_operation_needs_not_only_the_missing_one()
    {
        // Claude asks for the union of the challenge's scopes and its discovery-time scope, and it
        // does not reliably carry forward what an earlier step-up granted. A challenge naming only
        // the delta re-authorizes the user into a narrower grant than they already had.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(fixture, "/mcp/write", Mint.AccessToken(scope: Build.ToolScope));

        var scopes = Parameter(response, "scope")!.Split(' ');

        Assert.Contains(Build.WriteScope, scopes);
        Assert.Contains(Build.ToolScope, scopes);
    }

    [Fact]
    public async Task The_403_still_carries_the_metadata_pointer()
    {
        // X-34 requires resource_metadata on this challenge too: the client is being asked to go
        // back to the authorization server, and the pointer is how it finds which one.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(fixture, "/mcp/write", Mint.AccessToken(scope: Build.ToolScope));

        Assert.Equal(Build.MetadataUrl, Parameter(response, "resource_metadata"));
    }

    [Fact]
    public async Task A_token_carrying_every_required_scope_reaches_the_endpoint()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await Get(
            fixture, "/mcp/write", Mint.AccessToken(scope: Build.ToolScope + " " + Build.WriteScope));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    // The scheme was claimed and nothing followed it.
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    // Outside RFC 6750 §2.1's b64token grammar.
    [InlineData("Bearer abc$def")]
    [InlineData("Bearer abc def")]
    [InlineData("Bearer \"quoted\"")]
    public async Task A_malformed_authorization_header_gets_a_400_not_a_401(string header)
    {
        // X-35, and the direction matters: "getting this backwards makes clients retry-loop forever
        // on refresh". A 401 tells a client to get a new token, and a new token presented through
        // the same broken header fails identically, so the loop never terminates.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.TryAddWithoutValidation("Authorization", header);

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", Parameter(response, "error"));
    }

    [Fact]
    public async Task Two_authorization_headers_get_a_400()
    {
        // RFC 6750 §3.1 makes "more than one method for including an access token" invalid_request.
        // Which of the two to honour is exactly the sort of decision a proxy and an origin make
        // differently.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Mint.AccessToken());
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Mint.AccessToken());

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", Parameter(response, "error"));
    }

    [Fact]
    public async Task A_token_in_the_query_string_gets_a_400_even_when_it_is_otherwise_valid()
    {
        // bearer_methods_supported advertises "header" only and the MCP specification forbids a
        // token in a URL, where it lands in access logs, proxy logs and Referer headers. A 400 says
        // this server will not read it; a 401 would invite a refresh that changes nothing.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(
            new Uri("/mcp?access_token=" + Mint.AccessToken(), UriKind.Relative));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", Parameter(response, "error"));
    }

    [Fact]
    public async Task A_valid_header_token_alongside_a_query_token_still_gets_a_400()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp?access_token=whatever");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Mint.AccessToken());

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_credential_in_another_scheme_gets_a_401_not_a_400()
    {
        // The inverse of X-35's reasoning. A client holding a Basic credential for some other
        // system has not failed to FORM a Bearer request, it has failed to MAKE one — and the
        // challenge that comes back tells it which scheme this resource speaks and where the
        // metadata is, which is actionable. A 400 would be terminal for a client that could have
        // authenticated correctly.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(Build.MetadataUrl, Parameter(response, "resource_metadata"));
    }

    [Fact]
    public async Task A_scheme_whose_name_merely_starts_with_bearer_is_not_a_bearer_credential()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.TryAddWithoutValidation("Authorization", "BearerToken abc");

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_crafted_authorization_header_cannot_inject_into_the_challenge()
    {
        // Every error_description this server writes is a compile-time constant, so there is
        // nothing for a crafted header to reach. The assertion is that the challenge is
        // well-formed and still carries the discovery pointer — because the failure being ruled out
        // is not "the attacker's text appears" but "the header is truncated at their quote and
        // resource_metadata disappears with it".
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer \"; evil=\"yes");

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(Build.MetadataUrl, Parameter(response, "resource_metadata"));
        Assert.DoesNotContain("evil", Challenge(response).Parameter!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_anonymous_endpoint_stays_reachable()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/open", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A_path_that_matched_no_endpoint_is_a_404_rather_than_a_challenge()
    {
        // Fail-closed stops at the routing table. A 401 on an unrouted path would turn every stray
        // probe into an authentication prompt, and it would do it on exactly the paths a client
        // probes during discovery — where a clean 404 is what lets it move to the next candidate.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/nothing-here", UriKind.Relative));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Turning_off_the_default_leaves_an_undeclared_endpoint_open()
    {
        // The opt-out exists for a resource server that mostly serves public content. Asserted so
        // that "RequireBearerByDefault protects everything" is a measured claim about the default
        // rather than an assumption about the flag in either position.
        await using var fixture = await ResourceServerFixture.StartAsync(o => o.RequireBearerByDefault = false);

        using var undeclared = await fixture.Client.GetAsync(new Uri("/protected", UriKind.Relative));
        using var declared = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, undeclared.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, declared.StatusCode);
    }

    [Fact]
    public async Task A_cors_enabled_host_gets_the_challenge_header_exposed_to_script()
    {
        // A browser hides every response header from script except a short safelist, and neither
        // WWW-Authenticate nor X-Request-Id is on it. Conditional on the host's own policy having
        // admitted the request, so this grants nothing that was not already granted.
        //
        // X-Request-Id is on the list for A-09: a browser-based client that can read the challenge
        // but not the correlation id can report "it failed" and nothing an operator can search for.
        await using var fixture = await ResourceServerFixture.StartAsync(corsEnabledByHost: true);

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.Equal(
            "WWW-Authenticate, X-Request-Id",
            Assert.Single(response.Headers.GetValues("Access-Control-Expose-Headers")));
    }

    [Fact]
    public async Task A_host_without_cors_gets_no_expose_header()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.False(response.Headers.Contains("Access-Control-Expose-Headers"));
    }

    internal static async Task<HttpResponseMessage> Get(
        ResourceServerFixture fixture, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await fixture.Client.SendAsync(request);
    }

    internal static AuthenticationHeaderValue Challenge(HttpResponseMessage response) =>
        Assert.Single(response.Headers.WwwAuthenticate);

    /// <summary>Pull one auth-param out of the challenge, unquoted.</summary>
    internal static string? Parameter(HttpResponseMessage response, string name)
    {
        var parameter = Challenge(response).Parameter;

        if (parameter is null)
        {
            return null;
        }

        foreach (var part in parameter.Split(", ", StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=', StringComparison.Ordinal);

            if (separator > 0 && string.Equals(part[..separator], name, StringComparison.Ordinal))
            {
                return part[(separator + 1)..].Trim('"');
            }
        }

        return null;
    }
}
