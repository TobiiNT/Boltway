using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Boltway.ResourceServer.Tests;

/// <summary>
/// The walk a client actually takes, end to end, in one test.
/// </summary>
/// <remarks>
/// <para>
/// Every step here is asserted somewhere else in this assembly in isolation. This file exists
/// because the audit's finding was not that any piece was wrong - the challenge builder and the
/// validation parameters were both complete and unit-tested - but that nothing joined them up, so
/// no test had ever followed the pointer from one to the next. A chain of individually correct
/// links is not a chain until something pulls on it.
/// </para>
/// <para>
/// The order is the documented one: 401 from the resource, read <c>resource_metadata</c> out of the
/// challenge, fetch that document, read <c>authorization_servers[0]</c>, come back with a token for
/// this resource.
/// </para>
/// </remarks>
public sealed class DiscoveryWalkTests
{
    [Fact]
    public async Task A_client_can_get_from_no_token_to_a_working_call_using_only_what_the_server_told_it()
    {
        await using var fixture = await ResourceServerFixture.StartAsync();

        // Step 1. The unauthenticated call. It has to be a real 401: Claude does not honour a
        // WWW-Authenticate header on a 200, and a 200 carrying isError: true produces no
        // authentication prompt at all.
        using var unauthenticated = await fixture.Client.PostAsync(
            new Uri("/mcp", UriKind.Relative), content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        // Step 2. Read the pointer out of the challenge. Nothing here is constructed by the test -
        // the URL is whatever the server said it was, which is the point.
        var metadataUrl = BearerChallengeTests.Parameter(unauthenticated, "resource_metadata");

        Assert.False(string.IsNullOrEmpty(metadataUrl));

        // Step 3. Fetch it. Absolute, so this proves the challenge carries a URL a client can use
        // without knowing anything about this deployment.
        using var metadata = await fixture.Client.GetAsync(new Uri(metadataUrl!, UriKind.Absolute));

        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        Assert.Equal("application/json", metadata.Content.Headers.ContentType?.MediaType);

        using var document = JsonDocument.Parse(await metadata.Content.ReadAsStringAsync());
        var root = document.RootElement;

        // Step 4. RFC 9728 §3.3, performed the way a conformant client performs it: the `resource`
        // must be the identifier whose insertion produced the URL just fetched. A client that finds
        // otherwise MUST NOT use what it fetched.
        var resource = root.GetProperty("resource").GetString();

        Assert.Equal(
            metadataUrl,
            Boltway.ResourceServer.Metadata.WellKnownResourceUri.Insert(resource!));

        // Step 5. The authorization server. Claude uses the first entry and does not fall back.
        var authorizationServer = root.GetProperty("authorization_servers")[0].GetString();

        Assert.Equal(Build.Issuer, authorizationServer);

        // Step 6. Which scopes to ask for. The challenge named them, so those win over the
        // document's scopes_supported.
        var scope = BearerChallengeTests.Parameter(unauthenticated, "scope");

        Assert.Contains(Build.ToolScope, scope!.Split(' '), StringComparer.Ordinal);

        // Steps 7-9 - /authorize, consent, /token - happen at the authorization server and are
        // covered by Boltway.AuthorizationServer.Tests. What arrives back here is a token
        // whose iss is the issuer this document named and whose aud is the resource it named. That
        // is what the minter is handed below: not a token the test invented, but one built from the
        // two values the walk just read off the wire.
        var token = Mint.AccessToken(
            audience: Build.Resolve(resource!, issuer: authorizationServer!),
            issuer: authorizationServer!,
            scope: scope!);

        // Step 10. The call that was refused in step 1 now works.
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var authenticated = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
    }

    [Fact]
    public async Task The_fallback_probe_finds_the_document_without_the_pointer()
    {
        // C-26: when a challenge carries no resource_metadata, Claude probes the MCP server's
        // origin - the path-inserted form first, then the root form. This server always emits the
        // pointer, so this is the belt to that braces: a client that ignores the header, or a proxy
        // that strips it, still lands on the document.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var inserted = await fixture.Client.GetAsync(
            new Uri("/.well-known/oauth-protected-resource/mcp", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, inserted.StatusCode);

        using var root = await fixture.Client.GetAsync(
            new Uri("/.well-known/oauth-protected-resource", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, root.StatusCode);
    }

    [Fact]
    public async Task The_challenge_points_at_the_path_inserted_form_rather_than_the_root_one()
    {
        // Which of the two shapes the pointer names is not arbitrary. RFC 9728 §3.1 makes the
        // path-inserted URL the normative location for an identifier that has a path, and it is the
        // only one whose §3.3 identity check succeeds - a client fetching the root form finds a
        // `resource` of https://mcp.example.com/mcp where it inserted into
        // https://mcp.example.com, and is required to discard the document. The root form is a
        // compatibility probe; the pointer names the answer.
        await using var fixture = await ResourceServerFixture.StartAsync();

        using var response = await fixture.Client.GetAsync(new Uri("/mcp", UriKind.Relative));

        Assert.Equal(Build.MetadataUrl, BearerChallengeTests.Parameter(response, "resource_metadata"));
    }
}
