using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Confidential clients authenticating with a shared secret, OAuth 2.1 §2.4.1 and §2.4.2.
/// </summary>
/// <remarks>
/// <para>
/// This file exists because mutation testing found the whole method missing from the suite rather
/// than any single assertion. <c>TestClientSecretStore</c> returned <see langword="null"/> for every
/// client, under the summary "No client has a secret; everything in these tests is a public
/// client" - so <c>SecretAsync</c> could only ever reach its "no secret is stored for this client"
/// refusal. Stryker reported the <c>Authenticated(...)</c> branch as <c>NoCoverage</c>, and a
/// cluster of guards on the road to it survived together:
/// </para>
/// <list type="bullet">
/// <item>the strict-UTF-8 decode of the Basic payload - both <c>throwOnInvalidBytes</c> mutants</item>
/// <item><c>separator &lt; 0</c>, the <c>':'</c> split that separates id from secret</item>
/// <item><c>separator + 1</c>, which cuts the secret out - mutating it to <c>separator - 1</c>
/// corrupts every secret read from a header, and nothing failed</item>
/// <item><c>usedHeader</c>, which decides whether the result reports
/// <c>client_secret_basic</c> or <c>client_secret_post</c></item>
/// </list>
/// <para>
/// None of them were killable by a suite in which no secret authentication ever succeeded. The
/// suite had 573 tests and could not tell you whether a confidential client could log in at all.
/// </para>
/// <para>
/// Neither shipped connector needs this: Claude and ChatGPT are both public clients using PKCE with
/// <c>token_endpoint_auth_method=none</c>. But both secret methods are implemented, both are
/// advertised in the authorization server metadata, and RFC 8414 §2 makes
/// <c>client_secret_basic</c> the default a client assumes when the metadata omits the list. A
/// method that is advertised and never proven is the one that breaks in front of the first customer
/// who registers a confidential client.
/// </para>
/// </remarks>
public sealed class ClientSecretAuthenticationTests
{
    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    /// <summary>A real minted secret: the server parses before it compares, so shape matters.</summary>
    private static readonly string Secret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

    private static Task<FlowFixture> StartAsync(ClientAuthMethod method, string secret = "") =>
        FlowFixture.StartAsync(seed =>
        {
            seed.Client = Build.Client(ClientId, ClientType.Confidential)
                with { TokenEndpointAuthMethod = method };

            // A deployment offers the methods its clients use, and the same list is what the
            // discovery document advertises and what ClientAuthenticator enforces. Seeding a
            // client with a method and not offering it is a state no deployment can be in, so
            // the fixture is held to the same thing - which is also what proves the arm works
            // for a deployment that does offer it.
            seed.ConfigureOptions = o =>
            {
                if (!o.TokenEndpointAuthMethods.Contains(method)) o.TokenEndpointAuthMethods.Add(method);
            };

            seed.ClientSecrets[ClientId] = secret.Length == 0 ? Secret : secret;
        });

    private static async Task<string> GetCodeAsync(FlowFixture fixture)
    {
        var query = string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(ClientId),
            "redirect_uri=" + Uri.EscapeDataString(RedirectUri),
            "code_challenge=" + Verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString("mcp:tools offline_access"),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque-state");

        var response = await fixture.Client.GetAsync("/authorize?" + query);

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var code = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query)["code"];

        Assert.False(string.IsNullOrEmpty(code), "no code was issued");
        return code!;
    }

    private static Dictionary<string, string> ExchangeFields(string code) =>
        new(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier.Value,
        };

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();

    private static string BasicOf(string clientId, string secret) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}"));

    // ─────────────────────────────────────────────────────────────────────────
    // §2.4.1 - client_secret_basic
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_confidential_client_authenticates_with_a_basic_header()
    {
        await using var fixture = await StartAsync(ClientAuthMethod.ClientSecretBasic);

        var code = await GetCodeAsync(fixture);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(ExchangeFields(code)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The token is what proves it: a 200 with no access token would mean the endpoint answered
        // without authenticating anybody.
        var body = await ReadJsonAsync(response);
        Assert.False(string.IsNullOrEmpty(body.GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task A_basic_header_carrying_the_wrong_secret_is_refused()
    {
        // The control for the test above. Without it, an authenticator that accepted ANY Basic
        // header would pass - and that is precisely the shape of the bug this file was written to
        // make expressible.
        await using var fixture = await StartAsync(ClientAuthMethod.ClientSecretBasic);

        var code = await GetCodeAsync(fixture);
        var wrong = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(ExchangeFields(code)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, wrong));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());

        // §5.2: a client that authenticated via the Authorization header gets a challenge back.
        Assert.True(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task A_basic_credential_is_form_decoded_before_it_is_compared()
    {
        // §2.4.1 sends the id and secret application/x-www-form-urlencoded inside the base64. A
        // server that skips the decoding compares the wrong bytes, and the failure looks like a
        // wrong password rather than an encoding bug.
        //
        // This is also what kills the `separator + 1` mutant: with `separator - 1` the secret is cut
        // one character early, so it can only be right when nothing checks it.
        await using var fixture = await StartAsync(ClientAuthMethod.ClientSecretBasic);

        var code = await GetCodeAsync(fixture);

        // The client id is a URL, so it already carries ':' and '/' - the characters that make the
        // colon split ambiguous if the id is not encoded.
        Assert.Contains(":", ClientId, StringComparison.Ordinal);
        Assert.Contains("%3A", Uri.EscapeDataString(ClientId), StringComparison.Ordinal);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(ExchangeFields(code)),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        Assert.Equal(HttpStatusCode.OK, (await fixture.Client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task A_basic_credential_carrying_ill_formed_utf8_is_refused()
    {
        // The decoder is strict on purpose: the permissive one substitutes U+FFFD for every
        // undecodable byte, which makes two different secrets compare equal. 0xC3 0x28 is a
        // truncated two-byte sequence - valid base64, invalid UTF-8.
        await using var fixture = await StartAsync(ClientAuthMethod.ClientSecretBasic);

        var payload = new List<byte>();
        payload.AddRange(Encoding.UTF8.GetBytes(Uri.EscapeDataString(ClientId)));
        payload.Add((byte)':');
        payload.AddRange([0xC3, 0x28]);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(ExchangeFields(await GetCodeAsync(fixture))),
        };

        request.Headers.TryAddWithoutValidation(
            "Authorization", "Basic " + Convert.ToBase64String([.. payload]));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());

        // The wire answer is NOT what distinguishes the two encoders, and measuring that is what
        // this assertion is for. Relaxing throwOnInvalidBytes leaves the response byte-identical:
        // the permissive decoder folds 0xC3 0x28 to U+FFFD, the folded value still fails
        // OpaqueSecret.TryParse because U+FFFD is not in the base64url alphabet, and the client
        // still gets invalid_client. A test that stopped at the line above passed under both - it
        // was written that way first, and the control run proved it worthless.
        //
        // So the real difference is the diagnosis. Strict refuses at the header - the credential
        // never parsed, and the server cannot say whose it was. Permissive invents a client id out
        // of replacement characters and then reports a failed secret comparison for it, sending
        // whoever reads the log looking for a client that was never named.
        //
        // This also corrects the claim the source comment used to make. Ill-formed bytes here
        // cannot produce a false ACCEPT, because a secret must survive OpaqueSecret.TryParse before
        // any comparison happens. What they produce is a wrong answer about who failed.
        var rejection = Assert.Single(fixture.Logs.Rejections);

        Assert.Equal(
            nameof(ReasonCode.ClientAuthorizationHeaderMalformed),
            rejection.Property("Reason"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §2.4.2 - client_secret_post, and the binding between them
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_confidential_client_authenticates_with_a_body_secret()
    {
        await using var fixture = await StartAsync(ClientAuthMethod.ClientSecretPost);

        var fields = ExchangeFields(await GetCodeAsync(fixture));
        fields["client_secret"] = Secret;

        var response = await fixture.Client.PostAsync("/token", new FormUrlEncodedContent(fields));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(string.IsNullOrEmpty(
            (await ReadJsonAsync(response)).GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task The_registered_method_decides_not_the_presented_one()
    {
        // A client registered for the body form that presents a correct secret in a Basic header is
        // refused. The secret is right; the method is not the one it registered. Without this, the
        // two branches of the `usedHeader` switch are interchangeable.
        await using var fixture = await StartAsync(ClientAuthMethod.ClientSecretPost);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(ExchangeFields(await GetCodeAsync(fixture))),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicOf(ClientId, Secret));

        var response = await fixture.Client.SendAsync(request);

        Assert.Equal("invalid_client", (await ReadJsonAsync(response)).GetProperty("error").GetString());
    }
}
