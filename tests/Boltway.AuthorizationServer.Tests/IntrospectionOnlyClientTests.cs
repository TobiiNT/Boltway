using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The third kind of client: a resource server that only calls <c>/introspect</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because the deployment that needed it could not be configured at all.</b> RFC 7662
/// §2.1 requires the introspection endpoint to be authorized, so a resource server wanting
/// revocation needs a confidential client - and the host refused to start with one, because its
/// <c>CLIENTS</c> rule demanded either a redirect URI or an owner and this client wants neither.
/// Measured against the running host: <c>CLIENTS entry 'northwind-connector' registers no redirect URI,
/// so no authorization could ever complete for it</c>, and the process exited. Not "revocation
/// quietly does nothing" - the authorization server does not boot, on the deploy that turns it on.
/// </para>
/// <para>
/// <b>Both available workarounds were worse than the gap.</b> A placeholder <c>redirectUris</c> is a
/// live authorization-code target for whoever steals the secret, and the parser's own comment
/// already refuses to invent "a URL that must never be used". <c>owner</c> makes the client act as
/// that account through <c>client_credentials</c> - trading "may ask whether a token is live" for
/// "may be issued a person's token", to get past a validation rule.
/// </para>
/// <para>
/// <b>What these tests pin is the claim the flag makes: it can introspect, and it can do nothing
/// else.</b> That claim rests on three separate refusals in three different places, so it is
/// asserted three times rather than reasoned about once. The shape under test is exactly what
/// <c>ParseClient</c> builds for <c>introspectionOnly</c> - no redirect URIs, no owner, a secret -
/// which is why the record is written out here rather than taken from <c>Build.Client</c>.
/// </para>
/// </remarks>
public sealed class IntrospectionOnlyClientTests
{
    private const string ResourceServer = "northwind-connector";

    private static readonly string Secret = OpaqueSecret.Generate(TokenPurpose.ClientSecret).Wire;

    /// <summary>It can authenticate at the one endpoint it exists for.</summary>
    /// <remarks>
    /// The control for everything below. Without it, three refusals would prove only that the
    /// client is broken - which is also what a client nobody registered looks like.
    /// </remarks>
    [Fact]
    public async Task It_can_introspect()
    {
        await using var fixture = await StartAsync();

        var (status, body) = await IntrospectAsync(fixture, "not-a-real-token");

        Assert.Equal(HttpStatusCode.OK, status);

        // §2.2: an unusable token is `active: false` with a 200, never an error. The point here is
        // the 200 - the credential was accepted - rather than the answer, which is about the token.
        Assert.False(body.GetProperty("active").GetBoolean());
    }

    /// <summary>It cannot be issued a token of its own, on either kind of server.</summary>
    /// <remarks>
    /// <para>
    /// The refusal that matters most, because <c>owner</c> was the workaround that would have
    /// granted exactly this. A client holding a valid secret is still not entitled to anybody's
    /// token.
    /// </para>
    /// <para>
    /// <b>Two servers, because the first draft of this test pinned the wrong one.</b> It asserted
    /// <c>unauthorized_client</c> and got <c>unsupported_grant_type</c>: a deployment with no
    /// service account does not advertise <c>client_credentials</c> at all, so the refusal comes
    /// from a server-wide gate that has nothing to do with this client. That refusal is real, and
    /// it would keep this test green while the client-level gate rotted underneath it - because
    /// the client-level gate is only reachable on a server that *does* advertise the grant. So
    /// both are driven, and each is pinned to the gate that actually stopped it.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(false, "unsupported_grant_type")]
    [InlineData(true, "unauthorized_client")]
    public async Task It_cannot_be_issued_a_token(bool serviceAccountsExist, string expected)
    {
        await using var fixture = await StartAsync(serviceAccountsExist);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "client_credentials",
                ["scope"] = "mcp:tools",
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Basic(ResourceServer, Secret));

        using var response = await fixture.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(expected, body.RootElement.GetProperty("error").GetString());
    }

    /// <summary>Nobody can authorize it, because there is nowhere to send a code.</summary>
    /// <remarks>
    /// The refusal a placeholder redirect URI would have removed. It is refused at the request
    /// rather than at the redirect, which is the part that matters: a refusal that redirects is one
    /// that hands something to an address, and there is no address here that should receive one.
    /// </remarks>
    [Fact]
    public async Task Nobody_can_authorize_it()
    {
        await using var fixture = await StartAsync();

        var query = string.Join('&',
            "response_type=code",
            "client_id=" + ResourceServer,
            "redirect_uri=" + Uri.EscapeDataString("https://example.com/anything"),
            "code_challenge=abc",
            "code_challenge_method=S256",
            "scope=mcp:tools");

        using var response = await fixture.Client.GetAsync("/authorize?" + query);

        Assert.NotEqual(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /// <param name="serviceAccountsExist">
    /// Whether this server advertises <c>client_credentials</c> at all. A host does that when some
    /// client names an owner, which is a fact about the deployment rather than about this client -
    /// and it decides which of two gates refuses the token request.
    /// </param>
    private static Task<FlowFixture> StartAsync(bool serviceAccountsExist = false) =>
        FlowFixture.StartAsync(seed =>
        {
            var now = DateTimeOffset.UtcNow;

            // Wall-clock, for the reason IntrospectionEndpointTests records: this is the one
            // endpoint that asks Microsoft.IdentityModel to judge expiry, and its TimeProvider is
            // internal in 8.22.0.
            seed.Now = now;
            seed.SignedInUser = new(SubjectId.FromStorage("user-1"), now.AddMinutes(-1));

            // Exactly what ParseClient produces for `introspectionOnly`: confidential, a secret,
            // and an empty redirect list. GrantTypes is the interactive pair because the library
            // derives it from the absence of an owner - this record is not tidied up to look like
            // what the tests want, because then the tests would be about the tidying.
            seed.Clients.Add(new ClientRecord
            {
                ClientId = ClientIdentifier.ForPreRegistered(ResourceServer),
                ClientType = ClientType.Confidential,
                TokenEndpointAuthMethod = ClientAuthMethod.ClientSecretBasic,
                RedirectUris = [],
                GrantTypes = ["authorization_code", "refresh_token"],
                ResponseTypes = ["code"],
                ClientName = "Northwind connector",
            });

            seed.ClientSecrets[ResourceServer] = Secret;

            seed.ConfigureOptions = o =>
            {
                o.IntrospectionEnabled = true;

                if (!o.TokenEndpointAuthMethods.Contains(ClientAuthMethod.ClientSecretBasic))
                {
                    o.TokenEndpointAuthMethods.Add(ClientAuthMethod.ClientSecretBasic);
                }

                if (serviceAccountsExist && !o.GrantTypesSupported.Contains("client_credentials"))
                {
                    o.GrantTypesSupported.Add("client_credentials");
                }
            };
        });

    private static async Task<(HttpStatusCode Status, JsonElement Body)> IntrospectAsync(
        FlowFixture fixture, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["token"] = token,
                ["token_type_hint"] = "access_token",
            }),
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Basic(ResourceServer, Secret));

        using var response = await fixture.Client.SendAsync(request);

        using var parsed = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        return (response.StatusCode, parsed.RootElement.Clone());
    }

    /// <summary>
    /// RFC 6749 §2.3.1: both halves are form-urlencoded before they are base64'd.
    /// </summary>
    /// <remarks>
    /// The step everybody skips until a secret contains a <c>+</c>. It is written out here rather
    /// than taken from a helper because the resource server this models does the same thing in
    /// <c>IntrospectionRevocationCheck</c>, and the two agreeing is the point.
    /// </remarks>
    private static string Basic(string id, string secret) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(id)}:{Uri.EscapeDataString(secret)}"));
}
