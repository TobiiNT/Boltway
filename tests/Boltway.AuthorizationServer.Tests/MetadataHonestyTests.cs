using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Consent;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Stores;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Metadata;
using Boltway.AuthorizationServer.Token;
using Boltway.Identity.Passwords;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// N-06, checked over the whole document rather than field by field.
/// </summary>
/// <remarks>
/// <para>
/// N-06 is "advertised capability == actual capability, generated from live config", and it is on
/// the never-cut list. It was violated four times over in the shipped defaults. An operability
/// review built a host the way a customer would and measured it:
/// </para>
/// <code>
/// /userinfo    -> 404      /revoke    -> 404
/// /introspect  -> 404      /logout    -> 404
/// </code>
/// <para>
/// Every one of them published in the discovery document, none routed. Nothing caught it because
/// every existing test asserted properties of *specific* fields, and the four nobody had
/// implemented were also the four nobody had written a test for. The check that would have caught
/// it does not need to know any field names: take the document the server actually serves, find
/// every URL in it, and ask the server for each one.
/// </para>
/// <para>
/// <b>Deliberately no <c>MapFallback</c> in this host.</b> The sibling fixture in
/// <c>DiscoveryEndpointTests</c> installs an HTML catch-all on purpose, to prove the well-known
/// probes survive a SPA shell — which means nothing 404s there and this sweep would pass over a
/// server that routed none of it.
/// </para>
/// </remarks>
public sealed partial class MetadataHonestyTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = await StartAsync(null);
        _client = _host.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    private static async Task<IHost> StartAsync(Action<AuthorizationServerOptions>? extra) =>
        await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(TestKeys.Ring());

                    // The seams a deployment supplies. Registered because /token resolves them on
                    // the first request rather than at startup — Every_advertised_grant_has_a_handler
                    // found that the hard way, with a host that started cleanly and threw
                    // "No service for type 'IClientSecretStore'" the moment a client showed up.
                    services.AddSingleton<IClientResolver>(new TestClientResolver([Build.Client()]));
                    services.AddSingleton<IResourceRegistry>(new TestResourceRegistry().Add(Build.Resource, "mcp:tools"));
                    services.AddSingleton<IGrantStore, InMemoryGrantStore>();
                    services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
                    services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
                    services.AddSingleton<IConsentStore, TestConsentStore>();
                    services.AddSingleton<IConsentPolicy>(_ => new TestConsentPolicy(ConsentDecision.AlreadyGranted));
                    // No secrets: this suite asks what the metadata advertises, not who can
                    // authenticate. The store takes its contents explicitly so that a fixture which
                    // wants a client to hold a secret has to say so — the previous double answered
                    // null for everyone and silently removed both secret methods from the suite.
                    services.AddSingleton<IClientSecretStore>(
                        new TestClientSecretStore(new Dictionary<string, string>(StringComparer.Ordinal)));


                    services.AddScoped<IUserSession>(_ => new TestUserSession(null));

                    // Required at Map time even though nothing here serves /login: local passwords
                    // are the only authentication this server has, so RequiredAtMapTime lists
                    // IUserStore and IPasswordHasher unconditionally. The shipped implementations,
                    // because a double here would test the fixture rather than the wiring.
                    services.AddSingleton<IUserStore>(new InMemoryUserStore());
                    services.AddSingleton<IRoleStore>(new InMemoryRoleStore());
                    services.AddSingleton<IPasswordHasher>(new Argon2idPasswordHasher());

                    services.AddBoltwayAuthorizationServer(o =>
                    {
                        o.Issuer = Build.Issuer;
                        o.ScopesSupported.Add("openid");
                        o.ScopesSupported.Add("offline_access");
                        o.ScopesSupported.Add("mcp:tools");
                        o.RefreshTokenDerivationKey = Build.DerivationKey;

                        extra?.Invoke(o);
                    });
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapBoltwayAuthorizationServer());
                }))
            .StartAsync();

    /// <summary>
    /// Every URL the discovery document publishes is answered by something.
    /// </summary>
    /// <remarks>
    /// 404 is the only failing status. A 400 from <c>/authorize</c> with no parameters and a 405
    /// from <c>/token</c> on GET both mean the route exists and disagreed with the request, which is
    /// the property under test — this asks whether the server has the endpoint, not whether a bare
    /// GET is a valid call to it.
    /// </remarks>
    [Fact]
    public async Task Every_advertised_endpoint_answers()
    {
        var (urls, unrouted) = await SweepAsync(_client);

        Assert.True(
            unrouted.Count == 0,
            "The discovery document advertises endpoints this server does not route. N-06: an "
            + "advertised capability that 404s is a protocol lie, and a client that reads the "
            + "document has no way to find out except by failing:" + Environment.NewLine
            + string.Join(Environment.NewLine, unrouted.Select(u => "  " + u)));

        // The control. A sweep that found no URLs would report success over a document containing
        // nothing but the issuer — which is what a change to the property-walk below would do
        // silently. These three are the endpoints without which there is no OAuth server at all.
        Assert.Contains("/authorize", urls.Select(u => u.AbsolutePath), StringComparer.Ordinal);
        Assert.Contains("/token", urls.Select(u => u.AbsolutePath), StringComparer.Ordinal);
        Assert.Contains("/.well-known/jwks.json", urls.Select(u => u.AbsolutePath), StringComparer.Ordinal);
    }

    /// <summary>
    /// The non-vacuity control: turning on an unimplemented endpoint makes the sweep fail.
    /// </summary>
    /// <remarks>
    /// Without this, <see cref="Every_advertised_endpoint_answers"/> is green both when the server
    /// is honest and when the sweep has quietly stopped looking. Here the exact defect that shipped
    /// is reconstructed on purpose — <c>UserInfoEnabled</c> was <see langword="true"/> by default —
    /// and the sweep is required to catch it.
    /// </remarks>
    [Fact]
    public async Task The_sweep_catches_an_endpoint_that_is_advertised_but_not_routed()
    {
        // This control has moved twice and has now run out of flags, which is the good outcome and
        // needs saying because the shape of the test changed with it.
        //
        // It was /userinfo, then /revoke: both were flags that advertised a path nothing routed, and
        // each stopped being one when its endpoint was written. `RevocationEnabled` was the last —
        // /userinfo, /introspect, /logout and /revoke now all route and advertise from one flag
        // apiece, so there is no configuration of this server that produces the defect this control
        // needs. Pointing it at a flag that routes would assert that a routed endpoint is unrouted,
        // and fail honestly; leaving it pointed at nothing would make it pass over an empty list.
        //
        // So the control is built from a document rather than from a flag, which is what the note
        // here always said to do when the flags ran out. The stub serves a discovery document naming
        // a path nothing routes, and the sweep is required to report it. What is under test is the
        // sweep — that it walks the document, probes what it finds, and can tell a 404 from an
        // answer — and that is the property Every_advertised_endpoint_answers is worthless without.
        using var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services.AddRouting())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        // Two members: one endpoint that answers and one that does not. A document
                        // with only the unrouted one would pass a sweep that reported every URL as
                        // unrouted without probing anything.
                        endpoints.MapGet("/.well-known/oauth-authorization-server", (HttpContext http) =>
                            http.Response.WriteAsync(
                                $$"""
                                {"issuer":"{{Build.Issuer}}",
                                 "token_endpoint":"{{Build.Issuer}}/token",
                                 "revocation_endpoint":"{{Build.Issuer}}/nothing-routes-this"}
                                """));

                        endpoints.MapGet("/token", () => Task.CompletedTask);
                    });
                }))
            .StartAsync();

        using var client = host.GetTestClient();

        var (urls, unrouted) = await SweepAsync(client);

        Assert.Equal(
            [Build.Issuer + "/nothing-routes-this"],
            unrouted.Select(u => u.AbsoluteUri).ToArray(),
            StringComparer.Ordinal);

        // The other half of the same control: the routed one was probed and not reported. Without
        // this, a sweep that flagged every URL it found would satisfy the assertion above.
        Assert.Contains("/token", urls.Select(u => u.AbsolutePath), StringComparer.Ordinal);

        await host.StopAsync();
    }

    /// <summary>
    /// Every grant the document advertises reaches a handler.
    /// </summary>
    /// <remarks>
    /// <para>
    /// N-06 again, on the other axis. <c>KnownGrantTypes</c> — the list options validation accepts —
    /// carried <c>client_credentials</c> and the jwt-bearer URN, and <c>TokenEndpoint</c>'s dispatch
    /// has arms for two grants. So a customer who enabled either got it advertised in the discovery
    /// document and then refused at runtime by the switch's fallthrough, while the options file
    /// asserted "enabling a grant here without a handler is a startup failure rather than a runtime
    /// surprise".
    /// </para>
    /// <para>
    /// The request is deliberately otherwise empty, so every grant is missing everything it needs.
    /// What matters is <i>which</i> refusal comes back: <c>unsupported_grant_type</c> means the
    /// dispatch fell through and there is no handler, and any other error means a handler ran and
    /// objected to the request — which is the property under test. Asserting a specific error per
    /// grant would just re-encode each handler's first validation check here.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Every_advertised_grant_has_a_handler()
    {
        using var response = await _client.GetAsync("/.well-known/oauth-authorization-server");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        var grants = document.RootElement.GetProperty("grant_types_supported")
            .EnumerateArray().Select(g => g.GetString()!).ToList();

        Assert.NotEmpty(grants);

        foreach (var grant in grants)
        {
            using var attempt = await _client.PostAsync("/token", new FormUrlEncodedContent(
                new Dictionary<string, string>(StringComparer.Ordinal) { ["grant_type"] = grant }));

            using var body = JsonDocument.Parse(await attempt.Content.ReadAsStringAsync());
            var error = body.RootElement.GetProperty("error").GetString();

            Assert.False(
                string.Equals(error, "unsupported_grant_type", StringComparison.Ordinal),
                $"'{grant}' is advertised in grant_types_supported and has no handler at /token. "
                + "A client that reads the document and uses it is refused by a server that "
                + "invited it.");
        }
    }

    /// <summary>
    /// The advertised prompt values are exactly the ones <c>/authorize</c> acts on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the only honesty check here that runs served-to-advertised, and it exists
    /// because the document under-stated for a release.</b> Everything else in this file runs the
    /// other way — every advertised endpoint answers, every advertised grant has a handler, the
    /// sweep catches a promise with a 404 behind it. Over-advertising is the expensive direction
    /// and it is guarded four ways. Under-advertising costs a client a wasted round trip and
    /// nothing else, so nothing caught it: <c>/authorize</c> honoured four prompt values and
    /// <c>prompt_values_supported</c> appeared nowhere in the repository.
    /// </para>
    /// <para>
    /// <b>Pinned to the code rather than to a list written twice.</b> The expectation is read out
    /// of the source that consumes the parameter, so adding a fifth <c>Prompt.Contains("…")</c>
    /// without advertising it fails here, and so does advertising one nothing reads. A hardcoded
    /// pair of lists would agree with itself forever and prove nothing about either.
    /// </para>
    /// <para>
    /// It scans source text because there is nothing to reflect over: the values are string
    /// literals compared ordinally at four call sites across two files, not an enum or a table.
    /// That is the right shape for the code — matching a wire value is what those lines do — and
    /// it leaves the test as the only place the set is written down once.
    /// </para>
    /// </remarks>
    [Fact]
    public void The_advertised_prompt_values_are_exactly_the_ones_authorize_acts_on()
    {
        var root = RepositoryRoot();
        var server = Path.Combine(root, "src", "Boltway.AuthorizationServer");

        var honoured = new SortedSet<string>(StringComparer.Ordinal);
        var scanned = 0;

        foreach (var file in Directory.EnumerateFiles(server, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var line in File.ReadLines(file))
            {
                var match = PromptRead().Match(line);

                if (match.Success)
                {
                    scanned++;
                    honoured.Add(match.Groups[1].Value);
                }
            }
        }

        // The control. A rename of the context property, or a move of these files, would leave the
        // set empty and make the comparison below pass against nothing.
        Assert.True(
            scanned >= 4,
            $"Only {scanned} `Prompt.Contains(\"…\")` call sites were found under {server}. "
            + "If the parameter is now read some other way, this test has to learn the new shape "
            + "rather than be deleted.");

        var options = Build.Options();

        Assert.True(
            options.TryValidate(out var invalid),
            string.Join(Environment.NewLine, invalid));

        var advertised = new SortedSet<string>(
            MetadataBuilder.Build(options).PromptValuesSupported ?? [],
            StringComparer.Ordinal);

        Assert.True(
            advertised.SetEquals(honoured),
            "prompt_values_supported and the values /authorize acts on have diverged."
            + Environment.NewLine
            + "  advertised: " + string.Join(", ", advertised)
            + Environment.NewLine
            + "  honoured:   " + string.Join(", ", honoured));
    }

    /// <summary>Every <c>Prompt.Contains("…")</c>, which is how a prompt value is acted on here.</summary>
    [GeneratedRegex(@"Prompt\.Contains\(""([a-z_]+)""")]
    private static partial Regex PromptRead();

    /// <summary>Walk up from the test binary to the repository root, by shape.</summary>
    /// <remarks>
    /// By shape rather than a fixed count of <c>..</c> segments: that count changes with the target
    /// framework and configuration in the output path, and a path that silently resolves to nothing
    /// turns the scan above into a vacuous pass.
    /// </remarks>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(
            Path.GetDirectoryName(typeof(MetadataHonestyTests).Assembly.Location)!);

        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "tests")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        Assert.Fail("Could not find the repository root above the test binary.");
        return null!;
    }

    /// <summary>
    /// <c>claims_supported</c> is exactly what the ID token and <c>/userinfo</c> emit between them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both directions, because each catches a different lie. A claim advertised and never emitted
    /// is a promise to a relying party that nothing keeps — five of them shipped
    /// (<c>name</c>, <c>preferred_username</c>, <c>email</c>, <c>email_verified</c>,
    /// <c>updated_at</c>), against a doc comment on the very same list asserting that could not
    /// happen. A claim emitted and never advertised is the reverse: an RP that trusts the document
    /// to be complete will not look for it.
    /// </para>
    /// <para>
    /// The union rather than the ID token alone, and that is the second lie arriving by a different
    /// route. This test asserted over one surface, so when <c>/userinfo</c> shipped it kept passing
    /// while the document told every RP this server had no <c>email</c> to give. A test scoped to
    /// one endpoint cannot notice a second one appearing.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_advertised_claims_are_exactly_what_the_two_token_surfaces_emit()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var verifier = CodeVerifier.Generate();

        // openid for an ID token at all, a nonce so `nonce` applies, max_age so `auth_time` does,
        // and the authorization-code flow always carries an access token alongside, so `at_hash`
        // does too. That is every conditional claim the minter knows how to write.
        var authorize = "/authorize?" + string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(ClientId),
            "redirect_uri=" + Uri.EscapeDataString(RedirectUri),
            "code_challenge=" + verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString("openid offline_access mcp:tools"),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "nonce=n-abc",
            "max_age=3600",
            "state=opaque-state");

        var redirect = await fixture.Client.GetAsync(authorize);

        Assert.Equal(HttpStatusCode.SeeOther, redirect.StatusCode);

        var code = HttpUtility.ParseQueryString(
            new Uri(redirect.Headers.Location!.ToString()).Query)["code"];

        Assert.False(string.IsNullOrEmpty(code), "No code came back from /authorize.");

        using var tokenResponse = await fixture.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code!,
                ["client_id"] = ClientId,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = verifier.Value,
            }));

        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        using var tokens = JsonDocument.Parse(await tokenResponse.Content.ReadAsByteArrayAsync());
        var idToken = tokens.RootElement.GetProperty("id_token").GetString()!;

        // The other surface, measured the same way: a fully populated account, asked with `email`
        // granted, is the most /userinfo will ever say about anybody.
        var fromUserInfo = await MaximalUserInfoClaimsAsync();

        Assert.Equal(
            MetadataBuilder.ClaimsSupported.Order(StringComparer.Ordinal),
            ClaimNames(idToken).Union(fromUserInfo, StringComparer.Ordinal).Order(StringComparer.Ordinal));
    }

    /// <summary>Every claim <c>/userinfo</c> can produce, from an account with nothing missing.</summary>
    /// <remarks>
    /// A second fixture rather than reusing the flow above, because the two surfaces are maximal
    /// under different conditions and one request cannot be both: the ID token needs <c>max_age</c>
    /// and a <c>nonce</c>, and /userinfo needs a stored account carrying an address and a role. The
    /// principal is stubbed the way every other test of this endpoint stubs it — what is being
    /// measured is which claims the handler writes, not how a bearer token is validated.
    /// </remarks>
    private static async Task<IReadOnlyList<string>> MaximalUserInfoClaimsAsync()
    {
        const string Subject = "01J8XKQ7M3N4P5R6S7T8V9W0AD";

        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
            };
            seed.ConfigureOptions = o => o.ScopesSupported.Add("email");

            seed.ConfigureApp = app => app.Use(async (http, next) =>
            {
                http.User = new ClaimsPrincipal(new ClaimsIdentity(
                    [new Claim("scope", "openid email"), new Claim("sub", Subject)],
                    "Bearer"));

                await next(http);
            });
        });

        await users.StoreAsync(
            new UserAccount(
                SubjectId.FromStorage(Subject),
                "ada",
                "ada@example.com",
                EmailVerified: true,
                PasswordHash: null),
            CancellationToken.None);

        if (await roles.FindAsync(RealmId.Default, "founder", CancellationToken.None) is null)
        {
            await roles.StoreAsync(new RoleDefinition("founder", "founder", []), CancellationToken.None);
        }
        await users.SetRolesAsync(SubjectId.FromStorage(Subject), ["founder"], CancellationToken.None);

        using var response = await fixture.Client.GetAsync(new Uri("/userinfo", UriKind.Relative));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());

        return [.. body.RootElement.EnumerateObject().Select(p => p.Name)];
    }

    private const string ClientId = "https://claude.ai/.well-known/oauth-client";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    /// <summary>Every claim name in a JWT payload.</summary>
    private static IReadOnlyList<string> ClaimNames(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var padded = payload.Replace('-', '+').Replace('_', '/').PadRight((payload.Length + 3) / 4 * 4, '=');

        using var document = JsonDocument.Parse(Convert.FromBase64String(padded));

        return [.. document.RootElement.EnumerateObject().Select(p => p.Name)];
    }

    /// <summary>Fetch the document, find every URL under this issuer, and ask the server for each.</summary>
    private static async Task<(IReadOnlyList<Uri> Urls, IReadOnlyList<Uri> Unrouted)> SweepAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/.well-known/oauth-authorization-server");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        List<Uri> urls = [];

        foreach (var property in document.RootElement.EnumerateObject())
        {
            // `issuer` is the server's name, not an endpoint — RFC 8414 §2 makes it an identifier
            // that need not dereference to anything. Everything else under it is a URL this server
            // claims to serve.
            if (string.Equals(property.Name, "issuer", StringComparison.Ordinal)
                || property.Value.ValueKind is not JsonValueKind.String)
            {
                continue;
            }

            var value = property.Value.GetString();

            if (value is not null
                && value.StartsWith(Build.Issuer + "/", StringComparison.Ordinal)
                && Uri.TryCreate(value, UriKind.Absolute, out var url))
            {
                urls.Add(url);
            }
        }

        List<Uri> unrouted = [];

        foreach (var url in urls)
        {
            using var probe = await client.GetAsync(url.PathAndQuery);

            if (probe.StatusCode is HttpStatusCode.NotFound)
            {
                unrouted.Add(url);
            }
        }

        return (urls, unrouted);
    }
}
