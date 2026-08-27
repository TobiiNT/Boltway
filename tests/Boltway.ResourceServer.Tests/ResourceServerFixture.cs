using System.Security.Cryptography;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.OAuth.Tokens;
using Boltway.ResourceServer.Authorization;
using Boltway.ResourceServer.Configuration;
using Boltway.ResourceServer.DependencyInjection;
using Boltway.ResourceServer.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.ResourceServer.Tests;

/// <summary>The constants every test in this assembly shares.</summary>
internal static class Build
{
    public const string Issuer = "https://auth.example.com";

    /// <summary>
    /// A resource identifier with a path, because that is the case everything here is about.
    /// </summary>
    /// <remarks>
    /// A path-less identifier would make the RFC 9728 §3.1 insertion rule and the root-form
    /// fallback the same URL, and every routing test would pass without the catch-all route
    /// existing at all. A-22 also puts the path at the centre of the audience comparison.
    /// </remarks>
    public const string Resource = "https://mcp.example.com/mcp";

    /// <summary>A second, unrelated resource. What N-01's "presented at resource B" means.</summary>
    public const string OtherResource = "https://other-mcp.example.com/mcp";

    public const string ToolScope = "mcp:tools";
    public const string WriteScope = "story:write";

    /// <summary>The path-inserted metadata URL for <see cref="Resource"/>, written out by hand.</summary>
    /// <remarks>
    /// Spelled literally rather than computed, so a test comparing against it is comparing against
    /// the specification's example rather than against the same function under test.
    /// </remarks>
    public const string MetadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

    public const string MetadataPath = "/.well-known/oauth-protected-resource/mcp";

    public const string RootMetadataPath = "/.well-known/oauth-protected-resource";

    public static IssuerString ValidatedIssuer =>
        IssuerString.TryCreate(Issuer, out var issuer, out _) ? issuer : throw new InvalidOperationException();

    /// <summary>
    /// A validated resource, which is also the only route to a <see cref="ResourceIdentifier"/>.
    /// </summary>
    /// <remarks>
    /// Deliberately no test-only factory in the shipping assembly. <c>ResourceIdentifier</c>'s
    /// factory is internal to Primitives so that N-01 has no public bypass, and this test project
    /// reaches one the same way production code does - by validating configuration.
    /// </remarks>
    public static ProtectedResource Resolve(string canonical, string issuer = Issuer)
    {
        var options = new ProtectedResourceOptions { Resource = canonical, AuthorizationServer = issuer };

        return ProtectedResource.TryCreate(options, out var resource, out var error)
            ? resource!
            : throw new InvalidOperationException(error);
    }

    public static ScopeSet Scopes(string wire) =>
        ScopeSet.TryParse(wire, out var scopes, out _) ? scopes : throw new InvalidOperationException(wire);
}

/// <summary>
/// One RSA key, used to sign in the test and to verify in the server under test.
/// </summary>
/// <remarks>
/// <para>
/// The same <see cref="SecurityKey"/> instance on both sides. A production resource server holds
/// only the public half, fetched from JWKS; holding the private half here changes nothing about
/// what is verified, because verification uses the public parameters either way.
/// </para>
/// <para>
/// The <c>kid</c> matters more than it looks. The verifier runs with
/// <c>TryAllIssuerSigningKeys = false</c>, so it considers only keys whose identifier matches the
/// token's <c>kid</c> header - an unlabelled key matches nothing and every signature check fails
/// with a message that reads like a missing key rather than an unnamed one.
/// </para>
/// </remarks>
internal static class TestKeys
{
    private static readonly RSA Rsa = RSA.Create(2048);

    internal static SigningKeyHandle Handle { get; } =
        new("test-key", SigningAlgorithm.RS256, new RsaSecurityKey(Rsa));

    /// <summary>A second key nobody publishes, for the "signed by a stranger" case.</summary>
    internal static SigningKeyHandle Stranger { get; } =
        new("stranger-key", SigningAlgorithm.RS256, new RsaSecurityKey(RSA.Create(2048)));
}

/// <summary>Mints the tokens a test presents, with the real minter.</summary>
/// <remarks>
/// The real <see cref="JwtTokenMinter"/> rather than a hand-rolled JWT, because half of what these
/// tests prove is that the two halves of the product agree: the minter writes <c>typ: at+jwt</c>,
/// a space-delimited <c>scope</c> string and a full-string <c>aud</c>, and the middleware is
/// configured to require exactly those. A test that built its own token would be asserting the
/// middleware agrees with the test's idea of a token.
/// </remarks>
internal static class Mint
{
    private static readonly JwtTokenMinter Minter = new();

    internal static string AccessToken(
        ProtectedResource? audience = null,
        string scope = Build.ToolScope,
        string issuer = Build.Issuer,
        TimeSpan? lifetime = null,
        SigningKeyHandle? key = null,
        DateTimeOffset? issuedAt = null)
    {
        var resource = audience ?? Build.Resolve(Build.Resource);
        var now = issuedAt ?? DateTimeOffset.UtcNow;

        var descriptor = new AccessTokenDescriptor(
            IssuerString.TryCreate(issuer, out var iss, out var error) ? iss : throw new InvalidOperationException(error),
            resource.Identifier,
            SubjectId.FromStorage("user-1"),
            ClientIdentifier.ForCimd("https://claude.ai/.well-known/oauth-client"),
            GrantId: "grant-1",
            Build.Scopes(scope),
            now,
            now + (lifetime ?? TimeSpan.FromHours(1)),
            JwtId: "jti-1");

        return Minter.MintAccessToken(descriptor, key ?? TestKeys.Handle).Wire;
    }

    /// <summary>
    /// An ID token for the same user, signed by the same key.
    /// </summary>
    /// <param name="audience">
    /// The <c>aud</c>, as a client identifier - which is what an ID token's audience is (N-10).
    /// </param>
    /// <param name="issuer">The <c>iss</c>.</param>
    /// <remarks>
    /// <para>
    /// The audience is a parameter, and that is the difference between a test of N-09 and a test
    /// that looks like one. <b>Measured:</b> with the audience fixed at an ordinary client id, this
    /// token is refused because its <c>aud</c> is not the resource - so unpinning
    /// <c>ValidTypes</c> entirely left the test green, and the <c>typ</c> check it claimed to prove
    /// was never exercised.
    /// </para>
    /// <para>
    /// The interesting case is a JWT the same issuer signed, for the same subject, that happens to
    /// carry <b>this resource's identifier</b> in <c>aud</c>. A CIMD client identifier is a URL, so
    /// such a token is constructible; and once it exists, <c>typ</c> is the only thing between it
    /// and a validated access token. That is what RFC 9068 §5 means by cross-JWT confusion, and it
    /// is what <c>ValidTypes</c> - unset by default in the library - is the whole defence against.
    /// </para>
    /// </remarks>
    internal static string IdToken(string audience, string issuer = Build.Issuer)
    {
        var now = DateTimeOffset.UtcNow;

        var descriptor = new IdTokenDescriptor(
            IssuerString.TryCreate(issuer, out var iss, out var error) ? iss : throw new InvalidOperationException(error),
            ClientIdentifier.ForCimd(audience),
            SubjectId.FromStorage("user-1"),
            now,
            now.AddHours(1));

        return Minter.MintIdToken(descriptor, TestKeys.Handle).Wire;
    }

    /// <summary>
    /// An <c>at+jwt</c> whose <c>aud</c> is an arbitrary string, minted outside the descriptor path.
    /// </summary>
    /// <remarks>
    /// The descriptor path cannot produce one: <c>AccessTokenDescriptor</c> requires a
    /// <see cref="ResourceIdentifier"/>, and <c>TryRegister</c> refuses any string that is not in
    /// canonical form - so a Boltway issuer can no longer mint a token whose audience is, say,
    /// this resource with a trailing slash. The token that can still arrive is a foreign one, whose
    /// <c>aud</c> is whatever its issuer wrote. This is that token, signed by the key the fixture
    /// trusts and shaped correctly everywhere else, so the audience comparison is the one check
    /// doing the refusing.
    /// </remarks>
    internal static string AccessTokenForAudience(string audience, string issuer = Build.Issuer)
    {
        var now = DateTimeOffset.UtcNow;

        // A fresh RsaSecurityKey over the same RSA, because the kid rides on SecurityKey.KeyId and
        // setting it on TestKeys.Handle.Key would mutate a key every other test shares.
        var rsa = ((RsaSecurityKey)TestKeys.Handle.Key).Rsa
            ?? throw new InvalidOperationException("The test key does not wrap an RSA instance.");
        var signing = new RsaSecurityKey(rsa) { KeyId = TestKeys.Handle.Kid };

        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false,
        };

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.AddHours(1).UtcDateTime,
            Claims = new Dictionary<string, object> { ["sub"] = "user-1", ["scope"] = Build.ToolScope },
            SigningCredentials = new SigningCredentials(signing, SecurityAlgorithms.RsaSha256),
            TokenType = "at+jwt",
        });
    }
}

/// <summary>
/// A whole resource server, over real HTTP.
/// </summary>
/// <remarks>
/// Built the way a customer's host would build it. Everything these tests are about is wiring: a
/// route that does not exist, a middleware in the wrong place, a status the framework chose. None
/// of it is visible from a unit test of a handler, and the audit's finding was precisely that the
/// pieces were correct and unit-tested while nothing hosted them.
/// </remarks>
internal sealed class ResourceServerFixture : IAsyncDisposable
{
    private readonly IHost _host;

    private ResourceServerFixture(IHost host, HttpClient client)
    {
        _host = host;
        Client = client;
    }

    /// <summary>A client that does not follow redirects, so each hop is observable.</summary>
    public HttpClient Client { get; }

    /// <summary>
    /// Everything the server logged, captured through the real <see cref="ILoggerProvider"/> seam.
    /// </summary>
    /// <remarks>
    /// On every fixture rather than behind a flag. A-09 is a property of every rejection path, and a
    /// sink that only exists in the tests that ask for it cannot notice a path that stopped logging.
    /// </remarks>
    public LogSink Logs { get; private set; } = null!;

    /// <param name="configure">Options for the resource server under test.</param>
    /// <param name="corsEnabledByHost">Stand in for a host running its own CORS policy.</param>
    /// <param name="configureServices">Seams a deployment supplies rather than configures.</param>
    /// <param name="hostMiddleware">
    /// A middleware the host runs before this library's, for the case where a deployment has
    /// authentication of its own. It is what the sabotage derivation of the shipped contract uses.
    /// </param>
    public static async Task<ResourceServerFixture> StartAsync(
        Action<ProtectedResourceOptions>? configure = null,
        bool corsEnabledByHost = false,
        Action<IServiceCollection>? configureServices = null,
        Action<IApplicationBuilder>? hostMiddleware = null)
    {
        var sink = new LogSink();

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();

                    // Registered at Trace, so a test asserting "one line" is measuring the server
                    // rather than the level filter.
                    services.AddSingleton<ILoggerProvider>(sink);
                    services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace));

                    services.AddBoltwayProtectedResource(options =>
                    {
                        options.Resource = Build.Resource;
                        options.AuthorizationServer = Build.Issuer;
                        options.ResourceName = "Example MCP";
                        options.ResourceDocumentation = "https://example.com/docs/mcp";
                        options.ScopesSupported.Add(Build.ToolScope);
                        options.ScopesSupported.Add(Build.WriteScope);
                        options.SigningKeys.Add(TestKeys.Handle.Key);

                        configure?.Invoke(options);
                    });

                    // For the seams a deployment supplies rather than configures - today that is
                    // IAccessTokenRevocationCheck, which is absent unless somebody registers one.
                    configureServices?.Invoke(services);
                })
                .Configure(app =>
                {
                    app.UseRouting();

                    // Stands in for a host that runs its own CORS policy, so the challenge's
                    // conditional Access-Control-Expose-Headers has something to react to.
                    if (corsEnabledByHost)
                    {
                        app.Use(async (context, next) =>
                        {
                            context.Response.Headers.AccessControlAllowOrigin = "*";
                            await next(context);
                        });
                    }

                    // Before this library's, which is where a host's own authentication middleware
                    // goes and is the ordering that produced the defect the shipped contract was
                    // written from.
                    hostMiddleware?.Invoke(app);

                    app.UseBoltwayProtectedResource();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapProtectedResourceMetadata();

                        endpoints
                            .MapMethods("/mcp", ["GET", "POST"], (HttpContext context) =>
                                Results.Json(new { subject = context.User.Identity?.Name ?? "anonymous" }))
                            .RequireScope(Build.ToolScope);

                        endpoints
                            .MapMethods("/mcp/write", ["GET", "POST"], () => Results.Ok())
                            .RequireScope(Build.ToolScope, Build.WriteScope);

                        // No RequireScope: covered by RequireBearerByDefault.
                        endpoints.MapGet("/protected", () => Results.Ok());

                        endpoints.MapGet("/open", () => Results.Ok()).AllowAnonymous();
                    });
                }))
            .StartAsync();

        var client = host.GetTestClient();

        // https, because a resource identifier must be. Nothing here depends on the request's host
        // - the resource identifier comes from configuration and is never rebuilt from the request
        // - but a fixture on http would be exercising a deployment shape this server refuses.
        client.BaseAddress = new Uri("https://mcp.example.com");

        return new ResourceServerFixture(host, client) { Logs = sink };
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }
}
