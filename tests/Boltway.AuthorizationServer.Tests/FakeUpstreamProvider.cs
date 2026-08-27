using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Encoding;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// What the fake upstream should do on the next exchange.
/// </summary>
/// <remarks>
/// Every field here exists because a test needs the upstream to misbehave in one specific way. They
/// are settable rather than constructor arguments because a test sets one and leaves the rest, and a
/// constructor with fourteen parameters is a test that is hard to read and easy to get wrong.
/// </remarks>
internal sealed class UpstreamBehaviour
{
    /// <summary>The <c>sub</c> the upstream asserts.</summary>
    public string Subject { get; set; } = "upstream-subject-1";

    /// <summary>The <c>nonce</c> to echo. A test copies it out of the authorization request.</summary>
    public string? Nonce { get; set; }

    /// <summary>Omit <c>nonce</c> from the ID token entirely.</summary>
    public bool OmitNonce { get; set; }

    /// <summary>
    /// Sign with a key that is not in the published JWKS, under the <b>published</b> <c>kid</c>.
    /// </summary>
    /// <remarks>
    /// The sharper of the two forgeries: the verifier finds a key for the <c>kid</c> and the
    /// signature does not check out. Nothing about it looks like a key rotation, so it must not
    /// provoke a refetch.
    /// </remarks>
    public bool SignWithWrongKey { get; set; }

    /// <summary>Sign with a key under a <c>kid</c> the published JWKS does not carry.</summary>
    /// <remarks>
    /// What an upstream mid-rotation looks like, and also what an attacker sending a random
    /// <c>kid</c> looks like - which is why the refetch it provokes has a floor under it.
    /// </remarks>
    public bool SignWithUnknownKid { get; set; }

    /// <summary>Emit an unsigned token with <c>alg: none</c>.</summary>
    public bool UseAlgNone { get; set; }

    /// <summary>Issue an ID token whose <c>iss</c> is not the configured issuer.</summary>
    public string? ForcedIssuer { get; set; }

    /// <summary>Issue an ID token whose <c>aud</c> is not this server's client id.</summary>
    public string? ForcedAudience { get; set; }

    /// <summary>Issue an ID token that expired an hour ago.</summary>
    public bool Expired { get; set; }

    /// <summary>Return a token response with no <c>id_token</c> member.</summary>
    public bool OmitIdToken { get; set; }

    /// <summary>Issue an ID token with no <c>sub</c> claim.</summary>
    public bool OmitSubject { get; set; }

    /// <summary>Answer the token endpoint with this status instead of 200.</summary>
    public int TokenEndpointStatus { get; set; } = 200;

    /// <summary>Declare a different <c>issuer</c> in the discovery document.</summary>
    public string? ForcedDiscoveryIssuer { get; set; }

    /// <summary>Refuse to serve discovery at all, as an upstream having a bad minute does.</summary>
    /// <remarks>
    /// Not the same as being slow or unreachable, and close enough: what the server sees either way
    /// is a metadata resolution that failed, which is the state a cold cache and a broken network
    /// both produce.
    /// </remarks>
    public bool DiscoveryUnavailable { get; set; }

    /// <summary>An <c>email</c> claim, or none.</summary>
    public string? Email { get; set; }

    /// <summary>The value of <c>email_verified</c> when <see cref="Email"/> is set.</summary>
    public bool EmailVerified { get; set; } = true;

    /// <summary>
    /// The PKCE challenge the token endpoint will check <c>code_verifier</c> against.
    /// </summary>
    /// <remarks>
    /// Set by a test from the authorization request the server composed. The fake enforcing it is
    /// what makes "the relying party sends a correct S256 verifier" an end-to-end fact rather than a
    /// unit test of a hash.
    /// </remarks>
    public string? ExpectedCodeChallenge { get; set; }

    /// <summary>The <c>redirect_uri</c> the token endpoint will require, byte for byte.</summary>
    public string? ExpectedRedirectUri { get; set; }
}

/// <summary>
/// A real OpenID Connect provider, hosted on Kestrel over TLS on a loopback port.
/// </summary>
/// <remarks>
/// <para>
/// Serving discovery, JWKS and a token endpoint, and signing ID tokens with an RSA key generated
/// when it starts. There is no network access to Google here and there must not be one: an upstream
/// this suite controls is also the only way to produce the failures that matter - a token signed
/// with the wrong key, <c>alg: none</c>, a wrong <c>iss</c>, an expired token - which are exactly
/// the cases a live provider will never send.
/// </para>
/// <para>
/// It is reached through the shipped <c>UpstreamEndpointClient</c>, over real TLS, with the real
/// address check and the real byte caps. The two concessions are that the certificate is trusted
/// through the transport's internal test seam, and that <c>upstream.example</c> resolves to loopback
/// through an injected resolver - both of which keep the URL a genuine <c>https</c> URL with a name,
/// which is what the client's own guards are written against.
/// </para>
/// </remarks>
internal sealed class FakeUpstreamProvider : IAsyncDisposable
{
    /// <summary>The host name in every URL. Resolved to loopback by <see cref="Resolver"/>.</summary>
    public const string HostName = "upstream.example";

    private readonly IHost _host;
    private readonly RsaSecurityKey _signingKey;
    private readonly RsaSecurityKey _otherKey;

    private FakeUpstreamProvider(IHost host, int port, RsaSecurityKey signingKey, RsaSecurityKey otherKey)
    {
        _host = host;
        _signingKey = signingKey;
        _otherKey = otherKey;

        Issuer = $"https://{HostName}:{port}";
    }

    /// <summary>The issuer identifier, which is also the base of every endpoint.</summary>
    public string Issuer { get; }

    /// <summary>This server's client identifier at the fake upstream.</summary>
    public string ClientId { get; } = "boltway-at-upstream.apps.example";

    /// <summary>The client secret the fake upstream expects.</summary>
    public string ClientSecret { get; } = "upstream-secret-7f21c0d4e9";

    /// <summary>What the next exchange should do.</summary>
    public UpstreamBehaviour Behaviour { get; } = new();

    /// <summary>Everything the token endpoint has been sent, decoded, most recent last.</summary>
    public List<Dictionary<string, string>> TokenRequests { get; } = [];

    /// <summary>How many times the JWKS document has been fetched.</summary>
    public int JwksFetches { get; private set; }

    /// <summary>How many times the discovery document has been fetched.</summary>
    public int DiscoveryFetches { get; private set; }

    /// <summary>Start it.</summary>
    public static async Task<FakeUpstreamProvider> StartAsync()
    {
        var signingKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "upstream-key-1" };
        var otherKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "upstream-key-1" };

        FakeUpstreamProvider? provider = null;

        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseKestrel(kestrel => kestrel.Listen(
                    IPAddress.Loopback,
                    0,
                    listen => listen.UseHttps(h => h.ServerCertificate = UpstreamCertificate.Certificate)))
                .ConfigureServices(services => services.AddLogging(l => l.SetMinimumLevel(LogLevel.Warning)))
                .Configure(app => app.Run(context => provider!.HandleAsync(context))))
            .StartAsync();

        var address = host.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.First();

        provider = new FakeUpstreamProvider(host, new Uri(address).Port, signingKey, otherKey);

        return provider;
    }

    /// <summary>
    /// An address resolver that sends <see cref="HostName"/> to loopback.
    /// </summary>
    /// <remarks>
    /// A name rather than an address literal in the URL, because the transport pins TLS to the URL's
    /// host and the certificate carries that name - and because a literal would exercise a different
    /// path through <c>DnsAddressResolver</c> than a deployment ever takes.
    /// </remarks>
    public static IAddressResolver Resolver { get; } = new LoopbackResolver();

    private sealed class LoopbackResolver : IAddressResolver
    {
        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
    }

    /// <summary>The transport options a test wires the relying party with.</summary>
    /// <remarks>
    /// <c>AllowPrivateAddresses</c> is on because the upstream is on loopback, which is exactly the
    /// on-premises case the option exists for. The shipped default is off, and
    /// <c>UpstreamEndpointClientTests</c> is where that default is measured.
    /// </remarks>
    public static UpstreamEndpointClientOptions TransportOptions() => new()
    {
        AllowPrivateAddresses = true,
        ConnectTimeout = TimeSpan.FromSeconds(30),
        TotalTimeout = TimeSpan.FromSeconds(60),
        SslOptionsForTests = UpstreamCertificate.ClientOptions(),
    };

    private async Task HandleAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        switch (path)
        {
            case "/.well-known/openid-configuration":
                DiscoveryFetches++;

                if (Behaviour.DiscoveryUnavailable)
                {
                    context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                    return;
                }

                await WriteJsonAsync(context, Discovery());
                return;

            case "/jwks":
                JwksFetches++;
                await WriteJsonAsync(context, Jwks());
                return;

            case "/token":
                await TokenAsync(context);
                return;

            case "/authorize":
                // Present so the composed authorization URL is a real one. The suite drives the
                // callback directly rather than following the browser here, because a browser is not
                // what is under test and the upstream's own consent screen has no behaviour worth
                // simulating.
                context.Response.StatusCode = StatusCodes.Status200OK;
                await context.Response.WriteAsync("upstream authorize");
                return;

            default:
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
        }
    }

    private string Discovery() => new JsonObject
    {
        ["issuer"] = Behaviour.ForcedDiscoveryIssuer ?? Issuer,
        ["authorization_endpoint"] = Issuer + "/authorize",
        ["token_endpoint"] = Issuer + "/token",
        ["jwks_uri"] = Issuer + "/jwks",
        ["response_types_supported"] = new JsonArray("code"),
        ["subject_types_supported"] = new JsonArray("public"),
        ["id_token_signing_alg_values_supported"] = new JsonArray("RS256"),
    }.ToJsonString();

    private string Jwks()
    {
        var parameters = _signingKey.Rsa is { } rsa
            ? rsa.ExportParameters(includePrivateParameters: false)
            : _signingKey.Parameters;

        return new JsonObject
        {
            ["keys"] = new JsonArray(new JsonObject
            {
                ["kty"] = "RSA",
                ["use"] = "sig",
                ["alg"] = "RS256",
                ["kid"] = _signingKey.KeyId,
                ["n"] = Base64Url.Encode(parameters.Modulus!),
                ["e"] = Base64Url.Encode(parameters.Exponent!),
            }),
        }.ToJsonString();
    }

    private async Task TokenAsync(HttpContext context)
    {
        var form = await context.Request.ReadFormAsync();
        var fields = form.ToDictionary(f => f.Key, f => f.Value.ToString(), StringComparer.Ordinal);

        // The Authorization header goes into the same dictionary, so a test asserting on how the
        // credential arrived does not have to know which of the two shapes was used.
        if (context.Request.Headers.Authorization.ToString() is { Length: > 0 } authorization)
        {
            fields["__authorization"] = authorization;
        }

        TokenRequests.Add(fields);

        if (Behaviour.TokenEndpointStatus is not 200)
        {
            context.Response.StatusCode = Behaviour.TokenEndpointStatus;
            await WriteJsonAsync(context, "{\"error\":\"invalid_grant\"}", setStatus: false);
            return;
        }

        // PKCE, checked by the upstream exactly as a real one does. This is what makes "the relying
        // party sends a correct S256 verifier for the challenge it sent" an end-to-end fact.
        if (Behaviour.ExpectedCodeChallenge is { } challenge)
        {
            var presented = fields.GetValueOrDefault("code_verifier") ?? string.Empty;
            var computed = Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(presented)));

            if (!string.Equals(computed, challenge, StringComparison.Ordinal))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await WriteJsonAsync(context, "{\"error\":\"invalid_grant\"}", setStatus: false);
                return;
            }
        }

        if (Behaviour.ExpectedRedirectUri is { } redirect
            && !string.Equals(fields.GetValueOrDefault("redirect_uri"), redirect, StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await WriteJsonAsync(context, "{\"error\":\"invalid_grant\"}", setStatus: false);
            return;
        }

        if (Behaviour.OmitIdToken)
        {
            await WriteJsonAsync(context, "{\"access_token\":\"upstream-access\",\"token_type\":\"Bearer\"}");
            return;
        }

        var body = new JsonObject
        {
            ["access_token"] = "upstream-access",
            ["token_type"] = "Bearer",
            ["expires_in"] = 3600,
            ["id_token"] = IdToken(),
        };

        await WriteJsonAsync(context, body.ToJsonString());
    }

    /// <summary>Mint the ID token the behaviour asks for.</summary>
    private string IdToken()
    {
        var now = DateTimeOffset.UtcNow;

        var claims = new JsonObject
        {
            ["iss"] = Behaviour.ForcedIssuer ?? Issuer,
            ["aud"] = Behaviour.ForcedAudience ?? ClientId,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = Behaviour.Expired
                ? now.AddHours(-1).ToUnixTimeSeconds()
                : now.AddMinutes(10).ToUnixTimeSeconds(),
        };

        if (!Behaviour.OmitSubject)
        {
            claims["sub"] = Behaviour.Subject;
        }

        if (!Behaviour.OmitNonce && Behaviour.Nonce is { } nonce)
        {
            claims["nonce"] = nonce;
        }

        if (Behaviour.Email is { } email)
        {
            claims["email"] = email;
            claims["email_verified"] = Behaviour.EmailVerified;
        }

        if (Behaviour.UseAlgNone)
        {
            // Hand-built, because no library will produce one: `alg: none` is the token that says
            // "trust me". A verifier with RequireSignedTokens off, or with ValidAlgorithms unset,
            // accepts it - which is the whole reason both are pinned.
            var header = new JsonObject { ["alg"] = "none", ["typ"] = "JWT" }.ToJsonString();

            return Base64Url.Encode(Encoding.UTF8.GetBytes(header))
                + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(claims.ToJsonString()))
                + ".";
        }

        var key = Behaviour.SignWithWrongKey || Behaviour.SignWithUnknownKid ? _otherKey : _signingKey;

        // The `kid` is what decides which failure this is. Same as the published one and the
        // verifier finds a key and rejects the signature; different, and it looks like a rotation.
        key.KeyId = Behaviour.SignWithUnknownKid ? "upstream-key-2" : "upstream-key-1";

        return new JsonWebTokenHandler().CreateToken(
            claims.ToJsonString(), new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
    }

    private static async Task WriteJsonAsync(HttpContext context, string json, bool setStatus = true)
    {
        if (setStatus)
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
        }

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(json);
    }

    /// <summary>The upstream's provider options, pointed at this instance.</summary>
    /// <param name="discover">
    /// Whether to make the relying party fetch the discovery document, or to configure the three
    /// endpoints outright. Both are supported shapes and both are exercised.
    /// </param>
    public Federation.Oidc.OidcProviderOptions Options(bool discover = true)
    {
        var options = new Federation.Oidc.OidcProviderOptions
        {
            Scheme = "google",
            DisplayName = "Google",
            Issuer = Issuer,
            ClientId = ClientId,
        };

        options.SetClientSecret(ClientSecret);

        if (!discover)
        {
            options.AuthorizationEndpoint = Issuer + "/authorize";
            options.TokenEndpoint = Issuer + "/token";
            options.JwksUri = Issuer + "/jwks";
        }

        return options;
    }

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();

        _signingKey.Rsa?.Dispose();
        _otherKey.Rsa?.Dispose();
    }
}

/// <summary>A self-signed certificate for the loopback identity provider.</summary>
/// <remarks>
/// A copy of the helper in <c>Boltway.OAuth.Net.Tests</c> rather than a shared one: two test
/// projects sharing a file means a project reference between test assemblies, and the certificate
/// here carries a different subject name because it fronts a different host.
/// </remarks>
internal static class UpstreamCertificate
{
    internal static X509Certificate2 Certificate { get; } = Create();

    private static X509Certificate2 Create()
    {
        using var rsa = RSA.Create(2048);

        var request = new CertificateRequest(
            $"CN={FakeUpstreamProvider.HostName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(FakeUpstreamProvider.HostName);
        request.CertificateExtensions.Add(names.Build());

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), password: null);
    }

    /// <summary>Trust exactly this certificate, and nothing else.</summary>
    /// <remarks>
    /// Not a blanket accept-anything callback. The point of running real TLS is that a wrong
    /// certificate still fails, so the transport's certificate handling stays under test.
    /// </remarks>
    internal static SslClientAuthenticationOptions ClientOptions() => new()
    {
        TargetHost = FakeUpstreamProvider.HostName,
        RemoteCertificateValidationCallback = (_, presented, _, _) =>
            presented is not null && presented.GetCertHashString() == Certificate.GetCertHashString(),
    };
}
