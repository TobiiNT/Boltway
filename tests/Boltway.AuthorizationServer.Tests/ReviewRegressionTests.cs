using System.Net;
using System.Security.Cryptography;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Abstractions.Resources;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.AuthorizationServer.Metadata;
using Boltway.Identity.Passwords;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Tokens;
using Boltway.Storage.InMemory;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// One test per defect two review passes found. Each names the thing that was wrong.
/// </summary>
/// <remarks>
/// Kept together rather than scattered into the files they belong to, because what they have in
/// common is more useful than what each one covers: every one of them is a claim the code made in a
/// comment and did not keep, and the suite that was supposed to cover it passed.
/// </remarks>
public sealed class ReviewRegressionTests
{
    private static async Task<AuthorizeOutcome> RunAsync(
        Dictionary<string, string[]> parameters, AuthorizePipeline? pipeline = null) =>
        await (pipeline ?? Build.Pipeline()).ValidateAsync(Build.Context(parameters), CancellationToken.None);

    // ─────────────────────────────────────────────────────────────────────────
    // N-11: the capability could be forged, and a reordering compiled
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A redirect error cannot be built without a real <see cref="ValidatedRedirect"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="ValidatedRedirect"/> was a <c>readonly struct</c>, and every struct has a public
    /// parameterless constructor — so <c>AuthorizeRedirectError.Create(default, …)</c> compiled from
    /// any assembly, with no <c>InternalsVisibleTo</c> needed, and produced an error pointing at a
    /// <see langword="null"/> target. As a class the forgery is <see langword="null"/> and this is
    /// what happens to it.
    /// </remarks>
    [Fact]
    public void A_redirect_error_cannot_be_built_from_a_forged_capability()
    {
        Assert.Throws<ArgumentNullException>(() =>
            AuthorizeRedirectError.Create(
                null!,
                Rejection.Of(ReasonCode.RedirectUriMismatch, OAuthErrorCode.InvalidRequest, "forged"),
                "state",
                Build.ValidatedIssuer,
                "correlation-1"));
    }

    /// <summary>
    /// A registration that never parses does not crash the pipeline.
    /// </summary>
    /// <remarks>
    /// <c>RedirectMatchFor</c> discarded the <c>TryParse</c> result and dereferenced its
    /// out-parameter. <see cref="RegisteredRedirectUri"/> is a public struct and
    /// <c>ClientRecord.RedirectUris</c> is unvalidated, so any resolver could supply a
    /// <c>default</c> — and with <c>redirect_uri</c> omitted the request took the
    /// single-registration branch and threw out of <c>/authorize</c>, before the line where a
    /// <c>server_error</c> redirect would even be possible.
    /// </remarks>
    [Fact]
    public async Task A_default_valued_registration_does_not_crash_the_pipeline()
    {
        var client = Build.Client() with { RedirectUris = [default] };
        var request = Build.ValidRequest();
        request.Remove("redirect_uri");

        var outcome = await RunAsync(request, Build.Pipeline(new TestClientResolver(client)));

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, html.Error.Code);
    }

    /// <summary>
    /// A requested URI that merely <b>starts with</b> a registered one is refused.
    /// </summary>
    /// <remarks>
    /// A mutation making the matcher prefix-match — the single most dangerous change possible here —
    /// failed two rows in the primitives suite and <b>nothing</b> at pipeline level, because every
    /// "unregistered" URI in those tests altered or shortened the registered one instead of
    /// extending it. These two extend it, which is the shape an attacker actually controls: a
    /// hostname suffix and a traversal.
    /// </remarks>
    [Theory]
    [InlineData("https://claude.ai/api/mcp/auth_callback.attacker.example/")]
    [InlineData("https://claude.ai/api/mcp/auth_callback/../../evil")]
    [InlineData("https://claude.ai/api/mcp/auth_callback?next=https://evil.example")]
    [InlineData("https://claude.ai/api/mcp/auth_callbackX")]
    public async Task A_redirect_uri_that_extends_a_registered_one_is_refused(string requested)
    {
        var request = Build.ValidRequest();
        request["redirect_uri"] = [requested];

        var outcome = await RunAsync(request);

        Assert.IsType<AuthorizeOutcome.Html>(outcome);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error descriptions were an unfiltered, unbounded sink
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A description carries nothing outside OAuth 2.1's permitted character set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §4.1.2.1 limits <c>error_description</c> to %x20-21 / %x23-5B / %x5D-7E, which excludes CR
    /// and LF. Measured before the fix: <c>code_challenge_method=a\r\nSet-Cookie: x=1</c> reached
    /// <c>Description</c> with the CRLF intact, and <c>scope=&lt;script&gt;alert(1)&lt;/script&gt;</c>
    /// came back whole.
    /// </para>
    /// <para>
    /// <b>This test passes with the filter removed</b>, and that is worth saying rather than
    /// leaving for someone to discover: the pipeline no longer echoes these values at all, so there
    /// is nothing left for the filter to catch on this path. What this asserts is the no-echo
    /// property. The filter is asserted directly below, where a mutation does fail.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("code_challenge_method", "a\r\nSet-Cookie: x=1")]
    [InlineData("code_challenge_method", "<script>alert(1)</script>")]
    [InlineData("scope", "<script>alert(1)</script>")]
    [InlineData("scope", "a\"b\\c")]
    public async Task No_description_carries_a_forbidden_character(string parameter, string payload)
    {
        var request = Build.ValidRequest();
        request[parameter] = [payload];

        var outcome = await RunAsync(request);

        var description = outcome switch
        {
            AuthorizeOutcome.Html html => html.Error.Description,
            AuthorizeOutcome.Redirect redirect => redirect.Error.Description,
            _ => throw new InvalidOperationException("Expected a refusal."),
        };

        foreach (var c in description)
        {
            Assert.True(
                c is '\x20' or '\x21' or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E'),
                $"U+{(int)c:X4} is outside the set OAuth 2.1 §4.1.2.1 permits: '{description}'");
        }
    }

    /// <summary>
    /// The filter itself, exercised directly.
    /// </summary>
    /// <remarks>
    /// <b>These are the tests that hold the filter up.</b> The end-to-end case above passes even
    /// with the filter removed — measured, a mutation that made <c>Safe</c> the identity function
    /// failed nothing — because the pipeline also stopped echoing caller-controlled values, so no
    /// description it writes today contains one. That makes the filter defence in depth for the
    /// next description someone adds, and defence in depth still has to be tested where it lives.
    /// </remarks>
    [Theory]
    [InlineData("a\r\nSet-Cookie: x=1", "aSet-Cookie: x=1")]
    [InlineData("line\nbreak", "linebreak")]
    [InlineData("tab\there", "tabhere")]
    [InlineData("quote\"and\\slash", "quoteandslash")]
    [InlineData("null\0byte", "nullbyte")]
    [InlineData("delete\x7f", "delete")]
    [InlineData("plain text stays", "plain text stays")]
    [InlineData("<script>alert(1)</script>", "<script>alert(1)</script>")]
    public void The_description_filter_drops_exactly_the_forbidden_characters(string input, string expected)
    {
        Assert.Equal(expected, ErrorText.Safe(input));
    }

    /// <summary>The filter truncates, and marks that it did.</summary>
    [Fact]
    public void The_description_filter_truncates()
    {
        var filtered = ErrorText.Safe(new string('A', 4000));

        Assert.Equal(ErrorText.MaxLength, filtered.Length);
        Assert.EndsWith("~", filtered, StringComparison.Ordinal);
    }

    /// <summary>Every character the filter keeps is one OAuth 2.1 permits, across the whole range.</summary>
    /// <remarks>
    /// A sweep over U+0000..U+00FF rather than a handful of cases, because the property is about
    /// the boundaries of three ranges and a hand-picked set tests the middles.
    /// </remarks>
    [Fact]
    public void The_description_filter_agrees_with_the_specified_range()
    {
        for (var c = 0; c <= 0xFF; c++)
        {
            var permitted = c is 0x20 or 0x21 or (>= 0x23 and <= 0x5B) or (>= 0x5D and <= 0x7E);
            var filtered = ErrorText.Safe(((char)c).ToString());

            Assert.Equal(permitted ? 1 : 0, filtered.Length);
        }
    }

    /// <summary>A description is length-capped, so it cannot reflect a payload of size.</summary>
    [Fact]
    public async Task A_description_is_length_capped()
    {
        var request = Build.ValidRequest();
        request["code_challenge_method"] = [new string('A', 4000)];

        var outcome = await RunAsync(request);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.True(redirect.Error.Description.Length <= 240, $"length was {redirect.Error.Description.Length}");
    }

    /// <summary>
    /// The value that failed is not quoted back at all.
    /// </summary>
    /// <remarks>
    /// The control for the two tests above: filtering makes a payload harmless, but not echoing it
    /// means there is nothing to filter. Both are here because the filter has to hold for the
    /// descriptions that legitimately interpolate a fixed parameter <i>name</i>.
    /// </remarks>
    [Fact]
    public async Task A_rejected_parameter_value_is_not_echoed()
    {
        var request = Build.ValidRequest();
        request["code_challenge_method"] = ["S1024"];

        var outcome = await RunAsync(request);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.DoesNotContain("S1024", redirect.Error.Description, StringComparison.Ordinal);
        Assert.Contains("S256", redirect.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>The registration count is not disclosed to an unauthenticated caller.</summary>
    /// <remarks>
    /// The sibling branch withholds <i>which</i> URIs are registered for exactly this reason, and
    /// this one handed out how many.
    /// </remarks>
    [Fact]
    public async Task The_number_of_registered_redirect_uris_is_not_disclosed()
    {
        var client = Build.Client(redirectUris: ["https://claude.ai/a", "https://claude.ai/b", "https://claude.ai/c"]);
        var request = Build.ValidRequest();
        request.Remove("redirect_uri");

        var outcome = await RunAsync(request, Build.Pipeline(new TestClientResolver(client)));

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.DoesNotContain("3", html.Error.Description, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stages that validated and discarded, or diagnosed wrongly
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>An absent <c>response_type</c> is <c>invalid_request</c>, not "unsupported".</summary>
    /// <remarks>
    /// RFC 6749 §4.1.2.1 reserves <c>unsupported_response_type</c> for "obtaining an authorization
    /// code using this method", which presupposes a method was named. The two codes send a client
    /// debugging in different directions.
    /// </remarks>
    [Fact]
    public async Task An_absent_response_type_is_invalid_request()
    {
        var request = Build.ValidRequest();
        request.Remove("response_type");

        var outcome = await RunAsync(request);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, redirect.Error.Code);
    }

    /// <summary>
    /// A client that did not declare the <c>code</c> response type is refused. X-05's second half.
    /// </summary>
    /// <remarks>
    /// <c>ClientRecord.ResponseTypes</c> was populated and read by nothing, so a client declaring
    /// <c>"response_types": ["token"]</c> alongside <c>"grant_types": ["authorization_code"]</c> was
    /// issued a code — honouring neither half of what it said about itself.
    /// </remarks>
    [Fact]
    public async Task A_client_that_did_not_declare_the_code_response_type_is_refused()
    {
        var client = Build.Client() with { ResponseTypes = ["token"] };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.UnauthorizedClient, redirect.Error.Code);
    }

    /// <summary>A client that declared nothing is permitted. C-14.</summary>
    /// <remarks>
    /// The control for the test above. Treating an empty declaration as refusal would reject a
    /// client whose metadata document simply says less than ours would like — and C-14 is explicit
    /// that a client declaring a grant we have not enabled is not an error.
    /// </remarks>
    [Fact]
    public async Task A_client_that_declared_no_response_types_is_permitted()
    {
        var client = Build.Client() with { ResponseTypes = [] };

        var outcome = await RunAsync(Build.ValidRequest(), Build.Pipeline(new TestClientResolver(client)));

        Assert.IsType<AuthorizeOutcome.Validated>(outcome);
    }

    /// <summary>
    /// <c>prompt</c> and <c>max_age</c> survive stage 8.
    /// </summary>
    /// <remarks>
    /// Both were parsed into locals and dropped. Stage 9 needs <c>login</c> to force
    /// re-authentication and stage 10 needs <c>consent</c> to force re-consent; without carriage
    /// those stages would re-read and re-validate the raw parameters, which is what the context type
    /// exists to prevent.
    /// </remarks>
    [Fact]
    public async Task Prompt_and_max_age_reach_the_stages_that_need_them()
    {
        var request = Build.ValidRequest();
        request["prompt"] = ["login consent"];
        request["max_age"] = ["300"];

        var outcome = await RunAsync(request);

        var context = Assert.IsType<AuthorizeOutcome.Validated>(outcome).Context;
        Assert.Equal(["login", "consent"], context.Prompt);
        Assert.Equal(TimeSpan.FromMinutes(5), context.MaxAge);
    }

    /// <summary>An explicitly empty <c>redirect_uri</c> is malformed, not omitted.</summary>
    /// <remarks>
    /// RFC 6749 §3.1.2.3's permission is for a parameter that is <i>absent</i>. Silently
    /// substituting the registered URI for an empty one hides a client that built its URL wrongly
    /// from whoever has to debug it.
    /// </remarks>
    [Fact]
    public async Task An_empty_redirect_uri_is_refused()
    {
        var request = Build.ValidRequest();
        request["redirect_uri"] = [""];

        var outcome = await RunAsync(request);

        var html = Assert.IsType<AuthorizeOutcome.Html>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidRequest, html.Error.Code);
    }

    /// <summary>Repeated <c>resource</c> values are deduplicated rather than granted twice.</summary>
    [Fact]
    public async Task A_repeated_resource_value_is_deduplicated()
    {
        var request = Build.ValidRequest();
        request["resource"] = [Build.Resource, Build.Resource, Build.Resource];

        var outcome = await RunAsync(request);

        var context = Assert.IsType<AuthorizeOutcome.Validated>(outcome).Context;
        Assert.Single(context.Resources);
    }

    /// <summary>
    /// Too many <c>resource</c> values are refused rather than resolved one lookup at a time.
    /// </summary>
    /// <remarks>
    /// RFC 8707 §2 sets no limit, but every value costs a registry lookup inside the endpoint's
    /// ten-second budget, so an unbounded list is a cheap way to spend all of it.
    /// </remarks>
    [Fact]
    public async Task An_unreasonable_number_of_resource_values_is_refused()
    {
        var request = Build.ValidRequest();
        request["resource"] = [.. Enumerable.Range(0, 200).Select(i => $"https://r{i}.example/api")];

        var outcome = await RunAsync(request);

        var redirect = Assert.IsType<AuthorizeOutcome.Redirect>(outcome);
        Assert.Equal(OAuthErrorCode.InvalidTarget, redirect.Error.Code);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Repetition refusal, tested so that "first wins" would fail it
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A repeated parameter is refused <b>as repetition</b>, with a valid first value.
    /// </summary>
    /// <remarks>
    /// The earlier version of this test used <c>["a", "b"]</c>, so for four of its ten rows — one of
    /// them <c>redirect_uri</c>, the case its own remarks were about — a first-wins implementation
    /// also produced <c>invalid_request</c>, for the unrelated reason that <c>"a"</c> is malformed.
    /// Measured: a first-wins mutation survived those four. Here the first value is the one a valid
    /// request carries, so first-wins would <i>succeed</i>, and the assertion is on the reason.
    /// </remarks>
    [Theory]
    [InlineData("client_id", "https://claude.ai/.well-known/oauth-client")]
    [InlineData("redirect_uri", "https://claude.ai/api/mcp/auth_callback")]
    [InlineData("response_type", "code")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")]
    [InlineData("code_challenge_method", "S256")]
    [InlineData("scope", "mcp:tools")]
    [InlineData("state", "opaque-state")]
    [InlineData("nonce", "client-nonce")]
    [InlineData("prompt", "login")]
    [InlineData("max_age", "300")]
    public async Task A_repeated_parameter_is_refused_as_repetition(string parameter, string valid)
    {
        var request = Build.ValidRequest();
        request[parameter] = [valid, "second-value"];

        var outcome = await RunAsync(request);

        var (code, description) = outcome switch
        {
            AuthorizeOutcome.Html html => (html.Error.Code, html.Error.Description),
            AuthorizeOutcome.Redirect redirect => (redirect.Error.Code, redirect.Error.Description),
            _ => (OAuthErrorCode.None, "the request was accepted"),
        };

        Assert.Equal(OAuthErrorCode.InvalidRequest, code);
        Assert.Contains("more than once", description, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Aliasing and staleness
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The key ring does not alias the caller's list.
    /// </summary>
    /// <remarks>
    /// <c>IReadOnlyList&lt;T&gt;</c> is not immutable, and the ring is captured once for the process
    /// lifetime while <c>PublishedKeys()</c> runs on every JWKS request. Measured against the
    /// aliasing version: clearing the caller's list emptied the JWKS, and mutating it during a poll
    /// threw "Collection was modified". The obvious rotation implementation — keep a
    /// <c>List</c> and add to it — is the unsafe one.
    /// </remarks>
    [Fact]
    public void The_key_ring_copies_the_keys_it_is_given()
    {
        var rsa = RSA.Create(2048);
        var handle = new SigningKeyHandle("k1", SigningAlgorithm.RS256, new RsaSecurityKey(rsa));
        var mutable = new List<ManagedSigningKey>
        {
            new(handle, SigningKeyState.Active, DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-1)),
        };

        var ring = new SigningKeyRing(mutable);
        mutable.Clear();

        Assert.Single(ring.PublishedKeys());
        Assert.Equal("k1", ring.ActiveKey(SigningAlgorithm.RS256).Kid);
    }

    /// <summary>
    /// A failed validation leaves no stale <see cref="AuthorizationServerOptions.ValidatedIssuer"/>.
    /// </summary>
    /// <remarks>
    /// It was assigned only on success and never reset, so setting <c>Issuer</c> to something
    /// invalid produced <c>TryValidate() == false</c> alongside a <c>ValidatedIssuer</c> that still
    /// returned the previously-valid https URL — a property whose name asserted something it had
    /// stopped guaranteeing.
    /// </remarks>
    [Fact]
    public void A_failed_validation_clears_the_validated_issuer()
    {
        var options = Build.Options();
        Assert.True(options.TryValidate(out _));
        Assert.Equal(Build.Issuer, options.ValidatedIssuer.Value);

        options.Issuer = "http://evil.example";

        Assert.False(options.TryValidate(out _));
        Assert.Null(options.ValidatedIssuer.Value);
    }

    /// <summary>
    /// A failed validation leaves no stale <see cref="AuthorizationServerOptions.ValidatedScopes"/>.
    /// </summary>
    /// <remarks>
    /// The scope half of the same defect, and it needs its own case because the two are validated
    /// independently: an invalid issuer does not stop the scopes validating, so
    /// <see cref="AuthorizationServerOptions.ValidatedScopes"/> being populated after that run is
    /// correct rather than stale. What must not survive is a scope set the current configuration no
    /// longer produces.
    /// </remarks>
    [Fact]
    public void A_failed_validation_clears_the_validated_scopes()
    {
        var options = Build.Options();
        Assert.True(options.TryValidate(out _));
        Assert.Contains("mcp:tools", options.ValidatedScopes.Values);

        options.ScopesSupported.Add("story:read ");

        Assert.False(options.TryValidate(out _));
        Assert.True(options.ValidatedScopes.IsEmpty);
    }

    /// <summary>
    /// Options are frozen once the document has been serialized.
    /// </summary>
    /// <remarks>
    /// After registration the served bytes are fixed. A host adding a scope would create a
    /// divergence nothing detects: the options singleton would report a scope the published document
    /// does not advertise, and the authorize pipeline — built from the same options — would accept
    /// one no client can discover.
    /// </remarks>
    [Fact]
    public void Options_cannot_be_mutated_after_registration()
    {
        var services = new ServiceCollection();
        services.AddBoltwayAuthorizationServer(o =>
        {
            o.Issuer = Build.Issuer;
            o.ScopesSupported.Add("openid");
            o.ScopesSupported.Add("offline_access");
            o.ScopesSupported.Add("mcp:tools");
                        o.RefreshTokenDerivationKey = Build.DerivationKey;
        });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<AuthorizationServerOptions>();

        Assert.True(options.IsFrozen);
        Assert.Throws<NotSupportedException>(() => options.ScopesSupported.Add("admin:everything"));
        Assert.Throws<NotSupportedException>(() => options.GrantTypesSupported.Add("client_credentials"));
        Assert.Throws<NotSupportedException>(() => options.TokenEndpointAuthMethods.Clear());
    }

    /// <summary>
    /// The served bytes cannot be written through.
    /// </summary>
    /// <remarks>
    /// <c>ReadOnlyMemory&lt;byte&gt;</c> is not read-only in the sense the ETag needs:
    /// <c>MemoryMarshal.TryGetArray</c> handed back the live array, and writing through it changed
    /// the body every subsequent request received while <c>ETag</c> went on advertising the old
    /// bytes. On a singleton that is a cache-poisoning primitive.
    /// </remarks>
    [Fact]
    public void The_served_bytes_cannot_be_written_through()
    {
        var document = MetadataDocument.Create(Build.Options());

        var copy = document.Json.AsSpan().ToArray();
        copy[0] = (byte)'X';

        Assert.Equal((byte)'{', document.Json[0]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Advertised capability equals actual capability
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// <c>form_post</c> is not advertised, because nothing renders it.
    /// </summary>
    /// <remarks>
    /// N-06. Nothing reads <c>response_mode</c> and no self-submitting form exists, so listing it
    /// was an advertised capability with no implementation. Neither vendor sends
    /// <c>response_mode</c>, so removing it costs nothing.
    /// </remarks>
    [Fact]
    public void Only_response_modes_that_exist_are_advertised()
    {
        var document = MetadataDocument.Create(Build.Options());

        Assert.Equal(["query"], document.Metadata.ResponseModesSupported);
    }
}

/// <summary>
/// The discovery endpoints in a host that never configures CORS.
/// </summary>
/// <remarks>
/// A separate fixture because it is the whole point: <c>RequireCors</c> attaches metadata the CORS
/// <i>middleware</i> acts on, and ASP.NET Core throws <c>"contains CORS metadata, but a middleware
/// was not found"</c> when it is absent. That was a 500 on every discovery document for any host
/// that had not added <c>UseCors()</c> — and the main test fixture called it, so nothing saw it.
/// </remarks>
public sealed class DiscoveryWithoutCorsMiddlewareTests : IAsyncLifetime
{
    private IHost _host = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    // The minimum a host can do: routing, the seams the startup check requires,
                    // and the server. Still no AddCors, no UseCors, no authorization and no
                    // fallback — which is the part this fixture is about, and it is unchanged. The
                    // seam registrations are not a relaxation of it: MapBoltwayAuthorizationServer
                    // verifies the whole required list before it maps a route, so a host cannot get
                    // as far as serving a discovery document without them.
                    services.AddRouting();
                    services.AddSingleton(TestKeys.Ring());
                    services.AddSingleton<IClientResolver>(new TestClientResolver([Build.Client()]));
                    services.AddSingleton<IResourceRegistry>(new TestResourceRegistry().Add(Build.Resource, "mcp:tools"));
                    services.AddBoltwayInMemoryStores();
                    services.AddScoped<IUserSession>(_ => new TestUserSession(null));
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
                    });
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints => endpoints.MapBoltwayAuthorizationServer());
                }))
            .StartAsync();

        _client = _host.GetTestClient();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _host.StopAsync();
        _host.Dispose();
    }

    /// <summary>Discovery works in a host with no CORS middleware at all.</summary>
    [Theory]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks.json")]
    public async Task Discovery_works_without_the_cors_middleware(string url)
    {
        var response = await _client.GetAsync(url);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }

    /// <summary>The 404 is CORS-readable too, so a browser prober sees a status and not an error.</summary>
    [Fact]
    public async Task The_wellknown_404_is_cors_readable()
    {
        var response = await _client.GetAsync("/.well-known/nothing-here");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }

    /// <summary>
    /// The <c>Access-Control-Allow-Origin</c> header appears exactly once.
    /// </summary>
    /// <remarks>
    /// Two values is a CORS failure in every browser, so a server that "helpfully" adds its own
    /// alongside a host's global policy breaks the case it meant to serve.
    /// </remarks>
    [Fact]
    public async Task The_cors_header_is_not_duplicated()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        request.Headers.Add("Origin", "https://claude.ai");

        var response = await _client.SendAsync(request);

        Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin"));
    }

    /// <summary>
    /// A single-line, comma-separated <c>If-None-Match</c> is honoured.
    /// </summary>
    /// <remarks>
    /// RFC 9110 §13.1.2 permits <c>If-None-Match: "a", "b"</c> on one line. Comparing each whole
    /// header value against the tag handles multiple header lines and silently fails this spelling,
    /// so such a client would be answered 200 with a full body every time.
    /// </remarks>
    [Fact]
    public async Task A_comma_separated_if_none_match_is_honoured()
    {
        var first = await _client.GetAsync("/.well-known/openid-configuration");
        var etag = first.Headers.ETag!.ToString();

        using var conditional = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        conditional.Headers.TryAddWithoutValidation("If-None-Match", $"\"stale-one\", {etag}, \"stale-two\"");

        var response = await _client.SendAsync(conditional);

        Assert.Equal(HttpStatusCode.NotModified, response.StatusCode);
    }
}
