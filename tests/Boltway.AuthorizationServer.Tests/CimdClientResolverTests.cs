using System.Globalization;
using System.Text;
using Boltway.AuthorizationServer.Abstractions.Clients;
using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Clients;
using Boltway.OAuth.Net;
using Boltway.OAuth.Primitives.Http;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Secrets;
using Boltway.OAuth.Primitives.Redirects;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// A fetcher a test programmes by URL.
/// </summary>
/// <remarks>
/// The URL is the key, ordinal, because the whole point of CIMD is that the <c>client_id</c> and the
/// fetch target are the same string. A stub keyed on anything else could not tell the "document
/// declares a different client_id" case from the "we fetched the wrong URL" case.
/// </remarks>
internal sealed class StubFetcher : ISafeHttpFetcher
{
    private readonly Dictionary<string, FetchOutcome> _responses = new(StringComparer.Ordinal);

    /// <summary>How many outbound fetches were made. The measurement several tests turn on.</summary>
    public int Calls { get; private set; }

    /// <summary>Every URL asked for, in order.</summary>
    public List<string> Requested { get; } = [];

    public StubFetcher Respond(string url, FetchOutcome outcome)
    {
        _responses[url] = outcome;
        return this;
    }

    public StubFetcher Serve(
        string url, string json, string contentType = "application/json", TimeSpan? maxAge = null) =>
        Respond(url, Ok(json, contentType, maxAge));

    public static FetchOutcome.Ok Ok(string json, string contentType = "application/json", TimeSpan? maxAge = null)
    {
        _ = MediaType.TryParse(contentType, out var parsed);
        return new FetchOutcome.Ok(Encoding.UTF8.GetBytes(json), parsed, ETag: null, maxAge);
    }

    public Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Calls++;
        Requested.Add(request.Url.Value);

        // An unprogrammed URL answers 404 rather than throwing: a test that fetches something it did
        // not intend to should fail on the assertion it wrote, not on a stub's exception.
        return Task.FromResult(
            _responses.TryGetValue(request.Url.Value, out var outcome) ? outcome : new FetchOutcome.NotOk(404));
    }
}

/// <summary>A fetcher that refuses everything. The default for hosts that are not testing CIMD.</summary>
internal sealed class NoNetworkFetcher : ISafeHttpFetcher
{
    public Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken cancellationToken) =>
        Task.FromResult<FetchOutcome>(
            new FetchOutcome.Blocked(BlockReason.DnsFailed, "this test host makes no outbound requests"));
}

/// <summary>A client store that answers nothing and counts every call. A-08.</summary>
internal sealed class CountingClientStore : IClientStore
{
    public int Calls { get; private set; }

    public Task<ClientRecord?> FindAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult<ClientRecord?>(null);
    }

    public Task StoreAsync(
        ClientRecord client, Sha256Hash? secretHash, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.CompletedTask;
    }

    public Task<bool> DeleteAsync(ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(false);
    }

    // Counted like the rest. A-08 is about the client table being untouched by a CIMD connection,
    // not about which method did the touching — a resolver that "only looked up the owner" would
    // still be a resolver reaching the table, and this counter is what says so.
    public Task<ClientRecord?> FindByOwnerAsync(SubjectId owner, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult<ClientRecord?>(null);
    }

    public Task<Sha256Hash?> FindSecretAsync(
        ClientIdentifier clientId, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult<Sha256Hash?>(null);
    }

    public Task<bool> SetEnabledAsync(
        ClientIdentifier clientId, bool enabled, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(false);
    }
}

/// <summary>
/// The CIMD client resolver: CIMD §3, §4, §4.1, §4.2, §5, §5.2, §8.6.
/// </summary>
/// <remarks>
/// <para>
/// S-16, S-29, S-30, X-03, C-01, C-04, A-03, A-07, A-08, A-20, U-17.
/// </para>
/// <para>
/// Every guard below has been seen to fail. 38 mutations were applied to the resolver one at a
/// time — each §3 rule, the §4 self-reference check and its ordinality, §4.1's four bans, §4.2,
/// U-17's rule and both of its exemptions, C-04's two spellings and its default, S-30's floor and
/// ceiling, the injected clock, the never-cache-an-error rule, the cache bound, the DI registration
/// — and in every case the test named beside it went red and went green again on restore.
/// </para>
/// <para>
/// Two of those 38 first came back green while broken, and the cause is worth recording because it
/// is a way of fooling yourself that costs nothing to fall for: the harness was splitting
/// <c>dotnet build</c> from <c>dotnet test --no-build</c>, and the second command ran a stale
/// assembly. A hand-run of the same two mutations showed both tests failing. A control harness that
/// can report green where there is red is worse than no harness at all.
/// </para>
/// </remarks>
public sealed class CimdClientResolverTests
{
    private const string ClaudeId = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    private const string ClaudeCallback = "https://claude.ai/api/mcp/auth_callback";

    /// <summary>The minimum document that validates, for a test that wants to change one thing.</summary>
    private static string Document(
        string clientId = ClaudeId,
        string members = "\"redirect_uris\":[\"" + ClaudeCallback + "\"]") =>
        $$"""{"client_id":"{{clientId}}",{{members}}}""";

    private static DateTimeOffset Start => new(2026, 8, 4, 12, 0, 0, TimeSpan.Zero);

    private static CimdClientResolver Resolver(
        StubFetcher fetcher, TimeProvider? time = null, CimdClientResolverOptions? options = null) =>
        new(fetcher, time ?? new MovableClock(Start), options);

    private static ValueTask<ClientResolution> ResolveAsync(
        string clientId,
        StubFetcher? fetcher = null,
        TimeProvider? time = null,
        CimdClientResolverOptions? options = null) =>
        Resolver(fetcher ?? new StubFetcher(), time, options)
            .ResolveAsync(Identifier(clientId), CancellationToken.None);

    private static ClientIdentifier Identifier(string clientId) =>
        ClientIdentifier.TryParseFromRequest(clientId, out var parsed)
            ? parsed
            : throw new InvalidOperationException($"'{clientId}' is not a usable client_id.");

    // ─────────────────────────────────────────────────────────────────────────
    // CanResolve: the cheap shape test, §7.1
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Only an <c>https://</c> identifier is this resolver's business.</summary>
    [Theory]
    [InlineData("https://claude.ai/oauth/client.json", true)]
    [InlineData("https://claude.ai", true)]
    [InlineData("http://claude.ai/oauth/client.json", false)]
    [InlineData("s6BhdRkqt3", false)]
    [InlineData("", false)]
    public void CanResolve_answers_on_shape_alone(string clientId, bool expected)
    {
        var resolver = Resolver(new StubFetcher());

        var actual = ClientIdentifier.TryParseFromRequest(clientId, out var parsed) && resolver.CanResolve(parsed);

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// <c>CanResolve</c> makes no outbound request.
    /// </summary>
    /// <remarks>
    /// It runs for every resolver in the chain on every authorization request, including the ones
    /// that will be answered by a pre-registered client. A fetch here would put an outbound request
    /// on the critical path of connections that never needed one.
    /// </remarks>
    [Fact]
    public void CanResolve_does_not_fetch()
    {
        var fetcher = new StubFetcher();
        var resolver = Resolver(fetcher);

        for (var i = 0; i < 10; i++)
        {
            _ = resolver.CanResolve(Identifier($"https://client{i.ToString(CultureInfo.InvariantCulture)}.example/c.json"));
        }

        Assert.Equal(0, fetcher.Calls);
    }

    /// <summary>
    /// A <c>client_id</c> that violates §3 is refused by <b>this</b> resolver, not skipped.
    /// </summary>
    /// <remarks>
    /// A-07. <c>CanResolve</c> deliberately accepts more than §3 does, so the resolver that
    /// recognised the identifier is the one that gets to name the rule it broke. Answering
    /// <see langword="false"/> instead would let the chain fall through to "no client is registered
    /// with that identifier", which sends the reader looking for a registration rather than at their
    /// URL.
    /// </remarks>
    [Fact]
    public async Task A_url_that_violates_section_3_is_refused_here_rather_than_skipped()
    {
        var resolver = Resolver(new StubFetcher());
        var clientId = Identifier("https://claude.ai");

        Assert.True(resolver.CanResolve(clientId));

        var resolution = await resolver.ResolveAsync(clientId, CancellationToken.None);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("path component", resolution.Detail, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §3, the Client Identifier URL rules
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Every §3 MUST, and the phrase that identifies which one refused it.</summary>
    [Theory]
    [InlineData("https://claude.ai", "path component")]
    [InlineData("https://claude.ai?x=1", "path component")]
    [InlineData("https://claude.ai/c#f", "fragment")]
    [InlineData("https://user@claude.ai/c", "userinfo")]
    [InlineData("https://user:pw@claude.ai/c", "userinfo")]
    [InlineData("https://claude.ai/a/../b", "path segments")]
    [InlineData("https://claude.ai/a/./b", "path segments")]
    [InlineData("https://claude.ai/..", "path segments")]
    [InlineData("https://claude.ai/a/%2e%2e/b", "path segments")]
    [InlineData("https://claude.ai/a/%2E%2E/b", "path segments")]
    [InlineData("https://claude.ai/a/%2e/b", "path segments")]
    public async Task A_client_id_url_that_breaks_section_3_names_the_rule(string clientId, string phrase)
    {
        var resolution = await ResolveAsync(clientId);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains(phrase, resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A §3 violation is refused before any socket is opened.
    /// </summary>
    /// <remarks>
    /// Not merely tidiness. §8.6 is about not dereferencing attacker-chosen URLs carelessly, and a
    /// URL this server has already decided is not a Client Identifier URL is one it has no reason to
    /// dereference at all.
    /// </remarks>
    [Fact]
    public async Task A_section_3_violation_never_reaches_the_fetcher()
    {
        var fetcher = new StubFetcher();

        _ = await ResolveAsync("https://claude.ai/a/../b", fetcher);

        Assert.Equal(0, fetcher.Calls);
    }

    /// <summary>
    /// §3 permits a port, a query and a path of <c>/</c>, so none of them is refused.
    /// </summary>
    /// <remarks>
    /// The control for the theory above: a rule set that refuses everything passes every negative
    /// test. §3 states the query rule as SHOULD NOT and the bare-<c>/</c> rule as NOT RECOMMENDED,
    /// and neither is promoted to a refusal here — refusing would turn a specification's advice into
    /// this server's rejection of a client that is legal everywhere else.
    /// </remarks>
    [Theory]
    // Each row's redirect URI is same-origin with its own client_id, so this measures §3 and not
    // U-17. The port row is the one that would otherwise fail for the wrong reason: an origin
    // includes the port, so `https://claude.ai:8443/…` is not same-origin with a 443 callback.
    [InlineData("https://claude.ai:8443/oauth/client.json", "https://claude.ai:8443/cb")]
    [InlineData("https://claude.ai/oauth/client.json?v=2", "https://claude.ai/cb")]
    [InlineData("https://claude.ai/", "https://claude.ai/cb")]
    public async Task A_url_section_3_permits_is_accepted(string clientId, string callback)
    {
        var fetcher = new StubFetcher().Serve(clientId, Document(clientId, $"\"redirect_uris\":[\"{callback}\"]"));

        var resolution = await ResolveAsync(clientId, fetcher);

        Assert.Null(resolution.Detail);
        Assert.NotNull(resolution.Client);
    }

    /// <summary>The identifier is fetched exactly as it was sent.</summary>
    [Fact]
    public async Task The_url_fetched_is_the_client_id_verbatim()
    {
        var fetcher = new StubFetcher().Serve(ClaudeId, Document());

        _ = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal([ClaudeId], fetcher.Requested);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §5, retrieval
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A redirect is reported, never followed. §5.
    /// </summary>
    /// <remarks>
    /// The fetcher is what refuses to follow it; this asserts the resolver reports it as its own
    /// condition rather than collapsing it into "could not fetch". §3 explains why it matters
    /// operationally — a URL shortener as a <c>client_id</c> fails here and nowhere else.
    /// </remarks>
    [Fact]
    public async Task A_redirect_is_reported_and_not_followed()
    {
        var fetcher = new StubFetcher()
            .Respond(ClaudeId, new FetchOutcome.Redirected(302, "https://elsewhere.example/c.json"))
            .Serve("https://elsewhere.example/c.json", Document());

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("redirects are not followed", resolution.Detail, StringComparison.Ordinal);

        // One fetch, so the hop really was not taken. Without this the assertion above passes even
        // if the resolver followed the redirect and then failed for some other reason.
        Assert.Equal(1, fetcher.Calls);
    }

    /// <summary>Only 200 is a document. §5.</summary>
    [Theory]
    [InlineData(201)]
    [InlineData(204)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task Only_200_is_accepted(int status)
    {
        var fetcher = new StubFetcher().Respond(ClaudeId, new FetchOutcome.NotOk(status));

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("only 200 is accepted", resolution.Detail, StringComparison.Ordinal);
        Assert.Contains(status.ToString(CultureInfo.InvariantCulture), resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>The resolver asks for the §8.7 read limit, and reports reaching it.</summary>
    [Fact]
    public async Task The_read_limit_is_five_kilobytes_and_exceeding_it_is_reported()
    {
        var options = new CimdClientResolverOptions();
        Assert.Equal(5 * 1024, options.MaxDocumentBytes);

        var fetcher = new StubFetcher().Respond(ClaudeId, new FetchOutcome.TooLarge(options.MaxDocumentBytes));

        var resolution = await ResolveAsync(ClaudeId, fetcher, options: options);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("read limit", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>The cap the resolver asks for is the cap the fetcher is given.</summary>
    /// <remarks>
    /// A separate assertion from the one above, because <see cref="StubFetcher"/> does not enforce
    /// the cap — it answers whatever it was programmed with. Without this, the resolver could pass
    /// <c>int.MaxValue</c> and the <c>TooLarge</c> test would still be green.
    /// </remarks>
    [Fact]
    public async Task The_configured_cap_reaches_the_fetch_request()
    {
        var options = new CimdClientResolverOptions { MaxDocumentBytes = 777 };
        var observed = 0;
        var fetcher = new CapturingFetcher(request => observed = request.MaxBytes);

        _ = await new CimdClientResolver(fetcher, new MovableClock(Start), options)
            .ResolveAsync(Identifier(ClaudeId), CancellationToken.None);

        Assert.Equal(777, observed);
    }

    private sealed class CapturingFetcher(Action<SafeFetchRequest> observe) : ISafeHttpFetcher
    {
        public Task<FetchOutcome> FetchAsync(SafeFetchRequest request, CancellationToken cancellationToken)
        {
            observe(request);
            return Task.FromResult<FetchOutcome>(new FetchOutcome.NotOk(404));
        }
    }

    /// <summary>Every non-<c>Ok</c> fetch outcome gets its own sentence. X-03, A-07, A-12.</summary>
    [Theory]
    [InlineData("special-use")]
    [InlineData("dns")]
    [InlineData("scheme")]
    [InlineData("timeout")]
    [InlineData("transport")]
    public async Task Each_fetch_failure_names_what_happened(string kind)
    {
        FetchOutcome outcome = kind switch
        {
            "special-use" => new FetchOutcome.Blocked(
                BlockReason.SpecialUseAddress, "'claude.ai' resolves to 169.254.169.254, which is a special-use address (RFC 6890)."),
            "dns" => new FetchOutcome.Blocked(BlockReason.DnsFailed, "'claude.ai' did not resolve."),
            "scheme" => new FetchOutcome.Blocked(BlockReason.NotAnHttpsUrl, "not an https URL"),
            "timeout" => new FetchOutcome.Timeout(TimeSpan.FromSeconds(5)),
            _ => new FetchOutcome.TransportFailed("the SSL connection could not be established"),
        };

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Respond(ClaudeId, outcome));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);

        var expected = kind switch
        {
            "special-use" => "special-use address",
            "dns" => "did not resolve",
            "scheme" => "refused before connecting",
            "timeout" => "timed out",
            _ => "TLS handshake failed",
        };

        Assert.Contains(expected, resolution.Detail, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §4, the document
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The document's <c>client_id</c> must be the URL it came from. §4.
    /// </summary>
    /// <remarks>
    /// This is the whole security model. Without it, anyone who can host a JSON file can publish a
    /// document claiming to be Claude, and the <c>client_id</c> in the authorization request stops
    /// naming anything.
    /// </remarks>
    [Fact]
    public async Task A_document_that_names_a_different_client_id_is_refused()
    {
        var fetcher = new StubFetcher().Serve(ClaudeId, Document(clientId: "https://evil.example/c.json"));

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("not the URL it was fetched from", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// The match is simple string comparison, so a URL that merely denotes the same resource fails.
    /// </summary>
    /// <remarks>
    /// §4 and §3 both require RFC 3986 §6.2.1, and §3 gives this exact example:
    /// "https://example.com/client and https://example.com:443/client are not equivalent even though
    /// 443 is the default port for the https scheme". A comparison through <see cref="Uri"/> would
    /// equate them, and would equate a percent-encoded path with its decoded form.
    /// </remarks>
    [Theory]
    [InlineData("https://claude.ai:443/oauth/mcp-oauth-client-metadata")]
    [InlineData("https://CLAUDE.AI/oauth/mcp-oauth-client-metadata")]
    [InlineData("https://claude.ai/oauth/mcp-oauth-client-metadata/")]
    public async Task The_self_reference_check_is_ordinal(string declared)
    {
        var fetcher = new StubFetcher().Serve(ClaudeId, Document(clientId: declared));

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("not the URL it was fetched from", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>A body that is not JSON, and a body served without a JSON content type.</summary>
    [Theory]
    [InlineData("<!doctype html><html></html>", "text/html", "not JSON")]
    [InlineData("{\"client_id\":", "application/json", "not valid JSON")]
    [InlineData("[]", "application/json", "not a JSON object")]
    [InlineData("\"a string\"", "application/json", "not a JSON object")]
    public async Task A_body_that_is_not_a_json_object_is_refused(string body, string contentType, string phrase)
    {
        var fetcher = new StubFetcher().Respond(ClaudeId, StubFetcher.Ok(body, contentType));

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains(phrase, resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Both content types the two vendors actually send are accepted. U-03.
    /// </summary>
    /// <remarks>
    /// Measured on 2026-08-03: <c>claude.ai</c> serves a bare <c>application/json</c> and
    /// <c>chatgpt.com</c> serves <c>application/json; charset=utf-8</c>. A resolver comparing the
    /// header by string equality accepts one vendor and refuses the other — and the refusal surfaces
    /// as <c>invalid_client</c>, which reads as the client's fault. The <c>+json</c> row is §4's
    /// "conforms to application/&lt;AS-defined&gt;+json".
    /// </remarks>
    [Theory]
    [InlineData("application/json")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("Application/JSON")]
    [InlineData("application/client-metadata+json")]
    public async Task The_content_types_vendors_send_are_accepted(string contentType)
    {
        var fetcher = new StubFetcher().Respond(ClaudeId, StubFetcher.Ok(Document(), contentType));

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Null(resolution.Detail);
        Assert.NotNull(resolution.Client);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §4.1, credential and key material restrictions
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A document carrying a shared secret, in any of the ways §4.1 names.</summary>
    [Theory]
    [InlineData("\"client_secret\":\"s3cret\"", "client_secret")]
    [InlineData("\"client_secret_expires_at\":0", "client_secret_expires_at")]
    [InlineData("\"token_endpoint_auth_method\":\"client_secret_basic\"", "shared secret")]
    [InlineData("\"token_endpoint_auth_method\":\"client_secret_post\"", "shared secret")]
    [InlineData("\"token_endpoint_auth_method\":\"client_secret_jwt\"", "shared secret")]
    [InlineData("\"token_endpoint_auth_methods_supported\":[\"none\",\"client_secret_basic\"]", "shared secret")]
    public async Task A_document_carrying_a_symmetric_secret_is_refused(string member, string phrase)
    {
        var document = Document(members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],{member}");
        var fetcher = new StubFetcher().Serve(ClaudeId, document);

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains(phrase, resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>Private and symmetric key material in an inline <c>jwks</c>. §4.1.</summary>
    [Theory]
    [InlineData("\"d\":\"x\"", "private key material")]
    [InlineData("\"p\":\"x\"", "private key material")]
    [InlineData("\"q\":\"x\"", "private key material")]
    [InlineData("\"dp\":\"x\"", "private key material")]
    [InlineData("\"dq\":\"x\"", "private key material")]
    [InlineData("\"qi\":\"x\"", "private key material")]
    [InlineData("\"k\":\"x\"", "private key material")]
    [InlineData("\"kty\":\"oct\"", "symmetric key")]
    public async Task An_inline_jwks_carrying_private_key_material_is_refused(string member, string phrase)
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"jwks\":{{\"keys\":[{{\"kty\":\"RSA\",\"n\":\"a\",\"e\":\"AQAB\",{member}}}]}}");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains(phrase, resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>An inline <c>jwks</c> of public keys only is fine. The control for the theory above.</summary>
    [Fact]
    public async Task An_inline_jwks_of_public_keys_is_accepted()
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"jwks\":{{\"keys\":[{{\"kty\":\"RSA\",\"n\":\"a\",\"e\":\"AQAB\"}}]}}");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Null(resolution.Detail);
        Assert.NotNull(resolution.Client);
    }

    /// <summary><c>jwks</c> and <c>jwks_uri</c> together. RFC 7591 §2, and X-03 names it.</summary>
    [Fact]
    public async Task A_document_with_both_jwks_and_jwks_uri_is_refused()
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"jwks\":{{\"keys\":[]}},\"jwks_uri\":\"https://claude.ai/jwks.json\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("both 'jwks' and 'jwks_uri'", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>A URL member that is not an absolute https URL. §8.6 names <c>javascript:</c>.</summary>
    [Theory]
    [InlineData("jwks_uri", "javascript:alert(1)")]
    [InlineData("jwks_uri", "http://claude.ai/jwks.json")]
    [InlineData("jwks_uri", "file:///etc/passwd")]
    [InlineData("logo_uri", "javascript:alert(1)")]
    [InlineData("logo_uri", "data:image/png;base64,AAAA")]
    public async Task A_url_member_with_an_unsupported_scheme_is_refused(string member, string value)
    {
        var document = Document(members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"{member}\":\"{value}\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains(member, resolution.Detail, StringComparison.Ordinal);
        Assert.Contains("absolute https URL", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary><c>private_key_jwt</c> with nowhere to find the key. §8.2.</summary>
    [Fact]
    public async Task Private_key_jwt_without_a_jwks_uri_is_refused()
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"token_endpoint_auth_method\":\"private_key_jwt\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("needs a 'jwks_uri'", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary><c>private_key_jwt</c> with a <c>jwks_uri</c> is a confidential client. §8.2.</summary>
    [Fact]
    public async Task Private_key_jwt_with_a_jwks_uri_is_a_confidential_client()
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"token_endpoint_auth_method\":\"private_key_jwt\","
                + "\"jwks_uri\":\"https://claude.ai/jwks.json\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        Assert.Equal(ClientType.Confidential, client.ClientType);
        Assert.Equal(ClientAuthMethod.PrivateKeyJwt, client.TokenEndpointAuthMethod);
        Assert.Equal("https://claude.ai/jwks.json", client.JwksUri);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C-04, both spellings of the auth-method field
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Both spellings are read, and an absent field means <c>none</c>.
    /// </summary>
    /// <remarks>
    /// C-04. RFC 7591 §2 makes the default <c>client_secret_basic</c>, which §4.1 forbids — so a
    /// resolver applying RFC 7591's default literally refuses every document that omits the field,
    /// including two of the four captured on 2026-08-03. The plural spelling is ChatGPT's, and it is
    /// RFC 8414's <i>server</i> field appearing in a client document.
    /// </remarks>
    [Theory]
    [InlineData("", ClientAuthMethod.None)]
    [InlineData(",\"token_endpoint_auth_method\":\"none\"", ClientAuthMethod.None)]
    [InlineData(",\"token_endpoint_auth_methods_supported\":[\"none\"]", ClientAuthMethod.None)]
    [InlineData(",\"token_endpoint_auth_methods_supported\":[\"none\",\"private_key_jwt\"]", ClientAuthMethod.None)]
    [InlineData(",\"token_endpoint_auth_methods_supported\":[]", ClientAuthMethod.None)]
    public async Task Both_spellings_are_read_and_the_default_is_none(string member, ClientAuthMethod expected)
    {
        var document = Document(members: $"\"redirect_uris\":[\"{ClaudeCallback}\"]{member}");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        Assert.Equal(expected, client.TokenEndpointAuthMethod);
        Assert.Equal(ClientType.Public, client.ClientType);
    }

    /// <summary>The plural spelling selects <c>private_key_jwt</c> when that is all it offers.</summary>
    [Fact]
    public async Task The_plural_spelling_selects_the_only_method_offered()
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\"],"
                + "\"jwks_uri\":\"https://claude.ai/jwks.json\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        Assert.Equal(ClientAuthMethod.PrivateKeyJwt, client.TokenEndpointAuthMethod);
    }

    /// <summary>
    /// ChatGPT's live document, byte for byte, resolves to a public client.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured 2026-08-17 from <c>https://chatgpt.com/oauth/mcp/client.json</c>. It carries
    /// <b>both</b> spellings — the singular naming <c>private_key_jwt</c>, the plural offering
    /// <c>none</c> beside it — which no document captured on 2026-08-03 did.
    /// </para>
    /// <para>
    /// While <c>TryReadAuthMethod</c> read one member or the other, the singular won and every
    /// ChatGPT connection registered a confidential client this server has no implementation to
    /// authenticate: <c>/token</c> answered <c>invalid_client</c>, "This client is registered for an
    /// authentication method this server does not offer", and ChatGPT reported "There was a problem
    /// connecting". This is that document, and the assertion is the connection.
    /// </para>
    /// <para>
    /// Both paths are here because <b>production uses the per-connector one</b>, and it was not the
    /// URL this was first written against. A deployment's authorization-server log named
    /// <c>https://chatgpt.com/oauth/&lt;callback-id&gt;/client.json</c> — a document minted per
    /// connector instance, at the path OpenAI's Apps SDK documents — where the reproduction had used
    /// the well-known <c>/oauth/mcp/client.json</c>. Both were fetched on 2026-08-17 and carry the
    /// same two members, so the fix covers both; asserting it beats inferring it from "same shape".
    /// The id in the per-connector URL below is a placeholder: the real one identifies somebody's
    /// connector instance and belongs in their deployment's logs, not in this repository.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("https://chatgpt.com/oauth/client.json")]
    [InlineData("https://chatgpt.com/oauth/mcp/client.json")]
    [InlineData("https://chatgpt.com/oauth/aaaaaaaaaaaa/client.json")]
    public async Task The_live_chatgpt_document_is_a_public_client(string chatgptId)
    {
        var document = Document(
            clientId: chatgptId,
            members: """
                "client_uri":"https://chatgpt.com/",
                "redirect_uris":["https://chatgpt.com/connector/oauth/mcp"],
                "token_endpoint_auth_method":"private_key_jwt",
                "token_endpoint_auth_methods_supported":["none","private_key_jwt"],
                "grant_types":["authorization_code","refresh_token"],
                "response_types":["code"],
                "client_name":"ChatGPT",
                "logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png",
                "token_endpoint_auth_signing_alg":"RS256",
                "jwks_uri":"https://chatgpt.com/oauth/jwks.json"
                """.ReplaceLineEndings(string.Empty));

        var resolution = await ResolveAsync(chatgptId, new StubFetcher().Serve(chatgptId, document));

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        Assert.Equal(ClientAuthMethod.None, client.TokenEndpointAuthMethod);
        Assert.Equal(ClientType.Public, client.ClientType);
    }

    /// <summary>
    /// With both members present the offer is their union, and <c>none</c> wins from either.
    /// </summary>
    /// <remarks>
    /// The singular is RFC 7591's field and the plural is RFC 8414's, so a document carrying both is
    /// stating a preference and a set. This server records one method and can complete only
    /// <c>none</c> of the two §4.1 leaves legal, so the set is what it reads — see
    /// <c>CimdDocument.TryReadAuthMethod</c> for why that is a policy choice rather than a rule.
    /// </remarks>
    [Theory]
    [InlineData("\"private_key_jwt\"", "[\"none\",\"private_key_jwt\"]", ClientAuthMethod.None)]
    [InlineData("\"private_key_jwt\"", "[\"private_key_jwt\",\"none\"]", ClientAuthMethod.None)]
    [InlineData("\"none\"", "[\"none\",\"private_key_jwt\"]", ClientAuthMethod.None)]
    [InlineData("\"private_key_jwt\"", "[\"private_key_jwt\"]", ClientAuthMethod.PrivateKeyJwt)]
    [InlineData("\"private_key_jwt\"", "[]", ClientAuthMethod.PrivateKeyJwt)]
    public async Task Both_members_together_are_the_offer(string singular, string plural, ClientAuthMethod expected)
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],"
                + $"\"token_endpoint_auth_method\":{singular},"
                + $"\"token_endpoint_auth_methods_supported\":{plural},"
                + "\"jwks_uri\":\"https://claude.ai/jwks.json\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        Assert.Equal(expected, client.TokenEndpointAuthMethod);
    }

    /// <summary>
    /// §4.1's ban applies wherever the symmetric method is spelled, not only in the member read
    /// first.
    /// </summary>
    /// <remarks>
    /// The branch that short-circuited the plural also skipped its §4.1 check, so a document naming
    /// <c>none</c> in the singular carried <c>client_secret_basic</c> through the plural untouched —
    /// while the identical plural on its own was refused. A rule that holds in one spelling and not
    /// the other is not a rule.
    /// </remarks>
    [Theory]
    [InlineData("\"none\"", "[\"none\",\"client_secret_basic\"]")]
    [InlineData("\"private_key_jwt\"", "[\"client_secret_jwt\"]")]
    public async Task A_symmetric_method_is_refused_from_either_member(string singular, string plural)
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],"
                + $"\"token_endpoint_auth_method\":{singular},"
                + $"\"token_endpoint_auth_methods_supported\":{plural}");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("shared secret", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>An authentication method this server does not implement is named, not ignored.</summary>
    [Fact]
    public async Task An_unsupported_auth_method_is_refused_by_name()
    {
        var document = Document(
            members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],\"token_endpoint_auth_method\":\"tls_client_auth\"");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("tls_client_auth", resolution.Detail, StringComparison.Ordinal);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §4.2 and U-17, redirect registration
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Redirect URIs come from the document, through the one registration path.</summary>
    [Fact]
    public async Task Redirect_uris_are_registered_from_the_document()
    {
        var fetcher = new StubFetcher().Serve(ClaudeId, Document());

        var resolution = await ResolveAsync(ClaudeId, fetcher);

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        var registered = Assert.Single(client.RedirectUris);

        Assert.Equal(ClaudeCallback, registered.Value);
        Assert.Equal(RedirectKind.Https, registered.Kind);
    }

    /// <summary>A document with no usable redirect URI cannot run an authorization code flow.</summary>
    [Theory]
    [InlineData("", "no 'redirect_uris'")]
    [InlineData(",\"redirect_uris\":[]", "is empty")]
    [InlineData(",\"redirect_uris\":\"https://claude.ai/cb\"", "array of strings")]
    [InlineData(",\"redirect_uris\":[42]", "array of strings")]
    public async Task A_document_without_usable_redirect_uris_is_refused(string member, string phrase)
    {
        var document = $$"""{"client_id":"{{ClaudeId}}","client_name":"Claude"{{member}}}""";

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains(phrase, resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>A redirect URI the registration rules refuse names the rule that refused it.</summary>
    [Theory]
    [InlineData("https://claude.ai/cb#f")]
    [InlineData("https://user@claude.ai/cb")]
    [InlineData("http://not-loopback.example/cb")]
    [InlineData("/relative")]
    public async Task A_redirect_uri_the_registration_rules_refuse_is_reported(string redirect)
    {
        var document = Document(members: $"\"redirect_uris\":[\"{redirect}\"]");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("redirect URI in the client metadata document was refused", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// U-17: an https redirect URI must share the <c>client_id</c>'s origin.
    /// </summary>
    /// <remarks>
    /// §8.1: without a restriction like this, "the client attempts to impersonate a more well-known
    /// client". A document at <c>evil.example</c> declaring <c>client_name: "Claude"</c> and a
    /// redirect to itself is the whole attack, and the consent page's hostname display is the only
    /// other defence.
    /// </remarks>
    [Theory]
    [InlineData("https://evil.example/cb", false)]
    [InlineData("https://sub.claude.ai/cb", false)]
    [InlineData("https://claude.ai:8443/cb", false)]
    [InlineData("https://claude.ai/anything", true)]
    [InlineData("https://claude.ai:443/anything", true)]
    public async Task An_https_redirect_uri_must_be_same_origin_with_the_client_id(string redirect, bool permitted)
    {
        var document = Document(members: $"\"redirect_uris\":[\"{redirect}\"]");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        if (permitted)
        {
            Assert.NotNull(resolution.Client);
            return;
        }

        Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        Assert.Contains("same-origin", resolution.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// Loopback and private-use redirect URIs are exempt from the origin rule. U-17.
    /// </summary>
    /// <remarks>
    /// This is the measurement U-17 turns on, not a softening. Claude Code's published document has
    /// <c>client_id</c> on <c>claude.ai</c> and redirect URIs on <c>localhost</c> and
    /// <c>127.0.0.1</c>, so a same-origin rule without this exemption refuses one of the two clients
    /// this server exists to serve.
    /// </remarks>
    [Theory]
    [InlineData("http://localhost/callback")]
    [InlineData("http://127.0.0.1/callback")]
    [InlineData("http://127.0.0.1:8123/callback")]
    [InlineData("com.example.app:/oauth2redirect")]
    public async Task A_loopback_or_private_use_redirect_uri_is_exempt(string redirect)
    {
        var document = Document(members: $"\"redirect_uris\":[\"{redirect}\"]");

        var resolution = await ResolveAsync(ClaudeId, new StubFetcher().Serve(ClaudeId, document));

        Assert.Null(resolution.Detail);
        Assert.NotNull(resolution.Client);
    }

    /// <summary>The origin rule can be turned off, and can be waived for one named client.</summary>
    [Fact]
    public async Task The_origin_rule_has_an_escape_hatch()
    {
        var document = Document(members: "\"redirect_uris\":[\"https://elsewhere.example/cb\"]");
        var fetcher = new StubFetcher().Serve(ClaudeId, document);

        var disabled = new CimdClientResolverOptions { RequireSameOriginRedirectUris = false };
        Assert.NotNull((await ResolveAsync(ClaudeId, fetcher, options: disabled)).Client);

        var exempted = new CimdClientResolverOptions();
        exempted.SameOriginExemptClientIds.Add(ClaudeId);
        Assert.NotNull((await ResolveAsync(ClaudeId, fetcher, options: exempted)).Client);

        // The exemption is per client_id, not per host: a second document on the same host is still
        // subject to the rule.
        const string Sibling = "https://claude.ai/oauth/other";
        var siblingFetcher = new StubFetcher()
            .Serve(Sibling, Document(Sibling, "\"redirect_uris\":[\"https://elsewhere.example/cb\"]"));

        var refused = await ResolveAsync(Sibling, siblingFetcher, options: exempted);
        Assert.Equal(ClientResolutionError.MetadataUnusable, refused.Error);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // §5.2 and S-30, caching
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>A resolved document is served from cache on the next authorization.</summary>
    [Fact]
    public async Task A_resolved_document_is_cached()
    {
        var fetcher = new StubFetcher().Serve(ClaudeId, Document());
        var resolver = Resolver(fetcher);

        for (var i = 0; i < 5; i++)
        {
            Assert.NotNull((await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None)).Client);
        }

        Assert.Equal(1, fetcher.Calls);
    }

    /// <summary>S-30's clamp, at both bounds and in between.</summary>
    [Theory]
    [InlineData(0, 300)]
    [InlineData(1, 300)]
    [InlineData(299, 300)]
    [InlineData(300, 300)]
    [InlineData(3600, 3600)]
    [InlineData(86_400, 86_400)]
    [InlineData(86_401, 86_400)]
    [InlineData(31_536_000, 86_400)]
    public void The_cache_lifetime_is_clamped(int maxAgeSeconds, int expectedSeconds)
    {
        var clamped = CimdClientResolver.Clamp(TimeSpan.FromSeconds(maxAgeSeconds));

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), clamped);
    }

    /// <summary>
    /// The clamp is applied to the real cache, on the server's own clock.
    /// </summary>
    /// <remarks>
    /// The unit test above proves the arithmetic. This proves the arithmetic is what the cache uses,
    /// and that expiry is read from the injected <see cref="TimeProvider"/> — a resolver reading
    /// <c>DateTimeOffset.UtcNow</c> would ignore the clock this test moves and stay green for the
    /// wrong reason only until the suite ran slowly.
    /// </remarks>
    [Theory]
    [InlineData(60, 300)]
    [InlineData(3600, 3600)]
    [InlineData(1_000_000, 86_400)]
    public async Task The_cache_expires_on_the_clamped_lifetime(int maxAgeSeconds, int effectiveSeconds)
    {
        var clock = new MovableClock(Start);
        var fetcher = new StubFetcher().Serve(ClaudeId, Document(), maxAge: TimeSpan.FromSeconds(maxAgeSeconds));
        var resolver = Resolver(fetcher, clock);

        _ = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);
        Assert.Equal(1, fetcher.Calls);

        clock.Advance(TimeSpan.FromSeconds(effectiveSeconds - 1));
        _ = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);
        Assert.Equal(1, fetcher.Calls);

        clock.Advance(TimeSpan.FromSeconds(2));
        _ = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);
        Assert.Equal(2, fetcher.Calls);
    }

    /// <summary>No Cache-Control at all means the floor, not "do not cache".</summary>
    [Fact]
    public async Task A_document_without_cache_headers_gets_the_floor()
    {
        var clock = new MovableClock(Start);
        var fetcher = new StubFetcher().Serve(ClaudeId, Document(), maxAge: null);
        var resolver = Resolver(fetcher, clock);

        _ = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);

        clock.Advance(TimeSpan.FromSeconds(299));
        _ = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);
        Assert.Equal(1, fetcher.Calls);

        clock.Advance(TimeSpan.FromSeconds(2));
        _ = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);
        Assert.Equal(2, fetcher.Calls);
    }

    /// <summary>
    /// An error is never cached. §5.2, and it says so twice.
    /// </summary>
    /// <remarks>
    /// "The authorization server MUST NOT cache error responses. The authorization server also MUST
    /// NOT cache documents which are invalid or malformed." Caching either one turns a client's
    /// five-minute outage, or a typo they fixed immediately, into a five-minute outage on this
    /// server that no amount of fixing the document clears.
    /// </remarks>
    [Theory]
    [InlineData("status")]
    [InlineData("redirect")]
    [InlineData("blocked")]
    [InlineData("malformed-json")]
    [InlineData("wrong-client-id")]
    [InlineData("bad-redirect")]
    public async Task An_error_or_malformed_document_is_never_cached(string kind)
    {
        FetchOutcome failing = kind switch
        {
            "status" => new FetchOutcome.NotOk(503),
            "redirect" => new FetchOutcome.Redirected(302, "https://elsewhere.example/"),
            "blocked" => new FetchOutcome.Blocked(BlockReason.DnsFailed, "'claude.ai' did not resolve."),
            "malformed-json" => StubFetcher.Ok("{", maxAge: TimeSpan.FromHours(12)),
            "wrong-client-id" => StubFetcher.Ok(Document(clientId: "https://evil.example/c"), maxAge: TimeSpan.FromHours(12)),
            _ => StubFetcher.Ok(Document(members: "\"redirect_uris\":[\"https://evil.example/cb\"]"), maxAge: TimeSpan.FromHours(12)),
        };

        var fetcher = new StubFetcher().Respond(ClaudeId, failing);
        var resolver = Resolver(fetcher);

        for (var i = 0; i < 3; i++)
        {
            var resolution = await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None);
            Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
        }

        // Three attempts, three fetches: nothing was remembered. The Ok-but-invalid rows carry a
        // twelve-hour max-age precisely so that a cache keyed before validation would be caught.
        Assert.Equal(3, fetcher.Calls);
        Assert.Equal(0, resolver.CachedCount);
    }

    /// <summary>
    /// The cache is bounded, because its key is attacker-chosen.
    /// </summary>
    /// <remarks>
    /// Every distinct URL-shaped <c>client_id</c> that resolves is an entry, and nothing stops a
    /// caller sending a new one on each request. At the cap the cache stops accepting entries;
    /// resolution still succeeds.
    /// </remarks>
    [Fact]
    public async Task The_cache_is_bounded()
    {
        var options = new CimdClientResolverOptions { MaxCachedClients = 4 };
        var fetcher = new StubFetcher();
        var resolver = Resolver(fetcher, options: options);

        for (var i = 0; i < 50; i++)
        {
            var id = $"https://c{i.ToString(CultureInfo.InvariantCulture)}.example/client.json";
            fetcher.Serve(id, Document(id, $"\"redirect_uris\":[\"https://c{i.ToString(CultureInfo.InvariantCulture)}.example/cb\"]"));

            var resolution = await resolver.ResolveAsync(Identifier(id), CancellationToken.None);
            Assert.NotNull(resolution.Client);
        }

        Assert.True(resolver.CachedCount <= 4, $"The cache holds {resolver.CachedCount} entries, above the cap of 4.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-08, no persistent client record
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A hundred sequential CIMD connections leave the client store untouched. A-08.
    /// </summary>
    /// <remarks>
    /// A hundred <b>distinct</b> identifiers as well as a hundred repeats, because the repeat case
    /// is also satisfied by a resolver that persists once and reads back. The store here answers
    /// nothing and counts everything: the assertion is zero calls of any kind, which is the property
    /// A-08 states — "CIMD creates no per-connection persistent client record".
    /// </remarks>
    [Fact]
    public async Task A_hundred_connections_never_touch_the_client_store()
    {
        var store = new CountingClientStore();
        var fetcher = new StubFetcher().Serve(ClaudeId, Document());
        var resolver = Resolver(fetcher);

        for (var i = 0; i < 100; i++)
        {
            var id = $"https://client{i.ToString(CultureInfo.InvariantCulture)}.example/client.json";
            fetcher.Serve(id, Document(id, $"\"redirect_uris\":[\"https://client{i.ToString(CultureInfo.InvariantCulture)}.example/cb\"]"));

            Assert.NotNull((await resolver.ResolveAsync(Identifier(id), CancellationToken.None)).Client);
        }

        for (var i = 0; i < 100; i++)
        {
            Assert.NotNull((await resolver.ResolveAsync(Identifier(ClaudeId), CancellationToken.None)).Client);
        }

        Assert.Equal(0, store.Calls);
    }

    /// <summary>
    /// The resolver has no way to reach a client store at all.
    /// </summary>
    /// <remarks>
    /// The structural half of A-08, and the half the counting test cannot supply: a store the
    /// resolver never receives is a store it cannot write to, whereas "we counted zero calls" only
    /// describes the calls the test made. Reading it off the constructor means adding a store later
    /// is a diff a reviewer sees.
    /// </remarks>
    [Fact]
    public void The_resolver_takes_no_client_store()
    {
        var parameters = typeof(CimdClientResolver).GetConstructors().SelectMany(c => c.GetParameters()).ToList();

        Assert.NotEmpty(parameters);
        Assert.DoesNotContain(parameters, p => typeof(IClientStore).IsAssignableFrom(p.ParameterType));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // X-03, every failure condition distinguishable
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Each scenario, and the description it is expected to produce.</summary>
    private sealed record Scenario(string Name, string ClientId, StubFetcher Fetcher);

    private static IEnumerable<Scenario> FailureScenarios()
    {
        static StubFetcher Answering(FetchOutcome outcome) => new StubFetcher().Respond(ClaudeId, outcome);
        static StubFetcher Serving(string body) => new StubFetcher().Serve(ClaudeId, body);
        static string WithMembers(string extra) => Document(members: $"\"redirect_uris\":[\"{ClaudeCallback}\"],{extra}");

        // §3, before any fetch.
        yield return new("§3 scheme", "http://claude.ai/c", new StubFetcher());
        yield return new("§3 no path", "https://claude.ai", new StubFetcher());
        yield return new("§3 fragment", "https://claude.ai/c#f", new StubFetcher());
        yield return new("§3 userinfo", "https://u@claude.ai/c", new StubFetcher());
        yield return new("§3 dot segment", "https://claude.ai/a/../b", new StubFetcher());

        // §5, the fetch.
        yield return new("§5 status", ClaudeId, Answering(new FetchOutcome.NotOk(404)));
        yield return new("§5 redirect", ClaudeId, Answering(new FetchOutcome.Redirected(301, "https://x.example/")));
        yield return new("§8.7 too large", ClaudeId, Answering(new FetchOutcome.TooLarge(5 * 1024)));
        yield return new("§8.6 special-use", ClaudeId, Answering(new FetchOutcome.Blocked(
            BlockReason.SpecialUseAddress, "'claude.ai' resolves to 127.0.0.1, which is a special-use address (RFC 6890).")));
        yield return new("dns", ClaudeId, Answering(new FetchOutcome.Blocked(BlockReason.DnsFailed, "'claude.ai' did not resolve.")));
        yield return new("blocked scheme", ClaudeId, Answering(new FetchOutcome.Blocked(BlockReason.NotAnHttpsUrl, "not https")));
        yield return new("timeout", ClaudeId, Answering(new FetchOutcome.Timeout(TimeSpan.FromSeconds(5))));
        yield return new("transport", ClaudeId, Answering(new FetchOutcome.TransportFailed("connection reset")));

        // §4, the document.
        yield return new("§4 content type", ClaudeId, new StubFetcher().Respond(ClaudeId, StubFetcher.Ok(Document(), "text/html")));
        yield return new("§4 not json", ClaudeId, Serving("{"));
        yield return new("§4 not an object", ClaudeId, Serving("[]"));
        yield return new("§4 no client_id", ClaudeId, Serving($$"""{"redirect_uris":["{{ClaudeCallback}}"]}"""));
        yield return new("§4 client_id mismatch", ClaudeId, Serving(Document(clientId: "https://evil.example/c")));

        // §4.1, credentials and keys.
        yield return new("§4.1 client_secret", ClaudeId, Serving(WithMembers("\"client_secret\":\"s\"")));
        yield return new("§4.1 client_secret_expires_at", ClaudeId, Serving(WithMembers("\"client_secret_expires_at\":0")));
        yield return new("§4.1 symmetric method", ClaudeId, Serving(WithMembers("\"token_endpoint_auth_method\":\"client_secret_basic\"")));
        yield return new("unsupported method", ClaudeId, Serving(WithMembers("\"token_endpoint_auth_method\":\"tls_client_auth\"")));
        yield return new("jwks and jwks_uri", ClaudeId, Serving(WithMembers(
            "\"jwks\":{\"keys\":[]},\"jwks_uri\":\"https://claude.ai/j\"")));
        yield return new("§4.1 private key", ClaudeId, Serving(WithMembers(
            "\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"n\":\"a\",\"e\":\"AQAB\",\"d\":\"x\"}]}")));
        yield return new("§4.1 symmetric key", ClaudeId, Serving(WithMembers("\"jwks\":{\"keys\":[{\"kty\":\"oct\",\"k\":\"x\"}]}")));
        yield return new("malformed jwks", ClaudeId, Serving(WithMembers("\"jwks\":{\"keys\":\"nope\"}")));
        yield return new("§8.6 jwks_uri scheme", ClaudeId, Serving(WithMembers("\"jwks_uri\":\"javascript:alert(1)\"")));
        yield return new("§8.6 logo_uri scheme", ClaudeId, Serving(WithMembers("\"logo_uri\":\"javascript:alert(1)\"")));
        yield return new("§8.2 no jwks_uri", ClaudeId, Serving(WithMembers("\"token_endpoint_auth_method\":\"private_key_jwt\"")));

        // §4.2 and U-17, redirects.
        yield return new("§4.2 missing", ClaudeId, Serving($$"""{"client_id":"{{ClaudeId}}"}"""));
        yield return new("§4.2 empty", ClaudeId, Serving(Document(members: "\"redirect_uris\":[]")));
        yield return new("§4.2 not an array", ClaudeId, Serving(Document(members: "\"redirect_uris\":\"x\"")));
        yield return new("§4.2 unregisterable", ClaudeId, Serving(Document(members: "\"redirect_uris\":[\"https://claude.ai/cb#f\"]")));
        yield return new("U-17 cross-origin", ClaudeId, Serving(Document(members: "\"redirect_uris\":[\"https://evil.example/cb\"]")));

        // Shape of the remaining members.
        yield return new("grant_types shape", ClaudeId, Serving(WithMembers("\"grant_types\":\"authorization_code\"")));
        yield return new("response_types shape", ClaudeId, Serving(WithMembers("\"response_types\":42")));
        yield return new("client_name shape", ClaudeId, Serving(WithMembers("\"client_name\":42")));
        yield return new("auth method shape", ClaudeId, Serving(WithMembers("\"token_endpoint_auth_method\":42")));
        yield return new("auth methods shape", ClaudeId, Serving(WithMembers("\"token_endpoint_auth_methods_supported\":\"none\"")));
    }

    /// <summary>
    /// Every CIMD failure condition fires, and every one has its own description. X-03, A-07, A-12.
    /// </summary>
    /// <remarks>
    /// <para>
    /// X-03's row names the conditions this must cover: fetch failed, status ≠ 200, redirect
    /// encountered, over the size cap, resolved to a special-use IP, body not JSON, <c>client_id</c>
    /// ≠ fetch URL, <c>client_secret*</c> present, <c>jwks</c> and <c>jwks_uri</c> both present,
    /// private key material present. The scenario list above is a superset: it adds the §3 URL rules,
    /// §8.2, §8.6 and U-17, and splits the transport failures the row groups as "fetch failed".
    /// </para>
    /// <para>
    /// The distinctness assertion is the point. A description that appears twice is two conditions a
    /// reader cannot tell apart from the response body, which is the one artefact A-12 says has to be
    /// enough. The count assertion is the control: a <c>yield return</c> silently dropped would leave
    /// this test green over a smaller set.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Every_failure_condition_produces_metadata_unusable_with_its_own_description()
    {
        var observed = new List<(string Name, string Detail)>();

        foreach (var scenario in FailureScenarios())
        {
            var resolution = await ResolveAsync(scenario.ClientId, scenario.Fetcher);

            Assert.Equal(ClientResolutionError.MetadataUnusable, resolution.Error);
            Assert.Null(resolution.Client);
            Assert.False(string.IsNullOrWhiteSpace(resolution.Detail), $"'{scenario.Name}' produced no description.");

            observed.Add((scenario.Name, resolution.Detail!));
        }

        var collisions = observed
            .GroupBy(o => o.Detail, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => $"  \"{g.Key}\" <- {string.Join(", ", g.Select(x => x.Name))}")
            .ToList();

        Assert.True(
            collisions.Count == 0,
            "Two CIMD failure conditions are indistinguishable from the response body:" + Environment.NewLine
            + string.Join(Environment.NewLine, collisions));

        Assert.Equal(39, observed.Count);
    }

    /// <summary>
    /// Every description survives the filter the error page applies to it.
    /// </summary>
    /// <remarks>
    /// <c>ErrorText.Safe</c> drops characters outside OAuth 2.1 §4.1.2.1's set and truncates at 240.
    /// A description written past that limit reaches the reader with the sentence that explains the
    /// failure cut off — which is the failure mode A-12 exists to prevent, arriving through the
    /// mechanism meant to make the body safe.
    /// </remarks>
    [Fact]
    public async Task Every_description_survives_the_error_page_filter()
    {
        var overlong = new List<string>();

        foreach (var scenario in FailureScenarios())
        {
            var resolution = await ResolveAsync(scenario.ClientId, scenario.Fetcher);
            var rendered = new AuthorizeHtmlError(
                OAuth.Primitives.Diagnostics.Rejection.Of(
                    OAuth.Primitives.Diagnostics.ReasonCode.ClientMetadataUnusable,
                    OAuth.Primitives.Errors.OAuthErrorCode.InvalidClient,
                    resolution.Detail!),
                "test").Description;

            if (!string.Equals(rendered, resolution.Detail, StringComparison.Ordinal))
            {
                overlong.Add($"  {scenario.Name}: {resolution.Detail}");
            }
        }

        Assert.True(
            overlong.Count == 0,
            "A CIMD description is truncated or filtered before it reaches the response body:" + Environment.NewLine
            + string.Join(Environment.NewLine, overlong));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The live capture
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Every <c>cimd-live-*.json</c> capture that ships beside these tests.</summary>
    /// <remarks>
    /// Enumerated from disk rather than listed here, so a capture cannot be added and then read by
    /// nothing — which is what happened to <c>cimd-live-2026-08-17.json</c> for a release. The
    /// csproj globs them into the output directory; this finds whatever arrived.
    /// </remarks>
    public static TheoryData<string> Captures
    {
        get
        {
            var data = new TheoryData<string>();

            foreach (var name in CaptureNames())
            {
                data.Add(name);
            }

            return data;
        }
    }

    /// <summary>The capture files sitting beside the test assembly, by file name.</summary>
    private static List<string> CaptureNames() =>
        [.. Directory
            .GetFiles(AppContext.BaseDirectory, "cimd-live-*.json")
            .Select(path => Path.GetFileName(path) ?? path)];

    /// <summary>
    /// The glob found something, and something at least as new as the last capture taken.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The non-vacuity guard for every <c>[Theory]</c> below that is driven by
    /// <see cref="Captures"/>.</b> A theory over an empty set passes, loudly reporting nothing, and
    /// that is the exact failure this whole arrangement exists to prevent: a capture nobody reads.
    /// If the csproj glob breaks, this is what says so rather than four green tests that ran zero
    /// times.
    /// </para>
    /// <para>
    /// The named file is the newest capture at the time of writing. It is asserted by name on
    /// purpose: a glob that silently matched only the older one would satisfy a bare count.
    /// </para>
    /// </remarks>
    [Fact]
    public void Every_capture_in_spec_is_read()
    {
        var names = CaptureNames();

        Assert.Contains("cimd-live-2026-08-03.json", names, StringComparer.Ordinal);
        Assert.Contains("cimd-live-2026-08-17.json", names, StringComparer.Ordinal);
    }

    /// <summary>
    /// Every document captured from a live vendor resolves.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read from the <c>spec/cimd-live-*.json</c> captures rather than transcribed, so
    /// refreshing a capture re-tests this rather than leaving a copy behind. Each file is a
    /// <c>// url</c> comment line followed by the document body, repeated — a capture log, not one
    /// JSON document.
    /// </para>
    /// <para>
    /// This is the known-answer set. Documents whose answer is already established, re-run in full
    /// every time, because a rule tightened for one of them is exactly how the others regress.
    /// </para>
    /// </remarks>
    [Theory]
    [MemberData(nameof(Captures))]
    public async Task Every_live_vendor_document_resolves(string capture)
    {
        var captured = ReadCapture(capture);
        Assert.Equal(4, captured.Count);

        foreach (var (url, body) in captured)
        {
            var resolution = await ResolveAsync(url, new StubFetcher().Serve(url, body));

            Assert.True(
                resolution.Client is not null,
                $"{url} was refused: {resolution.Detail}");

            var client = resolution.Client!;

            // C-01: the identifier is a URL and carries the discriminator, not a GUID and not a
            // kind re-derived from the prefix.
            Assert.Equal(url, client.ClientId.Value);
            Assert.Equal(ClientIdKind.ClientIdMetadataDocument, client.ClientId.Kind);

            // Both vendors are public clients. C-04's default and the `none` preference are what
            // make that true for all four rather than for the two that spell the field correctly.
            Assert.Equal(ClientAuthMethod.None, client.TokenEndpointAuthMethod);
            Assert.Equal(ClientType.Public, client.ClientType);

            Assert.NotEmpty(client.RedirectUris);
            Assert.Contains("authorization_code", client.GrantTypes, StringComparer.Ordinal);
        }
    }

    /// <summary>Claude Code's loopback redirects survive, which is the U-17 exemption's whole reason.</summary>
    [Fact]
    public async Task The_live_claude_code_document_keeps_its_loopback_redirects()
    {
        var (url, body) = ReadCapture().Single(
            c => c.Url.Contains("claude-code", StringComparison.Ordinal));

        var resolution = await ResolveAsync(url, new StubFetcher().Serve(url, body));

        var client = Assert.IsType<ClientRecord>(resolution.Client);
        Assert.Equal(2, client.RedirectUris.Count);
        Assert.All(client.RedirectUris, r => Assert.Equal(RedirectKind.Loopback, r.Kind));
    }

    /// <summary>ChatGPT's misspelled auth-method field is read, and its jwks_uri is kept. C-04.</summary>
    /// <remarks>
    /// <b>Pinned to the 2026-08-03 capture, and it has to be.</b> The assertion below is that the
    /// singular member is <i>absent</i>, which is what made the plural the only thing to read. That
    /// stopped being true on 2026-08-17, so pointing this at the newest capture would assert the
    /// world had not moved when it had. The pair to this is
    /// <see cref="The_live_chatgpt_documents_carry_both_spellings_by_2026_08_17"/>.
    /// </remarks>
    [Fact]
    public async Task The_live_chatgpt_documents_are_read_through_the_plural_spelling()
    {
        var chatgpt = ReadCapture("cimd-live-2026-08-03.json")
            .Where(c => c.Url.Contains("chatgpt.com", StringComparison.Ordinal)).ToList();

        Assert.Equal(2, chatgpt.Count);

        foreach (var (url, body) in chatgpt)
        {
            // The document has no `token_endpoint_auth_method` at all, so this is the plural field
            // being read and not RFC 7591's default being applied.
            Assert.DoesNotContain("\"token_endpoint_auth_method\"", body, StringComparison.Ordinal);

            var resolution = await ResolveAsync(url, new StubFetcher().Serve(url, body));
            var client = Assert.IsType<ClientRecord>(resolution.Client);

            Assert.Equal(ClientAuthMethod.None, client.TokenEndpointAuthMethod);
            Assert.Equal("https://chatgpt.com/oauth/jwks.json", client.JwksUri);
            Assert.NotNull(client.LogoUri);
        }
    }

    /// <summary>
    /// By the 2026-08-17 capture both ChatGPT documents carry both spellings, and still resolve
    /// public.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>LESSONS #8, read from the capture rather than from a copy of it.</b> On 2026-08-03 every
    /// document carried exactly one spelling of the auth method, so the reader was written
    /// <c>if (singular) … else if (plural)</c>. On 2026-08-17 ChatGPT's carried both — the singular
    /// naming <c>private_key_jwt</c>, the plural offering <c>none</c> beside it — the
    /// <c>else</c> branch stopped being reached, and every ChatGPT connection resolved to a
    /// confidential client this server cannot authenticate.
    /// </para>
    /// <para>
    /// The document that broke it was already transcribed into this file, which is what the csproj's
    /// own comment says not to do: a copy stops tracking the capture the moment the capture is
    /// refreshed. This reads the bytes. <c>The_live_chatgpt_document_is_a_public_client</c> keeps its
    /// transcription because it varies the <i>client_id</i> across three URL shapes, one of which is
    /// a per-connector placeholder no capture can hold.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_live_chatgpt_documents_carry_both_spellings_by_2026_08_17()
    {
        var chatgpt = ReadCapture("cimd-live-2026-08-17.json")
            .Where(c => c.Url.Contains("chatgpt.com", StringComparison.Ordinal)).ToList();

        Assert.Equal(2, chatgpt.Count);

        foreach (var (url, body) in chatgpt)
        {
            // Both members, in the one document. This is the condition the reader was written as
            // though could not occur.
            Assert.Contains("\"token_endpoint_auth_method\"", body, StringComparison.Ordinal);
            Assert.Contains("\"token_endpoint_auth_methods_supported\"", body, StringComparison.Ordinal);

            var resolution = await ResolveAsync(url, new StubFetcher().Serve(url, body));
            var client = Assert.IsType<ClientRecord>(resolution.Client);

            // Public, because `none` is offered and this server prefers it. A confidential answer
            // here is the outage.
            Assert.Equal(ClientAuthMethod.None, client.TokenEndpointAuthMethod);
            Assert.Equal(ClientType.Public, client.ClientType);
        }
    }

    /// <summary>
    /// No captured vendor document asks for DPoP. The tripwire for D-02.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This test exists to fail.</b> <c>ProtectedResourceMetadata</c> records that setting
    /// <c>dpop_bound_access_tokens_required</c> breaks both Claude and ChatGPT "since neither sends
    /// DPoP" — a measurement, written as a standing fact, in a comment that cannot notice when it
    /// expires. That is LESSONS #8's shape exactly, and #8 says where a dated observation belongs:
    /// in a fixture that fails when the world moves.
    /// </para>
    /// <para>
    /// RFC 9449 §5.2 registers <c>dpop_bound_access_tokens</c> as client metadata, so a vendor that
    /// starts sender-constraining says so here first. When this goes red, DPoP has stopped being
    /// deferred and the comments that assert otherwise are the thing to fix — not this assertion.
    /// </para>
    /// <para>
    /// Substring rather than a parse, deliberately: any <c>dpop</c>-prefixed member is interesting,
    /// including ones neither this test nor the resolver knows the name of yet.
    /// </para>
    /// </remarks>
    [Theory]
    [MemberData(nameof(Captures))]
    public void No_captured_vendor_document_asks_for_dpop(string capture)
    {
        var captured = ReadCapture(capture);
        Assert.NotEmpty(captured);

        foreach (var (url, body) in captured)
        {
            Assert.False(
                body.Contains("dpop", StringComparison.OrdinalIgnoreCase),
                $"{url} in {capture} now mentions DPoP. D-02 defers it and "
                + "ProtectedResourceMetadata says neither vendor sends it — one of those is now "
                + "wrong. Re-read RFC 9449 §5.2 against this document before changing this line.");
        }
    }

    private static List<(string Url, string Body)> ReadCapture(string capture = "cimd-live-2026-08-03.json")
    {
        var path = Path.Combine(AppContext.BaseDirectory, capture);
        Assert.True(File.Exists(path), $"The capture is not beside the tests at {path}.");

        var captured = new List<(string, string)>();
        string? url = null;

        foreach (var line in File.ReadAllLines(path))
        {
            var trimmed = line.Trim();

            if (trimmed.Length == 0)
            {
                continue;
            }

            if (trimmed.StartsWith("//", StringComparison.Ordinal))
            {
                url = trimmed[2..].Trim();
                continue;
            }

            Assert.NotNull(url);
            captured.Add((url!, trimmed));
            url = null;
        }

        return captured;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A-03 / A-20, through the pipeline and through the endpoint
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A <c>client_id</c> never seen before validates, with no administrative step. A-03.
    /// </summary>
    /// <remarks>
    /// Through the real <see cref="AuthorizePipeline"/>, with the CIMD resolver as the only one
    /// registered and nothing seeded anywhere. The resolver has no store, so "never seen before" is
    /// not a fixture arrangement — there is nowhere it could have been seen.
    /// </remarks>
    [Fact]
    public async Task A_fresh_client_id_validates_with_zero_admin_steps()
    {
        const string Fresh = "https://never-seen.example/oauth/client.json";
        const string Callback = "https://never-seen.example/callback";

        var fetcher = new StubFetcher().Serve(
            Fresh,
            $$"""
              {"client_id":"{{Fresh}}","client_name":"Fresh","redirect_uris":["{{Callback}}"],
               "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
               "token_endpoint_auth_method":"none"}
              """);

        var pipeline = Build.Pipeline(resolver: Resolver(fetcher));

        var request = Build.ValidRequest(Fresh);
        request["redirect_uri"] = [Callback];

        var outcome = await pipeline.ValidateAsync(Build.Context(request), CancellationToken.None);

        var validated = Assert.IsType<AuthorizeOutcome.Validated>(outcome);
        Assert.Equal(Fresh, validated.Context.Client!.ClientId.Value);
        Assert.Equal(1, fetcher.Calls);
    }

    /// <summary>
    /// The same thing over HTTP: <c>/authorize</c> redirects rather than answering 400. A-03, A-20.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A-03's acceptance criterion is written as "⇒ <c>/authorize</c> returns 302". This server
    /// answers <b>303</b>, deliberately and everywhere: RFC 9700 §4.12 and OAuth 2.1 §7.5.3 require
    /// 303 so a browser rewrites the request as a GET, and an architecture test refuses 307 and 308
    /// outright. So the claim proved here is the one A-03 is about — a client nobody registered gets
    /// a redirect into the flow instead of <c>invalid_client</c> — and not the literal status digit.
    /// </para>
    /// <para>
    /// The host is built the way a customer's would be, so this also covers the wiring: that the
    /// CIMD profile registers a resolver at all, and that it is reached after the host's own.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_fresh_client_id_gets_a_redirect_from_the_authorize_endpoint()
    {
        const string Fresh = "https://never-seen.example/oauth/client.json";
        const string Callback = "https://never-seen.example/callback";

        var fetcher = new StubFetcher().Serve(
            Fresh,
            $$"""
              {"client_id":"{{Fresh}}","client_name":"Fresh","redirect_uris":["{{Callback}}"],
               "grant_types":["authorization_code"],"response_types":["code"],
               "token_endpoint_auth_method":"none"}
              """);

        await using var fixture = await FlowFixture.StartAsync(seed =>
        {
            // Nothing registered, by any route. The only way this request can succeed is by
            // dereferencing the client_id.
            seed.Clients.Clear();
            seed.Fetcher = fetcher;
        });

        var query = string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(Fresh),
            "redirect_uri=" + Uri.EscapeDataString(Callback),
            "scope=mcp:tools",
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque",
            "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method=S256");

        var response = await fixture.Client.GetAsync(new Uri("/authorize?" + query, UriKind.Relative));

        Assert.Equal(System.Net.HttpStatusCode.SeeOther, response.StatusCode);
        Assert.Equal(1, fetcher.Calls);
    }

    /// <summary>
    /// The control for the test above: without the fetched document, the same request is refused.
    /// </summary>
    /// <remarks>
    /// This is what the endpoint did before this resolver existed, for every client — a 400 whose
    /// body says <c>invalid_client</c> while the metadata document advertises
    /// <c>client_id_metadata_document_supported</c>. Without this row, the 303 above is not evidence
    /// that CIMD did anything: an over-permissive pipeline would produce it too.
    /// </remarks>
    [Fact]
    public async Task Without_a_resolvable_document_the_same_request_is_refused()
    {
        const string Fresh = "https://never-seen.example/oauth/client.json";

        await using var fixture = await FlowFixture.StartAsync(seed => seed.Clients.Clear());

        var query = string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString(Fresh),
            "redirect_uri=" + Uri.EscapeDataString("https://never-seen.example/callback"),
            "scope=mcp:tools",
            "state=opaque",
            "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method=S256");

        var response = await fixture.Client.GetAsync(new Uri("/authorize?" + query, UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);

        // A-12: the code and a description that names the failed check are both in the body, so
        // `curl -D-` is a sufficient debugging tool.
        Assert.Contains("invalid_client", body, StringComparison.Ordinal);
        Assert.Contains("did not resolve", body, StringComparison.Ordinal);
    }
}
