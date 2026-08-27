using System.Net;
using System.Text.Json;

namespace Boltway.ResourceServer.Testing;

/// <summary>
/// What a client meets when it reaches a protected resource, run against a wired pipeline.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every assertion here failed on a real deployment that had a green unit-test suite.</b> The
/// three defects this was written from were found by hand against a running process on 2026-08-26,
/// after 402 tests passed: the RFC 9728 document answered <c>401</c> at the URL the server's own
/// challenges pointed at, the process started with no signing keys, and the liveness probe answered
/// <c>401</c> too. None is reachable from a unit test, because none of them is about a unit. They
/// are about what a pipeline answers once the middleware is in some particular order, and they
/// present to a client as "OAuth is broken".
/// </para>
/// <para>
/// <b>Two markers, and this is the one that costs a day.</b> A host that runs its own
/// authentication middleware alongside this library's has two vocabularies for "this endpoint needs
/// no credential" - the framework's <c>AllowAnonymous</c>, which is what the library marks the
/// metadata endpoints with, and whatever the host's own middleware reads. Neither knows about the
/// other, so the document that must answer without a credential answers <c>401</c>, and the symptom
/// is a client that cannot discover where to authenticate.
/// <see cref="Both_well_known_forms_answer_without_a_credential" /> is that defect, as a test.
/// </para>
/// <para>
/// <b>Derive it, do not copy it.</b> Supply <see cref="Client" />, <see cref="Resource" /> and
/// <see cref="ProtectedPath" />, and the suite runs in your own test runner with your own wiring.
/// The names are underscored because a failing name is the finding a consumer reads.
/// </para>
/// </remarks>
public abstract class ProtectedResourceContract
{
    /// <summary>
    /// RFC 9728 §8.3's registered suffix, spelled here rather than imported.
    /// </summary>
    /// <remarks>
    /// A conformance check that shares a constant with the code under test agrees with that
    /// constant's bugs. A client builds this URL from the RFC, and so does this file.
    /// </remarks>
    protected const string WellKnownSuffix = "/.well-known/oauth-protected-resource";

    /// <summary>
    /// A client bound to the running application, with its base address set to the resource's own
    /// origin.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Yours, and never disposed here.</b> An in-memory test server hands out a client the host
    /// owns, so a contract that wrapped this in a <c>using</c> would dispose the consumer's client
    /// and every assertion after the first would fail with <c>ObjectDisposedException</c> - which is
    /// what the first draft of this file did, caught by deriving it inside this repository before it
    /// ever shipped. Create one per contract instance or hand over a shared one; either works.
    /// </para>
    /// <para>
    /// Nothing here sets a default header, so a client reused across the suite carries no credential
    /// from one assertion into the next. The one test that sends an <c>Authorization</c> header puts
    /// it on a single request message.
    /// </para>
    /// </remarks>
    protected abstract HttpClient Client { get; }

    /// <summary>
    /// The resource identifier this deployment is configured with, exactly as configured.
    /// </summary>
    /// <remarks>
    /// Byte for byte. RFC 9728 §3.3 has the client compare the document's <c>resource</c> against
    /// the identifier it inserted the suffix into, and §6 forbids Unicode normalization anywhere in
    /// between - so a value that has been through a URL type on either side is a different string
    /// and the client is required to discard the document.
    /// </remarks>
    protected abstract string Resource { get; }

    /// <summary>A path on this server that requires a credential.</summary>
    /// <remarks>
    /// The path a client would call, not a health probe: what is being checked is that refusing it
    /// produces a challenge a client can act on.
    /// </remarks>
    protected abstract string ProtectedPath { get; }

    /// <summary>
    /// Both the root form and the path-inserted form answer, and neither asks for a credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The document exists to tell a client where to authenticate, so a credential requirement on
    /// it is a loop no client can break out of. RFC 9728 §3.1 puts the suffix <em>between</em> the
    /// host and the path, and a conformant client constructs that form first - which is why a
    /// deployment that serves only the root form still fails against real clients.
    /// </para>
    /// <para>
    /// This is the assertion that catches a host whose own authentication middleware does not read
    /// the framework's anonymous marker. It went red on a real deployment on 2026-08-26, at both
    /// URLs, with everything else working.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Both_well_known_forms_answer_without_a_credential()
    {
        foreach (var url in MetadataUrls())
        {
            using var response = await Client.GetAsync(new Uri(url, UriKind.RelativeOrAbsolute));

            Assert.True(
                response.StatusCode == HttpStatusCode.OK,
                $"{url} answered {(int)response.StatusCode}. RFC 9728 metadata has to answer "
                    + "without a credential - it is what a client reads to find out how to get one.");
        }
    }

    /// <summary>The document is JSON, and says so.</summary>
    [Fact]
    public async Task The_metadata_document_is_json()
    {
        using var response = await Client.GetAsync(PathInsertedUrl());

        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>
    /// The document's <c>resource</c> is the configured identifier, byte for byte.
    /// </summary>
    /// <remarks>
    /// The client compares these two strings and discards the document when they differ (§3.3), and
    /// the usual cause is a server that rebuilt the value out of a URL type somewhere - which
    /// lowercases a host, elides a default port or percent-decodes a path. The failure surfaces on
    /// the client as a generic connection problem while this server's log shows a clean 200.
    /// </remarks>
    [Fact]
    public async Task The_documents_resource_is_the_configured_identifier_byte_for_byte()
    {
        var document = await Document();

        Assert.Equal(Resource, document.GetProperty("resource").GetString(), StringComparer.Ordinal);
    }

    /// <summary>At least one authorization server is named, or the document answers nothing.</summary>
    [Fact]
    public async Task The_document_names_an_authorization_server()
    {
        var document = await Document();

        Assert.True(
            document.TryGetProperty("authorization_servers", out var servers)
                && servers.ValueKind == JsonValueKind.Array
                && servers.GetArrayLength() > 0,
            "The document names no authorization server, so a client that reads it still does not "
                + "know where to authenticate.");
    }

    /// <summary>Both forms serve the same document.</summary>
    /// <remarks>
    /// Two routes to one document is two chances to build it differently. A client that probes the
    /// root form and gets a different answer from the one the challenge points at has no way to
    /// tell which is the resource it is talking to.
    /// </remarks>
    [Fact]
    public async Task The_two_forms_serve_the_same_document()
    {
        var insertedUrl = PathInsertedUrl();

        // A resource identifier with no path makes the two forms one URL, and there is nothing here
        // to compare. Skipped by returning rather than by asserting something vacuously true, so a
        // reader of the suite is not told this was checked when it was not.
        if (string.Equals(insertedUrl.OriginalString, WellKnownSuffix, StringComparison.Ordinal))
        {
            return;
        }

        var inserted = await Client.GetStringAsync(insertedUrl);
        var root = await Client.GetStringAsync(new Uri(WellKnownSuffix, UriKind.Relative));

        Assert.Equal(inserted, root, StringComparer.Ordinal);
    }

    /// <summary>
    /// A protected path with no credential answers <c>401</c> and a <c>Bearer</c> challenge.
    /// </summary>
    /// <remarks>
    /// <c>401</c> and not <c>403</c>: a bare <c>403</c> is terminal for at least one widely-used
    /// client, which produces no re-authentication prompt at all - so a resource that answers it
    /// leaves the person looking at a connector that simply does not work.
    /// </remarks>
    [Fact]
    public async Task A_protected_path_with_no_credential_challenges()
    {
        using var response = await Client.GetAsync(new Uri(ProtectedPath, UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, header =>
            string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The challenge names a metadata URL, and that URL is really there.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The one assertion that ties the other two together, and the one that would have saved the
    /// day this file came from. A challenge carrying <c>resource_metadata</c> is an instruction: the
    /// client goes there next. If that URL answers anything but the document, discovery stops - and
    /// the server's own logs show a 401 that looks like the caller's fault.
    /// </para>
    /// <para>
    /// The URL is followed as the client would follow it, on its own origin rather than reassembled
    /// from parts here.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_metadata_url_named_in_the_challenge_is_reachable()
    {
        using var refused = await Client.GetAsync(new Uri(ProtectedPath, UriKind.Relative));

        var named = refused.Headers.WwwAuthenticate
            .Select(header => header.Parameter)
            .Where(parameter => parameter is not null)
            .Select(parameter => Parameter(parameter!, "resource_metadata"))
            .FirstOrDefault(value => value is not null);

        Assert.True(
            named is not null,
            "The challenge carries no resource_metadata parameter, so a client meeting this server "
                + "for the first time has nothing to follow.");

        // Relative, so the client's own base address decides the origin - the same journey a real
        // client makes, and one that does not silently pass by reaching a different host.
        var path = named!.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? new Uri(named).PathAndQuery
            : named;

        using var followed = await Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.True(
            followed.StatusCode == HttpStatusCode.OK,
            $"The challenge points at {named}, which answered {(int)followed.StatusCode}. That is "
                + "the URL a client is told to read to find out how to authenticate.");
    }

    /// <summary>
    /// A credential that is not a usable token answers <c>401</c>, not <c>403</c> and not <c>500</c>.
    /// </summary>
    /// <remarks>
    /// Garbage rather than an expired token, because what is being checked is the shape of the
    /// refusal rather than the validation: a parse failure that escapes as a <c>500</c> tells a
    /// client to retry the same broken credential forever, and a <c>403</c> tells it not to retry
    /// at all.
    /// </remarks>
    [Fact]
    public async Task A_credential_that_is_not_a_token_is_refused_as_unauthorized()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(ProtectedPath, UriKind.Relative));
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer not-a-token");

        using var response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Both URLs a client may use, deduplicated.
    /// </summary>
    /// <remarks>
    /// A resource identifier that is a bare host makes the two forms the same string. Yielding it
    /// twice would turn a loop that looks like it covers both into one that covers one.
    /// </remarks>
    private IEnumerable<string> MetadataUrls()
    {
        var inserted = PathInsertedUrl().OriginalString;

        yield return WellKnownSuffix;

        if (!string.Equals(inserted, WellKnownSuffix, StringComparison.Ordinal))
        {
            yield return inserted;
        }
    }

    /// <summary>
    /// Where RFC 9728 §3.1 says this resource's document lives, built the way a client builds it.
    /// </summary>
    /// <remarks>
    /// The suffix is inserted after the authority and the resource's own path follows it. Built by
    /// string surgery on the configured value rather than through a URL type, because a URL type
    /// normalizes and §6 forbids that - the same rule this contract checks the server for.
    /// </remarks>
    private Uri PathInsertedUrl()
    {
        var identifier = Resource;
        var afterScheme = identifier.IndexOf("://", StringComparison.Ordinal);

        Assert.True(afterScheme > 0, $"'{identifier}' is not an absolute identifier.");

        var authorityStart = afterScheme + 3;
        var pathStart = identifier.IndexOf('/', authorityStart);

        var path = pathStart < 0 ? string.Empty : identifier[pathStart..];

        // A resource identifier that is bare host plus a single slash loses that slash: §3.1 says
        // the suffix takes the place of the one that follows the authority.
        if (path == "/")
        {
            path = string.Empty;
        }

        return new Uri(WellKnownSuffix + path, UriKind.Relative);
    }

    /// <summary>The document, read from the form a conformant client reads first.</summary>
    private async Task<JsonElement> Document()
    {
        var body = await Client.GetStringAsync(PathInsertedUrl());

        using var parsed = JsonDocument.Parse(body);
        return parsed.RootElement.Clone();
    }

    /// <summary>Read one parameter out of a challenge's parameter list.</summary>
    /// <remarks>
    /// By hand rather than with a parser, because the contract must not depend on this product's
    /// own parsing of a header this product wrote - that would be one implementation checking
    /// itself. RFC 6750 §3 quotes every value, so the shape is <c>name="value"</c>.
    /// </remarks>
    private static string? Parameter(string parameters, string name)
    {
        var marker = name + "=\"";
        var start = parameters.IndexOf(marker, StringComparison.Ordinal);

        if (start < 0)
        {
            return null;
        }

        start += marker.Length;
        var end = parameters.IndexOf('"', start);

        return end < 0 ? null : parameters[start..end];
    }
}
