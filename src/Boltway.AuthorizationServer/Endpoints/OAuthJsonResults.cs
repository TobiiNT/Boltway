using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>A successful token response. RFC 6749 §5.1.</summary>
/// <remarks>
/// Property order is the wire order, and <c>access_token</c> is first because that is the field a
/// human reads when they <c>curl</c> the endpoint.
/// </remarks>
public sealed record TokenResponseBody
{
    /// <summary>REQUIRED.</summary>
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    /// <summary>REQUIRED. Always <c>Bearer</c> here.</summary>
    /// <remarks>
    /// RFC 6750 §2.1 makes the scheme case-insensitive, but clients compare it literally often
    /// enough that the capitalisation is worth pinning: <c>Bearer</c>, as spelled in the RFC.
    /// </remarks>
    [JsonPropertyName("token_type")]
    public required string TokenType { get; init; }

    /// <summary>RECOMMENDED, and always sent.</summary>
    /// <remarks>
    /// Omitting it means the client must decode the access token to learn when to refresh — which
    /// works only because our access tokens happen to be JWTs, and would break the moment they were
    /// not. Claude refreshes proactively against this value.
    /// </remarks>
    [JsonPropertyName("expires_in")]
    public required int ExpiresIn { get; init; }

    /// <summary>Present when <c>offline_access</c> was granted.</summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    /// <summary>Present when <c>openid</c> was granted.</summary>
    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }

    /// <summary>
    /// The scopes actually granted.
    /// </summary>
    /// <remarks>
    /// RFC 6749 §5.1 makes this REQUIRED when it differs from what was requested and OPTIONAL
    /// otherwise. Always sent, because "optional when identical" asks the client to compare, and a
    /// client that assumes it got what it asked for discovers otherwise as a 403 from the resource
    /// server much later.
    /// </remarks>
    [JsonPropertyName("scope")]
    public required string Scope { get; init; }
}

/// <summary>An OAuth error body. RFC 6749 §5.2.</summary>
public sealed record OAuthErrorBody
{
    /// <summary>REQUIRED. One of the registered codes, never an invention.</summary>
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    /// <summary>OPTIONAL, and always sent. Filtered to the permitted character set.</summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }
}

/// <summary>Serializers for the OAuth JSON bodies.</summary>
/// <remarks>
/// <c>GenerationMode</c> is left at its default — both metadata and the fast path — rather than
/// <c>Serialization</c>. Serialization-only emits the synchronous fast path and no property
/// metadata, and <c>JsonSerializer.SerializeAsync</c> needs the metadata: it throws
/// "did not provide property metadata for type" at runtime, on every response this endpoint writes.
/// The metadata document's context can use Serialization-only because it serializes to a byte array
/// synchronously; these are written straight to the response stream.
/// </remarks>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(TokenResponseBody))]
[JsonSerializable(typeof(OAuthErrorBody))]
[JsonSerializable(typeof(IntrospectionResponseBody))]
internal sealed partial class OAuthJsonContext : JsonSerializerContext;

/// <summary>
/// Writes the OAuth JSON responses, with the headers the RFC makes mandatory.
/// </summary>
/// <remarks>
/// A single writer rather than <c>Results.Json(...)</c> at each call site, because two of the
/// requirements here are easy to satisfy at four call sites out of five.
/// <c>Cache-Control: no-store</c> is one — RFC 6749 §5.1 makes it a MUST on every token response
/// including the errors, and a cached token response on a shared proxy is a credential handed to
/// the next caller. <c>WWW-Authenticate</c> on a 401 is the other: §5.2 makes it mandatory, and it
/// is invisible when missing.
/// </remarks>
public static class OAuthJsonResults
{
    /// <summary>A successful token response.</summary>
    public static IResult Token(TokenResponseBody body) => new JsonBodyResult<TokenResponseBody>(
        body, StatusCodes.Status200OK, OAuthJsonContext.Default.TokenResponseBody);

    /// <summary>
    /// An introspection response. Always 200, including for a token that is not active.
    /// </summary>
    /// <param name="body">What the server can say about the token, which may be only that it is not active.</param>
    /// <remarks>
    /// Written through the same result as a token response so it carries <c>no-store</c> without
    /// anybody having to remember. RFC 6749 §5.1 phrases that requirement about token responses,
    /// and the reason reaches further than the letter does: this body describes a live credential —
    /// its scope, its subject, when it expires — and a shared proxy caching it hands the next
    /// caller an answer about somebody else's token.
    /// </remarks>
    public static IResult Introspection(IntrospectionResponseBody body) =>
        new JsonBodyResult<IntrospectionResponseBody>(
            body, StatusCodes.Status200OK, OAuthJsonContext.Default.IntrospectionResponseBody);

    /// <summary>
    /// The revocation answer: 200, no body, <c>no-store</c>. E-16, X-39.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No body at all rather than <c>{}</c>. RFC 7009 §2.2 describes the response as an HTTP 200
    /// with no content, and an empty JSON object is a body a client may try to read a field out of.
    /// </para>
    /// <para>
    /// <c>no-store</c> for the same reason every other response here carries it, and it is not
    /// ceremonial on an empty body: a cached 200 on a shared proxy answers the <i>next</i>
    /// revocation request without it reaching this server, so a real revocation silently does
    /// nothing.
    /// </para>
    /// </remarks>
    public static IResult RevocationDone() => EmptyBodyResult.Ok;

    /// <summary>
    /// An error, with the status and delivery the table dictates for this surface.
    /// </summary>
    /// <param name="surface">Which endpoint is answering.</param>
    /// <param name="rejection">
    /// Why the request was refused. Required, and that is the compile-time half of A-09: there is
    /// no overload taking a bare code and description, so a JSON error cannot be produced without
    /// the payload the writer logs.
    /// </param>
    /// <param name="correlationId">The id echoed in <c>X-Request-Id</c> and carried in the log.</param>
    /// <param name="usedAuthorizationHeader">
    /// Whether the client presented credentials in an <c>Authorization</c> header. Decides 401 vs
    /// 400 for <c>invalid_client</c>: RFC 6749 §5.2 says a 401 is correct only when the client
    /// authenticated by a method the server can challenge, and a blanket 401 tells a client with no
    /// credentials at all to go and find some.
    /// </param>
    /// <param name="challengeScheme">
    /// The scheme to echo in <c>WWW-Authenticate</c> on a 401, which RFC 6749 §5.2 requires to match
    /// the one the client used. Chosen by the caller from a closed set, never read from the request.
    /// </param>
    public static IResult Error(
        OAuthSurface surface,
        Rejection rejection,
        string correlationId,
        bool usedAuthorizationHeader = false,
        string challengeScheme = "Basic") =>
        new RejectionJsonResult(
            surface,
            rejection,
            correlationId,
            OAuthJsonContext.Default.OAuthErrorBody,
            usedAuthorizationHeader,
            challengeScheme);
}

/// <summary>
/// Writes one <b>successful</b> JSON body with the OAuth response headers.
/// </summary>
/// <remarks>
/// The error path used to share this type, with the status as a constructor parameter. It does not
/// any more, and the split is what makes the architecture rule checkable: this type never writes a
/// 4xx, so "a 4xx from this assembly came from the rejection writer" is a property of the type graph
/// rather than of which integer a caller happened to pass.
/// </remarks>
/// <summary>
/// Writes a bodiless <b>successful</b> response with the OAuth response headers.
/// </summary>
/// <remarks>
/// A sibling of <see cref="JsonBodyResult{T}"/> rather than a nullable body on it, and for the rule
/// that type's own remark states: neither writes a 4xx, so "a 4xx from this assembly came from the
/// rejection writer" stays a property of the type graph. One instance, because it holds nothing.
/// </remarks>
internal sealed class EmptyBodyResult : IResult
{
    /// <summary>The 200.</summary>
    internal static readonly EmptyBodyResult Ok = new();

    private EmptyBodyResult()
    {
    }

    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var response = httpContext.Response;

        response.StatusCode = StatusCodes.Status200OK;

        // No ContentType: setting one announces a body that is not coming, and a client that reads
        // `application/json` and then parses zero bytes gets a JSON error rather than a success.
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";

        return Task.CompletedTask;
    }
}

internal sealed class JsonBodyResult<T>(T body, int status, JsonTypeInfo<T> typeInfo) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var response = httpContext.Response;

        response.StatusCode = status;
        response.ContentType = "application/json";

        // RFC 6749 §5.1, on every token response and every error: "The authorization server MUST
        // include the HTTP 'Cache-Control' response header field with a value of 'no-store'".
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";

        await JsonSerializer.SerializeAsync(response.Body, body, typeInfo, httpContext.RequestAborted);
    }
}
