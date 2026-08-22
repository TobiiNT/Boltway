using Boltway.AuthorizationServer.Requests;
using Boltway.OAuth.Primitives.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// Reading a <c>application/x-www-form-urlencoded</c> body into <see cref="OAuthParameters"/>.
/// </summary>
/// <remarks>
/// <para>
/// One parser for every endpoint that takes a form body, which is <c>/token</c> and
/// <c>/introspect</c>. It lived inside <see cref="TokenEndpoint"/> while there was one such
/// endpoint; a second copy is how two OAuth surfaces on the same server come to disagree about
/// whether a repeated parameter is a violation, or about whether an unparseable body is a 400 or a
/// 500.
/// </para>
/// <para>
/// <b>Never <c>415</c>.</b> A <c>[FromBody]</c>-bound record answers <c>415 Unsupported Media
/// Type</c> to a JSON request, which is defensible HTTP and fatal in practice: it carries no
/// <c>error</c> member, so neither vendor's client parses it and the flow dies with nothing to
/// debug. Every rejection from here is an OAuth JSON body.
/// </para>
/// </remarks>
internal static class FormBody
{
    /// <summary>Read the body, or say why it could not be read.</summary>
    /// <param name="http">The request.</param>
    /// <param name="endpoint">
    /// What to call this endpoint in the media-type message, e.g. <c>"token"</c>. It reaches the
    /// client, so it is the word somebody debugging a client integration reads.
    /// </param>
    /// <param name="parameters">The parsed parameters, when this returns true.</param>
    /// <param name="rejection">Why not, when it returns false.</param>
    /// <remarks>
    /// <para>
    /// <b>An empty value is dropped rather than kept.</b> RFC 6749 §3.1 says parameters "sent
    /// without a value MUST be treated as if they were omitted", and it is why every caller tests
    /// for <c>string.IsNullOrEmpty</c> rather than for null. Note that <c>/authorize</c> treats an
    /// empty <c>redirect_uri</c> as malformed while this treats an empty parameter as absent — the
    /// asymmetry is the specification's, not an inconsistency here.
    /// </para>
    /// </remarks>
    internal static bool TryRead(
        HttpContext http, string endpoint, out OAuthParameters? parameters, out Rejection? rejection)
    {
        ArgumentNullException.ThrowIfNull(http);

        parameters = null;
        rejection = null;

        var contentType = http.Request.Headers[HeaderNames.ContentType].ToString();

        if (!MediaType.TryParse(contentType, out var parsed)
            || !string.Equals(parsed.Type, "application", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(parsed.SubType, "x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            rejection = Rejection.Of(
                ReasonCode.MediaTypeUnsupported,
                OAuthErrorCode.InvalidRequest,
                $"The {endpoint} endpoint accepts 'application/x-www-form-urlencoded' only. "
                + $"This request declared '{(string.IsNullOrEmpty(contentType) ? "nothing" : contentType)}'.",
                $"content_type={contentType}");
            return false;
        }

        IFormCollection form;

        try
        {
            form = http.Request.Form;
        }
        catch (InvalidOperationException ex)
        {
            // Request.Form throws rather than returning empty on a body it cannot parse. Caught so
            // a malformed body is an OAuth error rather than a 500 — which the client would read as
            // "the server is broken" rather than "my request was".
            //
            // The exception's own message goes to the log and not to the client. It names the
            // framework's parse failure, which is the difference between "their client is sending
            // JSON" and "a proxy is truncating the body"; the client is told only that the body did
            // not parse, because the body may well have carried a secret and the message quotes it.
            rejection = Rejection.Of(
                ReasonCode.RequestBodyUnreadable,
                OAuthErrorCode.InvalidRequest,
                "The request body could not be parsed as 'application/x-www-form-urlencoded'.",
                $"content_type={contentType}; parse_error={ex.Message}");
            return false;
        }

        var values = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);

        foreach (var (key, value) in form)
        {
            var present = value.Where(v => !string.IsNullOrEmpty(v)).Select(v => v!).ToList();

            if (present.Count > 0)
            {
                values[key] = present;
            }
        }

        parameters = new OAuthParameters(values);
        return true;
    }
}
