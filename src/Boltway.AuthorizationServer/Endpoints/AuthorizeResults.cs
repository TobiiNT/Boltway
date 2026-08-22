using Boltway.AuthorizationServer.Authorize;
using Boltway.AuthorizationServer.Diagnostics;
using Boltway.OAuth.Primitives.Errors;
using Boltway.OAuth.Primitives.Ids;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// A successful authorization response. RFC 6749 §4.1.2.
/// </summary>
/// <remarks>
/// Built the same way <see cref="AuthorizeRedirectError"/> is, and for the same reason: the target,
/// the state and the issuer are constructor parameters rather than settable properties, so "we
/// forgot to echo state" and "we forgot the RFC 9207 iss" have no code path. The success response
/// needs that at least as much as the error one — it is the response that carries the credential.
/// </remarks>
public sealed record AuthorizeSuccess
{
    private AuthorizeSuccess(ValidatedRedirect target, string code, string? state, IssuerString issuer)
    {
        Target = target;
        Code = code;
        State = state;
        Issuer = issuer;
    }

    /// <summary>Where it goes.</summary>
    public ValidatedRedirect Target { get; }

    /// <summary>The authorization code, in plaintext, for the only time it exists outside the redirect.</summary>
    public string Code { get; }

    /// <summary>The client's <c>state</c>, echoed verbatim, or absent when none was sent.</summary>
    public string? State { get; }

    /// <summary>The issuer, for RFC 9207's <c>iss</c>.</summary>
    public IssuerString Issuer { get; }

    /// <summary>The only factory.</summary>
    public static AuthorizeSuccess Create(ValidatedRedirect target, string code, string? state, IssuerString issuer)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentException.ThrowIfNullOrEmpty(code);

        return new AuthorizeSuccess(target, code, state, issuer);
    }
}

/// <summary>The three shapes an authorization response can take.</summary>
public static class AuthorizeResults
{
    /// <summary>A successful authorization response, delivered by redirect.</summary>
    public static IResult Redirect(AuthorizeSuccess success)
    {
        ArgumentNullException.ThrowIfNull(success);

        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["code"] = success.Code,
            ["iss"] = success.Issuer.Value,
        };

        // Omitted entirely when the client sent none. `state=` is not the same as no state, and a
        // client that stored nothing will compare against nothing.
        if (success.State is not null)
        {
            parameters["state"] = success.State;
        }

        return new SeeOtherResult(Build(success.Target.Value, parameters));
    }

    /// <summary>
    /// An error, delivered by redirect to the validated URI.
    /// </summary>
    /// <remarks>
    /// The response parameters are assembled inside <see cref="RejectionRedirectResult"/> rather
    /// than here, because the <c>error</c> value has to come from <c>OAuthErrors.Resolve</c> and an
    /// architecture rule asserts the rejection writer is that method's only caller in this assembly.
    /// A copy of the lookup here would be a second place an error response can be produced, which is
    /// exactly the shape A-09 was found in.
    /// </remarks>
    public static IResult Redirect(AuthorizeRedirectError error)
    {
        ArgumentNullException.ThrowIfNull(error);

        return new RejectionRedirectResult(error);
    }

    /// <summary>A redirect to one of this server's own pages.</summary>
    public static IResult SeeOther(string localUrl) => new SeeOtherResult(localUrl);

    /// <summary>An error rendered on our own origin, because no redirect is safe.</summary>
    /// <param name="error">The failure, carrying the rejection the writer logs.</param>
    /// <param name="surface">
    /// Which half of <c>/authorize</c> is answering. The pre-redirect surface renders 400; the
    /// exception boundary passes it explicitly so a crash before the redirect line renders 500.
    /// </param>
    /// <remarks>
    /// An error built by <see cref="AuthorizeHtmlError.Throttled"/> is answered 429 with a
    /// <c>Retry-After</c> and no <c>error</c> code, and is not looked up in <c>OAuthErrors</c>.
    /// That is following the table rather than working around it: X-31 is the one row whose
    /// <c>error</c> is <i>(none)</i>, and the table is keyed on an <see cref="OAuthErrorCode"/>.
    /// The branch lives in <c>RejectionResult</c> rather than here, so a throttled response is
    /// logged and stamped by the same code as every other refusal.
    /// </remarks>
    public static IResult Html(AuthorizeHtmlError error, OAuthSurface surface = OAuthSurface.AuthorizePreRedirect)
    {
        ArgumentNullException.ThrowIfNull(error);

        return new RejectionHtmlResult(error, surface);
    }

    /// <summary>
    /// Add the response parameters to the redirect URI's <b>query</b> component.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="QueryHelpers.AddQueryString(string, IEnumerable{KeyValuePair{string, string?}})"/>
    /// rather than concatenation, and three separate things break without it.
    /// </para>
    /// <para>
    /// OAuth 2.1 §2.3: a redirect URI "MAY include a query string component, which MUST be retained
    /// when adding additional query parameters". Concatenating <c>"?code=…"</c> onto
    /// <c>https://client.example/cb?tenant=42</c> produces a second <c>?</c>, which is a legal
    /// character inside a query string — so nothing errors, and the client parses one parameter
    /// named <c>tenant</c> whose value is <c>42?code=…</c>.
    /// </para>
    /// <para>
    /// Concatenation also skips percent-encoding, and one of these values is chosen by the caller.
    /// A <c>state</c> containing <c>&amp;code=</c> injects a second code; one containing <c>#</c>
    /// truncates the response at the fragment boundary so <c>iss</c> silently disappears — and a
    /// client that must reject a response without <c>iss</c> has just been handed a remote off
    /// switch for the flow.
    /// </para>
    /// <para>
    /// Query, never fragment. §4.1.2 says "the query component", and this server advertises
    /// <c>response_modes_supported: ["query"]</c>.
    /// </para>
    /// </remarks>
    internal static string Build(string target, Dictionary<string, string?> parameters) =>
        QueryHelpers.AddQueryString(target, parameters);
}

/// <summary>
/// A 303 See Other.
/// </summary>
/// <remarks>
/// <para>
/// Hand-written because ASP.NET Core has no 303 helper: <c>Results.Redirect</c> emits 302, and its
/// <c>preserveMethod</c> overload emits 307 or 308 — which is the status OAuth 2.1 §7.5.3 forbids
/// outright.
/// </para>
/// <para>
/// The reason is specific, not stylistic. The user reaches this redirect by POSTing credentials to
/// a login or consent form. "In HTTP, only the status code 303 unambiguously enforces rewriting the
/// HTTP POST request to an HTTP GET request. For all other status codes, including the popular 302,
/// user agents can opt not to rewrite POST to GET requests and therefore reveal the user
/// credentials to the client." Under 307 the browser replays the POST body — the user's password —
/// to the client's redirect URI. If the client is malicious it can then impersonate the user.
/// </para>
/// </remarks>
internal sealed class SeeOtherResult(string location) : IResult
{
    public Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        httpContext.Response.StatusCode = StatusCodes.Status303SeeOther;
        httpContext.Response.Headers[HeaderNames.Location] = location;

        return Task.CompletedTask;
    }
}

// The error page that used to live here is now RejectionHtmlResult, in Diagnostics, beside the
// other two deliveries. Moving it was the point rather than a tidy-up: while each delivery owned
// its own IResult, "every rejection is logged" was a claim about three files, and it was false in
// all three. They now share one ExecuteAsync that logs before it writes.
