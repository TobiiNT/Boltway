using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using Boltway.AuthorizationServer.Configuration;
using Boltway.OAuth.Primitives.Encoding;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Endpoints;

/// <summary>
/// The headers every browser-facing authorization page carries. N-15.
/// </summary>
/// <remarks>
/// <para>
/// These apply to <c>/authorize</c>, <c>/consent</c>, <c>/login</c> and <c>/error</c> - every page
/// where a user makes a decision that grants access. They do not apply to the JSON endpoints, which
/// no browser renders.
/// </para>
/// <para>
/// Written from <see cref="HttpResponse.OnStarting(Func{Task})"/> rather than set before calling
/// the next middleware, and the difference is not stylistic. A header set on the way in survives
/// only until something calls <c>Response.Clear()</c> - which is exactly what an exception boundary
/// does when it discards a half-written response to render an error page. That is the response most
/// in need of these headers and the one that would lose them. <c>OnStarting</c> runs at the moment
/// the response is committed, after every other component has had its say.
/// </para>
/// </remarks>
public static class SecurityHeaders
{
    /// <summary>
    /// The Content-Security-Policy for an authorization page.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><description>
    /// <c>frame-ancestors 'none'</c> - the consent page must never render inside someone else's
    /// frame. Framed, it is a clickjacking target: an attacker overlays their own UI and the user's
    /// click lands on "Allow" for a client they never saw.
    /// </description></item>
    /// <item><description>
    /// <c>default-src 'self'</c> - a client's <c>logo_uri</c> is a URL the client chose, and
    /// ChatGPT's live metadata points at a third-party CDN. Hotlinking it would tell that host
    /// about every consent-page view; this directive means the browser refuses even if the
    /// rendering code forgets to proxy it.
    /// </description></item>
    /// <item><description>
    /// <c>form-action 'self'</c> - the consent form must post back to us. Without it, an injected
    /// form action sends the user's decision, and the antiforgery token with it, elsewhere.
    /// </description></item>
    /// <item><description>
    /// <c>base-uri 'none'</c> - an injected <c>&lt;base&gt;</c> tag re-targets every relative URL on
    /// the page, which is enough to redirect the form post without touching the form.
    /// </description></item>
    /// </list>
    /// </remarks>
    public const string ContentSecurityPolicy =
        "default-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";

    /// <summary>
    /// Where <see cref="AllowFormActionTo"/> parks its source until the response is committed.
    /// </summary>
    /// <remarks>
    /// On the context rather than in a closure because <see cref="Apply"/> has to run <b>before</b>
    /// the redirect URI is known - it is called first in every handler precisely so an exception
    /// thrown during validation still gets these headers. The source is read at commit time, so
    /// whatever the pipeline learned in between is in the policy.
    /// </remarks>
    private const string FormActionItemKey = "Boltway.SecurityHeaders.FormAction";

    /// <summary>Where this response's nonce lives, when the deployment asked for one.</summary>
    /// <remarks>
    /// Same mechanism as <see cref="FormActionItemKey"/> and for the same reason: the header is
    /// written at commit time, the page is rendered before that, and both have to read one value.
    /// Parking it on the context is what makes "the nonce in the header is the nonce on the page" a
    /// property of there being one nonce rather than of two call sites agreeing.
    /// </remarks>
    private const string NonceItemKey = "Boltway.SecurityHeaders.Nonce";

    /// <summary>How many bytes of nonce. CSP Level 3 §1.4 asks for at least 128 bits.</summary>
    private const int NonceBytes = 16;

    /// <summary>What must never reach a header value: a separator, a quote, or whitespace.</summary>
    private static readonly SearchValues<char> UnsafeInSource = SearchValues.Create(" ;,\r\n\t\"'");

    /// <summary>Attach the headers to this response, whatever ends up producing it.</summary>
    public static void Apply(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Minted here rather than at commit time, because the page is rendered in between and needs
        // the same value. GetService rather than GetRequiredService: these headers must go on every
        // response including ones produced before or outside the server's own registrations, and a
        // missing options object means no deployment asked for a nonce rather than a failure.
        if (context.RequestServices?.GetService<AuthorizationServerOptions>()
            is { Interaction.UseContentSecurityPolicyNonce: true })
        {
            context.Items[NonceItemKey] = Base64Url.Encode(RandomNumberGenerator.GetBytes(NonceBytes));
        }

        context.Response.OnStarting(static state =>
        {
            var http = (HttpContext)state;
            var response = http.Response;
            var headers = response.Headers;

            headers.ContentSecurityPolicy = PolicyFor(
                http.Items.TryGetValue(FormActionItemKey, out var source) ? source as string : null,
                NonceFor(http));

            // Redundant with frame-ancestors for any browser released this decade, and kept because
            // the cost is one header and the failure it covers is a browser that understands one
            // directive and not the other.
            headers.XFrameOptions = "DENY";

            // The authorization request URL carries `state` and the client's redirect URI in its
            // query string. Any subresource the page loads would otherwise send that URL to the
            // host it came from in a Referer header - so this is what stops a leak that CSP only
            // makes unlikely.
            headers["Referrer-Policy"] = "no-referrer";

            headers["X-Content-Type-Options"] = "nosniff";

            // An authorization page is a decision point, never a cached artefact. A cached consent
            // page on a shared machine shows the next user what the last one was asked to approve.
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";

            return Task.CompletedTask;
        }, context);
    }

    /// <summary>
    /// Widen <c>form-action</c> to the client's redirect URI, for this response only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Chrome and Safari apply <c>form-action</c> to the redirect a submission follows, not only
    /// to its immediate target.</b> The consent POST is same-origin and allowed; the 303 it answers
    /// with, pointing at the client, is not. The authorization code has already been issued by then,
    /// so every log on this side reads as success - 303, no rejection - while the code never leaves
    /// the browser and the token endpoint is never called. <c>curl</c> does not enforce CSP, which is
    /// why an end-to-end check of every other step passes straight over it.
    /// </para>
    /// <para>
    /// Measured in Chromium before this was written, with a control: a one-hop redirect off-origin
    /// under <c>form-action 'self'</c> is blocked, a <b>two</b>-hop chain through a same-origin stop
    /// is also blocked, and naming the destination lets both through. The two-hop result is why
    /// <c>/login</c> calls this too - <c>POST /login</c> answers 303 to a local <c>/authorize</c>,
    /// which redirects to the client when consent already exists.
    /// </para>
    /// <para>
    /// <b>Only ever a redirect URI that has been matched against the client's registrations.</b> The
    /// value is emitted into a response header, and one taken from the query string would let a
    /// crafted <c>returnUrl</c> widen the policy on the page carrying the password. The origin is
    /// derived rather than the URI used whole, because the client is redirected to its path with
    /// <c>?code=…&amp;state=…</c> appended and CSP path matching is not what should decide whether a
    /// sign-in completes.
    /// </para>
    /// </remarks>
    /// <param name="context">The request.</param>
    /// <param name="validatedRedirectUri">
    /// The requested redirect URI, <b>after</b> it matched a registration - a
    /// <c>ValidatedRedirect.Value</c>. Ignored when it is null or cannot be read.
    /// </param>
    public static void AllowFormActionTo(HttpContext context, string? validatedRedirectUri)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (SourceFor(validatedRedirectUri) is not { } source)
        {
            return;
        }

        // Accumulated, not replaced. One page can need more than one destination: the sign-in page
        // carries both the client's redirect URI and every configured provider's authorization
        // endpoint, and the version that kept a single value silently dropped whichever was written
        // first. Ordinal-distinct so a repeated origin is named once - a policy listing the same
        // source three times is valid and reads like a bug.
        var existing = context.Items.TryGetValue(FormActionItemKey, out var current)
            ? current as string
            : null;

        if (string.IsNullOrEmpty(existing))
        {
            context.Items[FormActionItemKey] = source;
            return;
        }

        if (!existing.Split(' ').Contains(source, StringComparer.Ordinal))
        {
            context.Items[FormActionItemKey] = existing + " " + source;
        }
    }

    /// <summary>
    /// This response's nonce, or <see langword="null"/> when the deployment did not ask for one.
    /// </summary>
    /// <remarks>
    /// Read by the interaction endpoints so it reaches the view model, which is how it reaches a
    /// layout. The renderer seam takes a model rather than an <see cref="HttpContext"/> on purpose -
    /// a seam that could see the request could decide what the user is told - so the nonce travels
    /// the same way every other server-computed value does.
    /// </remarks>
    public static string? NonceFor(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Items.TryGetValue(NonceItemKey, out var nonce) ? nonce as string : null;
    }

    /// <summary>
    /// The policy, with an extra <c>form-action</c> source and a nonce when there are any.
    /// </summary>
    /// <remarks>
    /// <c>'self'</c> is repeated inside <c>script-src</c> and <c>style-src</c> rather than left to
    /// <c>default-src</c>, because naming a directive replaces the fallback for it completely. Without
    /// it, turning on a nonce would stop the deployment's own stylesheet loading - the one
    /// <c>InteractionOptions.StylesheetPaths</c> exists to link - and the page would render unstyled
    /// with the nonce working perfectly.
    /// </remarks>
    internal static string PolicyFor(string? formActionSource, string? nonce = null)
    {
        var formAction = string.IsNullOrEmpty(formActionSource)
            ? "form-action 'self'"
            : "form-action 'self' " + formActionSource;

        var sources = string.IsNullOrEmpty(nonce)
            ? string.Empty
            : $"; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'";

        return "default-src 'self'; " + formAction
            + "; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
            + sources;
    }

    /// <summary>
    /// The CSP source expression for a redirect URI, or <see langword="null"/> if there is not one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three shapes, because RFC 8252 permits three kinds of redirect. An <c>https</c> URI and a
    /// loopback URI both have an authority, so the source is their origin - and for loopback that is
    /// exact rather than wildcarded, because the value passed here is the <i>requested</i> URI and it
    /// carries the ephemeral port the app actually bound. A private-use scheme
    /// (<c>com.example.app:/cb</c>) has no authority at all, and the scheme is the narrowest source
    /// CSP can express for it.
    /// </para>
    /// <para>
    /// Returning <see langword="null"/> leaves the policy at <c>'self'</c>, which fails closed: the
    /// redirect is blocked and visibly so. That is the right way round - the alternative to a
    /// refused sign-in is a header assembled from something unparseable.
    /// </para>
    /// </remarks>
    internal static string? SourceFor(string? redirectUri)
    {
        if (string.IsNullOrEmpty(redirectUri)
            || !Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var source = string.IsNullOrEmpty(uri.Host)
            ? uri.Scheme + ':'
            : uri.IsDefaultPort
                ? uri.Scheme + "://" + uri.Host
                : uri.Scheme + "://" + uri.Host + ':' + uri.Port.ToString(CultureInfo.InvariantCulture);

        // A registered redirect URI cannot contain these - registration validation rejects them -
        // so this is not the check that stops an attack. It is the check that means a change to
        // registration validation cannot turn this into header injection without also failing here.
        return source.AsSpan().IndexOfAny(UnsafeInSource) < 0 ? source : null;
    }
}
