using System.Net;
using System.Web;
using Boltway.AuthorizationServer.Interaction;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The attributes on the pending-external-login cookie, as they reach the browser.
/// </summary>
/// <remarks>
/// <para>
/// Found by mutation testing. Every hardening flag on this cookie could be turned off without a
/// single test failing: <c>HttpOnly = true</c> to <c>false</c>, <c>Secure = true</c> to
/// <c>false</c>, and the whole <c>CookieOptions</c> initializer replaced by <c>{}</c> — at both the
/// write site and the delete site. The suite drove the federated login flow end to end and never
/// once looked at the <c>Set-Cookie</c> header it produced.
/// </para>
/// <para>
/// The cookie is named <c>__Host-boltway-external</c>, and that name is a promise. RFC 6265bis
/// §4.1.3.2 lets a browser accept a <c>__Host-</c> cookie only when it is <c>Secure</c>, has
/// <c>Path=/</c>, and carries no <c>Domain</c>. A real browser therefore rejects this cookie
/// outright if <c>Secure</c> is dropped — the flow would break in the field while the test suite
/// stayed green, because <see cref="System.Net.CookieContainer"/> does not enforce the prefix.
/// That gap between what the tests tolerate and what a browser enforces is exactly why these
/// assertions read the raw header rather than the client's cookie jar.
/// </para>
/// <para>
/// What this file does <b>not</b> pin: <c>IsEssential</c>. It is not an attribute and never appears
/// in <c>Set-Cookie</c> — it tells an ASP.NET Core cookie-consent policy that this cookie is exempt
/// from consent suppression. Its mutant survives here and will keep surviving; killing it needs a
/// host with a <c>CookiePolicy</c> configured, which this server does not add. Said out loud rather
/// than left as an unexplained survivor.
/// </para>
/// </remarks>
public sealed partial class ExternalLoginFlowTests
{
    /// <summary>Drive an anonymous /authorize to the POST that mints the pending cookie.</summary>
    private static async Task<HttpResponseMessage> StartExternalAsync(Server server)
    {
        var start = await server.Client.GetAsync(AuthorizeUrl());

        Assert.Equal(HttpStatusCode.SeeOther, start.StatusCode);

        var page = await server.Client.GetStringAsync(start.Headers.Location!.ToString());
        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        Assert.True(token.Success, "the sign-in page rendered no antiforgery field");

        return await server.Client.PostAsync(
            "/external/google/start",
            new FormUrlEncodedContent(
            [
                new(token.Groups[1].Value, token.Groups[2].Value),
                new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            ]));
    }

    private static string PendingCookieHeader(HttpResponseMessage response)
    {
        Assert.True(
            response.Headers.TryGetValues("Set-Cookie", out var values),
            "the response set no cookies at all");

        var header = values!.FirstOrDefault(v =>
            v.StartsWith(ExternalLoginStateStore.CookieName + "=", StringComparison.Ordinal));

        Assert.NotNull(header);
        return header!;
    }

    [Fact]
    public async Task The_pending_login_cookie_is_host_only_secure_and_script_invisible()
    {
        await using var server = await StartAsync();

        var header = PendingCookieHeader(await StartExternalAsync(server));

        // The cookie carries the upstream state, nonce and PKCE verifier for the leg that is still
        // in flight. Script access to it is a CSRF token in the DOM; plaintext transport is the
        // same value on the wire.
        Assert.Contains("httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", header, StringComparison.OrdinalIgnoreCase);

        // __Host- forbids Domain outright, and a Domain here would widen the cookie to every
        // sibling host on the registrable domain.
        Assert.DoesNotContain("domain=", header, StringComparison.OrdinalIgnoreCase);

        // No Expires and no Max-Age: a session cookie. The payload carries its own absolute expiry
        // and that is the one enforced, so a browser rounding a lifetime cannot resurrect a pending
        // request the server already considers dead.
        Assert.DoesNotContain("expires=", header, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("max-age=", header, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_pending_login_cookie_is_deleted_with_the_same_attributes()
    {
        // The delete site had its own copy of the options and its own surviving mutants. A deletion
        // whose attributes do not match the ones the cookie was written with does not delete it:
        // the browser keeps the original, and the callback stays replayable — which is the one
        // thing TakeAndClear exists to prevent.
        await using var server = await StartAsync();

        var challenge = await BeginAsync(server);
        var callback = await CallbackAsync(server, challenge);

        var header = PendingCookieHeader(callback);

        Assert.Contains("httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", header, StringComparison.OrdinalIgnoreCase);

        // A deletion is an empty value with an expiry in the past.
        Assert.Contains(ExternalLoginStateStore.CookieName + "=;", header, StringComparison.Ordinal);
        Assert.Contains("expires=", header, StringComparison.OrdinalIgnoreCase);
    }
}
