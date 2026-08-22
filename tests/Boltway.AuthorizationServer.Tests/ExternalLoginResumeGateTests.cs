using System.Net;
using Boltway.AuthorizationServer.Configuration;
using Boltway.AuthorizationServer.Interaction;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The second return-URL gate, and the upstream's word about an email address.
/// </summary>
public sealed partial class ExternalLoginFlowTests
{
    /// <summary>
    /// Rewrite the pending request's return URL, leaving everything else alone.
    /// </summary>
    /// <remarks>
    /// <c>Resume</c> re-gates a value that <c>POST /external/{scheme}/start</c> already gated, and
    /// the source says why: "Validated when it was written is a claim about a request that is over."
    /// The consequence is that <b>no ordinary request can reach the second gate with a bad value</b>
    /// — which is exactly why both of its mutants survived, and why proving it does anything needs a
    /// planted pending request rather than a crafted URL.
    /// <para>
    /// This is not a claim that the cookie is forgeable. It is authenticated and it is not. What is
    /// being tested is the thing the comment says the second gate is for: a future change that
    /// writes a pending request from a path that did not gate.
    /// </para>
    /// </remarks>
    private static void TamperMiddleware(IApplicationBuilder app) =>
        app.Use(async (http, next) =>
        {
            if (!http.Request.Path.StartsWithSegments("/__test/return-url"))
            {
                await next(http);
                return;
            }

            var store = http.RequestServices.GetRequiredService<ExternalLoginStateStore>();
            var pending = store.TakeAndClear(http);

            if (pending is null)
            {
                http.Response.StatusCode = StatusCodes.Status409Conflict;
                return;
            }

            store.Write(http, pending with { ReturnUrl = http.Request.Query["value"].ToString() });
            http.Response.StatusCode = StatusCodes.Status204NoContent;
        });

    [Theory]
    // Absolute, off-origin. What an open redirect looks like.
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    // Local, but not the path a sign-in may resume to. This is the row that separates the two
    // mutants: `acceptable` is computed as IsLocalPathTo(returnUrl, "/authorize") for a sign-in, and
    // a mutant that collapses it to IsLocal would wave this through while still refusing the two
    // above.
    [InlineData("/settings")]
    public async Task A_planted_return_url_is_refused_when_the_callback_resumes(string planted)
    {
        await using var server = await StartAsync(s =>
        {
            // Provision, so the callback would otherwise succeed. Under the default Refuse policy
            // an unknown upstream identity is turned away before Resume runs at all, and the whole
            // theory would have measured that refusal instead of the return-URL gate. The control
            // below is what caught it.
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision;
            s.ConfigureApp = TamperMiddleware;
        });

        var challenge = await BeginAsync(server);

        var tamper = await server.Client.GetAsync(
            "/__test/return-url?value=" + Uri.EscapeDataString(planted));

        Assert.Equal(HttpStatusCode.NoContent, tamper.StatusCode);

        var callback = await CallbackAsync(server, challenge);

        // Refused, and specifically not a redirect: a 3xx here is the open redirect itself.
        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        Assert.Null(callback.Headers.Location);
    }

    [Fact]
    public async Task The_control_an_untampered_return_url_still_resumes()
    {
        // Without this, "the callback 400s" would pass against a server whose callback is simply
        // broken, and the theory above would prove nothing about the gate.
        await using var server = await StartAsync(s =>
        {
            // Provision, so the callback would otherwise succeed. Under the default Refuse policy
            // an unknown upstream identity is turned away before Resume runs at all, and the whole
            // theory would have measured that refusal instead of the return-URL gate. The control
            // below is what caught it.
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision;
            s.ConfigureApp = TamperMiddleware;
        });

        var challenge = await BeginAsync(server);
        var callback = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.SeeOther, callback.StatusCode);
        Assert.StartsWith(
            AuthorizationServerPaths.Authorize,
            callback.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A provisioned account does not inherit a verified email from an unverified claim.
    /// </summary>
    /// <remarks>
    /// <c>EmailVerified: email is not null &amp;&amp; email_verified == "true"</c>, mutated to
    /// <c>||</c>, survived. Under the mutant every provisioned account with any email address at all
    /// is marked verified, whatever the upstream actually said — and `email_verified` is the claim
    /// downstream systems use to decide that an address has been proven. The suite only ever
    /// provisioned from an upstream asserting <c>true</c>, so the second operand was never the one
    /// deciding.
    /// </remarks>
    [Fact]
    public async Task An_unverified_upstream_email_does_not_provision_a_verified_account()
    {
        await using var server = await StartAsync(s =>
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision);

        server.Upstream.Behaviour.Email = "someone@example.com";
        server.Upstream.Behaviour.EmailVerified = false;

        var challenge = await BeginAsync(server);

        Assert.Equal(HttpStatusCode.SeeOther, (await CallbackAsync(server, challenge)).StatusCode);

        var link = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, server.Upstream.Behaviour.Subject, CancellationToken.None);

        Assert.NotNull(link);

        var account = await server.Users.FindBySubjectAsync(link!.Subject, CancellationToken.None);

        Assert.NotNull(account);
        Assert.Equal("someone@example.com", account!.Email);
        Assert.False(account.EmailVerified, "an unverified upstream claim provisioned a verified account");
    }

    [Fact]
    public async Task A_verified_upstream_email_does_provision_a_verified_account()
    {
        // The control. Without it, asserting False above would pass against a server that never
        // marks anything verified, which is a different bug wearing the same fix.
        await using var server = await StartAsync(s =>
            s.UnknownIdentity = UnknownExternalIdentityPolicy.Provision);

        server.Upstream.Behaviour.Email = "someone@example.com";
        server.Upstream.Behaviour.EmailVerified = true;

        var challenge = await BeginAsync(server);

        Assert.Equal(HttpStatusCode.SeeOther, (await CallbackAsync(server, challenge)).StatusCode);

        var link = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, server.Upstream.Behaviour.Subject, CancellationToken.None);

        var account = await server.Users.FindBySubjectAsync(link!.Subject, CancellationToken.None);

        Assert.True(account!.EmailVerified);
    }
}
