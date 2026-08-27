using System.Net;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// The sign-in page needs the same <c>form-action</c> source the consent page needs.
/// </summary>
/// <remarks>
/// <para>
/// Less obvious than the consent page, and the reason it is here is a measurement rather than an
/// argument. <c>POST /login</c> answers 303 to a <b>local</b> <c>/authorize</c>, so nothing leaves
/// this origin on the hop the form itself makes. It leaves on the next one, when <c>/authorize</c>
/// finds standing consent and redirects to the client.
/// </para>
/// <para>
/// Chromium was asked directly whether that second hop is covered: a form submission redirected
/// off-origin through one same-origin stop, under <c>form-action 'self'</c>, is blocked exactly like
/// a direct one, and naming the destination lets both through. So every returning user - everyone
/// past their first authorization, which is everyone most days - would have signed in successfully
/// and gone nowhere.
/// </para>
/// </remarks>
public sealed partial class LoginFlowTests
{
    [Fact]
    public async Task The_login_page_names_the_client_in_form_action()
    {
        await using var server = await StartAsync();

        var start = await server.Client.GetAsync(AuthorizeUrl());
        var login = await server.Client.GetAsync(start.Headers.Location!.ToString());

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains(
            "form-action 'self' https://claude.ai;",
            string.Join(' ', login.Headers.GetValues("Content-Security-Policy")),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// And the page re-rendered after a wrong password carries it too.
    /// </summary>
    /// <remarks>
    /// That page has the same form on it, so a first attempt that fails and a second that succeeds is
    /// the ordinary case rather than an edge - and it is the one where a policy set only on the
    /// initial <c>GET</c> would be missing.
    /// </remarks>
    [Fact]
    public async Task The_page_re_rendered_after_a_wrong_password_names_it_too()
    {
        await using var server = await StartAsync();

        var rejected = await PostLoginAsync(server, "ada", "not-the-password");

        Assert.Equal(HttpStatusCode.OK, rejected.StatusCode);
        Assert.Contains(
            "form-action 'self' https://claude.ai;",
            string.Join(' ', rejected.Headers.GetValues("Content-Security-Policy")),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A <c>returnUrl</c> whose query carries no <c>redirect_uri</c> renders the page at
    /// <c>'self'</c>, rather than throwing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The method deciding this source documents every failure as silent - a returnUrl that names no
    /// client, an unparseable redirect URI, one matching no registration - and then read the query
    /// with an indexer, which throws on a key that is absent rather than yielding empty. So the one
    /// case nobody listed was the one that escaped: an unhandled <c>KeyNotFoundException</c>, and a
    /// browser given an empty 500 with no body, no reason and no reference.
    /// </para>
    /// <para>
    /// Found on a running deployment by typing a shortened <c>returnUrl</c> at
    /// <c>/login</c>, which is anonymous and takes it from anyone. The theatre is a defence of A-09:
    /// what is asserted is not that this URL is refused but that it is <b>answered</b>.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("/authorize?client_id=northwind-admin")]
    [InlineData("/authorize?client_id=northwind-admin&response_type=code")]
    [InlineData("/authorize?")]
    public async Task A_return_url_with_no_redirect_uri_still_renders(string returnUrl)
    {
        await using var server = await StartAsync();

        var page = await server.Client.GetAsync(
            $"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains(
            "form-action 'self';",
            string.Join(' ', page.Headers.GetValues("Content-Security-Policy")),
            StringComparison.Ordinal);
    }
}
