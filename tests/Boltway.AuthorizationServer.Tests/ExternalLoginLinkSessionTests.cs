using System.Net;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.Identity.Passwords;
using Boltway.Identity.Subjects;
using Boltway.OAuth.Primitives.Ids;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Account linking when the session changes between the two legs.
/// </summary>
public sealed partial class ExternalLoginFlowTests
{
    /// <summary>
    /// A link completes against the session that started it, not whoever is signed in now.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The callback guard reads
    /// <c>user is null || !string.Equals(user.Value.Subject.Value, pending.LinkSubject, Ordinal)</c>,
    /// and mutating <c>||</c> to <c>&amp;&amp;</c> survived. Under the mutant a session that exists
    /// but belongs to somebody else evaluates <c>false &amp;&amp; true</c>, the guard does not fire,
    /// and the upstream identity is attached to whoever holds the browser at the end — a shared
    /// machine, or a sign-out and sign-in between the two legs. That is an account takeover with no
    /// password involved.
    /// </para>
    /// <para>
    /// It survived for a reason worth writing down, because on paper the case looked covered.
    /// <c>Linking_without_a_session_is_refused_before_the_browser_leaves</c> asserts exactly this
    /// <c>ReasonCode</c> — but it refuses at <c>POST /external/{scheme}/link</c>, before the browser
    /// ever leaves, so it never reaches the callback where this line lives. A grep for the reason
    /// code said "covered"; the mutant said otherwise, and the mutant was right.
    /// </para>
    /// <para>
    /// The <i>different subject</i> case is the one that matters and the one no test could express:
    /// the no-session case is caught earlier anyway.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task A_link_is_refused_when_the_session_changed_between_the_two_legs()
    {
        const string AdaPassword = "correct horse battery staple";
        const string BobPassword = "a different correct horse";

        var hasher = new Argon2idPasswordHasher(TestCost);
        var factory = new UlidSubjectIdFactory(TimeProvider.System);
        var ada = factory.Mint();
        var bob = factory.Mint();

        await using var server = await StartAsync(s => s.Seed = async (users, _) =>
        {
            await users.StoreAsync(
                new UserAccount(ada, "ada", "ada@example.com", EmailVerified: true, hasher.Hash(AdaPassword)),
                CancellationToken.None);

            await users.StoreAsync(
                new UserAccount(bob, "bob", "bob@example.com", EmailVerified: true, hasher.Hash(BobPassword)),
                CancellationToken.None);
        });

        await SignInAsync(server, "ada", AdaPassword);

        // Ada starts the link. pending.LinkSubject is ada from here on.
        var linkPage = await server.Client.GetStringAsync(
            "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));
        var linkToken = AntiforgeryField().Match(linkPage);

        var began = await server.Client.PostAsync("/external/google/link", new FormUrlEncodedContent(
        [
            new(linkToken.Groups[1].Value, linkToken.Groups[2].Value),
            new("returnUrl", "/error"),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, began.StatusCode);

        var query = HttpUtility.ParseQueryString(new Uri(began.Headers.Location!.ToString()).Query);
        var challenge = new Challenge(
            began.Headers.Location!.ToString(),
            query["state"]!,
            query["nonce"]!,
            query["code_challenge"]!,
            query["redirect_uri"]!);

        // Same browser, different person. The pending request still names ada.
        await SignInAsync(server, "bob", BobPassword);

        var callback = await CallbackAsync(server, challenge);

        Assert.Equal(HttpStatusCode.BadRequest, callback.StatusCode);
        AssertRejected(server, "ExternalLinkRequiresSession");

        // The assertion that names the actual harm: the upstream identity is attached to nobody.
        // Under the mutant it is attached to bob, who never proved anything about it.
        var linked = await server.Users.FindByExternalLoginAsync(RealmId.Default, 
            server.Upstream.Issuer, server.Upstream.Behaviour.Subject, CancellationToken.None);

        Assert.Null(linked);
    }

    /// <summary>Sign in with a password, replacing whatever session the client already held.</summary>
    private static async Task SignInAsync(Server server, string username, string password)
    {
        var page = await server.Client.GetStringAsync(
            "/login?returnUrl=" + Uri.EscapeDataString(AuthorizeUrl()));

        var token = AntiforgeryField().Match(page);
        var returnUrl = ReturnUrlField().Match(page);

        Assert.True(token.Success, "the sign-in page rendered no antiforgery field");

        var response = await server.Client.PostAsync("/login", new FormUrlEncodedContent(
        [
            new(token.Groups[1].Value, token.Groups[2].Value),
            new("returnUrl", HttpUtility.HtmlDecode(returnUrl.Groups[1].Value)),
            new("username", username),
            new("password", password),
        ]));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
    }
}
