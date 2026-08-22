using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Boltway.AdminBff.Tests;

/// <summary>
/// The lookup that turns a ULID in the rail into a handle.
/// </summary>
/// <remarks>
/// <para>
/// Every assertion here is about a way the lookup does <i>not</i> get an answer, and that ratio is
/// the point. The happy path is two lines; what this had to be written for is that a label drawn in
/// the page shell must never be able to stop somebody signing in, and each of these is a shape that
/// would have if <c>GetClaimsFromUserInfoEndpoint</c> had been the fetch instead — the framework's
/// switch throws on all four of them.
/// </para>
/// <para>
/// The one exception is the transport failure, which is deliberately let through: it is the only
/// outcome worth a log line, and <c>Program.cs</c> is where that log knows enough to say what the
/// operator will see instead.
/// </para>
/// </remarks>
public sealed class OperatorProfileTests
{
    private const string Endpoint = "https://auth.example/userinfo";
    private const string Token = "not-a-real-token";

    /// <summary>The ordinary answer: a handle, under the claim OIDC defines for it.</summary>
    [Fact]
    public async Task The_handle_comes_from_preferred_username()
    {
        var stub = Json("""{"sub":"01KZX253NGXW6MPB13Y4X2GPE7","preferred_username":"ada"}""");

        Assert.Equal("ada", await Ask(stub));
    }

    /// <summary>
    /// It is asked for with the token, as a bearer credential.
    /// </summary>
    /// <remarks>
    /// <c>/userinfo</c> is bearer-only — <c>N-17</c> — so a request that carried the token any other
    /// way would be refused, and the refusal would look exactly like a server that does not serve
    /// the endpoint. Worth pinning rather than inferring from a passing happy path.
    /// </remarks>
    [Fact]
    public async Task The_token_goes_out_as_a_bearer_credential()
    {
        var stub = Json("""{"preferred_username":"ada"}""");

        await Ask(stub);

        Assert.Equal("Bearer", stub.Authorization?.Scheme);
        Assert.Equal(Token, stub.Authorization?.Parameter);
        Assert.Equal(Endpoint, stub.Uri?.ToString());
    }

    /// <summary>
    /// A server advertising no <c>userinfo_endpoint</c> is not asked at all.
    /// </summary>
    /// <remarks>
    /// <c>UserInfoEnabled</c> defaults to true and is a deployment's to turn off; the document then
    /// names no endpoint. That absence is the answer, and it is the case that decided this is not
    /// <c>GetClaimsFromUserInfoEndpoint</c> — that switch would have made such a deployment one
    /// where the admin UI cannot be entered.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task A_server_that_advertises_no_endpoint_is_not_asked(string? endpoint)
    {
        var stub = Json("""{"preferred_username":"ada"}""");

        Assert.Null(await Ask(stub, endpoint, Token));
        Assert.Equal(0, stub.Calls);
    }

    /// <summary>A session holding no access token is not asked either.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task A_session_with_no_access_token_is_not_asked(string? token)
    {
        var stub = Json("""{"preferred_username":"ada"}""");

        Assert.Null(await Ask(stub, Endpoint, token));
        Assert.Equal(0, stub.Calls);
    }

    /// <summary>
    /// Every refusal is nothing, and none of them is an exception.
    /// </summary>
    /// <remarks>
    /// A 404 is an authorization server that predates the endpoint or has it switched off; a 401 or
    /// 403 is a token this endpoint will not take, which is what a misderived audience produces.
    /// All of them end with the header naming somebody by subject, which is what it did before this
    /// lookup existed.
    /// </remarks>
    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task A_refusal_is_nothing_rather_than_a_failure(HttpStatusCode status)
    {
        var stub = new Stub(_ => new HttpResponseMessage(status));

        Assert.Null(await Ask(stub));
        Assert.Equal(1, stub.Calls);
    }

    /// <summary>
    /// An account with no username answers <c>sub</c> and nothing else, which is not a name.
    /// </summary>
    /// <remarks>
    /// OIDC Core §5.3.2 requires <c>sub</c> in every response and the endpoint sends the handle only
    /// when the account has one — so a body without it is a well-formed answer, not a broken one.
    /// </remarks>
    [Fact]
    public async Task An_account_with_no_username_is_nothing() =>
        Assert.Null(await Ask(Json("""{"sub":"01KZX253NGXW6MPB13Y4X2GPE7"}""")));

    /// <summary>A handle that is blank, or is not a string, is not a handle.</summary>
    /// <remarks>
    /// The shell tests <c>Length: &gt; 0</c> before drawing the element, so an empty string would
    /// render as an empty span rather than as a fallback to the subject — the label would simply be
    /// missing. Folding it to null here is what keeps the subject as the answer.
    /// </remarks>
    [Theory]
    [InlineData("""{"preferred_username":""}""")]
    [InlineData("""{"preferred_username":null}""")]
    [InlineData("""{"preferred_username":42}""")]
    [InlineData("""{"preferred_username":["ada"]}""")]
    [InlineData("""["ada"]""")]
    public async Task A_value_that_is_not_a_handle_is_nothing(string body) =>
        Assert.Null(await Ask(Json(body)));

    /// <summary>
    /// A 200 that is not JSON is nothing, rather than an exception.
    /// </summary>
    /// <remarks>
    /// This is the case that decided the body is parsed from a string instead of through
    /// <c>ReadFromJsonAsync</c>: that helper checks the media type first and throws
    /// <c>NotSupportedException</c> — which no <c>catch (JsonException)</c> covers — for exactly the
    /// proxy error page this has to survive.
    /// </remarks>
    [Fact]
    public async Task A_body_that_is_not_json_is_nothing()
    {
        var stub = new Stub(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<html>502 Bad Gateway</html>", Encoding.UTF8, "text/html"),
        });

        Assert.Null(await Ask(stub));
    }

    /// <summary>
    /// A transport failure reaches the caller, and that is the one thing here that is not swallowed.
    /// </summary>
    /// <remarks>
    /// It is the only outcome worth a line in a log, and the log belongs where it knows this ran
    /// during a sign-in. <c>Program.cs</c> catches it, writes that line, and lets the sign-in finish
    /// — swallowing it here would leave nothing able to say it happened.
    /// </remarks>
    [Fact]
    public async Task A_transport_failure_reaches_the_caller() =>
        await Assert.ThrowsAsync<HttpRequestException>(
            () => Ask(new Stub(_ => throw new HttpRequestException("connection refused"))));

    /// <summary>The lookup, against a stub, with the arguments a sign-in would supply.</summary>
    private static async Task<string?> Ask(Stub stub)
    {
        using var client = new HttpClient(stub);

        return await OperatorProfile.HandleAsync(client, Endpoint, Token);
    }

    /// <summary>The same, for the two cases that vary an argument into nothing.</summary>
    private static async Task<string?> Ask(Stub stub, string? endpoint, string? token)
    {
        using var client = new HttpClient(stub);

        return await OperatorProfile.HandleAsync(client, endpoint, token);
    }

    /// <summary>A stub answering 200 with a JSON body.</summary>
    private static Stub Json(string body) => new(_ => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    });

    /// <summary>
    /// An authorization server that answers however a test needs it to.
    /// </summary>
    /// <remarks>
    /// Recorded inside <see cref="SendAsync"/> rather than by keeping the request, because
    /// <c>HandleAsync</c> disposes it — a test reading the headers afterwards would be asserting
    /// against an object the code under test has finished with.
    /// </remarks>
    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        /// <summary>How many requests were made, so "not asked" is assertable.</summary>
        internal int Calls { get; private set; }

        /// <summary>What the request carried as its credential.</summary>
        internal AuthenticationHeaderValue? Authorization { get; private set; }

        /// <summary>Where it was sent.</summary>
        internal Uri? Uri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);

            Calls++;
            Authorization = request.Headers.Authorization;
            Uri = request.RequestUri;

            return Task.FromResult(respond(request));
        }
    }
}
