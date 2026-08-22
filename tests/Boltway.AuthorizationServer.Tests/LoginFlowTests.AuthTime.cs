using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Interaction;
using Boltway.OAuth.Primitives.Pkce;
using Microsoft.AspNetCore.Http;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// <c>auth_time</c>, from the sign-in that produced it to the token that reports it.
/// </summary>
/// <remarks>
/// <para>
/// <c>CookieUserSignIn</c> and <c>CookieUserSession</c> had no test of any kind. A mutation review
/// measured three separate breakages that the whole 640-test suite could not see: writing the claim
/// as "now on the machine clock" instead of the user's actual authentication time; defaulting a
/// missing or malformed claim to <c>DateTimeOffset.UtcNow</c>; and completing a consent flow for a
/// browser with no session at all. All three survived because <c>FlowFixture</c> substituted
/// <c>TestUserSession</c> and no test pipeline called <c>UseAuthentication</c>, so the production
/// session reader never ran anywhere.
/// </para>
/// <para>
/// Every one of those breakages has the same shape: <c>max_age</c> keeps being satisfied. A relying
/// party doing step-up authentication is told the user just authenticated, forever, and there is no
/// signal on the wire that would let it notice. The class doc calls that out — "silently a no-op" —
/// and until now nothing held it.
/// </para>
/// </remarks>
public sealed partial class LoginFlowTests
{
    /// <summary>
    /// The <c>auth_time</c> in the ID token is when the user signed in, not when the token was made.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The clock moves twenty minutes forward <b>between the sign-in and the rest of the flow</b>,
    /// so the authentication time and the mint time are far apart and the assertion can tell them
    /// apart. With them equal — which is what a fixture that never moves its clock produces — this
    /// test passes against a server that stamps <c>auth_time</c> at mint time, which is exactly the
    /// mutation that survived.
    /// </para>
    /// <para>
    /// Between the sign-in and the code, not after it: an authorization code outlives its issuance
    /// by a minute, so advancing twenty after issuing one only proves that expiry works. First
    /// attempt did that and got a <c>400</c>.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Auth_time_is_when_the_user_signed_in_not_when_the_token_was_issued()
    {
        await using var server = await StartAsync();

        var verifier = CodeVerifier.Generate();
        var signedInAt = server.Fixture.Clock.GetUtcNow();

        var code = await SignInAndAuthorizeAsync(server, verifier, advanceAfterSignIn: TimeSpan.FromMinutes(20));

        var tokens = await ExchangeAsync(server, code, verifier);
        var authTime = AuthTimeOf(tokens.GetProperty("id_token").GetString()!);

        Assert.Equal(signedInAt.ToUnixTimeSeconds(), authTime);

        // The control: the value is genuinely not "now". Without this the assertion above is also
        // satisfied by a clock that never moved.
        Assert.NotEqual(server.Fixture.Clock.GetUtcNow().ToUnixTimeSeconds(), authTime);
    }

    /// <summary>
    /// A session cookie carrying no readable <c>auth_time</c> is not a session.
    /// </summary>
    /// <remarks>
    /// The alternative — defaulting to now — is the mutation that survived, and it is the worst
    /// available answer: it does not fail, it silently reports that the user authenticated this
    /// instant. Refusing means the user signs in again, which is correct and visible.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData(" 1754000000")]
    [InlineData("+1754000000")]
    [InlineData("9223372036854775807")]
    [InlineData("253402300800")]
    public async Task A_session_without_a_readable_auth_time_is_anonymous(string claim)
    {
        var user = SessionReadingPrincipal(claim);

        Assert.Null(await user.GetAsync(CancellationToken.None));
    }

    /// <summary>
    /// The control for the theory above: a well-formed claim does produce a session.
    /// </summary>
    /// <remarks>
    /// Without it, every row passes against a reader that returns <see langword="null"/>
    /// unconditionally — which would break every flow and still look like a hardened parser.
    /// </remarks>
    [Fact]
    public async Task A_session_with_a_well_formed_auth_time_is_read()
    {
        var user = SessionReadingPrincipal("1754000000");

        var session = await user.GetAsync(CancellationToken.None);

        Assert.NotNull(session);
        Assert.Equal(1754000000, session.Value.AuthenticatedAt.ToUnixTimeSeconds());
    }

    /// <summary>The two out-of-range rows above throw rather than parse, without the range check.</summary>
    /// <remarks>
    /// Stated separately because the failure mode differs from the others: <c>long.TryParse</c>
    /// accepts <c>9223372036854775807</c> and <c>253402300800</c>, and
    /// <c>DateTimeOffset.FromUnixTimeSeconds</c> throws <c>ArgumentOutOfRangeException</c> on both —
    /// out of a method with no exception boundary above it, on the path every authenticated request
    /// takes. So those rows are not testing parsing, they are testing that a 500 became a sign-in
    /// prompt.
    /// </remarks>
    [Fact]
    public void An_out_of_range_auth_time_would_throw_if_it_reached_the_conversion()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DateTimeOffset.FromUnixTimeSeconds(long.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => DateTimeOffset.FromUnixTimeSeconds(253402300800));
    }

    /// <summary>
    /// The production session reader over a principal carrying exactly this <c>auth_time</c>.
    /// </summary>
    /// <remarks>
    /// Constructed rather than driven through a real sign-in, because <c>CookieUserSignIn</c> can
    /// only write well-formed values — the malformed cases arrive from a cookie some other
    /// application encrypted with shared data-protection keys, which is an ordinary deployment and
    /// not an attack. The type under test is still the shipped one.
    /// </remarks>
    private static CookieUserSession SessionReadingPrincipal(string authTime)
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "user-1"),
                new Claim(CookieUserSignIn.AuthTimeClaim, authTime),
            ],
            authenticationType: "Cookies",
            nameType: ClaimTypes.NameIdentifier,
            roleType: ClaimTypes.Role);

        var accessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(identity) },
        };

        return new CookieUserSession(accessor);
    }

    /// <summary>Sign in for real, then run an authorization request to a code.</summary>
    private static async Task<string> SignInAndAuthorizeAsync(
        Server server, CodeVerifier verifier, TimeSpan? advanceAfterSignIn = null)
    {
        var authorize = "/authorize?response_type=code"
            + "&client_id=" + Uri.EscapeDataString(ClientId)
            + "&redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback")
            + "&code_challenge=" + verifier.ComputeS256Challenge()
            + "&code_challenge_method=S256"
            + "&scope=" + Uri.EscapeDataString("openid mcp:tools offline_access")
            + "&resource=" + Uri.EscapeDataString(Build.Resource)
            + "&state=opaque-state";

        var toLogin = await server.Client.GetAsync(authorize);

        Assert.Equal(HttpStatusCode.SeeOther, toLogin.StatusCode);

        var signedIn = await PostLoginAsync(server, Username, Password, toLogin.Headers.Location!.ToString());

        Assert.Equal(HttpStatusCode.SeeOther, signedIn.StatusCode);

        // The session is now twenty minutes old, if the caller asked for that. No `max_age` and no
        // `prompt` on this request, so an old session is perfectly acceptable — which is what makes
        // the gap observable rather than merely present.
        if (advanceAfterSignIn is { } advance)
        {
            server.Fixture.Clock.Advance(advance);
        }

        // Back to /authorize, which now finds a session and goes on to consent.
        var resumed = await server.Client.GetAsync(signedIn.Headers.Location!.ToString());
        var page = await server.Client.GetStringAsync(resumed.Headers.Location!.ToString());
        var (field, token, returnUrl) = FormFields(page);

        var approved = await server.Client.PostAsync("/consent", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [field] = token,
                ["returnUrl"] = returnUrl,
                ["decision"] = "approve",
            }));

        Assert.Equal(HttpStatusCode.SeeOther, approved.StatusCode);

        var code = HttpUtility.ParseQueryString(
            new Uri(approved.Headers.Location!.ToString()).Query)["code"];

        Assert.False(string.IsNullOrEmpty(code), $"No code in {approved.Headers.Location}");

        return code!;
    }

    private static async Task<JsonElement> ExchangeAsync(Server server, string code, CodeVerifier verifier)
    {
        using var response = await server.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["client_id"] = ClientId,
                ["redirect_uri"] = "https://claude.ai/api/mcp/auth_callback",
                ["code_verifier"] = verifier.Value,
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();
    }

    private static long AuthTimeOf(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var padded = payload.Replace('-', '+').Replace('_', '/').PadRight((payload.Length + 3) / 4 * 4, '=');

        using var document = JsonDocument.Parse(Convert.FromBase64String(padded));

        return document.RootElement.GetProperty("auth_time").GetInt64();
    }
}
