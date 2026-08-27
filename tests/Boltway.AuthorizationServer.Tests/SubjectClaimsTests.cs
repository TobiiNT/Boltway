using System.Net;
using System.Text.Json;
using System.Web;
using Boltway.AuthorizationServer.Abstractions.Tokens;
using Boltway.AuthorizationServer.Abstractions.Users;
using Boltway.AuthorizationServer.DependencyInjection;
using Boltway.OAuth.Primitives.Encoding;
using Boltway.OAuth.Primitives.Ids;
using Boltway.OAuth.Primitives.Pkce;
using Boltway.OAuth.Primitives.Scopes;
using Boltway.Storage.InMemory;
using Microsoft.Extensions.DependencyInjection;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// What an access token says about the person it was issued for.
/// </summary>
/// <remarks>
/// <para>
/// The defect these are a reaction to: an access token carried <c>iss</c>, <c>aud</c>, <c>sub</c>,
/// <c>scope</c>, <c>client_id</c>, <c>gid</c>, <c>iat</c>, <c>exp</c> and <c>jti</c>, and nothing
/// else. Downstream, a connector with a whole attribution path - commit author, actor line,
/// refusals naming the caller - degraded every one of them to a ULID the moment it moved off
/// static tokens onto this server. Nothing failed. The git history simply stopped naming people,
/// and would have been noticed months later by someone reading it.
/// </para>
/// <para>
/// So the assertions here are about <b>presence</b> more than shape. A claim that quietly is not
/// there is the failure; a claim that is wrong would at least be visible.
/// </para>
/// </remarks>
public sealed class SubjectClaimsTests
{
    private const string Handle = "ada";
    private const string Address = "ada@example.com";

    /// <summary>The subject <see cref="AuthorizationServerOptionsSeed.SignedInUser"/> uses.</summary>
    private static readonly SubjectId SignedIn = SubjectId.FromStorage("user-1");

    // ─────────────────────────────────────────────────────────────────────────
    // Fixtures
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A server whose access tokens name the account, with that account present.
    /// </summary>
    /// <remarks>
    /// The shipped <see cref="InMemoryUserStore"/> and the shipped <see cref="UserAccountClaims"/>,
    /// registered through the public extension a host calls. A double for either would test this
    /// file rather than the wiring, and the wiring is what was missing.
    /// </remarks>
    private static Task<FlowFixture> ServerNamingTheAccountAsync(
        string? email = Address, bool emailVerified = true, bool withAccount = true, string? role = null)
    {
        var roles = new InMemoryRoleStore();
        var users = new InMemoryUserStore(roles);

        if (withAccount)
        {
            users.StoreAsync(
                new UserAccount(SignedIn, Handle, email, emailVerified, PasswordHash: null),
                CancellationToken.None).GetAwaiter().GetResult();

            if (role is { Length: > 0 })
            {
                // Defined, then held. Creation does not assign, and assignment refuses an id the
                // realm does not define.
                roles.StoreAsync(new RoleDefinition(role, role, []), CancellationToken.None)
                    .GetAwaiter().GetResult();

                users.SetRolesAsync(SignedIn, [role], CancellationToken.None).GetAwaiter().GetResult();
            }
        }

        return FlowFixture.StartAsync(seed =>
        {
            seed.ConfigureServices = services =>
            {
                services.AddSingleton<IUserStore>(users);
                services.AddSingleton<IRoleStore>(roles);
                services.AddSubjectClaimsFromAccounts();
            };

            seed.ConfigureOptions = options => options.ScopesSupported.Add("email");
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Driving the flow
    // ─────────────────────────────────────────────────────────────────────────

    private static readonly CodeVerifier Verifier = CodeVerifier.Generate();

    private static async Task<string> CodeAsync(FlowFixture fixture, string scope)
    {
        var response = await fixture.Client.GetAsync("/authorize?" + string.Join('&',
            "response_type=code",
            "client_id=" + Uri.EscapeDataString("https://claude.ai/.well-known/oauth-client"),
            "redirect_uri=" + Uri.EscapeDataString("https://claude.ai/api/mcp/auth_callback"),
            "code_challenge=" + Verifier.ComputeS256Challenge(),
            "code_challenge_method=S256",
            "scope=" + Uri.EscapeDataString(scope),
            "resource=" + Uri.EscapeDataString(Build.Resource),
            "state=opaque-state"));

        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);

        var code = HttpUtility.ParseQueryString(new Uri(response.Headers.Location!.ToString()).Query)["code"];
        Assert.False(string.IsNullOrEmpty(code), $"No code in {response.Headers.Location}");

        return code!;
    }

    private static Task<HttpResponseMessage> ExchangeAsync(FlowFixture fixture, string code) =>
        fixture.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["client_id"] = "https://claude.ai/.well-known/oauth-client",
                ["redirect_uri"] = "https://claude.ai/api/mcp/auth_callback",
                ["code_verifier"] = Verifier.Value,
            }));

    private static Task<HttpResponseMessage> RefreshAsync(FlowFixture fixture, string refreshToken) =>
        fixture.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = "https://claude.ai/.well-known/oauth-client",
            }));

    /// <summary>
    /// The access token's payload, decoded rather than validated.
    /// </summary>
    /// <remarks>
    /// A test asking "what does this token say" wants the bytes on the wire. Running it through a
    /// validator first would make an assertion about a claim depend on the validator agreeing about
    /// the signature, which is a different test's job and a different failure.
    /// </remarks>
    private static async Task<JsonElement> PayloadAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement;
        var wire = body.GetProperty("access_token").GetString()!;

        Assert.True(Base64Url.TryDecode(wire.Split('.')[1], out var payload), "The token's payload is not base64url.");

        return JsonDocument.Parse(payload).RootElement.Clone();
    }

    private static async Task<string> RefreshTokenAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync())
            .RootElement.GetProperty("refresh_token").GetString()!;

    /// <summary>A scalar claim, or the first element when the claim is an array.</summary>
    /// <remarks>
    /// <c>role</c> became an array when an account started holding several. It stays an array with
    /// one element rather than collapsing to a string, so this reads either shape - the assertions
    /// are about which role travels, not about the JSON type, and the type is asserted on its own
    /// below.
    /// </remarks>
    private static string? Claim(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value)
            ? value.ValueKind == JsonValueKind.Array
                ? value.EnumerateArray().FirstOrDefault().GetString()
                : value.GetString()
            : null;

    // ─────────────────────────────────────────────────────────────────────────
    // The token names the person
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>The handle is in the token, so a resource server can attribute a write to a person.</summary>
    [Fact]
    public async Task An_access_token_carries_the_handle()
    {
        await using var fixture = await ServerNamingTheAccountAsync();

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools")));

        Assert.Equal(Handle, Claim(payload, "preferred_username"));

        // And `sub` is untouched. The handle is what an audit trail reads; the subject is what
        // every stored grant, consent record and refresh family is keyed on, and a mapper that
        // could move it would break all three at once.
        Assert.Equal(SignedIn.Value, Claim(payload, "sub"));
    }

    /// <summary>Nothing is released without the mapper - the default is a token that names nobody.</summary>
    /// <remarks>
    /// This is the state the whole file is about, kept as a test rather than a memory. It is a
    /// correct default: a resource server that only needs to know a request is authorised should
    /// not be handed a name and an address. It is a bad surprise, which is why
    /// <c>AddSubjectClaimsFromAccounts</c> is one line and the host calls it.
    /// </remarks>
    [Fact]
    public async Task Without_a_mapper_the_token_says_nothing_beyond_the_subject()
    {
        await using var fixture = await FlowFixture.StartAsync();

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools")));

        Assert.False(payload.TryGetProperty("preferred_username", out _));
        Assert.False(payload.TryGetProperty("email", out _));
        Assert.Equal(SignedIn.Value, Claim(payload, "sub"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The token says what the person is
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The role reaches the access token, which is the whole point of storing one.
    /// </summary>
    /// <remarks>
    /// <c>role</c> is the claim name because that is the one
    /// <c>ResourceServerAuthenticator.FromClaims</c> reads by default. The two live in different
    /// assemblies with no compiler relationship, so this test is the only thing holding them to
    /// the same string.
    /// </remarks>
    [Fact]
    public async Task An_access_token_carries_the_role()
    {
        await using var fixture = await ServerNamingTheAccountAsync(role: "founder");

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools")));

        Assert.Equal("founder", Claim(payload, "role"));
    }

    /// <summary>No role on the account, no claim - rather than an empty string or a default.</summary>
    /// <remarks>
    /// An empty <c>role</c> claim is worse than an absent one: absent means "this server does not
    /// say", which a resource server answers with its own least-privileged fallback, while
    /// <c>""</c> is a value it has to be written to recognise.
    /// </remarks>
    [Fact]
    public async Task An_account_with_no_role_produces_no_role_claim()
    {
        await using var fixture = await ServerNamingTheAccountAsync();

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools")));

        Assert.False(payload.TryGetProperty("role", out _));

        // The rest still travelled, so this is the role being absent rather than the mapper.
        Assert.Equal(Handle, Claim(payload, "preferred_username"));
    }

    /// <summary>
    /// The role is not gated on a scope, unlike the address.
    /// </summary>
    /// <remarks>
    /// Deliberate asymmetry, pinned here because it looks like an oversight. An address is personal
    /// data the subject consents to release; a role is what the resource server needs in order to
    /// answer at all, and putting it behind a scope means a client that forgot to ask gets a token
    /// that authenticates and then reads nothing - which surfaces as an empty result set rather
    /// than as a missing scope.
    /// </remarks>
    [Fact]
    public async Task The_role_travels_without_the_email_scope()
    {
        await using var fixture = await ServerNamingTheAccountAsync(role: "employee");

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools")));

        Assert.Equal("employee", Claim(payload, "role"));
        Assert.False(payload.TryGetProperty("email", out _));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The address is scoped
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>No <c>email</c> scope, no address - even though the account has one.</summary>
    [Fact]
    public async Task The_address_stays_out_of_a_token_whose_grant_does_not_cover_it()
    {
        await using var fixture = await ServerNamingTheAccountAsync();

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools")));

        Assert.False(payload.TryGetProperty("email", out _));
        Assert.False(payload.TryGetProperty("email_verified", out _));

        // The handle still went out. The two are not released together on purpose: one is the
        // pseudonym the subject chose and already saw on the sign-in page, the other is a way to
        // reach them.
        Assert.Equal(Handle, Claim(payload, "preferred_username"));
    }

    /// <summary>With the scope, the address and its verification state travel together.</summary>
    [Fact]
    public async Task The_address_is_released_when_the_grant_covers_it()
    {
        await using var fixture = await ServerNamingTheAccountAsync();

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools email")));

        Assert.Equal(Address, Claim(payload, "email"));

        // Never one without the other. An absent `email_verified` reads as false to some clients
        // and as unknown to others, and a resource server deciding anything on an address wants to
        // know which it is looking at.
        Assert.True(payload.GetProperty("email_verified").GetBoolean());
    }

    /// <summary>An unverified address says so rather than being withheld or asserted.</summary>
    [Fact]
    public async Task An_unverified_address_is_released_marked_unverified()
    {
        await using var fixture = await ServerNamingTheAccountAsync(emailVerified: false);

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools email")));

        Assert.Equal(Address, Claim(payload, "email"));
        Assert.False(payload.GetProperty("email_verified").GetBoolean());
    }

    /// <summary>An account with no address produces no claim, rather than an empty one.</summary>
    [Fact]
    public async Task An_account_with_no_address_produces_no_claim()
    {
        await using var fixture = await ServerNamingTheAccountAsync(email: null);

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools email")));

        Assert.False(payload.TryGetProperty("email", out _));
        Assert.Equal(Handle, Claim(payload, "preferred_username"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The two issuing paths agree
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A refreshed token says exactly what the first one said.
    /// </summary>
    /// <remarks>
    /// The reason the mapper is called inside <c>TokenIssuer.MintAsync</c> rather than in the
    /// authorization-code handler. Calling it on one path only would give a client a token carrying
    /// a name for an hour and then, after the first silent refresh, one without - <c>TokenIssuer</c>'s
    /// own remarks call that the "it stopped working overnight" failure, and it is the shape hardest
    /// to attribute because nothing fails at the moment the behaviour changes.
    /// </remarks>
    [Fact]
    public async Task A_refreshed_token_carries_the_same_claims_as_the_first()
    {
        await using var fixture = await ServerNamingTheAccountAsync();

        var first = await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools email offline_access"));
        var refreshed = await RefreshAsync(fixture, await RefreshTokenAsync(first));

        var before = await PayloadAsync(first);
        var after = await PayloadAsync(refreshed);

        Assert.Equal(Claim(before, "preferred_username"), Claim(after, "preferred_username"));
        Assert.Equal(Claim(before, "email"), Claim(after, "email"));
        Assert.Equal(
            before.GetProperty("email_verified").GetBoolean(),
            after.GetProperty("email_verified").GetBoolean());

        Assert.Equal(Handle, Claim(after, "preferred_username"));
        Assert.Equal(Address, Claim(after, "email"));
    }

    /// <summary>A refresh that narrows away <c>email</c> stops releasing the address.</summary>
    /// <remarks>
    /// The mapper reads the scope of <i>this</i> issuance, not the scope the grant was created
    /// with. A client that narrows is asking for less, and a token that kept releasing the address
    /// would be answering the request it preferred.
    /// </remarks>
    [Fact]
    public async Task Narrowing_away_the_email_scope_on_refresh_withholds_the_address()
    {
        await using var fixture = await ServerNamingTheAccountAsync();

        var first = await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools email offline_access"));
        Assert.Equal(Address, Claim(await PayloadAsync(first), "email"));

        var narrowed = await fixture.Client.PostAsync("/token", new FormUrlEncodedContent(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = await RefreshTokenAsync(first),
                ["client_id"] = "https://claude.ai/.well-known/oauth-client",
                ["scope"] = "mcp:tools",
            }));

        var payload = await PayloadAsync(narrowed);

        Assert.False(payload.TryGetProperty("email", out _));
        Assert.Equal(Handle, Claim(payload, "preferred_username"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The mapper is not a way in
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A grant can outlive the account it was issued for, and that is not an outage.
    /// </summary>
    /// <remarks>
    /// A user deleted between sign-in and refresh. Failing the exchange here would turn a tidy-up
    /// into a token endpoint returning 500 on a path that has nothing to do with the deletion -
    /// and the grant is still valid for what it says. It just says less.
    /// </remarks>
    [Fact]
    public async Task A_grant_whose_account_is_gone_still_issues_a_token()
    {
        await using var fixture = await ServerNamingTheAccountAsync(withAccount: false);

        var payload = await PayloadAsync(await ExchangeAsync(fixture, await CodeAsync(fixture, "mcp:tools email")));

        Assert.False(payload.TryGetProperty("preferred_username", out _));
        Assert.False(payload.TryGetProperty("email", out _));
        Assert.Equal(SignedIn.Value, Claim(payload, "sub"));
    }

    /// <summary>
    /// A mapper cannot restate a protocol claim, and the refusal stops the token.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what keeps <see cref="IAccessTokenClaims"/> a convenience rather than an escalation
    /// seam. A mapper able to set <c>sub</c> would let whoever wrote it mint a token for anybody;
    /// one able to set <c>aud</c> or <c>scope</c> would defeat the audience binding and the consent
    /// the rest of this server exists to enforce.
    /// </para>
    /// <para>
    /// Driven through the whole flow rather than against the minter alone, because the property
    /// being pinned is that <b>nothing between the mapper and the wire re-adds the claim or
    /// swallows the refusal</b>. Every one of the four is asserted separately: a loop that stopped
    /// at the first would pass with three of them removed from the reserved set.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("sub")]
    [InlineData("aud")]
    [InlineData("scope")]
    [InlineData("client_id")]
    public async Task A_mapper_cannot_restate_a_protocol_claim(string claim)
    {
        const string Forged = "forged-by-the-mapper";

        await using var fixture = await FlowFixture.StartAsync(seed =>
            seed.ConfigureServices = services =>
                services.AddSingleton<IAccessTokenClaims>(new HostileClaims(claim, Forged)));

        var code = await CodeAsync(fixture, "mcp:tools");

        // Either shape is an acceptable outcome and both are the same event: the exchange did not
        // produce a token. TestServer surfaces an unhandled pipeline exception to the caller, so
        // which one arrives depends on the host's error handling rather than on this guarantee.
        var body = string.Empty;

        try
        {
            var response = await ExchangeAsync(fixture, code);
            body = await response.Content.ReadAsStringAsync();

            Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        }
        catch (InvalidOperationException refused)
        {
            Assert.Contains("protocol claim", refused.Message, StringComparison.Ordinal);
        }

        // And the forged value is nowhere on the wire, whichever way it came out.
        Assert.DoesNotContain(Forged, body, StringComparison.Ordinal);
    }

    private sealed class HostileClaims(string name, string value) : IAccessTokenClaims
    {
        public ValueTask<IReadOnlyDictionary<string, object?>> ForAsync(
            SubjectId subject, ScopeSet scope, CancellationToken ct = default) =>
            ValueTask.FromResult<IReadOnlyDictionary<string, object?>>(
                new Dictionary<string, object?>(StringComparer.Ordinal) { [name] = value });
    }
}
